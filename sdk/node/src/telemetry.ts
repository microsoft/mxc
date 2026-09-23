// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import {
  readTelemetryConsentStatusJsonAsync,
  TELEMETRY_CONSENT_DECISION_DISMISSED,
  TELEMETRY_CONSENT_DECISION_NO,
  TELEMETRY_CONSENT_DECISION_YES,
  withdrawTelemetryConsentJsonAsync,
} from './bindings/telemetry.js';
import { runTelemetryConsentRequestAsync } from './bindings/telemetry-request-worker.js';
import { MxcError } from './errors.js';

const TELEMETRY_CONSENT_STATES = ['granted', 'denied', 'undetermined', 'not-applicable'] as const;
const TELEMETRY_POLICY_STATES = ['unrestricted', 'allowed', 'blocked', 'not-applicable'] as const;
const TELEMETRY_CONSENT_DECISIONS = ['yes', 'no', 'dismissed'] as const;
const TELEMETRY_CONSENT_RESULTS = [
  'granted',
  'denied',
  'dismissed',
  'withdrawn',
  'alreadyGranted',
  'policyBlocked',
  'presentationUnavailable',
  'notApplicable',
] as const;
const CONSENT_STATUS_REASONS = [
  'no-record',
  'store-unreadable',
  'store-malformed',
  'consent-schema-unsupported',
  'prompt-version-missing',
  'prompt-version-unsupported',
  'policy-blocked',
  'presentation-unavailable',
  'not-applicable',
] as const;

export type TelemetryConsentState = (typeof TELEMETRY_CONSENT_STATES)[number];
export type TelemetryPolicyState = (typeof TELEMETRY_POLICY_STATES)[number];
export type TelemetryConsentDecision = (typeof TELEMETRY_CONSENT_DECISIONS)[number];
export type TelemetryConsentResult = (typeof TELEMETRY_CONSENT_RESULTS)[number];
type ConsentStatusReason = (typeof CONSENT_STATUS_REASONS)[number];

export interface TelemetryConsentMessage {
  id: string;
  text: string;
}

export interface TelemetryConsentPrompt {
  resourceVersion: number;
  locale: string;
  title: TelemetryConsentMessage;
  body: TelemetryConsentMessage;
  affirmativeLabel: TelemetryConsentMessage;
  negativeLabel: TelemetryConsentMessage;
  learnMoreLabel: TelemetryConsentMessage;
  learnMoreUrl: string;
}

export interface TelemetryConsentOutcome {
  action: 'request' | 'withdraw';
  result: TelemetryConsentResult;
  storedState: TelemetryConsentState;
  effectiveState: TelemetryConsentState;
  policy: TelemetryPolicyState;
  needsPrompt: boolean;
}

export type TelemetryConsentPresenter = (
  prompt: TelemetryConsentPrompt,
  signal?: AbortSignal,
) => TelemetryConsentDecision | Promise<TelemetryConsentDecision>;

export interface TelemetryConsentQuery {
  state: TelemetryConsentState;
  storedState: TelemetryConsentState;
  effectiveState: TelemetryConsentState;
  needsPrompt: boolean;
  policy: TelemetryPolicyState;
  error?: string;
}

interface TelemetryConsentStatusPayload {
  storedState: TelemetryConsentState;
  effectiveState: TelemetryConsentState;
  policy: TelemetryPolicyState;
  reason: ConsentStatusReason | null;
}

const MAX_REPORTED_FAILURE_CATEGORIES = 64;
const MAX_DIAGNOSTIC_LENGTH = 512;
const reportedFailureCategories = new Set<string>();
let platformOverride: NodeJS.Platform | null = null;

/** @internal Test-only. */
export function _setTelemetryPlatform(platform: NodeJS.Platform | null): void {
  platformOverride = platform;
}

/** @internal Test-only. */
export function _resetTelemetryFailureReporting(): void {
  reportedFailureCategories.clear();
}

function isWindows(): boolean {
  return (platformOverride ?? process.platform) === 'win32';
}

function includes<T extends string>(values: readonly T[], value: unknown): value is T {
  return typeof value === 'string' && values.includes(value as T);
}

function isConsentState(value: unknown): value is TelemetryConsentState {
  return includes(TELEMETRY_CONSENT_STATES, value);
}

function isPolicyState(value: unknown): value is TelemetryPolicyState {
  return includes(TELEMETRY_POLICY_STATES, value);
}

function isDecision(value: unknown): value is TelemetryConsentDecision {
  return includes(TELEMETRY_CONSENT_DECISIONS, value);
}

function isStatusReason(value: unknown): value is ConsentStatusReason {
  return includes(CONSENT_STATUS_REASONS, value);
}

function isConsentMessage(value: unknown): value is TelemetryConsentMessage {
  if (value === null || typeof value !== 'object') {
    return false;
  }
  const message = value as Record<string, unknown>;
  return typeof message.id === 'string' && typeof message.text === 'string';
}

function isConsentPrompt(value: unknown): value is TelemetryConsentPrompt {
  if (value === null || typeof value !== 'object') {
    return false;
  }
  const prompt = value as Record<string, unknown>;
  return Number.isSafeInteger(prompt.resourceVersion)
    && (prompt.resourceVersion as number) > 0
    && typeof prompt.locale === 'string'
    && isConsentMessage(prompt.title)
    && isConsentMessage(prompt.body)
    && isConsentMessage(prompt.affirmativeLabel)
    && isConsentMessage(prompt.negativeLabel)
    && isConsentMessage(prompt.learnMoreLabel)
    && typeof prompt.learnMoreUrl === 'string';
}

function isRequestResult(value: unknown): value is TelemetryConsentResult {
  return value === 'granted'
    || value === 'denied'
    || value === 'dismissed'
    || value === 'alreadyGranted'
    || value === 'policyBlocked'
    || value === 'notApplicable';
}

function isWithdrawResult(value: unknown): value is TelemetryConsentResult {
  return value === 'withdrawn' || value === 'notApplicable';
}

function shouldPrompt(
  effectiveState: TelemetryConsentState,
  policy: TelemetryPolicyState,
): boolean {
  return effectiveState === 'undetermined'
    && (policy === 'unrestricted' || policy === 'allowed');
}

function invalidTelemetryOutput(detail: string): Error {
  return new Error(`unrecognised telemetry consent output: ${detail.trim().slice(0, 200)}`);
}

function parseStatusPayload(json: string): TelemetryConsentStatusPayload {
  const parsed: unknown = JSON.parse(json);
  if (parsed === null || typeof parsed !== 'object') {
    throw invalidTelemetryOutput(json);
  }
  const value = parsed as Record<string, unknown>;
  if (
    !isConsentState(value.storedState)
    || !isConsentState(value.effectiveState)
    || !isPolicyState(value.policy)
    || !Object.hasOwn(value, 'reason')
    || (value.reason !== null && !isStatusReason(value.reason))
  ) {
    throw invalidTelemetryOutput(json);
  }
  return {
    storedState: value.storedState,
    effectiveState: value.effectiveState,
    policy: value.policy,
    reason: value.reason,
  };
}

function parseConsentOutcome(
  json: string,
  action: 'request' | 'withdraw',
): TelemetryConsentOutcome {
  const parsed: unknown = JSON.parse(json);
  if (parsed === null || typeof parsed !== 'object') {
    throw invalidTelemetryOutput(json);
  }
  const value = parsed as Record<string, unknown>;
  const status = parseStatusPayload(json);
  let result: TelemetryConsentResult;
  if (action === 'request') {
    if (!isRequestResult(value.result)) {
      throw invalidTelemetryOutput(json);
    }
    result = value.result;
  } else {
    if (!isWithdrawResult(value.result)) {
      throw invalidTelemetryOutput(json);
    }
    result = value.result;
  }
  return {
    action,
    result,
    storedState: status.storedState,
    effectiveState: status.effectiveState,
    policy: status.policy,
    needsPrompt: shouldPrompt(status.effectiveState, status.policy),
  };
}

function parseConsentPromptJson(promptJson: string): TelemetryConsentPrompt {
  const parsed: unknown = JSON.parse(promptJson);
  if (!isConsentPrompt(parsed)) {
    throw invalidTelemetryOutput(promptJson);
  }
  return parsed;
}

function decisionCode(decision: TelemetryConsentDecision): number {
  switch (decision) {
    case 'yes':
      return TELEMETRY_CONSENT_DECISION_YES;
    case 'no':
      return TELEMETRY_CONSENT_DECISION_NO;
    case 'dismissed':
      return TELEMETRY_CONSENT_DECISION_DISMISSED;
  }
}

function tryRegisterFailureCategory(category: string): boolean {
  if (
    reportedFailureCategories.has(category)
    || reportedFailureCategories.size >= MAX_REPORTED_FAILURE_CATEGORIES
  ) {
    return false;
  }
  reportedFailureCategories.add(category);
  return true;
}

function boundedDiagnostic(detail: string): string {
  const normalized = detail.replace(/\s+/g, ' ').trim();
  return normalized.length <= MAX_DIAGNOSTIC_LENGTH
    ? normalized
    : `${normalized.slice(0, MAX_DIAGNOSTIC_LENGTH)}...`;
}

function reportFailClosed(operation: string, safeResult: string, detail: string): void {
  try {
    const category = `${operation}:${safeResult}:failure`;
    if (tryRegisterFailureCategory(category)) {
      console.warn(
        `mxc-sdk: ${operation} failed and is reporting '${safeResult}' to stay fail-closed: ${boundedDiagnostic(detail)}`,
      );
    }
  } catch {
    // Reporting must not affect the fail-closed result.
  }
}

function notApplicable(action: 'request' | 'withdraw'): TelemetryConsentOutcome {
  return {
    action,
    result: 'notApplicable',
    storedState: 'not-applicable',
    effectiveState: 'not-applicable',
    needsPrompt: false,
    policy: 'not-applicable',
  };
}

function failedConsentQuery(operation: string, error: unknown): TelemetryConsentQuery {
  const detail = error instanceof Error ? error.message : String(error);
  reportFailClosed(operation, 'undetermined', detail);
  return {
    state: 'undetermined',
    storedState: 'undetermined',
    effectiveState: 'undetermined',
    needsPrompt: false,
    policy: 'blocked',
    error: `failed to read telemetry consent: ${detail}`,
  };
}

function validateLocale(locale?: string): void {
  if (locale?.includes('\0')) {
    throw new Error('Telemetry consent locale cannot contain embedded NUL characters.');
  }
}

async function presentConsentDecision(
  presenter: TelemetryConsentPresenter,
  promptJson: string,
  signal: AbortSignal,
): Promise<number> {
  const prompt = parseConsentPromptJson(promptJson);
  const decision = await presenter(prompt, signal);
  if (!isDecision(decision)) {
    throw new Error(`consent presenter returned invalid decision '${String(decision)}'`);
  }
  return decisionCode(decision);
}

/** Read persisted/effective consent and policy without blocking the event loop. */
export async function queryTelemetryConsentAsync(): Promise<TelemetryConsentQuery> {
  if (!isWindows()) {
    return {
      state: 'not-applicable',
      storedState: 'not-applicable',
      effectiveState: 'not-applicable',
      needsPrompt: false,
      policy: 'not-applicable',
    };
  }
  try {
    const status = parseStatusPayload(await readTelemetryConsentStatusJsonAsync());
    return {
      state: status.effectiveState,
      storedState: status.storedState,
      effectiveState: status.effectiveState,
      needsPrompt: shouldPrompt(status.effectiveState, status.policy),
      policy: status.policy,
    };
  } catch (error) {
    return failedConsentQuery('queryTelemetryConsentAsync', error);
  }
}

/** Request consent with the versioned canonical consent resource. */
export async function requestTelemetryConsent(
  presenter: TelemetryConsentPresenter,
  locale?: string,
): Promise<TelemetryConsentOutcome> {
  if (!isWindows()) {
    return notApplicable('request');
  }
  validateLocale(locale);
  const json = await runTelemetryConsentRequestAsync(
    locale,
    (promptJson, signal) => presentConsentDecision(presenter, promptJson, signal),
  );
  return parseConsentOutcome(json, 'request');
}

/** Idempotently withdraw telemetry consent without blocking the event loop. */
export async function withdrawTelemetryConsentAsync(): Promise<TelemetryConsentOutcome> {
  if (!isWindows()) {
    return notApplicable('withdraw');
  }
  try {
    const json = await withdrawTelemetryConsentJsonAsync();
    return parseConsentOutcome(json, 'withdraw');
  } catch (error) {
    if (error instanceof MxcError) {
      throw error;
    }
    throw new Error(
      `failed to withdraw telemetry consent: ${error instanceof Error ? error.message : String(error)}`,
      { cause: error instanceof Error ? error : undefined },
    );
  }
}
