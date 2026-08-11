// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { execFileSync, spawn } from 'node:child_process';
import type {
  TelemetryConsentDecision as WireConsentDecision,
  TelemetryConsentMaintenanceRequest,
  TelemetryConsentMaintenanceResponse,
  TelemetryConsentPolicyState,
  TelemetryConsentPrompt as WireConsentPrompt,
  TelemetryConsentResult,
  TelemetryConsentState,
  TelemetryConsentStatusReason,
} from './generated/telemetry-consent-wire.js';
import { findWxcExecutable } from './platform.js';

export type {
  TelemetryConsentPolicyState as TelemetryPolicyState,
  TelemetryConsentState,
  TelemetryConsentStatusReason,
};
export type TelemetryConsentPrompt = WireConsentPrompt;
export type TelemetryConsentDecision = WireConsentDecision;
export type TelemetryConsentOutcome = TelemetryConsentMaintenanceResponse;
export type TelemetryConsentPresenter = (
  prompt: TelemetryConsentPrompt,
) => TelemetryConsentDecision | Promise<TelemetryConsentDecision>;

export interface TelemetryConsentQuery {
  state: TelemetryConsentState;
  storedState: TelemetryConsentState;
  effectiveState: TelemetryConsentState;
  needsPrompt: boolean;
  policy: TelemetryConsentPolicyState;
  reason?: TelemetryConsentStatusReason;
  error?: string;
}

type ConsentRunner = (args: readonly string[]) => string;
type ConsentProtocolRunner = (
  locale: string | undefined,
  presenter: TelemetryConsentPresenter,
) => Promise<TelemetryConsentMaintenanceResponse>;

const CONSENT_REQUEST_TIMEOUT_MS = 30_000;

function maintenanceRequest(
  action: 'request' | 'withdraw' | 'status',
  locale?: string,
): TelemetryConsentMaintenanceRequest {
  return {
    command: 'telemetryConsent',
    action,
    ...(locale === undefined ? {} : { locale }),
  };
}

function maintenanceArgs(action: 'request' | 'withdraw' | 'status', locale?: string): string[] {
  const payload = Buffer.from(JSON.stringify(maintenanceRequest(action, locale)), 'utf8').toString('base64');
  return ['--config-base64', payload];
}

function executable(): string {
  const path = findWxcExecutable();
  if (!path) {
    throw new Error('wxc-exec was not found; the MXC native binary is missing from this installation');
  }
  return path;
}

function defaultConsentRunner(args: readonly string[]): string {
  return execFileSync(executable(), args, {
    timeout: 5000,
    encoding: 'utf-8',
    stdio: ['ignore', 'pipe', 'pipe'],
  });
}

async function defaultConsentProtocolRunner(
  locale: string | undefined,
  presenter: TelemetryConsentPresenter,
): Promise<TelemetryConsentMaintenanceResponse> {
  return new Promise((resolve, reject) => {
    const child = spawn(executable(), maintenanceArgs('request', locale), {
      env: { ...process.env, MXC_TELEMETRY_CONSENT_PRESENTER_PROTOCOL: '1' },
      stdio: ['pipe', 'pipe', 'pipe'],
      windowsHide: true,
    });
    let stdout = '';
    let stderr = '';
    let finalResponse: TelemetryConsentMaintenanceResponse | undefined;
    let presenterFailure: unknown;
    let settled = false;
    const timeout = setTimeout(() => {
      settled = true;
      child.kill();
      reject(new Error('telemetry consent request timed out'));
    }, CONSENT_REQUEST_TIMEOUT_MS);

    const fail = (error: unknown): void => {
      if (!settled) {
        settled = true;
        clearTimeout(timeout);
        reject(error instanceof Error ? error : new Error(String(error)));
      }
    };

    const processLine = async (line: string): Promise<void> => {
      if (line.trim() === '') return;
      let response: TelemetryConsentMaintenanceResponse;
      try {
        response = parseMaintenanceResponse(line);
      } catch (error) {
        fail(error);
        child.kill();
        return;
      }

      if (response.result !== 'presentationRequired') {
        finalResponse = response;
        return;
      }
      if (!response.prompt || !response.challenge) {
        fail(new Error('telemetry consent presentation omitted its prompt or challenge'));
        child.kill();
        return;
      }

      let decision: TelemetryConsentDecision = 'dismissed';
      try {
        decision = await presenter(response.prompt);
        if (!isDecision(decision)) {
          throw new Error(`consent presenter returned invalid decision '${String(decision)}'`);
        }
      } catch (error) {
        presenterFailure = error;
      }
      if (settled) {
        return;
      }
      child.stdin.write(`${JSON.stringify({
        challenge: response.challenge,
        resourceVersion: response.prompt.resourceVersion,
        decision,
      })}\n`);
      child.stdin.end();
    };

    child.stdout.setEncoding('utf8');
    child.stdout.on('data', (chunk: string) => {
      stdout += chunk;
      const lines = stdout.split(/\r?\n/);
      stdout = lines.pop() ?? '';
      for (const line of lines) {
        void processLine(line);
      }
    });
    child.stderr.setEncoding('utf8');
    child.stderr.on('data', (chunk: string) => {
      stderr += chunk;
    });
    child.stdin.on('error', (error) => {
      if (!settled) {
        fail(error);
      }
    });
    child.on('error', fail);
    child.on('close', (code) => {
      if (settled) return;
      clearTimeout(timeout);
      if (stdout.trim() !== '') {
        try {
          finalResponse = parseMaintenanceResponse(stdout);
        } catch (error) {
          fail(error);
          return;
        }
      }
      if (presenterFailure !== undefined) {
        fail(new Error(
          `telemetry consent presenter failed: ${
            presenterFailure instanceof Error ? presenterFailure.message : String(presenterFailure)
          }`,
        ));
        return;
      }
      if (code !== 0 || finalResponse === undefined) {
        fail(new Error(`telemetry consent process failed (${code ?? 'no exit code'}): ${stderr.trim()}`));
        return;
      }
      settled = true;
      resolve(finalResponse);
    });
  });
}

let consentRunner: ConsentRunner = defaultConsentRunner;
let protocolRunner: ConsentProtocolRunner = defaultConsentProtocolRunner;
let platformOverride: NodeJS.Platform | null = null;

/** @internal Test-only. */
export function _setTelemetryConsentRunner(runner: ConsentRunner | null): void {
  consentRunner = runner ?? defaultConsentRunner;
}

/** @internal Test-only. */
export function _setTelemetryConsentProtocolRunner(runner: ConsentProtocolRunner | null): void {
  protocolRunner = runner ?? defaultConsentProtocolRunner;
}

/** @internal Test-only. */
export function _setTelemetryPlatform(platform: NodeJS.Platform | null): void {
  platformOverride = platform;
}

function isWindows(): boolean {
  return (platformOverride ?? process.platform) === 'win32';
}

function isConsentState(value: unknown): value is TelemetryConsentState {
  return value === 'granted' || value === 'denied' || value === 'undetermined' || value === 'not-applicable';
}

function isPolicyState(value: unknown): value is TelemetryConsentPolicyState {
  return value === 'unrestricted' || value === 'allowed' || value === 'blocked' || value === 'not-applicable';
}

function isDecision(value: unknown): value is TelemetryConsentDecision {
  return value === 'yes' || value === 'no' || value === 'dismissed';
}

function isResult(value: unknown): value is TelemetryConsentResult {
  return [
    'status',
    'presentationRequired',
    'granted',
    'denied',
    'dismissed',
    'withdrawn',
    'alreadyGranted',
    'policyBlocked',
    'presentationUnavailable',
    'notApplicable',
  ].includes(value as string);
}

function parseMaintenanceResponse(stdout: string): TelemetryConsentMaintenanceResponse {
  const parsed: unknown = JSON.parse(stdout);
  if (parsed === null || typeof parsed !== 'object') {
    throw new Error('unrecognised telemetry consent output');
  }
  const value = parsed as Record<string, unknown>;
  if (
    !isConsentState(value.storedState)
    || !isConsentState(value.effectiveState)
    || !isPolicyState(value.policy)
    || !isResult(value.result)
    || typeof value.needsPrompt !== 'boolean'
  ) {
    throw new Error(`unrecognised telemetry consent output: ${stdout.trim().slice(0, 200)}`);
  }
  return parsed as TelemetryConsentMaintenanceResponse;
}

const reportedFailures = new Set<string>();

function reportFailClosed(operation: string, safeResult: string, detail: string): void {
  try {
    const message = `mxc-sdk: ${operation} failed and is reporting '${safeResult}' to stay fail-closed: ${detail}`;
    if (!reportedFailures.has(message)) {
      reportedFailures.add(message);
      console.warn(message);
    }
  } catch {
    // Diagnostics must never break a fail-closed status query.
  }
}

/** @internal Test-only. */
export function _resetTelemetryFailureReporting(): void {
  reportedFailures.clear();
}

function notApplicable(action: 'request' | 'withdraw' | 'status'): TelemetryConsentMaintenanceResponse {
  return {
    action,
    result: 'notApplicable',
    storedState: 'not-applicable',
    effectiveState: 'not-applicable',
    needsPrompt: false,
    policy: 'not-applicable',
    reason: 'not-applicable',
  };
}

/** Read persisted/effective consent and policy. Never throws. */
export function queryTelemetryConsent(): TelemetryConsentQuery {
  if (!isWindows()) {
    return {
      state: 'not-applicable',
      storedState: 'not-applicable',
      effectiveState: 'not-applicable',
      needsPrompt: false,
      policy: 'not-applicable',
      reason: 'not-applicable',
    };
  }
  try {
    const response = parseMaintenanceResponse(consentRunner(maintenanceArgs('status')));
    return {
      state: response.effectiveState,
      storedState: response.storedState,
      effectiveState: response.effectiveState,
      needsPrompt: response.needsPrompt && response.policy !== 'blocked',
      policy: response.policy,
      ...(response.reason === undefined || response.reason === null ? {} : { reason: response.reason }),
    };
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    reportFailClosed('queryTelemetryConsent', 'undetermined', detail);
    return {
      state: 'undetermined',
      storedState: 'undetermined',
      effectiveState: 'undetermined',
      needsPrompt: false,
      policy: 'blocked',
      reason: 'store-unreadable',
      error: `failed to read telemetry consent: ${detail}`,
    };
  }
}

export function getTelemetryConsent(): TelemetryConsentState {
  return queryTelemetryConsent().effectiveState;
}

export function needsTelemetryConsentPrompt(): boolean {
  return queryTelemetryConsent().needsPrompt;
}

export function getTelemetryPolicy(): TelemetryConsentPolicyState {
  return queryTelemetryConsent().policy;
}

/**
 * Request consent through the private, session-bound executor protocol.
 * The presenter must render every supplied prompt field verbatim.
 */
export async function requestTelemetryConsent(
  presenter: TelemetryConsentPresenter,
  locale?: string,
): Promise<TelemetryConsentOutcome> {
  if (!isWindows()) {
    return notApplicable('request');
  }
  return protocolRunner(locale, presenter);
}

/** Idempotently withdraw telemetry consent. */
export function withdrawTelemetryConsent(): TelemetryConsentOutcome {
  if (!isWindows()) {
    return notApplicable('withdraw');
  }
  try {
    return parseMaintenanceResponse(consentRunner(maintenanceArgs('withdraw')));
  } catch (error) {
    throw new Error(
      `failed to withdraw telemetry consent: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}
