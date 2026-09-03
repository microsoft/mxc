// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { execFile, spawn } from 'node:child_process';
import { findWxcExecutable } from './platform.js';

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
const CONSENT_PROTOCOL_RESULTS = [
  'status',
  'presentationRequired',
  ...TELEMETRY_CONSENT_RESULTS,
] as const;

export type TelemetryConsentState = (typeof TELEMETRY_CONSENT_STATES)[number];
export type TelemetryPolicyState = (typeof TELEMETRY_POLICY_STATES)[number];
export type TelemetryConsentDecision = (typeof TELEMETRY_CONSENT_DECISIONS)[number];
export type TelemetryConsentResult = (typeof TELEMETRY_CONSENT_RESULTS)[number];
type ConsentStatusReason = (typeof CONSENT_STATUS_REASONS)[number];
type TelemetryConsentProtocolResult = (typeof CONSENT_PROTOCOL_RESULTS)[number];

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

interface TelemetryConsentProtocolResponse
  extends Omit<TelemetryConsentOutcome, 'action' | 'result'> {
  action: ConsentAction;
  result: TelemetryConsentProtocolResult;
  reason?: ConsentStatusReason | null;
  prompt?: TelemetryConsentPrompt | null;
  challenge?: string | null;
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

interface ConsentCommandOutput {
  stdout: string;
  stderr: string;
}

type ConsentAsyncRunner = (args: readonly string[]) => Promise<ConsentCommandOutput>;
type ConsentAction = 'request' | 'withdraw' | 'status';
type ConsentProtocolRunner = (
  locale: string | undefined,
  presenter: TelemetryConsentPresenter,
) => Promise<TelemetryConsentOutcome>;
type ConsentChildFactory = (args: readonly string[]) => ReturnType<typeof spawn>;

const DEFAULT_CONSENT_REQUEST_TIMEOUT_MS = 30_000;
const MAX_CONSENT_STDOUT_BYTES = 1024 * 1024;
const MAX_CONSENT_STDERR_BYTES = 64 * 1024;
const MAX_CONSENT_PROTOCOL_LINES = 16;
let consentRequestTimeoutMs = DEFAULT_CONSENT_REQUEST_TIMEOUT_MS;
const defaultConsentChildFactory: ConsentChildFactory = (args) =>
  spawn(executable(), [...args], {
    env: process.env,
    stdio: ['pipe', 'pipe', 'pipe'],
    windowsHide: true,
  });
let consentChildFactory: ConsentChildFactory = defaultConsentChildFactory;

function maintenanceArgs(action: 'request' | 'withdraw' | 'status', locale?: string): string[] {
  const args = ['--telemetry-consent', action];
  if (action === 'request') {
    if (locale !== undefined) {
      args.push(`--telemetry-consent-locale=${locale}`);
    }
  }
  return args;
}

function executable(): string {
  const path = findWxcExecutable();
  if (!path) {
    throw new Error('wxc-exec was not found; the MXC native binary is missing from this installation');
  }
  return path;
}

function defaultConsentAsyncRunner(args: readonly string[]): Promise<ConsentCommandOutput> {
  return new Promise((resolve, reject) => {
    execFile(
      executable(),
      [...args],
      {
        timeout: 5000,
        encoding: 'utf-8',
        windowsHide: true,
      },
      (error, stdout, stderr) => {
        if (error) {
          reject(error);
        } else {
          resolve({ stdout, stderr });
        }
      },
    );
  });
}

async function defaultConsentProtocolRunner(
  locale: string | undefined,
  presenter: TelemetryConsentPresenter,
): Promise<TelemetryConsentOutcome> {
  return new Promise((resolve, reject) => {
    const child = consentChildFactory(maintenanceArgs('request', locale));
    const childStdin = child.stdin;
    const childStdout = child.stdout;
    const childStderr = child.stderr;
    if (childStdin === null || childStdout === null || childStderr === null) {
      child.kill();
      reject(new Error('telemetry consent process did not expose stdio pipes'));
      return;
    }
    let stdout = '';
    let stderr = '';
    let finalResponse: TelemetryConsentOutcome | undefined;
    let presentationSeen = false;
    let terminalSeen = false;
    let settled = false;
    let timeout: NodeJS.Timeout | null = null;
    let timeoutStartedAt = 0;
    let timeoutRemainingMs = consentRequestTimeoutMs;
    let lineQueue: Promise<void> = Promise.resolve();
    let childKilled = false;
    let stdoutBytes = 0;
    let stderrBytes = 0;
    let protocolLines = 0;
    let childExitCode: number | null | undefined;
    const presenterAbort = new AbortController();
    let rejectPresenterWait: ((error: Error) => void) | undefined;

    const clearProtocolDeadline = (): void => {
      if (timeout !== null) {
        clearTimeout(timeout);
        timeout = null;
      }
    };
    const pauseProtocolDeadline = (): void => {
      if (timeout !== null) {
        timeoutRemainingMs -= Date.now() - timeoutStartedAt;
        clearProtocolDeadline();
      }
    };
    const resumeProtocolDeadline = (): void => {
      if (settled) {
        return;
      }
      clearProtocolDeadline();
      if (timeoutRemainingMs <= 0) {
        fail(new Error('telemetry consent request timed out'));
        return;
      }
      timeoutStartedAt = Date.now();
      timeout = setTimeout(() => {
        fail(new Error('telemetry consent request timed out'));
      }, timeoutRemainingMs);
    };

    const fail = (error: unknown): void => {
      if (!settled) {
        settled = true;
        clearProtocolDeadline();
        presenterAbort.abort();
        rejectPresenterWait?.(
          error instanceof Error ? error : new Error(String(error)),
        );
        rejectPresenterWait = undefined;
        if (!childKilled) {
          childKilled = true;
          child.kill();
        }
        reject(error instanceof Error ? error : new Error(String(error)));
      }
    };
    resumeProtocolDeadline();

    const processLine = async (line: string): Promise<void> => {
      if (settled) {
        return;
      }
      if (line.trim() === '') return;
      let response: TelemetryConsentProtocolResponse;
      try {
        response = parseMaintenanceResponse(line, 'request');
      } catch (error) {
        fail(error);
        return;
      }

      if (response.result !== 'presentationRequired') {
        if (terminalSeen) {
          fail(new Error('telemetry consent protocol emitted multiple terminal responses'));
          return;
        }
        terminalSeen = true;
        finalResponse = toConsentOutcome(response);
        return;
      }
      if (terminalSeen) {
        fail(new Error('telemetry consent protocol emitted a presentation after its terminal response'));
        return;
      }
      if (presentationSeen) {
        fail(new Error('telemetry consent protocol emitted multiple presentations'));
        return;
      }
      presentationSeen = true;
      if (!isConsentPrompt(response.prompt) || !isChallenge(response.challenge)) {
        fail(new Error('telemetry consent presentation omitted its prompt or challenge'));
        return;
      }
      if (childExitCode !== undefined) {
        fail(new Error(
          `telemetry consent process exited before presentation completed (${childExitCode ?? 'no exit code'})`,
        ));
        return;
      }

      let decision: TelemetryConsentDecision = 'dismissed';
      pauseProtocolDeadline();
      try {
        const processEnded = new Promise<never>((_resolve, reject) => {
          rejectPresenterWait = reject;
        });
        decision = await Promise.race([
          Promise.resolve(presenter(response.prompt, presenterAbort.signal)),
          processEnded,
        ]);
        if (!isDecision(decision)) {
          throw new Error(`consent presenter returned invalid decision '${String(decision)}'`);
        }
      } catch (error) {
        rejectPresenterWait = undefined;
        fail(error);
        return;
      } finally {
        rejectPresenterWait = undefined;
      }
      if (settled) {
        return;
      }
      resumeProtocolDeadline();
      childStdin.write(`${JSON.stringify({
        challenge: response.challenge,
        resourceVersion: response.prompt.resourceVersion,
        decision,
      })}\n`);
      childStdin.end();
    };

    childStdout.setEncoding('utf8');
    childStdout.on('data', (chunk: string) => {
      if (settled) {
        return;
      }
      stdoutBytes += Buffer.byteLength(chunk, 'utf8');
      if (stdoutBytes > MAX_CONSENT_STDOUT_BYTES) {
        fail(new Error('telemetry consent process exceeded the stdout limit'));
        return;
      }
      stdout += chunk;
      const lines = stdout.split(/\r?\n/);
      stdout = lines.pop() ?? '';
      for (const line of lines) {
        protocolLines += 1;
        if (protocolLines > MAX_CONSENT_PROTOCOL_LINES) {
          fail(new Error('telemetry consent process exceeded the protocol line limit'));
          return;
        }
        lineQueue = lineQueue
          .then(() => processLine(line))
          .catch(fail);
      }
    });
    childStdout.on('error', fail);
    childStderr.setEncoding('utf8');
    childStderr.on('data', (chunk: string) => {
      if (settled) {
        return;
      }
      stderrBytes += Buffer.byteLength(chunk, 'utf8');
      if (stderrBytes > MAX_CONSENT_STDERR_BYTES) {
        fail(new Error('telemetry consent process exceeded the stderr limit'));
        return;
      }
      stderr += chunk;
    });
    childStderr.on('error', fail);
    childStdin.on('error', (error) => {
      if (!settled) {
        fail(error);
      }
    });
    child.on('error', fail);
    child.on('close', (code) => {
      childExitCode = code;
      if (rejectPresenterWait !== undefined) {
        presenterAbort.abort();
        rejectPresenterWait(
          new Error(`telemetry consent process exited before presentation completed (${code ?? 'no exit code'})`),
        );
        rejectPresenterWait = undefined;
      }
      void (async (): Promise<void> => {
        await lineQueue;
        if (settled) return;
        clearProtocolDeadline();
        if (stdout.trim() !== '') {
          protocolLines += 1;
          if (protocolLines > MAX_CONSENT_PROTOCOL_LINES) {
            fail(new Error('telemetry consent process exceeded the protocol line limit'));
            return;
          }
          await processLine(stdout);
          if (settled) return;
        }
        if (code !== 0 || finalResponse === undefined) {
          fail(new Error(`telemetry consent process failed (${code ?? 'no exit code'}): ${stderr.trim()}`));
          return;
        }
        reportNativeDiagnostic('requestTelemetryConsent', stderr);
        settled = true;
        resolve(finalResponse);
      })().catch(fail);
    });
  });
}

let consentAsyncRunner: ConsentAsyncRunner = defaultConsentAsyncRunner;
let protocolRunner: ConsentProtocolRunner = defaultConsentProtocolRunner;
let platformOverride: NodeJS.Platform | null = null;

/** @internal Test-only. */
export function _setTelemetryConsentAsyncRunner(runner: ConsentAsyncRunner | null): void {
  consentAsyncRunner = runner ?? defaultConsentAsyncRunner;
}

/** @internal Test-only. */
export function _setTelemetryConsentProtocolRunner(runner: ConsentProtocolRunner | null): void {
  protocolRunner = runner ?? defaultConsentProtocolRunner;
}

/** @internal Test-only. */
export function _setTelemetryConsentChildFactory(factory: ConsentChildFactory | null): void {
  consentChildFactory = factory ?? defaultConsentChildFactory;
}

/** @internal Test-only. */
export function _setTelemetryConsentTimeoutMs(timeoutMs: number | null): void {
  consentRequestTimeoutMs = timeoutMs ?? DEFAULT_CONSENT_REQUEST_TIMEOUT_MS;
}

/** @internal Test-only. */
export function _setTelemetryPlatform(platform: NodeJS.Platform | null): void {
  platformOverride = platform;
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

function isChallenge(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0;
}

function isResult(value: unknown): value is TelemetryConsentProtocolResult {
  return includes(CONSENT_PROTOCOL_RESULTS, value);
}

function isResultForAction(
  action: ConsentAction,
  result: TelemetryConsentProtocolResult,
): boolean {
  switch (action) {
    case 'status':
      return result === 'status' || result === 'notApplicable';
    case 'withdraw':
      return result === 'withdrawn' || result === 'notApplicable';
    case 'request':
      return [
        'presentationRequired',
        'granted',
        'denied',
        'dismissed',
        'alreadyGranted',
        'policyBlocked',
        'presentationUnavailable',
        'notApplicable',
      ].includes(result);
  }
}

function parseMaintenanceResponse(
  stdout: string,
  expectedAction: ConsentAction,
): TelemetryConsentProtocolResponse {
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
    || value.action !== expectedAction
    || !isResultForAction(expectedAction, value.result)
    || typeof value.needsPrompt !== 'boolean'
    || (
      value.reason !== undefined
      && value.reason !== null
      && !isStatusReason(value.reason)
    )
  ) {
    throw new Error(`unrecognised telemetry consent output: ${stdout.trim().slice(0, 200)}`);
  }
  if (
    value.result === 'presentationRequired'
    && (!isConsentPrompt(value.prompt) || !isChallenge(value.challenge))
  ) {
    throw new Error(`unrecognised telemetry consent output: ${stdout.trim().slice(0, 200)}`);
  }
  return parsed as TelemetryConsentProtocolResponse;
}

function toConsentOutcome(response: TelemetryConsentProtocolResponse): TelemetryConsentOutcome {
  if (
    response.action === 'status'
    || response.result === 'status'
    || response.result === 'presentationRequired'
  ) {
    throw new Error('unrecognised telemetry consent terminal output');
  }
  return {
    action: response.action,
    result: response.result,
    storedState: response.storedState,
    effectiveState: response.effectiveState,
    policy: response.policy,
    needsPrompt: response.needsPrompt,
  };
}

const reportedFailureCategories = new Set<string>();

function reportFailClosed(operation: string, safeResult: string, detail: string): void {
  try {
    const category = `${operation}:${safeResult}:${detail}`;
    const message = `mxc-sdk: ${operation} failed and is reporting '${safeResult}' to stay fail-closed: ${detail}`;
    if (!reportedFailureCategories.has(category)) {
      reportedFailureCategories.add(category);
      console.warn(message);
    }
  } catch {
    // Reporting must not affect the fail-closed result.
  }
}

function reportNativeDiagnostic(operation: string, stderr: string): void {
  const detail = stderr.trim();
  if (detail === '') {
    return;
  }
  try {
    const category = `${operation}:native:${detail}`;
    if (!reportedFailureCategories.has(category)) {
      reportedFailureCategories.add(category);
      console.warn(`mxc-sdk: ${operation} native diagnostic: ${detail}`);
    }
  } catch {
    // Reporting must not affect the native result.
  }
}

/** @internal Test-only. */
export function _resetTelemetryFailureReporting(): void {
  reportedFailureCategories.clear();
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

function consentQueryFromResponse(
  response: TelemetryConsentProtocolResponse,
): TelemetryConsentQuery {
  return {
    state: response.effectiveState,
    storedState: response.storedState,
    effectiveState: response.effectiveState,
    needsPrompt: response.needsPrompt && response.policy !== 'blocked',
    policy: response.policy,
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
    const output = await consentAsyncRunner(maintenanceArgs('status'));
    reportNativeDiagnostic('queryTelemetryConsentAsync', output.stderr);
    return consentQueryFromResponse(
      parseMaintenanceResponse(output.stdout, 'status'),
    );
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
  return protocolRunner(locale, presenter);
}

/** Idempotently withdraw telemetry consent without blocking the event loop. */
export async function withdrawTelemetryConsentAsync(): Promise<TelemetryConsentOutcome> {
  if (!isWindows()) {
    return notApplicable('withdraw');
  }
  try {
    const output = await consentAsyncRunner(maintenanceArgs('withdraw'));
    reportNativeDiagnostic('withdrawTelemetryConsentAsync', output.stderr);
    return toConsentOutcome(parseMaintenanceResponse(
      output.stdout,
      'withdraw',
    ));
  } catch (error) {
    throw new Error(
      `failed to withdraw telemetry consent: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}
