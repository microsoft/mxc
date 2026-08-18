// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { execFile, execFileSync, spawn } from 'node:child_process';
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
  signal?: AbortSignal,
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
type ConsentAsyncRunner = (args: readonly string[]) => Promise<string>;
type ConsentProtocolRunner = (
  locale: string | undefined,
  presenter: TelemetryConsentPresenter,
) => Promise<TelemetryConsentMaintenanceResponse>;
type ConsentChildFactory = (locale: string | undefined) => ReturnType<typeof spawn>;

const DEFAULT_CONSENT_REQUEST_TIMEOUT_MS = 30_000;
const MAX_CONSENT_STDOUT_BYTES = 1024 * 1024;
const MAX_CONSENT_STDERR_BYTES = 64 * 1024;
const MAX_CONSENT_PROTOCOL_LINES = 16;
let consentRequestTimeoutMs = DEFAULT_CONSENT_REQUEST_TIMEOUT_MS;
const defaultConsentChildFactory: ConsentChildFactory = (locale) =>
  spawn(executable(), maintenanceArgs('request', locale), {
    env: { ...process.env, MXC_TELEMETRY_CONSENT_PRESENTER_PROTOCOL: '1' },
    stdio: ['pipe', 'pipe', 'pipe'],
    windowsHide: true,
  });
let consentChildFactory: ConsentChildFactory = defaultConsentChildFactory;

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

function defaultConsentAsyncRunner(args: readonly string[]): Promise<string> {
  return new Promise((resolve, reject) => {
    execFile(
      executable(),
      [...args],
      {
        timeout: 5000,
        encoding: 'utf-8',
        windowsHide: true,
      },
      (error, stdout) => {
        if (error) {
          reject(error);
        } else {
          resolve(stdout);
        }
      },
    );
  });
}

async function defaultConsentProtocolRunner(
  locale: string | undefined,
  presenter: TelemetryConsentPresenter,
): Promise<TelemetryConsentMaintenanceResponse> {
  return new Promise((resolve, reject) => {
    const child = consentChildFactory(locale);
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
    let finalResponse: TelemetryConsentMaintenanceResponse | undefined;
    let settled = false;
    let timeout: NodeJS.Timeout | null = null;
    let timeoutStartedAt = 0;
    let timeoutRemainingMs = consentRequestTimeoutMs;
    let lineQueue: Promise<void> = Promise.resolve();
    let childKilled = false;
    let stdoutBytes = 0;
    let stderrBytes = 0;
    let protocolLines = 0;
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
      let response: TelemetryConsentMaintenanceResponse;
      try {
        response = parseMaintenanceResponse(line);
      } catch (error) {
        fail(error);
        return;
      }

      if (response.result !== 'presentationRequired') {
        finalResponse = response;
        return;
      }
      if (!response.prompt || !response.challenge) {
        fail(new Error('telemetry consent presentation omitted its prompt or challenge'));
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
    childStdin.on('error', (error) => {
      if (!settled) {
        fail(error);
      }
    });
    child.on('error', fail);
    child.on('close', (code) => {
      if (rejectPresenterWait !== undefined) {
        presenterAbort.abort();
        rejectPresenterWait(
          new Error(`telemetry consent process exited while awaiting presentation (${code ?? 'no exit code'})`),
        );
        rejectPresenterWait = undefined;
      }
      void (async (): Promise<void> => {
        await lineQueue;
        if (settled) return;
        clearProtocolDeadline();
        if (stdout.trim() !== '') {
          try {
            finalResponse = parseMaintenanceResponse(stdout);
          } catch (error) {
            fail(error);
            return;
          }
        }
        if (code !== 0 || finalResponse === undefined) {
          fail(new Error(`telemetry consent process failed (${code ?? 'no exit code'}): ${stderr.trim()}`));
          return;
        }
        settled = true;
        resolve(finalResponse);
      })().catch(fail);
    });
  });
}

let consentRunner: ConsentRunner = defaultConsentRunner;
let consentAsyncRunner: ConsentAsyncRunner = defaultConsentAsyncRunner;
let protocolRunner: ConsentProtocolRunner = defaultConsentProtocolRunner;
let platformOverride: NodeJS.Platform | null = null;
let convenienceQueryCache: TelemetryConsentQuery | undefined;
let convenienceCacheClearScheduled = false;

function invalidateConvenienceQueryCache(): void {
  convenienceQueryCache = undefined;
}

function convenienceTelemetryConsentQuery(): TelemetryConsentQuery {
  convenienceQueryCache ??= queryTelemetryConsent();
  if (!convenienceCacheClearScheduled) {
    convenienceCacheClearScheduled = true;
    queueMicrotask(() => {
      convenienceQueryCache = undefined;
      convenienceCacheClearScheduled = false;
    });
  }
  return convenienceQueryCache;
}

/** @internal Test-only. */
export function _setTelemetryConsentRunner(runner: ConsentRunner | null): void {
  consentRunner = runner ?? defaultConsentRunner;
  invalidateConvenienceQueryCache();
}

/** @internal Test-only. */
export function _setTelemetryConsentAsyncRunner(runner: ConsentAsyncRunner | null): void {
  consentAsyncRunner = runner ?? defaultConsentAsyncRunner;
  invalidateConvenienceQueryCache();
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
  invalidateConvenienceQueryCache();
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

const reportedFailureCategories = new Set<string>();

function reportFailClosed(operation: string, safeResult: string, detail: string): void {
  try {
    const category = `${operation}:${safeResult}`;
    const message = `mxc-sdk: ${operation} failed and is reporting '${safeResult}' to stay fail-closed: ${detail}`;
    if (!reportedFailureCategories.has(category)) {
      reportedFailureCategories.add(category);
      console.warn(message);
    }
  } catch {
    // Reporting must not affect the fail-closed result.
  }
}

/** @internal Test-only. */
export function _resetTelemetryFailureReporting(): void {
  reportedFailureCategories.clear();
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

function consentQueryFromResponse(
  response: TelemetryConsentMaintenanceResponse,
): TelemetryConsentQuery {
  return {
    state: response.effectiveState,
    storedState: response.storedState,
    effectiveState: response.effectiveState,
    needsPrompt: response.needsPrompt && response.policy !== 'blocked',
    policy: response.policy,
    ...(response.reason === undefined || response.reason === null ? {} : { reason: response.reason }),
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
    reason: 'store-unreadable',
    error: `failed to read telemetry consent: ${detail}`,
  };
}

/**
 * Read persisted/effective consent and policy synchronously.
 *
 * This compatibility API starts a subprocess and can block the event loop for
 * up to five seconds. Prefer {@link queryTelemetryConsentAsync} outside
 * startup-only code.
 */
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
    return consentQueryFromResponse(
      parseMaintenanceResponse(consentRunner(maintenanceArgs('status'))),
    );
  } catch (error) {
    return failedConsentQuery('queryTelemetryConsent', error);
  }
}

/** Read persisted/effective consent and policy without blocking the event loop. */
export async function queryTelemetryConsentAsync(): Promise<TelemetryConsentQuery> {
  if (!isWindows()) {
    return queryTelemetryConsent();
  }
  try {
    return consentQueryFromResponse(
      parseMaintenanceResponse(await consentAsyncRunner(maintenanceArgs('status'))),
    );
  } catch (error) {
    return failedConsentQuery('queryTelemetryConsentAsync', error);
  }
}

/** Synchronous compatibility getter; may block for up to five seconds. */
export function getTelemetryConsent(): TelemetryConsentState {
  return convenienceTelemetryConsentQuery().effectiveState;
}

/** Synchronous compatibility getter; may block for up to five seconds. */
export function needsTelemetryConsentPrompt(): boolean {
  return convenienceTelemetryConsentQuery().needsPrompt;
}

/** Synchronous compatibility getter; may block for up to five seconds. */
export function getTelemetryPolicy(): TelemetryConsentPolicyState {
  return convenienceTelemetryConsentQuery().policy;
}

/** Request consent with the versioned canonical consent resource. */
export async function requestTelemetryConsent(
  presenter: TelemetryConsentPresenter,
  locale?: string,
): Promise<TelemetryConsentOutcome> {
  if (!isWindows()) {
    return notApplicable('request');
  }
  invalidateConvenienceQueryCache();
  try {
    return await protocolRunner(locale, presenter);
  } finally {
    invalidateConvenienceQueryCache();
  }
}

/**
 * Idempotently withdraw telemetry consent synchronously.
 *
 * This compatibility API can block the event loop for up to five seconds.
 * Prefer {@link withdrawTelemetryConsentAsync}.
 */
export function withdrawTelemetryConsent(): TelemetryConsentOutcome {
  if (!isWindows()) {
    return notApplicable('withdraw');
  }
  invalidateConvenienceQueryCache();
  try {
    const outcome = parseMaintenanceResponse(consentRunner(maintenanceArgs('withdraw')));
    invalidateConvenienceQueryCache();
    return outcome;
  } catch (error) {
    invalidateConvenienceQueryCache();
    throw new Error(
      `failed to withdraw telemetry consent: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}

/** Idempotently withdraw telemetry consent without blocking the event loop. */
export async function withdrawTelemetryConsentAsync(): Promise<TelemetryConsentOutcome> {
  if (!isWindows()) {
    return notApplicable('withdraw');
  }
  invalidateConvenienceQueryCache();
  try {
    return parseMaintenanceResponse(
      await consentAsyncRunner(maintenanceArgs('withdraw')),
    );
  } catch (error) {
    throw new Error(
      `failed to withdraw telemetry consent: ${error instanceof Error ? error.message : String(error)}`,
    );
  } finally {
    invalidateConvenienceQueryCache();
  }
}
