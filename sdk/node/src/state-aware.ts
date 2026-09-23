// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { Readable } from 'node:stream';
import { SandboxSpawnOptions } from './sandbox.js';
import { diagLog } from './diagnostic.js';
import { MxcError } from './errors.js';
import { runBindingStateAwareRequestAsync } from './bindings/state-aware.js';
import { spawnStateAwareBindingSandboxProcess } from './bindings/streaming.js';
import {
  DeprovisionConfigFor,
  DeprovisionResult,
  EveryBackendConfigIsOptional,
  ExecConfigFor,
  ExecResult,
  IsolationSessionExecConfig,
  ProvisionConfigFor,
  ProvisionMetadataFor,
  ProvisionResult,
  SandboxId,
  StartConfigFor,
  StartResult,
  StateAwareContainmentBackend,
  StopConfigFor,
  StopResult,
} from './state-aware-types.js';
import type { MxcSandboxProcess } from './sandbox-process.js';
import {
  backendForSandboxId,
  buildStateAwareEnvelope,
  parseNonExecResponse,
} from './state-aware-helper.js';

/**
 * Trailing parameters of {@link provisionSandbox}: the config is required
 * unless *every* backend in `C` has an all-optional provision config. See
 * {@link EveryBackendConfigIsOptional} for why the check is written over the
 * backend union rather than over the union of configs.
 */
export type ProvisionArgs<C extends StateAwareContainmentBackend> =
  EveryBackendConfigIsOptional<C> extends true
    ? [config?: ProvisionConfigFor<C>, options?: SandboxSpawnOptions]
    : [config: ProvisionConfigFor<C>, options?: SandboxSpawnOptions];

/** Options for live state-aware streaming. */
export interface StateAwareStreamingOptions {
  /** Authorizes a backend that is experimental in the selected contract. */
  experimental?: boolean;
}

type StateAwareOptionSupport = 'supported' | 'unsupported-when-true' | 'unsupported-when-defined';

const STATE_AWARE_OPTION_SUPPORT = {
  debug: 'unsupported-when-true',
  experimental: 'supported',
  allowTestingFeatures: 'unsupported-when-true',
  inheritDefaultEnv: 'unsupported-when-defined',
  executablePath: 'unsupported-when-defined',
  skipPlatformCheck: 'unsupported-when-true',
  ptyOptions: 'unsupported-when-defined',
  dryRun: 'supported',
  logDir: 'unsupported-when-defined',
  usePty: 'unsupported-when-true',
  signal: 'supported',
} satisfies Record<keyof SandboxSpawnOptions, StateAwareOptionSupport>;

function assertStateAwareOptions(
  apiName: string,
  options: SandboxSpawnOptions,
): void {
  for (const key of Object.keys(options) as Array<keyof SandboxSpawnOptions>) {
    const support = STATE_AWARE_OPTION_SUPPORT[key];
    const value = options[key];
    const unsupported = support === 'unsupported-when-true'
      ? value === true
      : support === 'unsupported-when-defined' && value !== undefined;
    if (!unsupported) continue;
    throw new MxcError(
      'malformed_request',
      `${apiName} does not support option '${key}'`,
    );
  }
}

function assertNativeExecBackend(
  apiName: string,
  sandboxId: SandboxId<StateAwareContainmentBackend>,
): void {
  const backend = backendForSandboxId(sandboxId);
  if (backend !== 'isolation_session') {
    throw new MxcError(
      'unsupported_containment',
      `${apiName} supports native execution only for IsolationSession; ${backend} does not expose piped native exec streams.`,
    );
  }
}

function abortReason(signal: AbortSignal): unknown {
  return signal.reason ?? new Error('Aborted');
}

function logBackgroundFailure(operation: string, error: unknown): void {
  const message = error instanceof Error ? error.message : String(error);
  diagLog(`state-aware: ${operation} failed: ${message}`);
}

function scheduleAbortedProvisionCleanup(
  responseJson: string,
  envelope: Record<string, unknown>,
  experimental: boolean,
): void {
  if (envelope.phase !== 'provision' || envelope.containment === undefined) {
    return;
  }
  try {
    const sandboxId = parseNonExecResponse<{ sandboxId?: string }>(responseJson).sandboxId;
    if (!sandboxId) return;
    const cleanup = buildStateAwareEnvelope({
      phase: 'deprovision',
      backendKey: backendForSandboxId(sandboxId),
      sandboxId,
    });
    if (typeof envelope.version === 'string') {
      cleanup.version = envelope.version;
    }
    void runBindingStateAwareRequestAsync({
      requestJson: JSON.stringify(cleanup),
      dryRun: false,
      experimental,
    }).catch((error: unknown) => {
      logBackgroundFailure(
        `aborted provision cleanup for sandbox '${sandboxId}'`,
        error,
      );
    });
  } catch (error) {
    logBackgroundFailure('preparing aborted provision cleanup', error);
  }
}

async function runStateAwareEnvelopeRequest(
  apiName: string,
  envelope: Record<string, unknown>,
  options: SandboxSpawnOptions,
): Promise<string> {
  assertStateAwareOptions(apiName, options);

  const signal = options.signal;
  if (signal?.aborted) {
    throw abortReason(signal);
  }

  const experimental = options.experimental === true;
  const request = runBindingStateAwareRequestAsync({
    requestJson: JSON.stringify(envelope),
    dryRun: options.dryRun === true,
    experimental,
  });

  if (!signal) {
    return request;
  }

  return new Promise<string>((resolve, reject) => {
    let settled = false;
    let aborted = false;
    const finish = (action: () => void) => {
      if (settled) return;
      settled = true;
      signal.removeEventListener('abort', onAbort);
      action();
    };
    const onAbort = () => {
      aborted = true;
      finish(() => reject(abortReason(signal)));
    };

    signal.addEventListener('abort', onAbort, { once: true });
    void request.then((responseJson) => {
      if (aborted) {
        scheduleAbortedProvisionCleanup(responseJson, envelope, experimental);
        return;
      }
      finish(() => resolve(responseJson));
    }, (error) => {
      if (aborted) {
        logBackgroundFailure(`${apiName} after cancellation`, error);
        return;
      }
      finish(() => reject(error));
    });
  });
}

async function nonExecBindingCall<T>(
  apiName: string,
  envelope: Record<string, unknown>,
  options: SandboxSpawnOptions,
): Promise<T> {
  return parseNonExecResponse<T>(await runStateAwareEnvelopeRequest(apiName, envelope, options));
}

function buildExecEnvelope<C extends StateAwareContainmentBackend>(
  sandboxId: SandboxId<C>,
  config: ExecConfigFor<C>,
): Record<string, unknown> {
  return buildStateAwareEnvelope({
    phase: 'exec',
    backendKey: backendForSandboxId(sandboxId) as C,
    sandboxId,
    config: config as unknown as Record<string, unknown>,
  });
}

function spawnStateAwareExecProcess<C extends StateAwareContainmentBackend>(
  sandboxId: SandboxId<C>,
  config: ExecConfigFor<C>,
  options: SandboxSpawnOptions,
  apiName: string,
): MxcSandboxProcess {
  assertStateAwareOptions(apiName, options);
  assertNativeExecBackend(apiName, sandboxId);
  return spawnStateAwareBindingSandboxProcess(
    JSON.stringify(buildExecEnvelope(sandboxId, config)),
    options.experimental === true,
    config.process.timeout,
  );
}

function collectStream(stream: Readable | null): Promise<string> {
  if (stream === null) {
    return Promise.resolve('');
  }
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    stream.on('data', (chunk: Buffer | string) => {
      chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
    });
    stream.once('end', () => resolve(Buffer.concat(chunks).toString('utf-8')));
    stream.once('error', reject);
  });
}

function createAbortPromise(
  proc: MxcSandboxProcess,
  signal: AbortSignal | undefined,
): { promise?: Promise<never>; cleanup: () => void } {
  if (!signal) {
    return { cleanup: () => {} };
  }
  let onAbort: (() => void) | undefined;
  const promise = new Promise<never>((_, reject) => {
    onAbort = () => {
      try {
        proc.kill();
      } catch (error) {
        logBackgroundFailure('cancelling buffered exec', error);
      }
      reject(abortReason(signal));
    };
    if (signal.aborted) {
      onAbort();
      return;
    }
    signal.addEventListener('abort', onAbort, { once: true });
  });
  return {
    promise,
    cleanup: () => {
      if (onAbort) {
        signal.removeEventListener('abort', onAbort);
      }
    },
  };
}

/**
 * Provisions a state-aware sandbox of the requested backend. Returns a
 * branded sandbox id and any provision-time metadata the backend produces.
 *
 * The config parameter is **required for backends whose provision config has
 * a required member**, and optional otherwise — see {@link ProvisionArgs}.
 * Without that, a config type could declare a field as required and still be
 * skipped entirely by omitting the argument, which is a guarantee the type
 * appears to offer but does not enforce. IsolationSession relies on this: its
 * explicit unrestricted `network` posture is mandatory. Later phases reject
 * supplied network policy because the posture is fixed at provision.
 */
export async function provisionSandbox<C extends StateAwareContainmentBackend>(
  containment: C,
  ...rest: ProvisionArgs<C>
): Promise<ProvisionResult<C>> {
  const [config, options = {}] = rest as [
    ProvisionConfigFor<C> | undefined,
    SandboxSpawnOptions | undefined,
  ];
  const envelope = buildStateAwareEnvelope({
    phase: 'provision',
    backendKey: containment,
    containment,
    config: config as Record<string, unknown> | undefined,
  });
  const result = await nonExecBindingCall<{
    sandboxId: string;
    metadata?: ProvisionMetadataFor<C>;
  }>('provisionSandbox', envelope, options);
  return {
    sandboxId: result.sandboxId as SandboxId<C>,
    metadata: result.metadata,
  };
}

/**
 * Starts a previously provisioned sandbox. The backend is inferred from
 * the `sandboxId` prefix.
 */
export async function startSandbox<C extends StateAwareContainmentBackend>(
  sandboxId: SandboxId<C>,
  config?: StartConfigFor<C>,
  options: SandboxSpawnOptions = {},
): Promise<StartResult<C>> {
  const backendKey = backendForSandboxId(sandboxId) as C;
  const envelope = buildStateAwareEnvelope({
    phase: 'start',
    backendKey,
    sandboxId,
    config: config as Record<string, unknown> | undefined,
  });
  return nonExecBindingCall<StartResult<C>>('startSandbox', envelope, options);
}

/**
 * Streams a script execution inside a started IsolationSession over Node
 * pipes, returning an owning `MxcSandboxProcess` for waiting, termination,
 * stream access, and disposal.
 */
export function execInSandbox(
  sandboxId: SandboxId<'isolation_session'>,
  config: IsolationSessionExecConfig,
  options: StateAwareStreamingOptions = {},
): MxcSandboxProcess {
  const uncheckedOptions = options as SandboxSpawnOptions;
  if (uncheckedOptions.dryRun === true) {
    throw new MxcError(
      'malformed_request',
      'execInSandbox does not support dryRun; use execInSandboxAsync to validate exec requests.',
    );
  }
  if (uncheckedOptions.signal !== undefined) {
    throw new MxcError(
      'malformed_request',
      'execInSandbox does not support AbortSignal; call kill() on the returned MxcSandboxProcess.',
    );
  }
  return spawnStateAwareExecProcess(
    sandboxId,
    config,
    uncheckedOptions,
    'execInSandbox',
  );
}

/**
 * Buffered exec convenience. Resolves with `{stdout, stderr, exitCode}`
 * on script completion. Native dispatch failures reject with `MxcError`;
 * workload failures are returned through the process exit code and streams.
 */
export async function execInSandboxAsync<C extends StateAwareContainmentBackend>(
  sandboxId: SandboxId<C>,
  config: ExecConfigFor<C>,
  options: SandboxSpawnOptions & { dryRun: true },
): Promise<ExecResult>;
export async function execInSandboxAsync(
  sandboxId: SandboxId<'isolation_session'>,
  config: IsolationSessionExecConfig,
  options?: SandboxSpawnOptions,
): Promise<ExecResult>;
export async function execInSandboxAsync<C extends StateAwareContainmentBackend>(
  sandboxId: SandboxId<C>,
  config: ExecConfigFor<C>,
  options: SandboxSpawnOptions = {},
): Promise<ExecResult> {
  const envelope = buildExecEnvelope(sandboxId, config);
  if (options.dryRun === true) {
    const responseJson = await runStateAwareEnvelopeRequest(
      'execInSandboxAsync',
      envelope,
      options,
    );
    parseNonExecResponse<unknown>(responseJson);
    return {
      stdout: responseJson,
      stderr: '',
      exitCode: 0,
    };
  }

  if (options.signal?.aborted) {
    throw abortReason(options.signal);
  }

  const proc = spawnStateAwareExecProcess(
    sandboxId,
    config,
    { ...options, signal: undefined },
    'execInSandboxAsync',
  );
  const stdoutPromise = collectStream(proc.standardOutput);
  const stderrPromise = collectStream(proc.standardError);
  const waitPromise = Promise.all([proc.waitAsync(), stdoutPromise, stderrPromise]);
  const abort = createAbortPromise(proc, options.signal);

  let failed = false;
  try {
    const [result, stdout, stderr] = abort.promise
      ? await Promise.race([waitPromise, abort.promise])
      : await waitPromise;
    return { stdout, stderr, exitCode: result.exitCode };
  } catch (error) {
    failed = true;
    throw error;
  } finally {
    abort.cleanup();
    try {
      proc.dispose();
    } catch (error) {
      if (!failed) throw error;
      logBackgroundFailure('disposing buffered exec after failure', error);
    }
  }
}

/**
 * Stops a started sandbox without releasing its provision-side resources.
 * The same sandbox can be started again via `startSandbox`.
 */
export async function stopSandbox<C extends StateAwareContainmentBackend>(
  sandboxId: SandboxId<C>,
  config?: StopConfigFor<C>,
  options: SandboxSpawnOptions = {},
): Promise<StopResult<C>> {
  const backendKey = backendForSandboxId(sandboxId) as C;
  const envelope = buildStateAwareEnvelope({
    phase: 'stop',
    backendKey,
    sandboxId,
    config: config as Record<string, unknown> | undefined,
  });
  return nonExecBindingCall<StopResult<C>>('stopSandbox', envelope, options);
}

/**
 * Releases all backend resources associated with a provisioned sandbox.
 * The id becomes invalid after this call returns successfully.
 */
export async function deprovisionSandbox<C extends StateAwareContainmentBackend>(
  sandboxId: SandboxId<C>,
  config?: DeprovisionConfigFor<C>,
  options: SandboxSpawnOptions = {},
): Promise<DeprovisionResult<C>> {
  const backendKey = backendForSandboxId(sandboxId) as C;
  const envelope = buildStateAwareEnvelope({
    phase: 'deprovision',
    backendKey,
    sandboxId,
    config: config as Record<string, unknown> | undefined,
  });
  return nonExecBindingCall<DeprovisionResult<C>>('deprovisionSandbox', envelope, options);
}
