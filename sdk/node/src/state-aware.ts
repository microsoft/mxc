// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import pty from 'node-pty';
import { Readable } from 'node:stream';
import { resolveBinaryAndCommonArgs } from './helper.js';
import { SandboxSpawnOptions } from './sandbox.js';
import { MxcError } from './errors.js';
import { diagLog } from './diagnostic.js';
import { runBindingStateAwareRequestAsync } from './bindings/state-aware-worker.js';
import { spawnStateAwareBindingSandboxProcess } from './bindings/streaming.js';
import {
  DeprovisionConfigFor,
  DeprovisionResult,
  EveryBackendConfigIsOptional,
  ExecConfigFor,
  ExecResult,
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

function unsupportedStateAwareFfiOption(
  options: SandboxSpawnOptions,
  allowDryRun: boolean,
): string | undefined {
  if (options.debug === true) return 'debug';
  if (options.allowTestingFeatures === true) return 'allowTestingFeatures';
  if (options.executablePath !== undefined) return 'executablePath';
  if (options.ptyOptions !== undefined) return 'ptyOptions';
  if (!allowDryRun && options.dryRun === true) return 'dryRun';
  if (options.logDir !== undefined) return 'logDir';
  if (options.usePty === true) return 'usePty';
  return undefined;
}

function assertStateAwareFfiOptions(
  apiName: string,
  options: SandboxSpawnOptions,
  allowDryRun: boolean,
): void {
  const unsupportedOption = unsupportedStateAwareFfiOption(options, allowDryRun);
  if (unsupportedOption !== undefined) {
    throw new MxcError(
      'malformed_request',
      `${apiName} does not support executor-only option '${unsupportedOption}'`,
    );
  }
}

function abortReason(signal: AbortSignal): unknown {
  return signal.reason ?? new Error('Aborted');
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
    }).catch(() => {});
  } catch {
    // Best-effort cleanup only.
  }
}

async function runStateAwareEnvelopeRequest(
  apiName: string,
  envelope: Record<string, unknown>,
  options: SandboxSpawnOptions,
): Promise<string> {
  assertStateAwareFfiOptions(apiName, options, true);

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
      if (aborted) return;
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
  assertStateAwareFfiOptions(apiName, options, false);
  return spawnStateAwareBindingSandboxProcess(
    JSON.stringify(buildExecEnvelope(sandboxId, config)),
    options.experimental === true,
    config.process.timeout,
  );
}

function wireAbortToStateAwareProcess(
  proc: MxcSandboxProcess,
  signal: AbortSignal | undefined,
): void {
  if (!signal) {
    return;
  }
  const onAbort = () => {
    try {
      proc.kill();
    } catch {
      // Best-effort cancellation only.
    }
  };
  if (signal.aborted) {
    onAbort();
    return;
  }
  signal.addEventListener('abort', onAbort, { once: true });
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
      } catch {
        // Best-effort cancellation only.
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
 * Legacy PTY-backed exec surface. Returns an `IPty` for live
 * stdout/stderr/exit handling, mirroring `spawnSandbox`.
 *
 * On dispatch failure the executor emits a single error envelope on stdout;
 * the SDK does not parse it here — callers consuming `IPty.onData` see the
 * raw bytes. Prefer `execInSandboxProcess` for in-process pipe streaming or
 * `execInSandboxAsync` when typed-error throwing is needed.
 */
export function execInSandbox<C extends StateAwareContainmentBackend>(
  sandboxId: SandboxId<C>,
  config: ExecConfigFor<C>,
  options: SandboxSpawnOptions = {},
): pty.IPty {
  const backendKey = backendForSandboxId(sandboxId) as C;
  const envelope = buildStateAwareEnvelope({
    phase: 'exec',
    backendKey,
    sandboxId,
    config: config as unknown as Record<string, unknown>,
  });
  const { executablePath, args } = resolveBinaryAndCommonArgs(JSON.stringify(envelope), options);
  diagLog(`state-aware: spawning exec via PTY`);
  const ptyProcess = pty.spawn(executablePath, args, {
    name: 'xterm-color',
    cols: 120,
    rows: 80,
    cwd: process.cwd(),
    ...options.ptyOptions,
  });
  const signal = options.signal;
  if (signal) {
    if (signal.aborted) {
      ptyProcess.kill();
    } else {
      const onAbort = () => ptyProcess.kill();
      signal.addEventListener('abort', onAbort, { once: true });
      ptyProcess.onExit(() => signal.removeEventListener('abort', onAbort));
    }
  }
  return ptyProcess;
}

/**
 * Streams a script execution inside a started sandbox over Node pipes backed
 * by `mxc_ffi`, returning the shared `MxcSandboxProcess` controller used by
 * `spawnSandboxProcess()`.
 *
 * Unlike the legacy `execInSandbox()` PTY API, this never launches an
 * executor process and keeps stdout and stderr separate.
 */
export function execInSandboxProcess<C extends StateAwareContainmentBackend>(
  sandboxId: SandboxId<C>,
  config: ExecConfigFor<C>,
  options: SandboxSpawnOptions = {},
): MxcSandboxProcess {
  if (options.dryRun === true) {
    throw new MxcError(
      'malformed_request',
      'execInSandboxProcess does not support dryRun; use execInSandboxAsync to validate exec requests.',
    );
  }
  const proc = spawnStateAwareExecProcess(sandboxId, config, options, 'execInSandboxProcess');
  wireAbortToStateAwareProcess(proc, options.signal);
  return proc;
}

/**
 * Buffered exec convenience. Resolves with `{stdout, stderr, exitCode}`
 * on script completion. Throws an `MxcError` (with the wire-format `code`
 * field set) when the executor reports a dispatch failure (recognised by
 * exit != 0 and stdout being a complete `{error}` envelope).
 */
export async function execInSandboxAsync<C extends StateAwareContainmentBackend>(
  sandboxId: SandboxId<C>,
  config: ExecConfigFor<C>,
  options: SandboxSpawnOptions = {},
): Promise<ExecResult> {
  const envelope = buildExecEnvelope(sandboxId, config);
  if (options.dryRun === true) {
    return {
      stdout: await runStateAwareEnvelopeRequest('execInSandboxAsync', envelope, options),
      stderr: '',
      exitCode: 0,
    };
  }

  const proc = execInSandboxProcess(sandboxId, config, { ...options, signal: undefined });
  const stdoutPromise = collectStream(proc.stdout);
  const stderrPromise = collectStream(proc.stderr);
  const waitPromise = Promise.all([proc.wait(), stdoutPromise, stderrPromise]);
  const abort = createAbortPromise(proc, options.signal);

  try {
    const [result, stdout, stderr] = abort.promise
      ? await Promise.race([waitPromise, abort.promise])
      : await waitPromise;
    return { stdout, stderr, exitCode: result.exitCode };
  } finally {
    abort.cleanup();
    proc.dispose();
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
