// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { Readable } from 'node:stream';
import { diagLog } from './diagnostic.js';
import { MxcError } from './errors.js';
import {
  runBindingStateAwareRequestAsync,
} from './bindings/state-aware.js';
import { spawnStateAwareBindingSandboxProcess } from './bindings/streaming.js';
import { execStateAwareBindingSandboxWithPty } from './bindings/pty.js';
import type { MxcPtyProcess, MxcPtySize } from './mxc-pty-process.js';
import {
  DeprovisionConfigFor,
  DeprovisionResult,
  EveryBackendConfigIsOptional,
  ExecConfigFor,
  ExecRequest,
  ExecResult,
  ProvisionConfigFor,
  ProvisionMetadataFor,
  ProvisionResult,
  ContainerId,
  StartConfigFor,
  StartResult,
  LifecycleBackend,
  StopConfigFor,
  StopResult,
} from './state-aware-types.js';
import type { MxcOptions } from './types.js';
import type {
  MxcProcess,
} from './sandbox-process.js';
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
export type ProvisionArgs<C extends LifecycleBackend> =
  EveryBackendConfigIsOptional<C> extends true
    ? [config?: ProvisionConfigFor<C>, options?: MxcOptions]
    : [config: ProvisionConfigFor<C>, options?: MxcOptions];

const PIPED_EXEC_BACKENDS = [
  'isolation_session',
  'wslc',
] as const satisfies readonly LifecycleBackend[];
type PipedExecBackend = typeof PIPED_EXEC_BACKENDS[number];

function assertStateAwareOptions(
  apiName: string,
  options: MxcOptions,
): void {
  if (options === null || typeof options !== 'object' || Array.isArray(options)) {
    throw new MxcError('malformed_request', `${apiName} options must be an object`);
  }
  for (const [key, value] of Object.entries(options)) {
    if (key !== 'experimental' && key !== 'dryRun') {
      throw new MxcError(
        'malformed_request',
        `${apiName} does not support option '${key}'`,
      );
    }
    if (value !== undefined && typeof value !== 'boolean') {
      throw new MxcError(
        'malformed_request',
        `${apiName} option '${key}' must be a boolean`,
      );
    }
  }
}

function assertPipedExecBackend(
  apiName: string,
  sandboxId: ContainerId<LifecycleBackend>,
): void {
  const backend = backendForSandboxId(sandboxId);
  const supportedBackends: readonly LifecycleBackend[] = PIPED_EXEC_BACKENDS;
  if (!supportedBackends.includes(backend)) {
    throw new MxcError(
      'unsupported_containment',
      `${apiName} requires piped native exec streams; ${backend} does not expose them.`,
    );
  }
}

function logBackgroundFailure(operation: string, error: unknown): void {
  const message = error instanceof Error ? error.message : String(error);
  diagLog(`state-aware: ${operation} failed: ${message}`);
}

async function runStateAwareEnvelopeRequest(
  apiName: string,
  envelope: Record<string, unknown>,
  options: MxcOptions,
): Promise<string> {
  assertStateAwareOptions(apiName, options);
  return runBindingStateAwareRequestAsync({
    requestJson: JSON.stringify(envelope),
    dryRun: options.dryRun === true,
    experimental: options.experimental === true,
  });
}

async function nonExecBindingCall<T>(
  apiName: string,
  envelope: Record<string, unknown>,
  options: MxcOptions,
): Promise<T> {
  return parseNonExecResponse<T>(await runStateAwareEnvelopeRequest(apiName, envelope, options));
}

function buildExecEnvelope<C extends LifecycleBackend>(
  sandboxId: ContainerId<C>,
  config: ExecConfigFor<C>,
): Record<string, unknown> {
  return buildStateAwareEnvelope({
    phase: 'exec',
    backendKey: backendForSandboxId(sandboxId) as C,
    sandboxId,
    config: config as unknown as Record<string, unknown>,
  });
}

function spawnStateAwareExecProcess<C extends LifecycleBackend>(
  sandboxId: ContainerId<C>,
  config: ExecConfigFor<C>,
  options: MxcOptions,
  apiName: string,
): MxcProcess {
  assertStateAwareOptions(apiName, options);
  assertPipedExecBackend(apiName, sandboxId);
  return spawnStateAwareBindingSandboxProcess(
    JSON.stringify(buildExecEnvelope(sandboxId, config)),
    options.experimental === true,
    config.process.timeout,
  );
}

function assertStateAwareStreamingOptions(
  apiName: string,
  options: MxcOptions,
): void {
  assertStateAwareOptions(apiName, options);
  if (options.dryRun === true) {
    throw new MxcError(
      'malformed_request',
      `${apiName} does not support dryRun because it returns a live process`,
    );
  }
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
export async function provisionSandbox<C extends LifecycleBackend>(
  containment: C,
  ...rest: ProvisionArgs<C>
): Promise<ProvisionResult<C>> {
  const [config, options = {}] = rest as [
    ProvisionConfigFor<C> | undefined,
    MxcOptions | undefined,
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
    containerId: result.sandboxId as ContainerId<C>,
    metadata: result.metadata,
  };
}

/**
 * Starts a previously provisioned sandbox. The backend is inferred from
 * the `sandboxId` prefix.
 */
export async function startSandbox<C extends LifecycleBackend>(
  sandboxId: ContainerId<C>,
  config?: StartConfigFor<C>,
  options: MxcOptions = {},
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
 * Streams a script execution inside a started IsolationSession or WSLC sandbox over Node
 * pipes, returning an owning `MxcProcess` for waiting, termination,
 * stream access, and disposal.
 */
export function execInSandbox<C extends PipedExecBackend>(
  sandboxId: ContainerId<C>,
  config: ExecConfigFor<C>,
  options: MxcOptions = {},
): MxcProcess {
  assertStateAwareStreamingOptions('execInSandbox', options);
  return spawnStateAwareExecProcess(
    sandboxId,
    config,
    options,
    'execInSandbox',
  );
}

/** Spawn an exec request in an existing container with an MXC-owned PTY. */
export function spawnInContainerWithPty<C extends LifecycleBackend>(
  sandboxId: ContainerId<C>,
  config: ExecConfigFor<C>,
  size: MxcPtySize = { rows: 24, columns: 80 },
  options: MxcOptions = {},
): Promise<MxcPtyProcess> {
  assertStateAwareStreamingOptions('spawnInContainerWithPty', options);
  if (
    !Number.isInteger(size.rows) ||
    !Number.isInteger(size.columns) ||
    size.rows < 1 ||
    size.rows > 32767 ||
    size.columns < 1 ||
    size.columns > 32767
  ) {
    throw new MxcError(
      'malformed_request',
      'PTY rows and columns must be integers between 1 and 32767',
    );
  }
  return execStateAwareBindingSandboxWithPty(
    JSON.stringify(buildExecEnvelope(sandboxId, config)),
    options.experimental === true,
    size.rows,
    size.columns,
    config.process.timeout,
  );
}

/**
 * Buffered exec convenience. Resolves with `{stdout, stderr, exitCode}`
 * on script completion. Native dispatch failures reject with `MxcError`;
 * workload failures are returned through the process exit code and streams.
 */
export async function execInSandboxAsync<C extends PipedExecBackend>(
  sandboxId: ContainerId<C>,
  config: ExecConfigFor<C>,
  options?: MxcOptions,
): Promise<ExecResult>;
export async function execInSandboxAsync<C extends PipedExecBackend>(
  sandboxId: ContainerId<C>,
  config: ExecConfigFor<C>,
  options: MxcOptions = {},
): Promise<ExecResult> {
  assertStateAwareOptions('execInSandboxAsync', options);
  assertPipedExecBackend('execInSandboxAsync', sandboxId);
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
      timedOut: false,
      warnings: [],
    };
  }

  const proc = spawnStateAwareExecProcess(sandboxId, config, options, 'execInSandboxAsync');
  const stdoutPromise = collectStream(proc.standardOutput);
  const stderrPromise = collectStream(proc.standardError);
  const waitPromise = Promise.all([proc.waitAsync(), stdoutPromise, stderrPromise]);
  let failed = false;
  try {
    const [result, stdout, stderr] = await waitPromise;
    return {
      stdout,
      stderr,
      exitCode: result.exitCode,
      timedOut: result.timedOut,
      warnings: [...proc.warnings],
      ...(proc.outputMetadata === undefined
        ? {}
        : { outputMetadata: proc.outputMetadata }),
    };
  } catch (error) {
    failed = true;
    throw error;
  } finally {
    try {
      proc.dispose();
    } catch (error) {
      if (!failed) throw error;
      logBackgroundFailure('disposing buffered exec after failure', error);
    }
  }
}

/** Spawn a workload in an existing container with live standard pipes. */
export function spawnInContainer<C extends PipedExecBackend>(
  containerId: ContainerId<C>,
  request: ExecRequest<C>,
  options: MxcOptions = {},
): MxcProcess {
  return execInSandbox(containerId, request, options);
}

/** Run a workload in an existing container and capture its output. */
export function runInContainer<C extends PipedExecBackend>(
  containerId: ContainerId<C>,
  request: ExecRequest<C>,
  options?: MxcOptions,
): Promise<ExecResult> {
  return execInSandboxAsync(containerId, request, options);
}

/**
 * Stops a started sandbox without releasing its provision-side resources.
 * The same sandbox can be started again via `startSandbox`.
 */
export async function stopSandbox<C extends LifecycleBackend>(
  sandboxId: ContainerId<C>,
  config?: StopConfigFor<C>,
  options: MxcOptions = {},
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
export async function deprovisionSandbox<C extends LifecycleBackend>(
  sandboxId: ContainerId<C>,
  config?: DeprovisionConfigFor<C>,
  options: MxcOptions = {},
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
