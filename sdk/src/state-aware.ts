// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import pty from 'node-pty';
import { spawn } from 'child_process';
import { resolveBinaryAndCommonArgs } from './helper.js';
import { SandboxSpawnOptions } from './sandbox.js';
import { mxcErrorFromCode } from './errors.js';
import { diagLog } from './diagnostic.js';
import {
  DeprovisionConfigFor,
  DeprovisionMetadataFor,
  DeprovisionResult,
  ExecConfigFor,
  ExecResult,
  Phase,
  ProvisionConfigFor,
  ProvisionMetadataFor,
  ProvisionResult,
  SandboxId,
  StartConfigFor,
  StartMetadataFor,
  StartResult,
  StateAwareSandboxingMethod,
  StopConfigFor,
  StopMetadataFor,
  StopResult,
} from './state-aware-types.js';

const STATE_AWARE_VERSION = '0.6.0-alpha';

// Wire-format cross-cutting fields that live at the envelope's top level.
// Anything else on a per-(backend, phase) Config is backend-specific and is
// nested under `experimental.<backend>.<phase>`.
const CROSS_CUTTING_FIELDS = ['filesystem', 'network', 'ui', 'process'] as const;

// Mapping from a sandboxId's leading prefix segment to the wire-format
// backend key. Extended as more state-aware backends opt in.
const PREFIX_TO_BACKEND: Record<string, StateAwareSandboxingMethod> = {
  iso: 'isolation_session',
};

/**
 * Resolves the wire-format backend key for a sandbox id by reading its
 * leading prefix segment. Throws `MxcMalformedIdError` when the id has no
 * recognised prefix.
 */
function backendForSandboxId(sandboxId: string): StateAwareSandboxingMethod {
  const colon = sandboxId.indexOf(':');
  if (colon < 0) {
    throw mxcErrorFromCode('malformed_id', `sandboxId must carry a backend prefix: ${sandboxId}`);
  }
  const prefix = sandboxId.slice(0, colon);
  const backend = PREFIX_TO_BACKEND[prefix];
  if (!backend) {
    throw mxcErrorFromCode('malformed_id', `sandboxId prefix '${prefix}' does not match a known state-aware backend`);
  }
  return backend;
}

interface BuildEnvelopeArgs {
  phase: Phase;
  backendKey: StateAwareSandboxingMethod;
  containment?: StateAwareSandboxingMethod; // provision only
  sandboxId?: string;                        // non-provision only
  config?: Record<string, unknown>;
}

/**
 * Constructs the wire-format JSON-shaped envelope for a state-aware request
 * from a per-(backend, phase) Config. Lifts cross-cutting fields
 * (filesystem, network, ui, process) to envelope top-level; nests any
 * remaining backend-specific fields under `experimental.<backend>.<phase>`.
 * Exported for unit testing; consumers do not call this directly.
 */
export function buildStateAwareEnvelope(args: BuildEnvelopeArgs): Record<string, unknown> {
  const { phase, backendKey, containment, sandboxId, config } = args;
  const remaining: Record<string, unknown> = { ...(config ?? {}) };
  const version = (typeof remaining.version === 'string' && remaining.version) || STATE_AWARE_VERSION;
  delete remaining.version;

  const envelope: Record<string, unknown> = { version, phase };
  if (containment) envelope.containment = containment;
  if (sandboxId) envelope.sandboxId = sandboxId;

  for (const field of CROSS_CUTTING_FIELDS) {
    if (remaining[field] !== undefined) {
      envelope[field] = remaining[field];
      delete remaining[field];
    }
  }

  if (Object.keys(remaining).length > 0) {
    envelope.experimental = { [backendKey]: { [phase]: remaining } };
  }

  return envelope;
}

interface WireErrorEnvelope {
  error: { code: string; message: string; details?: Record<string, unknown> };
}

interface WireResultEnvelope<T> {
  result: T;
}

/**
 * Parses the single-envelope JSON stdout produced by non-exec state-aware
 * phases. Throws the corresponding `MxcError` subclass on `{error}`,
 * returns the unwrapped `result` on `{result}`. Exported for unit testing.
 */
export function parseNonExecResponse<T>(stdout: string): T {
  let parsed: unknown;
  try {
    parsed = JSON.parse(stdout.trim());
  } catch (e) {
    throw new Error(`Failed to parse state-aware response envelope: ${(e as Error).message}`);
  }
  if (parsed && typeof parsed === 'object') {
    if ('error' in parsed) {
      const env = (parsed as WireErrorEnvelope).error;
      throw mxcErrorFromCode(env.code, env.message, env.details);
    }
    if ('result' in parsed) {
      return (parsed as WireResultEnvelope<T>).result;
    }
  }
  throw new Error(`Unexpected state-aware response envelope shape: ${stdout}`);
}

/**
 * Attempts to parse stdout as an `{error}` envelope. Returns the parsed
 * envelope when stdout is exactly that, or `null` otherwise (script output
 * mistaken for an envelope is suppressed). Used by exec to discriminate
 * dispatch failure from script failure.
 */
function tryParseErrorEnvelope(stdout: string): WireErrorEnvelope | null {
  try {
    const parsed = JSON.parse(stdout.trim());
    if (
      parsed && typeof parsed === 'object' && 'error' in parsed &&
      (parsed as WireErrorEnvelope).error?.code
    ) {
      return parsed as WireErrorEnvelope;
    }
  } catch {
    // Not JSON. Definitely script output.
  }
  return null;
}

// --- Spawn injection (test-only) ---

type SpawnImpl = (cmd: string, args: string[], opts: unknown) => unknown;
let spawnImpl: SpawnImpl = spawn as unknown as SpawnImpl;

/**
 * Test-only hook: replace the `child_process.spawn` implementation used by
 * non-exec state-aware calls and the buffered `execInSandboxAsync`. Not
 * exported from `index.ts` — production code uses the real `spawn`.
 */
export function _setSpawnImpl(fn: SpawnImpl): void {
  spawnImpl = fn;
}

/** Test-only hook: restore the default `child_process.spawn`. */
export function _resetSpawnImpl(): void {
  spawnImpl = spawn as unknown as SpawnImpl;
}

interface CollectedOutput {
  stdout: string;
  stderr: string;
  exitCode: number;
}

/**
 * Spawns the executor with the given envelope, captures stdout/stderr,
 * and resolves on close. Honors `options.signal` for cancellation.
 */
function spawnAndCollect(
  envelope: Record<string, unknown>,
  options: SandboxSpawnOptions,
): Promise<CollectedOutput> {
  return new Promise((resolve, reject) => {
    const signal = options.signal;
    if (signal?.aborted) {
      reject(signal.reason ?? new Error('Aborted'));
      return;
    }

    let executablePath: string;
    let args: string[];
    try {
      ({ executablePath, args } = resolveBinaryAndCommonArgs(JSON.stringify(envelope), options));
    } catch (err) {
      reject(err);
      return;
    }

    diagLog(`state-aware: spawning phase=${envelope.phase}`);

    const child = spawnImpl(executablePath, args, {
      stdio: ['pipe', 'pipe', 'pipe'],
    }) as {
      stdout: NodeJS.ReadableStream | null;
      stderr: NodeJS.ReadableStream | null;
      kill: (signal?: NodeJS.Signals | number) => boolean;
      on: (event: string, cb: (...a: unknown[]) => void) => unknown;
    };

    let stdoutData = '';
    let stderrData = '';

    child.stdout?.on('data', (d: Buffer | string) => {
      stdoutData += typeof d === 'string' ? d : d.toString('utf-8');
    });
    child.stderr?.on('data', (d: Buffer | string) => {
      stderrData += typeof d === 'string' ? d : d.toString('utf-8');
    });

    const onAbort = () => {
      child.kill();
    };
    if (signal) signal.addEventListener('abort', onAbort, { once: true });

    child.on('close', (...a: unknown[]) => {
      const code = a[0] as number | null;
      if (signal) signal.removeEventListener('abort', onAbort);
      if (signal?.aborted) {
        reject(signal.reason ?? new Error('Aborted'));
        return;
      }
      resolve({ stdout: stdoutData, stderr: stderrData, exitCode: code ?? -1 });
    });

    child.on('error', (...a: unknown[]) => {
      reject(a[0] as Error);
    });
  });
}

async function nonExecCall<T>(
  envelope: Record<string, unknown>,
  options: SandboxSpawnOptions,
): Promise<T> {
  const { stdout } = await spawnAndCollect(envelope, options);
  return parseNonExecResponse<T>(stdout);
}

// --- Public API: the 5 functions ---

/**
 * Provisions a state-aware sandbox of the requested backend. Returns a
 * branded sandbox id and any provision-time metadata the backend produces.
 */
export async function provisionSandbox<C extends StateAwareSandboxingMethod>(
  containment: C,
  config?: ProvisionConfigFor<C>,
  options: SandboxSpawnOptions = {},
): Promise<ProvisionResult<C>> {
  const envelope = buildStateAwareEnvelope({
    phase: 'provision',
    backendKey: containment,
    containment,
    config: config as Record<string, unknown> | undefined,
  });
  const result = await nonExecCall<{ sandboxId: string; metadata?: ProvisionMetadataFor<C> }>(
    envelope,
    options,
  );
  return {
    sandboxId: result.sandboxId as SandboxId<C>,
    metadata: result.metadata,
  };
}

/**
 * Starts a previously provisioned sandbox. The backend is inferred from
 * the `sandboxId` prefix.
 */
export async function startSandbox<C extends StateAwareSandboxingMethod>(
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
  return nonExecCall<StartResult<C>>(envelope, options);
}

/**
 * Streams a script execution inside a started sandbox. Returns an
 * `IPty` for live stdout/stderr/exit handling, mirroring `spawnSandbox`.
 * On dispatch failure the executor emits a single error envelope on stdout;
 * the SDK does not parse it here — callers consuming `IPty.onData` see the
 * raw bytes. Use `execInSandboxAsync` when typed-error throwing is needed.
 */
export function execInSandbox<C extends StateAwareSandboxingMethod>(
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
 * Buffered exec convenience. Resolves with `{stdout, stderr, exitCode}`
 * on script completion. Throws the typed `MxcError` subclass when the
 * executor reports a dispatch failure (recognised by exit != 0 and stdout
 * being a complete `{error}` envelope).
 */
export async function execInSandboxAsync<C extends StateAwareSandboxingMethod>(
  sandboxId: SandboxId<C>,
  config: ExecConfigFor<C>,
  options: SandboxSpawnOptions = {},
): Promise<ExecResult> {
  const backendKey = backendForSandboxId(sandboxId) as C;
  const envelope = buildStateAwareEnvelope({
    phase: 'exec',
    backendKey,
    sandboxId,
    config: config as unknown as Record<string, unknown>,
  });
  const { stdout, stderr, exitCode } = await spawnAndCollect(envelope, options);

  if (exitCode !== 0) {
    const errorEnvelope = tryParseErrorEnvelope(stdout);
    if (errorEnvelope) {
      const e = errorEnvelope.error;
      throw mxcErrorFromCode(e.code, e.message, e.details);
    }
  }

  return { stdout, stderr, exitCode };
}

/**
 * Stops a started sandbox without releasing its provision-side resources.
 * The same sandbox can be started again via `startSandbox`.
 */
export async function stopSandbox<C extends StateAwareSandboxingMethod>(
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
  return nonExecCall<StopResult<C>>(envelope, options);
}

/**
 * Releases all backend resources associated with a provisioned sandbox.
 * The id becomes invalid after this call returns successfully.
 */
export async function deprovisionSandbox<C extends StateAwareSandboxingMethod>(
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
  return nonExecCall<DeprovisionResult<C>>(envelope, options);
}
