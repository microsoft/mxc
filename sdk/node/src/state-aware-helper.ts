// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { spawn } from 'child_process';
import { resolveBinaryAndCommonArgs } from './helper.js';
import { SandboxSpawnOptions } from './sandbox.js';
import { mxcErrorFromCode, mxcErrorFromEnvelope, WireError } from './errors.js';
import { diagLog } from './diagnostic.js';
import {
  Phase,
  STATE_AWARE_VERSION,
  StateAwareContainmentBackend,
} from './state-aware-types.js';

export { STATE_AWARE_VERSION };

// Keep the WSLC constant separate because it is part of the public SDK surface
// and remains independently versioned, even though every state-aware backend
// currently uses the exact 0.9 development contract.
export const WSLC_STATE_AWARE_VERSION = '0.9.0-alpha';

// Wire-format cross-cutting fields that live at the envelope's top level.
// Anything else on a per-(backend, phase) Config is backend-specific and is
// nested under `experimental.<backend>.<phase>`.
export const CROSS_CUTTING_FIELDS = ['filesystem', 'network', 'ui', 'process', 'telemetry'] as const;

// Per-backend wire-format prefix. Each value mirrors the corresponding
// Rust `<Backend>Runner::ID_PREFIX` const and is the leading segment of a
// `sandboxId` produced by that backend. Each future state-aware backend
// declares its own `<BACKEND>_ID_PREFIX` const here.
export const ISOLATION_SESSION_ID_PREFIX = 'iso';
export const WINDOWS_SANDBOX_ID_PREFIX = 'wsb';
export const WSLC_ID_PREFIX = 'wslc';

// Per-backend default schema version stamped onto an envelope when the caller
// supplies none. Each backend's state-aware surface was promoted at its own
// schema version, so the default is backend-specific rather than a single
// global constant.
const DEFAULT_STATE_AWARE_VERSION: Record<StateAwareContainmentBackend, string> = {
  isolation_session: STATE_AWARE_VERSION,
  windows_sandbox: STATE_AWARE_VERSION,
  wslc: WSLC_STATE_AWARE_VERSION,
};

// Exhaustive backend→prefix map. Typed `Record<StateAwareContainmentBackend,
// string>` so adding a backend to the union without registering a prefix here
// is a compile error — the same exhaustiveness guarantee the config, metadata,
// and default-version registries carry. Without it a new backend would compile
// with no prefix and fail every non-provision call at runtime with
// `malformed_id`.
export const BACKEND_TO_PREFIX: Record<StateAwareContainmentBackend, string> = {
  isolation_session: ISOLATION_SESSION_ID_PREFIX,
  windows_sandbox: WINDOWS_SANDBOX_ID_PREFIX,
  wslc: WSLC_ID_PREFIX,
};

// Reverse lookup (prefix → backend), derived from the exhaustive map above so
// the two can never drift. Used to route a sandboxId's leading prefix segment
// to its wire-format backend key.
export const PREFIX_TO_BACKEND: Record<string, StateAwareContainmentBackend> = Object.fromEntries(
  (Object.entries(BACKEND_TO_PREFIX) as [StateAwareContainmentBackend, string][]).map(
    ([backend, prefix]) => [prefix, backend],
  ),
);

/**
 * Resolves the wire-format backend key for a sandbox id by reading its
 * leading prefix segment. Throws an `MxcError` with `code: 'malformed_id'`
 * when the id has no recognised prefix.
 */
export function backendForSandboxId(sandboxId: string): StateAwareContainmentBackend {
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

export interface BuildEnvelopeArgs {
  phase: Phase;
  backendKey: StateAwareContainmentBackend;
  containment?: StateAwareContainmentBackend; // provision only
  sandboxId?: string;                        // non-provision only
  config?: Record<string, unknown>;
}

/**
 * Constructs the wire-format JSON-shaped envelope for a state-aware request
 * from a per-(backend, phase) Config. Lifts cross-cutting fields
 * (filesystem, network, ui, process, telemetry) to envelope top-level; nests any
 * remaining backend-specific fields under `experimental.<backend>.<phase>`.
 */
export function buildStateAwareEnvelope(args: BuildEnvelopeArgs): Record<string, unknown> {
  const { phase, backendKey, containment, sandboxId, config } = args;
  // Copy of config; fields are removed as they are lifted into the envelope.
  // Anything left becomes experimental.<backend>.<phase>.
  const backendSpecific: Record<string, unknown> = { ...(config ?? {}) };
  const defaultVersion = DEFAULT_STATE_AWARE_VERSION[backendKey] ?? STATE_AWARE_VERSION;
  const requestedVersion = backendSpecific.version;
  if (requestedVersion !== undefined && requestedVersion !== defaultVersion) {
    throw mxcErrorFromCode(
      'malformed_request',
      `State-aware ${backendKey} requests require schema version '${defaultVersion}', ` +
      `got '${String(requestedVersion)}'.`,
    );
  }
  const version = defaultVersion;
  delete backendSpecific.version;

  const envelope: Record<string, unknown> = { version, phase };
  if (containment) {
    envelope.containment = containment;
  }
  if (sandboxId) {
    envelope.sandboxId = sandboxId;
  }

  for (const field of CROSS_CUTTING_FIELDS) {
    if (backendSpecific[field] !== undefined) {
      envelope[field] = backendSpecific[field];
      delete backendSpecific[field];
    }
  }

  if (Object.keys(backendSpecific).length > 0) {
    envelope.experimental = { [backendKey]: { [phase]: backendSpecific } };
  }

  return envelope;
}

export interface WireErrorEnvelope {
  error: WireError;
}

export interface WireResultEnvelope<T> {
  result: T;
}

/**
 * Parses the single-envelope JSON stdout produced by non-exec state-aware
 * phases. Throws the corresponding `MxcError` on `{error}`, returns the
 * unwrapped `result` on `{result}`.
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
      throw mxcErrorFromEnvelope(env);
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
export function tryParseErrorEnvelope(stdout: string): WireErrorEnvelope | null {
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

export type SpawnImpl = (cmd: string, args: string[], opts: unknown) => unknown;
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

export interface CollectedOutput {
  stdout: string;
  stderr: string;
  exitCode: number;
}

/**
 * Spawns the executor with the given envelope, captures stdout/stderr,
 * and resolves on close. Honors `options.signal` for cancellation.
 */
export function spawnAndCollect(
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
      stdin: NodeJS.WritableStream | null;
      stdout: NodeJS.ReadableStream | null;
      stderr: NodeJS.ReadableStream | null;
      kill: (signal?: NodeJS.Signals | number) => boolean;
      on: (event: string, cb: (...a: unknown[]) => void) => unknown;
    };

    // Buffered (non-streaming) exec supplies no stdin, so close the child's
    // write end immediately. The Rust state-aware exec path treats non-TTY
    // stdin as a pipe and blocks forwarding guest stdin until it sees EOF on
    // this handle; without the explicit end() a stdin-reading command (e.g.
    // `cat`) would hang until the phase timeout. EOF == "no input".
    //
    // Guard the stdin pipe with its own 'error' handler first: the child may
    // have already exited by the time we end(), in which case the write end
    // emits EPIPE. The child.on('error') below is on the process, not this
    // stream, so without this listener an unhandled 'error' would crash the
    // whole process instead of just failing this one call.
    child.stdin?.on('error', () => {});
    child.stdin?.end();

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
    if (signal) {
      signal.addEventListener('abort', onAbort, { once: true });
    }

    child.on('close', (...a: unknown[]) => {
      const code = a[0] as number | null;
      if (signal) {
        signal.removeEventListener('abort', onAbort);
      }
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

export async function nonExecCall<T>(
  envelope: Record<string, unknown>,
  options: SandboxSpawnOptions,
): Promise<T> {
  const { stdout } = await spawnAndCollect(envelope, options);
  return parseNonExecResponse<T>(stdout);
}
