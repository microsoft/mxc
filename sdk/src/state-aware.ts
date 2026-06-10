// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import type pty from 'node-pty';
import { resolveBinaryAndCommonArgs } from './helper.js';
import { loadPty } from './lazyPty.js';
import { SandboxSpawnOptions } from './sandbox.js';
import { mxcErrorFromCode } from './errors.js';
import { diagLog } from './diagnostic.js';
import {
  DeprovisionConfigFor,
  DeprovisionResult,
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
import {
  backendForSandboxId,
  buildStateAwareEnvelope,
  nonExecCall,
  spawnAndCollect,
  tryParseErrorEnvelope,
} from './state-aware-helper.js';

/**
 * Provisions a state-aware sandbox of the requested backend. Returns a
 * branded sandbox id and any provision-time metadata the backend produces.
 */
export async function provisionSandbox<C extends StateAwareContainmentBackend>(
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
  return nonExecCall<StartResult<C>>(envelope, options);
}

/**
 * Streams a script execution inside a started sandbox. Returns an
 * `IPty` for live stdout/stderr/exit handling, mirroring `spawnSandbox`.
 * On dispatch failure the executor emits a single error envelope on stdout;
 * the SDK does not parse it here — callers consuming `IPty.onData` see the
 * raw bytes. Use `execInSandboxAsync` when typed-error throwing is needed.
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
  const ptyProcess = loadPty().spawn(executablePath, args, {
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
 * on script completion. Throws an `MxcError` (with the wire-format `code`
 * field set) when the executor reports a dispatch failure (recognised by
 * exit != 0 and stdout being a complete `{error}` envelope).
 */
export async function execInSandboxAsync<C extends StateAwareContainmentBackend>(
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
  return nonExecCall<StopResult<C>>(envelope, options);
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
  return nonExecCall<DeprovisionResult<C>>(envelope, options);
}
