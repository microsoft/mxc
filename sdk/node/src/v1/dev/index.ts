// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/** Caller-authored exact-JSON operations. */

import type { ExecutionResult } from '../types.js';
import type { MxcProcess } from '../container-process.js';
import type { MxcPtyProcess, MxcPtySize } from '../mxc-pty-process.js';
import { MxcError } from '../errors.js';
import { captureProcessOutput } from '../capture.js';
import { diagLog } from '../../diagnostic.js';
import { runRawOneShotJsonAsync, type BindingRunResult } from '../../bindings/run.js';
import {
  spawnBindingSandboxProcessJson,
  spawnStateAwareBindingSandboxProcessAsync,
} from '../../bindings/streaming.js';
import {
  execStateAwareBindingSandboxWithPty,
  spawnBindingSandboxWithPtyJson,
} from '../../bindings/pty.js';
import { spawnProcessContainerWithPtyJson } from '../../bindings/process-container-pty.js';
import { runBindingStateAwareRequestAsync } from '../../bindings/state-aware.js';

/** Authorization supplied independently of the JSON contract version. */
export interface JsonOptions {
  experimental?: boolean;
}

/** Invocation controls for an exact-JSON PTY operation. */
export interface PtyJsonOptions extends JsonOptions {
  size?: MxcPtySize;
}

type Phase = 'provision' | 'start' | 'exec' | 'stop' | 'deprovision';

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function checkOptions(name: string, options: JsonOptions, pty = false): void {
  if (!isRecord(options)) {
    throw new MxcError('malformed_request', `${name} options must be an object`);
  }
  for (const [key, value] of Object.entries(options)) {
    if (key === 'experimental' && (value === undefined || typeof value === 'boolean')) continue;
    if (pty && key === 'size') continue;
    throw new MxcError('malformed_request', `${name} does not support option '${key}'`);
  }
}

function requestInfo(
  json: string,
  name: string,
  phase?: Phase,
): { containment: unknown; timeoutMs: number | undefined } {
  if (typeof json !== 'string') {
    throw new MxcError('malformed_request', `${name} requires a JSON string`);
  }
  if (Buffer.from(json, 'utf8').toString('utf8') !== json) {
    throw new MxcError('malformed_request', `${name} requires valid UTF-8 JSON text`);
  }
  let request: unknown;
  try {
    request = JSON.parse(json);
  } catch (error) {
    throw new MxcError(
      'malformed_request',
      `${name} received invalid JSON: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
  if (!isRecord(request)) {
    throw new MxcError('malformed_request', `${name} requires a JSON object`);
  }
  if (phase === undefined ? Object.hasOwn(request, 'phase') : request.phase !== phase) {
    throw new MxcError(
      'malformed_request',
      phase === undefined
        ? `${name} requires a one-shot document without phase`
        : `${name} requires phase '${phase}'`,
    );
  }
  const timeout = isRecord(request.process) ? request.process.timeout : undefined;
  return {
    containment: request.containment,
    timeoutMs: typeof timeout === 'number' && Number.isInteger(timeout)
      && timeout >= 0 && timeout <= 0xffff_ffff ? timeout : undefined,
  };
}

function ptySize(name: string, options: PtyJsonOptions): MxcPtySize {
  checkOptions(name, options, true);
  if (options.size === null) {
    throw new MxcError('malformed_request', `${name} size must be an object`);
  }
  const size = options.size ?? { rows: 24, columns: 80 };
  if (!isRecord(size) || typeof size.rows !== 'number' || typeof size.columns !== 'number'
      || !Number.isInteger(size.rows) || !Number.isInteger(size.columns)
      || size.rows < 1 || size.rows > 32767
      || size.columns < 1 || size.columns > 32767
      || Object.keys(size).some((key) => key !== 'rows' && key !== 'columns')) {
    throw new MxcError('malformed_request', 'PTY rows and columns must be integers between 1 and 32767');
  }
  return size;
}

function captureResult(result: BindingRunResult): ExecutionResult {
  return {
    stdout: result.stdout,
    stderr: result.stderr,
    exitCode: result.exitCode,
    timedOut: result.timedOut,
    warnings: result.warnings,
    ...(result.outputMetadata === undefined ? {} : { outputMetadata: result.outputMetadata }),
  };
}

function phaseResult(
  json: string,
  name: string,
  phase: Phase,
  dryRun: boolean,
  options: JsonOptions,
): Promise<string> {
  checkOptions(name, options);
  requestInfo(json, name, phase);
  return runBindingStateAwareRequestAsync({
    requestJson: json,
    dryRun,
    experimental: options.experimental === true,
  });
}

/** Capture a one-shot request. */
export async function runJson(json: string, options: JsonOptions = {}): Promise<ExecutionResult> {
  checkOptions('runJson', options);
  requestInfo(json, 'runJson');
  return captureResult(await runRawOneShotJsonAsync(json, options.experimental === true));
}

/** Spawn a one-shot request with pipes. */
export async function spawnJson(json: string, options: JsonOptions = {}): Promise<MxcProcess> {
  checkOptions('spawnJson', options);
  const { timeoutMs } = requestInfo(json, 'spawnJson');
  return spawnBindingSandboxProcessJson(json, options.experimental === true, timeoutMs);
}

/** Spawn a one-shot request with a PTY. */
export async function spawnWithPtyJson(
  json: string,
  options: PtyJsonOptions = {},
): Promise<MxcPtyProcess> {
  const size = ptySize('spawnWithPtyJson', options);
  const { containment, timeoutMs } = requestInfo(json, 'spawnWithPtyJson');
  if (process.platform === 'win32' &&
      (containment === undefined || containment === 'process'
        || containment === 'processcontainer' || containment === 'appcontainer')) {
    return spawnProcessContainerWithPtyJson(
      json, options.experimental === true, size.rows, size.columns,
    );
  }
  return spawnBindingSandboxWithPtyJson(
    json, options.experimental === true, size.rows, size.columns, timeoutMs,
  );
}

/** Capture execution in a caller-owned container. */
export async function runInContainerJson(
  json: string,
  options: JsonOptions = {},
): Promise<ExecutionResult> {
  checkOptions('runInContainerJson', options);
  const { timeoutMs } = requestInfo(json, 'runInContainerJson', 'exec');
  const proc = await spawnStateAwareBindingSandboxProcessAsync(
    json, options.experimental === true, timeoutMs,
  );
  let failed = false;
  try {
    const { result: outcome, stdout, stderr } = await captureProcessOutput(proc);
    return {
      stdout, stderr,
      exitCode: outcome.exitCode,
      timedOut: outcome.timedOut,
      warnings: [...proc.warnings],
      ...(proc.outputMetadata === undefined ? {} : { outputMetadata: proc.outputMetadata }),
    };
  } catch (error) {
    failed = true;
    throw error;
  } finally {
    try {
      proc.dispose();
    } catch (error) {
      if (!failed) throw error;
      diagLog(`state-aware: disposing buffered exact-JSON exec after failure: ${
        error instanceof Error ? error.message : String(error)
      }`);
    }
  }
}

/** Spawn execution with pipes in a caller-owned container. */
export async function spawnInContainerJson(
  json: string,
  options: JsonOptions = {},
): Promise<MxcProcess> {
  checkOptions('spawnInContainerJson', options);
  const { timeoutMs } = requestInfo(json, 'spawnInContainerJson', 'exec');
  return spawnStateAwareBindingSandboxProcessAsync(
    json, options.experimental === true, timeoutMs,
  );
}

/** Spawn execution with a PTY in a caller-owned container. */
export async function spawnInContainerWithPtyJson(
  json: string,
  options: PtyJsonOptions = {},
): Promise<MxcPtyProcess> {
  const size = ptySize('spawnInContainerWithPtyJson', options);
  const { timeoutMs } = requestInfo(json, 'spawnInContainerWithPtyJson', 'exec');
  return execStateAwareBindingSandboxWithPty(
    json, options.experimental === true, size.rows, size.columns, timeoutMs,
  );
}

/** Provision a container. */
export async function provisionContainerJson(
  json: string,
  options: JsonOptions = {},
): Promise<string> {
  return phaseResult(json, 'provisionContainerJson', 'provision', false, options);
}

/** Start a provisioned container. */
export async function startContainerJson(json: string, options: JsonOptions = {}): Promise<string> {
  return phaseResult(json, 'startContainerJson', 'start', false, options);
}

/** Stop a running container. */
export async function stopContainerJson(json: string, options: JsonOptions = {}): Promise<string> {
  return phaseResult(json, 'stopContainerJson', 'stop', false, options);
}

/** Deprovision a container. */
export async function deprovisionContainerJson(
  json: string,
  options: JsonOptions = {},
): Promise<string> {
  return phaseResult(json, 'deprovisionContainerJson', 'deprovision', false, options);
}

/** Validate a provision request. */
export async function validateProvisionJson(
  json: string,
  options: JsonOptions = {},
): Promise<string> {
  return phaseResult(json, 'validateProvisionJson', 'provision', true, options);
}

/** Validate a start request. */
export async function validateStartJson(json: string, options: JsonOptions = {}): Promise<string> {
  return phaseResult(json, 'validateStartJson', 'start', true, options);
}

/** Validate a stop request. */
export async function validateStopJson(json: string, options: JsonOptions = {}): Promise<string> {
  return phaseResult(json, 'validateStopJson', 'stop', true, options);
}

/** Validate a deprovision request. */
export async function validateDeprovisionJson(
  json: string,
  options: JsonOptions = {},
): Promise<string> {
  return phaseResult(json, 'validateDeprovisionJson', 'deprovision', true, options);
}

/** Validate an existing-container execution request. */
export async function validateProcessJson(
  json: string,
  options: JsonOptions = {},
): Promise<string> {
  return phaseResult(json, 'validateProcessJson', 'exec', true, options);
}
