// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Koffi wrappers for run-to-completion native requests. The async form uses
// Koffi's worker pool so the blocking native call does not block Node's event
// loop or require a dedicated Worker per request.

import koffi from 'koffi';
import { MxcError } from '../v1/errors.js';
import { loadMxcFfi } from '../native-library.js';
import type { OneShotRequest } from '../generated/v1_0_0/wire.js';
import type { ExecutionMetadata } from '../v1/types.js';
import { bindNativeFunction } from './native-function.js';
import {
  AbiErrorDetailType,
  decodeString,
  nativeStatusError,
  parseStringArray,
  parseExecutionMetadata,
  type AbiErrorDetail,
} from './native-error.js';

export { _errorCodeForNativeStatus } from './native-error.js';

interface AbiRunResult {
  status: number;
  exitCode: number;
  timedOut: number;
  stdout: unknown | null;
  stderr: unknown | null;
  error: AbiErrorDetail;
  outputMetadata: unknown | null;
  warnings: unknown | null;
}

type RunFunction = (
  request: string,
  experimental: number,
  result: AbiRunResult,
) => number;
type FreeFunction = (result: AbiRunResult) => void;

export interface BindingRunResult {
  stdout: string;
  stderr: string;
  exitCode: number;
  timedOut: boolean;
  outputMetadata?: ExecutionMetadata;
  warnings: string[];
}

const AbiRunResultType = koffi.struct('MxcNodeJsonRunResult', {
  status: 'int32_t',
  exitCode: 'int32_t',
  timedOut: 'int32_t',
  stdout: 'void *',
  stderr: 'void *',
  error: AbiErrorDetailType,
  outputMetadata: 'void *',
  warnings: 'void *',
});

function bindRunFunctions(
  native: ReturnType<typeof loadMxcFfi>,
  symbol = 'mxc_run_json',
): {
  run: ReturnType<typeof bindNativeFunction<RunFunction>>;
  free: ReturnType<typeof bindNativeFunction<FreeFunction>>;
} {
  return {
    run: bindNativeFunction<RunFunction>(native.handle, {
      symbol,
      result: 'int32_t',
      parameters: [
        'const char *',
        'int32_t',
        koffi.out(koffi.pointer(AbiRunResultType)),
      ],
    }),
    free: bindNativeFunction<FreeFunction>(native.handle, {
      symbol: 'mxc_run_result_free',
      result: 'void',
      parameters: [koffi.pointer(AbiRunResultType)],
    }),
  };
}

function decodeRunResult(status: number, result: AbiRunResult): BindingRunResult {
  if (status !== 0 || result.status !== 0) {
    throw nativeStatusError(result.status || status, result.error);
  }
  return {
    stdout: decodeString(result.stdout) ?? '',
    stderr: decodeString(result.stderr) ?? '',
    exitCode: result.exitCode,
    timedOut: result.timedOut !== 0,
    outputMetadata: parseExecutionMetadata(decodeString(result.outputMetadata)),
    warnings: parseStringArray(decodeString(result.warnings)),
  };
}

function runOneShotJsonNative(
  request: OneShotRequest,
  experimental: boolean,
): BindingRunResult {
  return runJsonNative(JSON.stringify(request), experimental, 'mxc_run_json');
}

function runJsonNative(
  requestJson: string,
  experimental: boolean,
  symbol: string,
): BindingRunResult {
  const native = loadMxcFfi();
  try {
    const { run, free } = bindRunFunctions(native, symbol);
    const result = {} as AbiRunResult;
    let filled = false;
    try {
      const status = run(requestJson, experimental ? 1 : 0, result);
      filled = true;
      return decodeRunResult(status, result);
    } finally {
      if (filled) free(result);
    }
  } finally {
    native.handle.unload();
  }
}

type StateAwareRunImplementation = (
  requestJson: string,
  experimental: boolean,
) => BindingRunResult;

const runStateAwareExecJsonNative: StateAwareRunImplementation = (requestJson, experimental) =>
  runJsonNative(requestJson, experimental, 'mxc_run_state_aware_exec_json');

let stateAwareRunImplementation = runStateAwareExecJsonNative;

/** @internal Replaces the synchronous captured lifecycle call for unit tests. */
export function _setBindingStateAwareRunImplementation(
  implementation?: StateAwareRunImplementation,
): void {
  stateAwareRunImplementation = implementation ?? runStateAwareExecJsonNative;
}

export function runStateAwareExecJson(
  requestJson: string,
  experimental = false,
): BindingRunResult {
  return stateAwareRunImplementation(requestJson, experimental);
}

type SyncRunImplementation = (
  request: OneShotRequest,
  experimental: boolean,
) => BindingRunResult;

let syncRunImplementation = runOneShotJsonNative;

/** @internal Replaces the synchronous native call for one process's unit tests. */
export function _setBindingRunImplementation(
  implementation?: SyncRunImplementation,
): void {
  syncRunImplementation = implementation ?? runOneShotJsonNative;
}

export function runOneShotJson(
  request: OneShotRequest,
  experimental = false,
): BindingRunResult {
  return syncRunImplementation(request, experimental);
}

async function runOneShotJsonAsyncNative(
  request: OneShotRequest,
  experimental: boolean,
): Promise<BindingRunResult> {
  const native = loadMxcFfi();
  try {
    const { run, free } = bindRunFunctions(native);
    const result = {} as AbiRunResult;
    let filled = false;
    try {
      const requestJson = JSON.stringify(request);
      const status = await new Promise<number>((resolve, reject) => {
        run.async(
          requestJson,
          experimental ? 1 : 0,
          result,
          (error, nativeStatus) => {
            if (error !== null) {
              reject(error);
              return;
            }
            filled = true;
            resolve(nativeStatus);
          },
        );
      });
      return decodeRunResult(status, result);
    } finally {
      if (filled) free(result);
    }
  } finally {
    native.handle.unload();
  }
}

type AsyncRunImplementation = (
  request: OneShotRequest,
  experimental: boolean,
) => Promise<BindingRunResult>;

let asyncRunImplementation = runOneShotJsonAsyncNative;

/** @internal Replaces the async native call for one process's unit tests. */
export function _setBindingRunAsyncImplementation(
  implementation?: AsyncRunImplementation,
): void {
  asyncRunImplementation = implementation ?? runOneShotJsonAsyncNative;
}

export function runOneShotJsonAsync(
  request: OneShotRequest,
  experimental = false,
): Promise<BindingRunResult> {
  return asyncRunImplementation(request, experimental).catch((error: unknown) => {
    if (error instanceof MxcError) throw error;
    throw new MxcError(
      'backend_error',
      error instanceof Error ? error.message : String(error),
    );
  });
}
