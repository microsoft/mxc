// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Koffi wrappers for run-to-completion native requests. The async form uses
// Koffi's worker pool so the blocking native call does not block Node's event
// loop or require a dedicated Worker per request.

import koffi from 'koffi';
import { MxcError } from '../errors.js';
import { loadMxcFfi } from '../native-library.js';
import type { RequestSpec } from './request.js';
import { bindNativeFunction } from './native-function.js';
import {
  AbiErrorDetailType,
  decodeString,
  nativeStatusError,
  parseStringArray,
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

type RunFunction = (request: string, result: AbiRunResult) => number;
type FreeFunction = (result: AbiRunResult) => void;

export interface BindingRunResult {
  stdout: string;
  stderr: string;
  exitCode: number;
  timedOut: boolean;
  outputMetadata?: unknown;
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
): {
  run: ReturnType<typeof bindNativeFunction<RunFunction>>;
  free: ReturnType<typeof bindNativeFunction<FreeFunction>>;
} {
  return {
    run: bindNativeFunction<RunFunction>(native.handle, {
      symbol: 'mxc_run_request',
      result: 'int32_t',
      parameters: [
        'const char *',
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
  const metadata = decodeString(result.outputMetadata);
  return {
    stdout: decodeString(result.stdout) ?? '',
    stderr: decodeString(result.stderr) ?? '',
    exitCode: result.exitCode,
    timedOut: result.timedOut !== 0,
    outputMetadata: metadata === undefined ? undefined : JSON.parse(metadata),
    warnings: parseStringArray(decodeString(result.warnings)),
  };
}

export function runBindingRequest(request: RequestSpec): BindingRunResult {
  const native = loadMxcFfi();
  try {
    const { run, free } = bindRunFunctions(native);
    const result = {} as AbiRunResult;
    let filled = false;
    try {
      const status = run(JSON.stringify(request), result);
      filled = true;
      return decodeRunResult(status, result);
    } finally {
      if (filled) free(result);
    }
  } finally {
    native.handle.unload();
  }
}

async function runBindingRequestAsyncNative(
  request: RequestSpec,
): Promise<BindingRunResult> {
  const native = loadMxcFfi();
  try {
    const { run, free } = bindRunFunctions(native);
    const result = {} as AbiRunResult;
    let filled = false;
    try {
      const requestJson = JSON.stringify(request);
      const status = await new Promise<number>((resolve, reject) => {
        run.async(requestJson, result, (error, nativeStatus) => {
          if (error !== null) {
            reject(error);
            return;
          }
          filled = true;
          resolve(nativeStatus);
        });
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
  request: RequestSpec,
) => Promise<BindingRunResult>;

let asyncRunImplementation = runBindingRequestAsyncNative;

/** @internal Replaces the async native call for one process's unit tests. */
export function _setBindingRunAsyncImplementation(
  implementation?: AsyncRunImplementation,
): void {
  asyncRunImplementation = implementation ?? runBindingRequestAsyncNative;
}

export function runBindingRequestAsync(
  request: RequestSpec,
): Promise<BindingRunResult> {
  return asyncRunImplementation(request).catch((error: unknown) => {
    if (error instanceof MxcError) throw error;
    throw new MxcError(
      'backend_error',
      error instanceof Error ? error.message : String(error),
    );
  });
}
