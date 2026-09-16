// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Synchronous Koffi wrapper for a run-to-completion native request. Async
// callers invoke this module through run-worker.ts.

import koffi from 'koffi';
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

export function runBindingRequest(request: RequestSpec): BindingRunResult {
  const native = loadMxcFfi();
  try {
    const run = bindNativeFunction<
      (request: string, result: AbiRunResult) => number
    >(native.handle, {
      symbol: 'mxc_run_request',
      result: 'int32_t',
      parameters: [
        'const char *',
        koffi.out(koffi.pointer(AbiRunResultType)),
      ],
    });

    const free = bindNativeFunction<(result: AbiRunResult) => void>(
      native.handle,
      {
        symbol: 'mxc_run_result_free',
        result: 'void',
        parameters: [koffi.pointer(AbiRunResultType)],
      },
    );

    const result = {} as AbiRunResult;
    let filled = false;

    try {
      const requestJson = JSON.stringify(request);
      const status = run(requestJson, result);
      filled = true;
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
    } finally {
      if (filled) free(result);
    }
  } finally {
    native.handle.unload();
  }
}
