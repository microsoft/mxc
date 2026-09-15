// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import koffi, { type KoffiFunc } from 'koffi';
import { loadMxcFfi } from '../native-library.js';
import type { BindingSandboxRequest } from './request.js';
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

type RunFunction = KoffiFunc<(request: string, result: AbiRunResult) => number>;

export function runBindingRequest(request: BindingSandboxRequest): BindingRunResult {
  const native = loadMxcFfi();
  try {
    const run = native.handle.func(
      'mxc_run_request',
      'int32_t',
      ['const char *', koffi.out(koffi.pointer(AbiRunResultType))],
    ) as RunFunction;
    const free = native.handle.func(
      'mxc_run_result_free',
      'void',
      [koffi.pointer(AbiRunResultType)],
    ) as (result: AbiRunResult) => void;
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
