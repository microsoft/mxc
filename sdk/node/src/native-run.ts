// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import koffi, { type KoffiFunc } from 'koffi';
import { MxcError, type ErrorCode } from './errors.js';
import { loadMxcFfi } from './native-library.js';

interface AbiErrorDetail {
  message: unknown | null;
  operation: unknown | null;
  nativeCode: unknown | null;
  remediation: unknown | null;
}

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

export interface NativeRunResult {
  stdout: string;
  stderr: string;
  exitCode: number;
  timedOut: boolean;
  outputMetadata?: unknown;
  warnings: string[];
}

const AbiErrorDetailType = koffi.struct('MxcNodeJsonErrorDetail', {
  message: 'void *',
  operation: 'void *',
  nativeCode: 'void *',
  remediation: 'void *',
});

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

function decodeString(pointer: unknown): string | undefined {
  if (pointer === null || pointer === undefined || pointer === 0 || pointer === 0n) {
    return undefined;
  }
  return koffi.decode(pointer, 'char', -1) as string;
}

/** @internal Stable native-status mapping, exported for deterministic tests. */
export function _errorCodeForNativeStatus(status: number): ErrorCode {
  const codes: Partial<Record<number, ErrorCode>> = {
    1: 'malformed_request',
    2: 'unsupported_containment',
    3: 'unsupported_phase',
    4: 'backend_unavailable',
    5: 'malformed_id',
    6: 'stale_id',
    7: 'not_provisioned',
    8: 'not_started',
    9: 'already_started',
    10: 'already_stopped',
    11: 'policy_validation',
    12: 'backend_error',
    100: 'malformed_request',
    101: 'malformed_request',
  };
  return codes[status] ?? 'backend_error';
}

function nativeError(status: number, detail: AbiErrorDetail): MxcError {
  return new MxcError({
    code: _errorCodeForNativeStatus(status),
    message: decodeString(detail.message) ?? `mxc_ffi failed with status ${status}`,
    operation: decodeString(detail.operation),
    nativeCode: decodeString(detail.nativeCode),
    remediation: decodeString(detail.remediation),
    details: { ffiStatus: status },
  });
}

function parseStringArray(json: string | undefined): string[] {
  if (json === undefined) return [];
  const value: unknown = JSON.parse(json);
  if (!Array.isArray(value) || value.some((entry) => typeof entry !== 'string')) {
    throw new MxcError('backend_error', 'mxc_ffi returned malformed warnings');
  }
  return value;
}

export function runNativeRequest(requestJson: string): NativeRunResult {
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
      const status = run(requestJson, result);
      filled = true;
      if (status !== 0 || result.status !== 0) {
        throw nativeError(result.status || status, result.error);
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
