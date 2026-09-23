// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Shared decoding for native status codes, owned strings, and error details.

import koffi from 'koffi';
import { MxcError, type ErrorCode } from '../errors.js';

export interface AbiErrorDetail {
  message: unknown | null;
  operation: unknown | null;
  nativeCode: unknown | null;
  remediation: unknown | null;
}

export const AbiErrorDetailType = koffi.struct('MxcNodeJsonErrorDetail', {
  message: 'void *',
  operation: 'void *',
  nativeCode: 'void *',
  remediation: 'void *',
});

export function decodeString(pointer: unknown): string | undefined {
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
    102: 'backend_error',
    103: 'backend_error',
  };
  return codes[status] ?? 'backend_error';
}

export function nativeStatusError(
  status: number,
  detail: Partial<AbiErrorDetail> = {},
  fallback = `native runtime failed with status ${status}`,
): MxcError {
  return new MxcError({
    code: _errorCodeForNativeStatus(status),
    message: decodeString(detail.message) ?? fallback,
    operation: decodeString(detail.operation),
    nativeCode: decodeString(detail.nativeCode),
    remediation: decodeString(detail.remediation),
    details: { ffiStatus: status },
  });
}

export function parseStringArray(
  json: string | undefined,
  message = 'native runtime returned malformed warnings',
): string[] {
  if (json === undefined) return [];
  const value: unknown = JSON.parse(json);
  if (!Array.isArray(value) || value.some((entry) => typeof entry !== 'string')) {
    throw new MxcError('backend_error', message);
  }
  return value;
}
