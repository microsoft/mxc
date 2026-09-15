// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import koffi, { type KoffiFunc } from 'koffi';
import { loadMxcFfi } from '../native-library.js';
import {
  AbiErrorDetailType,
  decodeString,
  nativeStatusError,
  type AbiErrorDetail,
} from './native-error.js';

interface AbiStateAwareResult {
  status: number;
  responseJsonUtf8: unknown | null;
  error: AbiErrorDetail;
}

export interface BindingStateAwareRequest {
  requestJson: string;
  dryRun: boolean;
  experimental: boolean;
}

const AbiStateAwareResultType = koffi.struct('MxcNodeStateAwareResult', {
  status: 'int32_t',
  responseJsonUtf8: 'void *',
  error: AbiErrorDetailType,
});

type StateAwareFunction = KoffiFunc<(
  request: string,
  dryRun: number,
  experimental: number,
  result: AbiStateAwareResult,
) => number>;

export function runBindingStateAwareRequest(
  request: BindingStateAwareRequest,
): string {
  const native = loadMxcFfi();
  try {
    const run = native.handle.func(
      'mxc_state_aware',
      'int32_t',
      ['const char *', 'int32_t', 'int32_t', koffi.out(koffi.pointer(AbiStateAwareResultType))],
    ) as StateAwareFunction;
    const free = native.handle.func(
      'mxc_state_aware_result_free',
      'void',
      [koffi.pointer(AbiStateAwareResultType)],
    ) as (result: AbiStateAwareResult) => void;
    const result = {} as AbiStateAwareResult;
    let filled = false;

    try {
      const status = run(
        request.requestJson,
        request.dryRun ? 1 : 0,
        request.experimental ? 1 : 0,
        result,
      );
      filled = true;
      if (status !== 0 || result.status !== 0) {
        throw nativeStatusError(result.status || status, result.error, 'state-aware request failed');
      }
      return decodeString(result.responseJsonUtf8) ?? '{}';
    } finally {
      if (filled) free(result);
    }
  } finally {
    native.handle.unload();
  }
}
