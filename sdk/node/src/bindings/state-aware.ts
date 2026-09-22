// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Async native binding for state-aware lifecycle phases that run to completion.

import koffi from 'koffi';
import { MxcError } from '../errors.js';
import { loadMxcFfi } from '../native-library.js';
import { bindNativeFunction } from './native-function.js';
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

type StateAwareFunction = (
  request: string,
  dryRun: number,
  experimental: number,
  result: AbiStateAwareResult,
) => number;
type FreeFunction = (result: AbiStateAwareResult) => void;

function bindStateAwareFunctions(native: ReturnType<typeof loadMxcFfi>) {
  return {
    run: bindNativeFunction<StateAwareFunction>(native.handle, {
      symbol: 'mxc_state_aware',
      result: 'int32_t',
      parameters: [
        'const char *',
        'int32_t',
        'int32_t',
        koffi.out(koffi.pointer(AbiStateAwareResultType)),
      ],
    }),
    free: bindNativeFunction<FreeFunction>(native.handle, {
      symbol: 'mxc_state_aware_result_free',
      result: 'void',
      parameters: [koffi.pointer(AbiStateAwareResultType)],
    }),
  };
}

function createStateAwareResult(): AbiStateAwareResult {
  return {
    status: 0,
    responseJsonUtf8: null,
    error: {
      message: null,
      operation: null,
      nativeCode: null,
      remediation: null,
    },
  };
}

function decodeStateAwareResult(
  nativeStatus: number,
  result: AbiStateAwareResult,
): string {
  if (nativeStatus !== 0 || result.status !== 0) {
    throw nativeStatusError(
      result.status || nativeStatus,
      result.error,
      'state-aware request failed',
    );
  }
  return decodeString(result.responseJsonUtf8) ?? '{}';
}

async function runBindingStateAwareRequestAsyncNative(
  request: BindingStateAwareRequest,
): Promise<string> {
  const native = loadMxcFfi();
  try {
    const { run, free } = bindStateAwareFunctions(native);
    const result = createStateAwareResult();
    let ownsResult = false;
    try {
      const nativeStatus = await new Promise<number>((resolve, reject) => {
        run.async(
          request.requestJson,
          request.dryRun ? 1 : 0,
          request.experimental ? 1 : 0,
          result,
          (error, status) => {
            if (error !== null) {
              reject(error);
              return;
            }
            ownsResult = true;
            resolve(status);
          },
        );
      });
      return decodeStateAwareResult(nativeStatus, result);
    } finally {
      if (ownsResult) free(result);
    }
  } finally {
    native.handle.unload();
  }
}

type AsyncStateAwareImplementation = (
  request: BindingStateAwareRequest,
) => Promise<string>;

let asyncStateAwareImplementation = runBindingStateAwareRequestAsyncNative;

/** @internal Replaces the async native call for one process's unit tests. */
export function _setBindingStateAwareAsyncImplementation(
  implementation?: AsyncStateAwareImplementation,
): void {
  asyncStateAwareImplementation =
    implementation ?? runBindingStateAwareRequestAsyncNative;
}

export function runBindingStateAwareRequestAsync(
  request: BindingStateAwareRequest,
): Promise<string> {
  return asyncStateAwareImplementation(request).catch((error: unknown) => {
    if (error instanceof MxcError) throw error;
    throw new MxcError(
      'backend_error',
      error instanceof Error ? error.message : String(error),
    );
  });
}
