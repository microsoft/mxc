// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Async native binding for state-aware lifecycle phases that run to completion.

import koffi from 'koffi';
import { MxcError, mxcErrorFromEnvelope, type WireError } from '../v1/errors.js';
import { loadMxcFfi } from '../native-library.js';
import { bindNativeFunction } from './native-function.js';
import {
  AbiErrorDetailType,
  decodeString,
  nativeStatusError,
  type AbiErrorDetail,
} from './native-error.js';

export interface StateAwareNativeResult {
  status: number;
  responseJsonUtf8: unknown | null;
  error: AbiErrorDetail;
}

export interface BindingStateAwareRequest {
  requestJson: string;
  dryRun: boolean;
  experimental: boolean;
}

export const AbiStateAwareResultType = koffi.struct('MxcNodeStateAwareResult', {
  status: 'int32_t',
  responseJsonUtf8: 'void *',
  error: AbiErrorDetailType,
});

type StateAwareFunction = (
  request: string,
  dryRun: number,
  experimental: number,
  result: StateAwareNativeResult,
) => number;
type FreeFunction = (result: StateAwareNativeResult) => void;
type StateAwareCompletion = (error: Error | null, status: number) => void;

export interface StateAwareNativeFacade {
  run(
    request: string,
    dryRun: number,
    experimental: number,
    result: StateAwareNativeResult,
    completion: StateAwareCompletion,
  ): void;
  free(result: StateAwareNativeResult): void;
}

function bindStateAwareNativeFacade(
  native: ReturnType<typeof loadMxcFfi>,
): StateAwareNativeFacade {
  const run = bindNativeFunction<StateAwareFunction>(native.handle, {
    symbol: 'mxc_run_state_aware_json_with_details',
    result: 'int32_t',
    parameters: [
      'const char *',
      'int32_t',
      'int32_t',
      koffi.out(koffi.pointer(AbiStateAwareResultType)),
    ],
  });
  const free = bindNativeFunction<FreeFunction>(native.handle, {
    symbol: 'mxc_state_aware_result_free',
    result: 'void',
    parameters: [koffi.pointer(AbiStateAwareResultType)],
  });
  return {
    run(request, dryRun, experimental, result, completion) {
      run.async(request, dryRun, experimental, result, completion);
    },
    free,
  };
}

export function createStateAwareResult(): StateAwareNativeResult {
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

function isWireError(value: unknown): value is WireError {
  if (value === null || typeof value !== 'object') return false;
  return 'code' in value && typeof value.code === 'string'
    && 'message' in value && typeof value.message === 'string'
    && (!('operation' in value) || typeof value.operation === 'string')
    && (!('nativeCode' in value) || typeof value.nativeCode === 'string')
    && (!('remediation' in value) || typeof value.remediation === 'string')
    && (!('details' in value) || (value.details !== null
      && typeof value.details === 'object' && !Array.isArray(value.details)));
}

export function decodeStateAwareResult(
  nativeStatus: number,
  result: StateAwareNativeResult,
): string {
  if (nativeStatus !== 0 || result.status !== 0) {
    const json = decodeString(result.responseJsonUtf8);
    if (json !== undefined) {
      const envelope: unknown = JSON.parse(json);
      if (envelope === null || typeof envelope !== 'object'
        || !('error' in envelope) || !isWireError(envelope.error)) {
        throw new MxcError('backend_error', 'native lifecycle error envelope is malformed');
      }
      throw mxcErrorFromEnvelope(envelope.error);
    }
    throw nativeStatusError(
      result.status || nativeStatus,
      result.error,
      'state-aware request failed',
    );
  }
  const responseJson = decodeString(result.responseJsonUtf8);
  if (responseJson === undefined || responseJson.length === 0) {
    throw new MxcError('backend_error', 'native lifecycle response is missing JSON');
  }
  return responseJson;
}

export async function runBindingStateAwareRequestWithNative(
  request: BindingStateAwareRequest,
  native: StateAwareNativeFacade,
): Promise<string> {
  const result = createStateAwareResult();
  let ownsResult = false;
  try {
    const nativeStatus = await new Promise<number>((resolve, reject) => {
      native.run(
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
    if (ownsResult) native.free(result);
  }
}

async function runBindingStateAwareRequestAsyncNative(
  request: BindingStateAwareRequest,
): Promise<string> {
  const native = loadMxcFfi();
  try {
    return await runBindingStateAwareRequestWithNative(
      request,
      bindStateAwareNativeFacade(native),
    );
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
