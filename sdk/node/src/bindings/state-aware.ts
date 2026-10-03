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

const AbiStateAwareResultType = koffi.struct('MxcNodeStateAwareResult', {
  status: 'int32_t',
  responseJsonUtf8: 'void *',
  error: AbiErrorDetailType,
});

const AbiExecOutcomeType = koffi.struct('MxcNodeExecOutcome', {
  timed_out: 'int32_t',
  exit_code: 'int32_t',
});

type StateAwareFunction = (
  request: string,
  dryRun: number,
  experimental: number,
  result: StateAwareNativeResult,
) => number;
type FreeFunction = (result: StateAwareNativeResult) => void;
type AttachedExecFunction = (
  request: string,
  experimental: number,
  outcome: StateAwareAttachedOutcome,
  error: AbiErrorDetail,
) => number;
type FreeErrorFunction = (error: AbiErrorDetail) => void;

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

export interface StateAwareAttachedOutcome {
  timed_out: number;
  exit_code: number;
}

export interface StateAwareAttachedNativeFacade {
  execAttached(
    request: string,
    experimental: number,
    outcome: StateAwareAttachedOutcome,
    error: AbiErrorDetail,
  ): number;
  freeError(error: AbiErrorDetail): void;
}

function bindStateAwareNativeFacade(
  native: ReturnType<typeof loadMxcFfi>,
): StateAwareNativeFacade {
  const run = bindNativeFunction<StateAwareFunction>(native.handle, {
    symbol: 'mxc_run_state_aware_json',
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

function bindStateAwareAttachedNativeFacade(
  native: ReturnType<typeof loadMxcFfi>,
): StateAwareAttachedNativeFacade {
  const execAttached = bindNativeFunction<AttachedExecFunction>(native.handle, {
    symbol: 'mxc_exec_state_aware_attached_json',
    result: 'int32_t',
    parameters: [
      'const char *',
      'int32_t',
      koffi.out(koffi.pointer(AbiExecOutcomeType)),
      koffi.out(koffi.pointer(AbiErrorDetailType)),
    ],
  });
  const freeError = bindNativeFunction<FreeErrorFunction>(native.handle, {
    symbol: 'mxc_error_detail_free',
    result: 'void',
    parameters: [koffi.pointer(AbiErrorDetailType)],
  });
  return { execAttached, freeError };
}

function createStateAwareResult(): StateAwareNativeResult {
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
  result: StateAwareNativeResult,
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

export function runBindingStateAwareAttachedRequestWithNative(
  requestJson: string,
  experimental: boolean,
  native: StateAwareAttachedNativeFacade,
): { exitCode: number; timedOut: boolean } {
  const outcome: StateAwareAttachedOutcome = { timed_out: 0, exit_code: 0 };
  const error: AbiErrorDetail = {
    message: null,
    operation: null,
    nativeCode: null,
    remediation: null,
  };
  let callCompleted = false;
  try {
    const status = native.execAttached(
      requestJson,
      experimental ? 1 : 0,
      outcome,
      error,
    );
    callCompleted = true;
    if (status !== 0) {
      throw nativeStatusError(status, error, 'state-aware attached exec failed');
    }
    return {
      exitCode: outcome.exit_code,
      timedOut: outcome.timed_out !== 0,
    };
  } finally {
    if (callCompleted) native.freeError(error);
  }
}

function runBindingStateAwareAttachedRequestNative(
  requestJson: string,
  experimental: boolean,
): { exitCode: number; timedOut: boolean } {
  const native = loadMxcFfi();
  try {
    return runBindingStateAwareAttachedRequestWithNative(
      requestJson,
      experimental,
      bindStateAwareAttachedNativeFacade(native),
    );
  } finally {
    native.handle.unload();
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

type AttachedStateAwareImplementation = (
  requestJson: string,
  experimental: boolean,
) => { exitCode: number; timedOut: boolean };

let asyncStateAwareImplementation = runBindingStateAwareRequestAsyncNative;
let attachedStateAwareImplementation = runBindingStateAwareAttachedRequestNative;

/** @internal Replaces the async native call for one process's unit tests. */
export function _setBindingStateAwareAsyncImplementation(
  implementation?: AsyncStateAwareImplementation,
): void {
  asyncStateAwareImplementation =
    implementation ?? runBindingStateAwareRequestAsyncNative;
}

/** @internal Replaces the attached native call for deterministic unit tests. */
export function _setBindingStateAwareAttachedImplementation(
  implementation?: AttachedStateAwareImplementation,
): void {
  attachedStateAwareImplementation =
    implementation ?? runBindingStateAwareAttachedRequestNative;
}

export function runBindingStateAwareAttachedRequest(
  requestJson: string,
  experimental: boolean,
): { exitCode: number; timedOut: boolean } {
  try {
    return attachedStateAwareImplementation(requestJson, experimental);
  } catch (error: unknown) {
    if (error instanceof MxcError) throw error;
    throw new MxcError(
      'backend_error',
      error instanceof Error ? error.message : String(error),
    );
  }
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
