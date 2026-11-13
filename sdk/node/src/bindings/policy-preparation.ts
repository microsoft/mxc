// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import koffi from 'koffi';
import { MxcError } from '../v1/errors.js';
import { loadMxcFfi } from '../native-library.js';
import { bindNativeFunction } from './native-function.js';
import {
  AbiErrorDetailType,
  createAbiErrorDetail,
  decodeString,
  nativeStatusError,
  type AbiErrorDetail,
} from './native-error.js';

type PrepareFunction = (
  requestJson: string,
  policyFailuresJson: string,
  experimental: number,
  out: unknown[],
  error: AbiErrorDetail,
) => number;
type StringFreeFunction = (value: unknown) => void;
type ErrorFreeFunction = (error: AbiErrorDetail) => void;

function nativeSetupError(action: 'load' | 'bind', error: unknown): MxcError {
  const diagnostic = error instanceof Error && error.message.length > 0
    ? error.message
    : 'Unknown native library setup error.';
  const operation = action === 'load' ? 'load' : 'bind';
  return new MxcError({
    code: 'backend_error',
    message: `Unable to ${operation} the MXC native library for policy preparation: ${diagnostic}`,
    remediation: 'Install or rebuild the MXC native library for this SDK version, operating system, '
      + 'and architecture, and ensure its runtime dependencies are available.',
  });
}

async function prepareBindingPolicyJsonAsyncNative(
  requestJson: string,
  policyFailuresJson: string,
  experimental: boolean,
): Promise<string> {
  let native: ReturnType<typeof loadMxcFfi>;
  try {
    native = loadMxcFfi();
  } catch (error) {
    throw nativeSetupError('load', error);
  }
  try {
    let freeString: ReturnType<typeof bindNativeFunction<StringFreeFunction>>;
    let freeError: ReturnType<typeof bindNativeFunction<ErrorFreeFunction>>;
    let prepare: ReturnType<typeof bindNativeFunction<PrepareFunction>>;
    try {
      freeString = bindNativeFunction<StringFreeFunction>(native.handle, {
        symbol: 'mxc_string_free',
        result: 'void',
        parameters: ['void *'],
      });
      freeError = bindNativeFunction<ErrorFreeFunction>(native.handle, {
        symbol: 'mxc_error_detail_free',
        result: 'void',
        parameters: [koffi.pointer(AbiErrorDetailType)],
      });
      prepare = bindNativeFunction<PrepareFunction>(native.handle, {
        symbol: 'mxc_prepare_policy_json',
        result: 'int32_t',
        parameters: [
          'const char *',
          'const char *',
          'int32_t',
          // Keep the owned char* opaque for mxc_string_free.
          koffi.out(koffi.pointer('void *')),
          koffi.out(koffi.pointer(AbiErrorDetailType)),
        ],
      });
    } catch (error) {
      throw nativeSetupError('bind', error);
    }
    const out: unknown[] = [null];
    const error = createAbiErrorDetail();
    try {
      const status = await new Promise<number>((resolve, reject) => {
        prepare.async(requestJson, policyFailuresJson, experimental ? 1 : 0, out, error,
          (failure, nativeStatus) => {
            if (failure !== null) reject(failure);
            else resolve(nativeStatus);
          });
      });
      if (status !== 0) {
        throw nativeStatusError(status, error, 'native policy preparation failed');
      }
      const json = decodeString(out[0]);
      if (json === undefined || json.length === 0) {
        throw new MxcError('backend_error', 'native policy preparation returned no JSON');
      }
      return json;
    } finally {
      try {
        if (out[0] !== null && out[0] !== undefined && out[0] !== 0 && out[0] !== 0n) {
          freeString(out[0]);
        }
      } finally {
        freeError(error);
      }
    }
  } finally {
    native.handle.unload();
  }
}

let asyncImplementation = prepareBindingPolicyJsonAsyncNative;

/** @internal Replaces the async native call for one process's unit tests. */
export function _setBindingPolicyPreparationAsyncImplementation(
  implementation?: typeof prepareBindingPolicyJsonAsyncNative,
): void {
  asyncImplementation = implementation ?? prepareBindingPolicyJsonAsyncNative;
}

/** Prepare on Koffi's worker pool and copy the result before releasing native allocations. */
export async function prepareBindingPolicyJsonAsync(
  requestJson: string,
  policyFailuresJson: string,
  experimental: boolean,
): Promise<string> {
  try {
    return await asyncImplementation(requestJson, policyFailuresJson, experimental);
  } catch (error) {
    if (error instanceof MxcError) throw error;
    throw new MxcError('backend_error', 'native policy preparation failed');
  }
}
