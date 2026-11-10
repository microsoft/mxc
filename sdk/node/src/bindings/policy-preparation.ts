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

async function prepareBindingPolicyJsonAsyncNative(
  requestJson: string,
  policyFailuresJson: string,
  experimental: boolean,
): Promise<string> {
  const native = loadMxcFfi();
  try {
    const freeString = bindNativeFunction<StringFreeFunction>(native.handle, {
      symbol: 'mxc_string_free',
      result: 'void',
      parameters: ['void *'],
    });
    const freeError = bindNativeFunction<ErrorFreeFunction>(native.handle, {
      symbol: 'mxc_error_detail_free',
      result: 'void',
      parameters: [koffi.pointer(AbiErrorDetailType)],
    });
    const prepare = bindNativeFunction<PrepareFunction>(native.handle, {
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
