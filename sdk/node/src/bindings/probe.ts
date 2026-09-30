// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import koffi from 'koffi';
import { MxcError } from '../errors.js';
import { loadMxcFfi } from '../native-library.js';
import {
  AbiErrorDetailType,
  decodeString,
  nativeStatusError,
  type AbiErrorDetail,
} from './native-error.js';
import { bindNativeFunction } from './native-function.js';

let loadProbeLibrary = loadMxcFfi;
let bindProbeFunction = bindNativeFunction;
let decodeProbeString = decodeString;

/** @internal Test seam for the synchronous native probe boundary. */
export function _setProbeNativeDependencies(
  load = loadMxcFfi,
  bind = bindNativeFunction,
  decode = decodeString,
): void {
  loadProbeLibrary = load;
  bindProbeFunction = bind;
  decodeProbeString = decode;
}

type Pointer = unknown;
type ProbeRequestFunction = (
  requestJson: string | null,
  outJson: Pointer[],
  outError: AbiErrorDetail,
) => number;
type FreeStringFunction = (value: Pointer) => void;
type FreeErrorFunction = (error: AbiErrorDetail) => void;

export interface ProbeNativeFacade {
  probeRequest(
    requestJson: string | null,
    outJson: Pointer[],
    outError: AbiErrorDetail,
  ): number;
  freeString(value: Pointer): void;
  freeError(error: AbiErrorDetail): void;
}

/**
 * Invoke the native request probe and release its owned result exactly once.
 *
 * @internal Exported for deterministic ownership tests.
 */
export function readProbeJsonWithNative(
  native: ProbeNativeFacade,
  requestJson?: string,
  decode: (pointer: Pointer) => string | undefined = decodeString,
): string {
  const output: Pointer[] = [null];
  const error = {} as AbiErrorDetail;
  const status = native.probeRequest(requestJson ?? null, output, error);
  if (status !== 0) {
    try {
      throw nativeStatusError(status, error);
    } finally {
      native.freeError(error);
    }
  }

  const pointer = output[0];
  if (pointer === null || pointer === undefined || pointer === 0 || pointer === 0n) {
    throw new MxcError(
      'backend_error',
      'native request probe returned a null success result',
    );
  }

  try {
    const json = decode(pointer);
    if (json === undefined) {
      throw new Error('native request probe returned an undecodable string');
    }
    return json;
  } finally {
    native.freeString(pointer);
  }
}

export function readProbeJson(requestJson?: string): string {
  const native = loadProbeLibrary();
  try {
    return readProbeJsonWithNative({
      probeRequest: bindProbeFunction<ProbeRequestFunction>(native.handle, {
        symbol: 'mxc_probe_request_json_with_error',
        result: 'int32_t',
        parameters: [
          'const char *',
          // Keep the owned char* opaque so Koffi does not convert it and lose
          // the allocation identity required by mxc_string_free.
          koffi.out(koffi.pointer('void *')),
          koffi.out(koffi.pointer(AbiErrorDetailType)),
        ],
      }),
      freeString: bindProbeFunction<FreeStringFunction>(native.handle, {
        symbol: 'mxc_string_free',
        result: 'void',
        parameters: ['void *'],
      }),
      freeError: bindProbeFunction<FreeErrorFunction>(native.handle, {
        symbol: 'mxc_error_detail_free',
        result: 'void',
        parameters: [koffi.pointer(AbiErrorDetailType)],
      }),
    }, requestJson, decodeProbeString);
  } finally {
    native.handle.unload();
  }
}
