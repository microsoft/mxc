// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Koffi wrapper for the request-aware probe. Runs in-process through
// mxc_ffi instead of spawning wxc-exec, matching the other bindings here.

import koffi from 'koffi';
import { loadMxcFfi } from '../native-library.js';
import { bindNativeFunction } from './native-function.js';
import {
  AbiErrorDetailType,
  decodeString,
  nativeStatusError,
  type AbiErrorDetail,
} from './native-error.js';

type Pointer = unknown;

type ProbeFunction = (
  requestJson: string | null,
  outJson: Pointer[],
  error: AbiErrorDetail,
) => number;
type FreeStringFunction = (value: Pointer) => void;
type FreeErrorFunction = (error: AbiErrorDetail) => void;

function bindProbeFunctions(
  native: ReturnType<typeof loadMxcFfi>,
): {
  probe: ReturnType<typeof bindNativeFunction<ProbeFunction>>;
  freeString: ReturnType<typeof bindNativeFunction<FreeStringFunction>>;
  freeError: ReturnType<typeof bindNativeFunction<FreeErrorFunction>>;
} {
  return {
    probe: bindNativeFunction<ProbeFunction>(native.handle, {
      symbol: 'mxc_probe_request_json',
      result: 'int32_t',
      parameters: [
        'const char *',
        koffi.out(koffi.pointer('char', 2)),
        koffi.out(koffi.pointer(AbiErrorDetailType)),
      ],
    }),
    freeString: bindNativeFunction<FreeStringFunction>(native.handle, {
      symbol: 'mxc_string_free',
      result: 'void',
      parameters: ['char *'],
    }),
    freeError: bindNativeFunction<FreeErrorFunction>(native.handle, {
      symbol: 'mxc_error_detail_free',
      result: 'void',
      parameters: [koffi.pointer(AbiErrorDetailType)],
    }),
  };
}

function emptyErrorDetail(): AbiErrorDetail {
  return {
    message: null,
    operation: null,
    nativeCode: null,
    remediation: null,
  };
}

/**
 * Probe an optional co-versioned request JSON and return the canonical probe
 * output JSON. `undefined` probes the default empty request.
 */
export function probeBindingRequestJson(requestJson?: string): string {
  const native = loadMxcFfi();
  try {
    const { probe, freeString, freeError } = bindProbeFunctions(native);
    const outJson: Pointer[] = [null];
    const error = emptyErrorDetail();
    try {
      const status = probe(requestJson ?? null, outJson, error);
      if (status !== 0) {
        throw nativeStatusError(status, error, 'request probe failed');
      }
      return decodeString(outJson[0]) ?? '{}';
    } finally {
      if (outJson[0] !== null) freeString(outJson[0]);
      freeError(error);
    }
  } finally {
    native.handle.unload();
  }
}
