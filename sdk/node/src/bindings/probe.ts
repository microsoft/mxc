// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { getMxcFfi } from '../native-library.js';
import { decodeString } from './native-error.js';
import { bindNativeFunction } from './native-function.js';

type Pointer = unknown;
type ProbeRequestFunction = (requestJson: string | null) => Pointer | null;
type FreeStringFunction = (value: Pointer) => void;

export interface ProbeNativeFacade {
  probeRequest(requestJson: string | null): Pointer | null;
  freeString(value: Pointer): void;
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
  const pointer = native.probeRequest(requestJson ?? null);
  if (pointer === null || pointer === undefined || pointer === 0 || pointer === 0n) {
    throw new Error('native request probe failed');
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
  const native = getMxcFfi();
  return readProbeJsonWithNative({
    probeRequest: bindNativeFunction<ProbeRequestFunction>(native.handle, {
      symbol: 'mxc_probe_request_json',
      result: 'void *',
      parameters: ['const char *'],
    }),
    freeString: bindNativeFunction<FreeStringFunction>(native.handle, {
      symbol: 'mxc_string_free',
      result: 'void',
      parameters: ['void *'],
    }),
  }, requestJson);
}
