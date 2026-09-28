// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { getMxcFfi } from '../native-library.js';
import { decodeString } from './native-error.js';
import { bindNativeFunction } from './native-function.js';

type Pointer = unknown;
type AvailableBackendsFunction = () => Pointer | null;
type FreeStringFunction = (value: Pointer) => void;

export interface AvailableBackendsNativeFacade {
  availableBackends(): Pointer | null;
  freeString(value: Pointer): void;
}

/**
 * Read an owned native discovery string and release it exactly once.
 *
 * @internal Exported for deterministic ownership tests.
 */
export function readAvailableBackendsJsonWithNative(
  native: AvailableBackendsNativeFacade,
  decode: (pointer: Pointer) => string | undefined = decodeString,
): string {
  const pointer = native.availableBackends();
  if (pointer === null || pointer === undefined || pointer === 0 || pointer === 0n) {
    throw new Error('probing available backends failed');
  }

  try {
    const json = decode(pointer);
    if (json === undefined) {
      throw new Error('probing available backends returned an undecodable string');
    }
    return json;
  } finally {
    native.freeString(pointer);
  }
}

export function readAvailableBackendsJson(): string {
  const native = getMxcFfi();
  return readAvailableBackendsJsonWithNative({
    availableBackends: bindNativeFunction<AvailableBackendsFunction>(native.handle, {
      symbol: 'mxc_available_backends_json',
      result: 'void *',
      parameters: [],
    }),
    freeString: bindNativeFunction<FreeStringFunction>(native.handle, {
      symbol: 'mxc_string_free',
      result: 'void',
      parameters: ['void *'],
    }),
  });
}
