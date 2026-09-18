// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import koffi, { type KoffiFunc, type TypeObject } from 'koffi';
import type { MxcNativeLibrary } from '../native-library.js';

type NativeLibraryHandle = MxcNativeLibrary['handle'];
type NativeType = string | TypeObject | ReturnType<typeof koffi.out>;
type NativeSignature = (...args: never[]) => unknown;

export interface NativeFunctionDefinition {
  symbol: string;
  result: NativeType;
  parameters: NativeType[];
}

/**
 * Binds a C ABI function using named signature fields so call sites do not
 * depend on remembering Koffi's positional `func(name, result, parameters)`
 * argument order.
 */
export function bindNativeFunction<T extends NativeSignature>(
  handle: NativeLibraryHandle,
  definition: NativeFunctionDefinition,
): KoffiFunc<T> {
  return handle.func(
    definition.symbol,
    definition.result,
    definition.parameters,
  ) as KoffiFunc<T>;
}
