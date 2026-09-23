// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import type { KoffiFunc } from 'koffi';
import { loadMxcFfi } from '../native-library.js';
import { decodeString } from './native-error.js';

export interface PlatformSupportSnapshotJson {
  platformSupportJson: string;
  availableBackendsJson: string;
}

type OwnedStringFunction = KoffiFunc<() => unknown | null>;
type StringFreeFunction = KoffiFunc<(value: unknown) => void>;

function isNonNullPointer(value: unknown): boolean {
  return value !== null && value !== undefined && value !== 0 && value !== 0n;
}

/** @internal Exported for native ownership regression tests. */
export function _readOwnedJson(
  call: OwnedStringFunction,
  stringFree: StringFreeFunction,
  operation: string,
): string {
  const pointer = call();
  try {
    if (!isNonNullPointer(pointer)) {
      throw new Error(`${operation} returned a null JSON payload`);
    }
    const json = decodeString(pointer);
    if (json === undefined) {
      throw new Error(`${operation} returned an unreadable JSON payload`);
    }
    return json;
  } finally {
    if (isNonNullPointer(pointer)) {
      stringFree(pointer);
    }
  }
}

function readNativeOwnedJson(exportName: string): string {
  const native = loadMxcFfi();
  try {
    const readJson = native.handle.func(exportName, 'void *', []) as OwnedStringFunction;
    const stringFree = native.handle.func('mxc_string_free', 'void', ['char *']) as StringFreeFunction;
    return _readOwnedJson(readJson, stringFree, exportName);
  } finally {
    native.handle.unload();
  }
}

export function readPlatformSupportJson(): string {
  return readNativeOwnedJson('mxc_platform_support_json');
}

export function readAvailableBackendsJson(): string {
  return readNativeOwnedJson('mxc_available_backends_json');
}
