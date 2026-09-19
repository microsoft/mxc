// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import * as fs from 'node:fs';
import * as net from 'node:net';
import * as os from 'node:os';
import type { Readable, Writable } from 'node:stream';

export type NativeHandle = number | bigint;

export interface NativeStdioHandles {
  stdin_handle: NativeHandle;
  stdout_handle: NativeHandle;
  stderr_handle: NativeHandle;
}

export interface NativeStreamFactory {
  readonly platform: NodeJS.Platform;
  readable(handle: NativeHandle): Readable;
  writable(handle: NativeHandle): Writable;
}

export interface AdoptedNativeStdio {
  readonly standardInput: Writable | null;
  readonly standardOutput: Readable | null;
  readonly standardError: Readable | null;
}

const WINDOWS_NATIVE_STDIO_MINIMUM_NODE_VERSION = [24, 21, 0] as const;

function windowsHandleOptions(
  handle: NativeHandle,
): { autoClose: true; windowsHandle: bigint } {
  return {
    autoClose: true,
    windowsHandle: typeof handle === 'bigint' ? handle : BigInt(handle),
  };
}

function unixFd(handle: NativeHandle): number {
  const fd = Number(handle);
  if (!Number.isSafeInteger(fd) || fd < 0) {
    throw new Error(`native runtime returned invalid file descriptor ${handle}`);
  }
  return fd;
}

export const nodeStreamFactory: NativeStreamFactory = {
  platform: os.platform(),
  readable(handle) {
    if (this.platform === 'win32') {
      return fs.createReadStream(
        '',
        windowsHandleOptions(handle) as unknown as
          Parameters<typeof fs.createReadStream>[1],
      );
    }
    return new net.Socket({
      fd: unixFd(handle),
      readable: true,
      writable: false,
    });
  },
  writable(handle) {
    if (this.platform === 'win32') {
      return fs.createWriteStream(
        '',
        windowsHandleOptions(handle) as unknown as
          Parameters<typeof fs.createWriteStream>[1],
      );
    }
    return new net.Socket({
      fd: unixFd(handle),
      readable: false,
      writable: true,
    });
  },
};

function isMissingHandle(
  handle: NativeHandle,
  platform: NodeJS.Platform,
): boolean {
  return platform === 'win32'
    ? handle === 0 || handle === 0n
    : handle === -1 || handle === -1n;
}

function adoptEndpoint(
  factory: NativeStreamFactory,
  handle: NativeHandle,
  writable: boolean,
): Readable | Writable | null {
  if (isMissingHandle(handle, factory.platform)) return null;
  return writable ? factory.writable(handle) : factory.readable(handle);
}

function closeUnadopted(
  handles: readonly NativeHandle[],
  firstUnadopted: number,
  factory: NativeStreamFactory,
  closeHandle: (handle: NativeHandle) => void,
): void {
  for (let index = firstUnadopted; index < handles.length; index += 1) {
    const handle = handles[index];
    if (!isMissingHandle(handle, factory.platform)) closeHandle(handle);
  }
}

export function adoptNativeStdio(
  stdio: NativeStdioHandles,
  factory: NativeStreamFactory,
  closeHandle: (handle: NativeHandle) => void,
): AdoptedNativeStdio {
  const handles = [
    stdio.stdin_handle,
    stdio.stdout_handle,
    stdio.stderr_handle,
  ];
  let firstUnadopted = 0;
  try {
    const standardInput = adoptEndpoint(factory, handles[0], true) as
      Writable | null;
    firstUnadopted = 1;
    const standardOutput = adoptEndpoint(factory, handles[1], false) as
      Readable | null;
    firstUnadopted = 2;
    const standardError = adoptEndpoint(factory, handles[2], false) as
      Readable | null;
    firstUnadopted = 3;
    return { standardInput, standardOutput, standardError };
  } catch (error) {
    closeUnadopted(handles, firstUnadopted, factory, closeHandle);
    throw error;
  }
}

export function supportsNativeStdio(
  platform: NodeJS.Platform,
  version: string,
): boolean {
  if (platform !== 'win32') return true;

  const current = version
    .split('.')
    .slice(0, 3)
    .map((component) => Number.parseInt(component, 10));
  const difference = current.findIndex(
    (component, index) =>
      component !== WINDOWS_NATIVE_STDIO_MINIMUM_NODE_VERSION[index],
  );
  return difference === -1 ||
    current[difference] > WINDOWS_NATIVE_STDIO_MINIMUM_NODE_VERSION[difference];
}

export function minimumWindowsNativeStdioNodeVersion(): string {
  return WINDOWS_NATIVE_STDIO_MINIMUM_NODE_VERSION.join('.');
}
