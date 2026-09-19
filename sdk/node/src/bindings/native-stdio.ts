// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import * as fs from 'node:fs';
import * as net from 'node:net';
import * as os from 'node:os';
import type { Readable, Writable } from 'node:stream';
import { MxcError } from '../errors.js';

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
    throw new MxcError(
      'backend_error',
      `native runtime returned invalid file descriptor ${handle}`,
    );
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
  writable: true,
): Writable | null;
function adoptEndpoint(
  factory: NativeStreamFactory,
  handle: NativeHandle,
  writable: false,
): Readable | null;
function adoptEndpoint(
  factory: NativeStreamFactory,
  handle: NativeHandle,
  writable: boolean,
): Readable | Writable | null {
  if (isMissingHandle(handle, factory.platform)) return null;
  return writable ? factory.writable(handle) : factory.readable(handle);
}

export function destroyNativeStream(
  stream: Readable | Writable | null,
): void {
  if (stream !== null && !stream.destroyed) stream.destroy();
}

function rollbackAdoption(
  adoptedStreams: readonly (Readable | Writable | null)[],
  handles: readonly NativeHandle[],
  firstUnadopted: number,
  factory: NativeStreamFactory,
  closeHandle: (handle: NativeHandle) => void,
): Error[] {
  const errors: Error[] = [];
  for (const stream of adoptedStreams) {
    try {
      destroyNativeStream(stream);
    } catch (error) {
      errors.push(error instanceof Error ? error : new Error(String(error)));
    }
  }
  for (let index = firstUnadopted; index < handles.length; index += 1) {
    const handle = handles[index];
    if (isMissingHandle(handle, factory.platform)) continue;
    try {
      closeHandle(handle);
    } catch (error) {
      errors.push(error instanceof Error ? error : new Error(String(error)));
    }
  }
  return errors;
}

/**
 * Adopts every available native endpoint transactionally. If any stream
 * constructor fails, already-adopted streams are destroyed and every remaining
 * raw endpoint is closed before the original error is rethrown.
 */
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
  const adoptedStreams: Array<Readable | Writable | null> = [];
  let firstUnadopted = 0;
  try {
    const standardInput = adoptEndpoint(factory, handles[0], true);
    adoptedStreams.push(standardInput);
    firstUnadopted = 1;
    const standardOutput = adoptEndpoint(factory, handles[1], false);
    adoptedStreams.push(standardOutput);
    firstUnadopted = 2;
    const standardError = adoptEndpoint(factory, handles[2], false);
    adoptedStreams.push(standardError);
    firstUnadopted = 3;
    return { standardInput, standardOutput, standardError };
  } catch (error) {
    const rollbackErrors = rollbackAdoption(
      adoptedStreams,
      handles,
      firstUnadopted,
      factory,
      closeHandle,
    );
    if (rollbackErrors.length > 0) {
      throw new MxcError({
        code: 'backend_error',
        message: 'native stdio adoption failed and rollback was incomplete',
        details: {
          adoptionError: error instanceof Error ? error.message : String(error),
          rollbackErrors: rollbackErrors.map((failure) => failure.message),
        },
      });
    }
    throw error;
  }
}

/** Accepts either `process.versions.node` or the `v`-prefixed `process.version`. */
export function supportsNativeStdio(
  platform: NodeJS.Platform,
  version: string,
): boolean {
  if (platform !== 'win32') return true;

  const normalized = version.replace(/^v/, '');
  if (!/^\d+(?:\.\d+){0,2}$/.test(normalized)) return false;
  const current = normalized
    .split('.')
    .map((component) => Number.parseInt(component, 10));
  while (current.length < WINDOWS_NATIVE_STDIO_MINIMUM_NODE_VERSION.length) {
    current.push(0);
  }
  if (current.some((component) => !Number.isFinite(component))) return false;
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
