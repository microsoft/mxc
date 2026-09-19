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

export interface NativeStdioStreams {
  readonly standardInput: Writable | null;
  readonly standardOutput: Readable | null;
  readonly standardError: Readable | null;
}

const MINIMUM_NATIVE_STDIO_NODE_VERSION: Partial<
  Record<NodeJS.Platform, readonly [number, number, number]>
> = {
  darwin: [24, 0, 0],
  linux: [24, 0, 0],
  win32: [24, 21, 0],
};

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

/** Creates a Node stream that owns and closes the transferred native endpoint. */
function createOwningStream(
  factory: NativeStreamFactory,
  handle: NativeHandle,
  direction: 'writable',
): Writable | null;

function createOwningStream(
  factory: NativeStreamFactory,
  handle: NativeHandle,
  direction: 'readable',
): Readable | null;

function createOwningStream(
  factory: NativeStreamFactory,
  handle: NativeHandle,
  direction: 'readable' | 'writable',
): Readable | Writable | null {
  if (isMissingHandle(handle, factory.platform)) return null;
  return direction === 'writable'
    ? factory.writable(handle)
    : factory.readable(handle);
}

export function destroyNativeStream(
  stream: Readable | Writable | null,
): void {
  if (stream !== null && !stream.destroyed) stream.destroy();
}

function rollbackStreamCreation(
  createdStreams: readonly (Readable | Writable | null)[],
  handles: readonly NativeHandle[],
  firstUnowned: number,
  factory: NativeStreamFactory,
  closeHandle: (handle: NativeHandle) => void,
): Error[] {
  const errors: Error[] = [];
  for (const stream of createdStreams) {
    try {
      destroyNativeStream(stream);
    } catch (error) {
      errors.push(error instanceof Error ? error : new Error(String(error)));
    }
  }
  for (let index = firstUnowned; index < handles.length; index += 1) {
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
 * Creates owning Node streams for every available native endpoint. If any
 * stream constructor fails, streams already created are destroyed and every
 * remaining raw endpoint is closed before the original error is rethrown.
 */
export function createNativeStdioStreams(
  stdio: NativeStdioHandles,
  factory: NativeStreamFactory,
  closeHandle: (handle: NativeHandle) => void,
): NativeStdioStreams {
  const handles = [
    stdio.stdin_handle,
    stdio.stdout_handle,
    stdio.stderr_handle,
  ];
  const createdStreams: Array<Readable | Writable | null> = [];
  let firstUnowned = 0;
  try {
    const standardInput = createOwningStream(
      factory,
      handles[0],
      'writable',
    );
    createdStreams.push(standardInput);
    firstUnowned = 1;

    const standardOutput = createOwningStream(
      factory,
      handles[1],
      'readable',
    );
    createdStreams.push(standardOutput);
    firstUnowned = 2;

    const standardError = createOwningStream(
      factory,
      handles[2],
      'readable',
    );
    createdStreams.push(standardError);
    firstUnowned = 3;

    return { standardInput, standardOutput, standardError };
  } catch (error) {
    const rollbackErrors = rollbackStreamCreation(
      createdStreams,
      handles,
      firstUnowned,
      factory,
      closeHandle,
    );
    if (rollbackErrors.length > 0) {
      throw new MxcError({
        code: 'backend_error',
        message: 'native stdio stream creation failed and rollback was incomplete',
        details: {
          streamCreationError:
            error instanceof Error ? error.message : String(error),
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
  const minimum = MINIMUM_NATIVE_STDIO_NODE_VERSION[platform];
  if (minimum === undefined) return true;

  const normalized = version.replace(/^v/, '');
  if (!/^\d+(?:\.\d+){0,2}$/.test(normalized)) return false;
  const current = normalized
    .split('.')
    .map((component) => Number.parseInt(component, 10));
  while (current.length < minimum.length) {
    current.push(0);
  }
  if (current.some((component) => !Number.isFinite(component))) return false;
  const difference = current.findIndex(
    (component, index) =>
      component !== minimum[index],
  );
  return difference === -1 ||
    current[difference] > minimum[difference];
}

export function minimumNativeStdioNodeVersion(
  platform: NodeJS.Platform,
): string | undefined {
  return MINIMUM_NATIVE_STDIO_NODE_VERSION[platform]?.join('.');
}
