// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import * as fs from 'node:fs';
import * as net from 'node:net';
import * as os from 'node:os';
import type { Readable, Writable } from 'node:stream';
import {
  satisfies as semverSatisfies,
  valid as semverValid,
} from 'semver';
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

export interface NodeStreamDependencies {
  createReadStream(path: string, options: unknown): Readable;
  createWriteStream(path: string, options: unknown): Writable;
  createSocket(options: ConstructorParameters<typeof net.Socket>[0]):
    Readable & Writable;
}

export interface NativeStdioStreams {
  readonly standardInput: Writable | null;
  readonly standardOutput: Readable | null;
  readonly standardError: Readable | null;
}

export function destroyNativeStreams(streams: NativeStdioStreams): void {
  destroyNativeStream(streams.standardInput);
  destroyNativeStream(streams.standardOutput);
  destroyNativeStream(streams.standardError);
}

interface NativeStdioPlatformSupport {
  readonly displayName: string;
  readonly nodeRange: string;
  readonly nodeRequirement: string;
}

const NATIVE_STDIO_PLATFORM_SUPPORT: Partial<
  Record<NodeJS.Platform, NativeStdioPlatformSupport>
> = {
  win32: {
    displayName: 'Windows',
    nodeRange: '>=24.21.0 <25 || >=26.8.0',
    nodeRequirement:
      '24.21.0 or newer within Node.js 24, or Node.js 26.8.0 or newer',
  },
  darwin: {
    displayName: 'macOS',
    nodeRange: '>=24.0.0',
    nodeRequirement: '24.0.0',
  },
  linux: {
    displayName: 'Linux',
    nodeRange: '>=24.0.0',
    nodeRequirement: '24.0.0',
  },
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

const nodeStreamDependencies: NodeStreamDependencies = {
  createReadStream: (path, options) => fs.createReadStream(
    path,
    options as Parameters<typeof fs.createReadStream>[1],
  ),
  createWriteStream: (path, options) => fs.createWriteStream(
    path,
    options as Parameters<typeof fs.createWriteStream>[1],
  ),
  createSocket: (options) => new net.Socket(options),
};

/** Internal constructor with injectable Node stream primitives for tests. */
export function createNodeStreamFactory(
  platform: NodeJS.Platform,
  dependencies: NodeStreamDependencies = nodeStreamDependencies,
): NativeStreamFactory {
  return {
    platform,
    readable(handle) {
      if (platform === 'win32') {
        return dependencies.createReadStream('', windowsHandleOptions(handle));
      }
      return dependencies.createSocket({
        fd: unixFd(handle),
        readable: true,
        writable: false,
      });
    },
    writable(handle) {
      if (platform === 'win32') {
        return dependencies.createWriteStream('', windowsHandleOptions(handle));
      }
      return dependencies.createSocket({
        fd: unixFd(handle),
        readable: false,
        writable: true,
      });
    },
  };
}

export const nodeStreamFactory = createNodeStreamFactory(os.platform());

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
  try {
    const standardInput = createOwningStream(
      factory,
      handles[0],
      'writable',
    );
    createdStreams.push(standardInput);

    const standardOutput = createOwningStream(
      factory,
      handles[1],
      'readable',
    );
    createdStreams.push(standardOutput);

    const standardError = createOwningStream(
      factory,
      handles[2],
      'readable',
    );
    createdStreams.push(standardError);

    return { standardInput, standardOutput, standardError };
  } catch (error) {
    const rollbackErrors = rollbackStreamCreation(
      createdStreams,
      handles,
      createdStreams.length,
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
  const support = NATIVE_STDIO_PLATFORM_SUPPORT[platform];
  if (support === undefined) return true;

  const normalized = semverValid(version.replace(/^v/, ''));
  if (normalized === null) return false;

  return semverSatisfies(normalized, support.nodeRange);
}

export function nativeStdioNodeRequirement(
  platform: NodeJS.Platform,
): string | undefined {
  return NATIVE_STDIO_PLATFORM_SUPPORT[platform]?.nodeRequirement;
}

export function nativeStdioPlatformName(
  platform: NodeJS.Platform,
): string {
  return NATIVE_STDIO_PLATFORM_SUPPORT[platform]?.displayName ?? platform;
}
