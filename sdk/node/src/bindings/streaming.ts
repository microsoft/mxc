// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Native stdio ownership is transferred once to Node. Rust retains only
// process lifecycle control, so bytes never cross Koffi callbacks.

import * as fs from 'node:fs';
import * as net from 'node:net';
import * as os from 'node:os';
import type { Readable, Writable } from 'node:stream';
import koffi, { type KoffiFunc } from 'koffi';
import {
  _createMxcSandboxProcess,
  type MxcSandboxProcess,
  type NativeLifecycleDriver,
  type NativeLifecycleStatus,
} from '../sandbox-process.js';
import { loadMxcFfi, type MxcNativeLibrary } from '../native-library.js';
import type { RequestSpec } from './request.js';
import { bindNativeFunction } from './native-function.js';
import {
  AbiErrorDetailType,
  decodeString,
  nativeStatusError,
  parseStringArray,
  type AbiErrorDetail,
} from './native-error.js';

type Pointer = unknown;
type NativeHandle = number | bigint;
type NativeLibraryHandle = MxcNativeLibrary['handle'];
type NativeFreeCompletion = (error: Error | null) => void;

interface AbiNativeStdio {
  stdin_handle: NativeHandle;
  stdout_handle: NativeHandle;
  stderr_handle: NativeHandle;
}

const AbiCoordinator = koffi.opaque('MxcNodeLifecycleCoordinator');
const AbiNativeStdioType = koffi.struct('MxcNodeNativeStdio', {
  stdin_handle: 'intptr_t',
  stdout_handle: 'intptr_t',
  stderr_handle: 'intptr_t',
});

export interface _StreamingNativeFacade {
  spawn(
    request: string,
    outHandle: Pointer[],
    error: AbiErrorDetail,
  ): number;
  id(handle: Pointer): number;
  takeNativeStdio(handle: Pointer, stdio: AbiNativeStdio): number;
  closeNativePipe(handle: NativeHandle): void;
  tryWait(
    handle: Pointer,
    outExit: number[],
    outRunning: number[],
    outTimedOut: number[],
  ): number;
  requestKill(handle: Pointer): number;
  requestShutdown(handle: Pointer): number;
  warningsJson(handle: Pointer, out: Pointer[]): number;
  outputMetadataJson(handle: Pointer, out: Pointer[]): number;
  free(handle: Pointer, completion: NativeFreeCompletion): void;
  freeError(error: AbiErrorDetail): void;
  freeString(value: Pointer): void;
}

export interface _NativeStreamFactory {
  readonly platform: NodeJS.Platform;
  readable(handle: NativeHandle): Readable;
  writable(handle: NativeHandle): Writable;
}

const MINIMUM_NODE_VERSION = [24, 21, 0] as const;

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

const nodeStreamFactory: _NativeStreamFactory = {
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

function bindCoordinatorFunctions(
  handle: NativeLibraryHandle,
): _StreamingNativeFacade {
  const pointer = koffi.pointer(AbiCoordinator);
  const free = bindNativeFunction<KoffiFunc<(coordinator: Pointer) => void>>(
    handle,
    {
      symbol: 'mxc_io_free',
      result: 'void',
      parameters: [pointer],
    },
  );
  return {
    spawn: bindNativeFunction(handle, {
      symbol: 'mxc_io_spawn_request',
      result: 'int32_t',
      parameters: [
        'const char *',
        koffi.out(koffi.pointer(AbiCoordinator, 2)),
        koffi.out(koffi.pointer(AbiErrorDetailType)),
      ],
    }),
    id: bindNativeFunction(handle, {
      symbol: 'mxc_io_id',
      result: 'uint32_t',
      parameters: [pointer],
    }),
    takeNativeStdio: bindNativeFunction(handle, {
      symbol: 'mxc_io_take_native_stdio',
      result: 'int32_t',
      parameters: [pointer, koffi.out(koffi.pointer(AbiNativeStdioType))],
    }),
    closeNativePipe: bindNativeFunction(handle, {
      symbol: 'mxc_native_pipe_close',
      result: 'void',
      parameters: ['intptr_t'],
    }),
    tryWait: bindNativeFunction(handle, {
      symbol: 'mxc_io_try_wait',
      result: 'int32_t',
      parameters: [
        pointer,
        koffi.out(koffi.pointer('int32_t')),
        koffi.out(koffi.pointer('int32_t')),
        koffi.out(koffi.pointer('int32_t')),
      ],
    }),
    requestKill: bindNativeFunction(handle, {
      symbol: 'mxc_io_request_kill',
      result: 'int32_t',
      parameters: [pointer],
    }),
    requestShutdown: bindNativeFunction(handle, {
      symbol: 'mxc_io_request_shutdown',
      result: 'int32_t',
      parameters: [pointer],
    }),
    warningsJson: bindNativeFunction(handle, {
      symbol: 'mxc_io_warnings_json',
      result: 'int32_t',
      parameters: [pointer, koffi.out(koffi.pointer('char', 2))],
    }),
    outputMetadataJson: bindNativeFunction(handle, {
      symbol: 'mxc_io_output_metadata_json',
      result: 'int32_t',
      parameters: [pointer, koffi.out(koffi.pointer('char', 2))],
    }),
    free(coordinator, completion) {
      free.async(coordinator, completion);
    },
    freeError: bindNativeFunction(handle, {
      symbol: 'mxc_error_detail_free',
      result: 'void',
      parameters: [koffi.pointer(AbiErrorDetailType)],
    }),
    freeString: bindNativeFunction(handle, {
      symbol: 'mxc_string_free',
      result: 'void',
      parameters: ['char *'],
    }),
  } as _StreamingNativeFacade;
}

let sharedNative: _StreamingNativeFacade | undefined;

function getNative(): _StreamingNativeFacade {
  return sharedNative ??= bindCoordinatorFunctions(loadMxcFfi().handle);
}

function throwIfFailed(status: number, message: string): void {
  if (status !== 0) throw nativeStatusError(status, {}, message);
}

function isMissingHandle(
  handle: NativeHandle,
  platform: NodeJS.Platform,
): boolean {
  return platform === 'win32'
    ? handle === 0 || handle === 0n
    : handle === -1 || handle === -1n;
}

function destroyStream(stream: Readable | Writable | null): void {
  if (stream !== null && !stream.destroyed) stream.destroy();
}

function freeCoordinatorAsync(
  native: _StreamingNativeFacade,
  handle: Pointer,
): Promise<void> {
  return new Promise<void>((resolve, reject) => {
    native.free(handle, (error) => {
      if (error === null) resolve();
      else reject(error);
    });
  });
}

class KoffiLifecycleDriver implements NativeLifecycleDriver {
  private freePromise: Promise<void> | undefined;
  private shutdownRequested = false;

  constructor(
    private readonly native: _StreamingNativeFacade,
    private readonly handle: Pointer,
    readonly id: number,
    readonly standardInput: Writable | null,
    readonly standardOutput: Readable | null,
    readonly standardError: Readable | null,
  ) {}

  poll(): NativeLifecycleStatus {
    const exit = [0];
    const running = [1];
    const timedOut = [0];
    throwIfFailed(
      this.native.tryWait(
        this.handle,
        exit,
        running,
        timedOut,
      ),
      'polling sandbox process failed',
    );
    return {
      exitCode: exit[0],
      running: running[0] !== 0,
      timedOut: timedOut[0] !== 0,
    };
  }

  warnings(): readonly string[] {
    return parseStringArray(
      this.readOwnedJson(this.native.warningsJson),
    );
  }

  outputMetadata(): unknown | undefined {
    const json = this.readOwnedJson(this.native.outputMetadataJson);
    return json === undefined ? undefined : JSON.parse(json);
  }

  kill(): void {
    throwIfFailed(
      this.native.requestKill(this.handle),
      'killing sandbox process failed',
    );
  }

  shutdown(): void {
    if (this.shutdownRequested) return;
    throwIfFailed(
      this.native.requestShutdown(this.handle),
      'shutting down sandbox process failed',
    );
    this.shutdownRequested = true;
  }

  free(): Promise<void> {
    return this.freePromise ??= freeCoordinatorAsync(this.native, this.handle);
  }

  private readOwnedJson(
    read: (handle: Pointer, out: Pointer[]) => number,
  ): string | undefined {
    const out: Pointer[] = [null];
    throwIfFailed(read(this.handle, out), 'reading sandbox process data failed');
    try {
      return decodeString(out[0]);
    } finally {
      if (out[0] !== null) this.native.freeString(out[0]);
    }
  }
}

function adoptEndpoint(
  factory: _NativeStreamFactory,
  handle: NativeHandle,
  writable: boolean,
): Readable | Writable | null {
  if (isMissingHandle(handle, factory.platform)) return null;

  return writable ? factory.writable(handle) : factory.readable(handle);
}

function closeUnadopted(
  native: _StreamingNativeFacade,
  factory: _NativeStreamFactory,
  handles: NativeHandle[],
): void {
  for (const handle of handles) {
    if (!isMissingHandle(handle, factory.platform)) {
      native.closeNativePipe(handle);
    }
  }
}

function beginFailedSpawnCleanup(
  native: _StreamingNativeFacade,
  handle: Pointer,
): void {
  try {
    native.requestShutdown(handle);
  } finally {
    void freeCoordinatorAsync(native, handle).catch(() => {});
  }
}

/** @internal Builds a driver with injectable native and stream facades. */
export function _spawnStreamingDriverForTest(
  request: RequestSpec,
  native: _StreamingNativeFacade,
  factory: _NativeStreamFactory,
): NativeLifecycleDriver {
  const outHandle: Pointer[] = [null];
  const error = {} as AbiErrorDetail;
  const status = native.spawn(JSON.stringify(request), outHandle, error);
  if (status !== 0) {
    try {
      throw nativeStatusError(status, error);
    } finally {
      native.freeError(error);
    }
  }

  const handle = outHandle[0];
  if (handle === null || handle === undefined) {
    throw new Error('native runtime returned a null lifecycle handle');
  }

  let input: Writable | null = null;
  let output: Readable | null = null;
  let errorOutput: Readable | null = null;
  try {
    const stdio = {} as AbiNativeStdio;
    throwIfFailed(
      native.takeNativeStdio(handle, stdio),
      'taking native stdio failed',
    );
    const remaining = [
      stdio.stdin_handle,
      stdio.stdout_handle,
      stdio.stderr_handle,
    ];
    try {
      const invalid = factory.platform === 'win32' ? 0 : -1;
      input = adoptEndpoint(factory, remaining[0], true) as Writable | null;
      remaining[0] = invalid;
      output = adoptEndpoint(
        factory,
        remaining[1],
        false,
      ) as Readable | null;
      remaining[1] = invalid;
      errorOutput = adoptEndpoint(
        factory,
        remaining[2],
        false,
      ) as Readable | null;
      remaining[2] = invalid;
    } catch (error) {
      closeUnadopted(native, factory, remaining);
      throw error;
    }

    const id = native.id(handle);
    return new KoffiLifecycleDriver(
      native,
      handle,
      id,
      input,
      output,
      errorOutput,
    );
  } catch (error) {
    destroyStream(input);
    destroyStream(output);
    destroyStream(errorOutput);
    beginFailedSpawnCleanup(native, handle);
    throw error;
  }
}

/** @internal Tests whether a Node.js version supports native Windows handles. */
export function _isSupportedNodeVersionForTest(version: string): boolean {
  const current = version
    .split('.')
    .slice(0, 3)
    .map((component) => Number.parseInt(component, 10));
  const difference = current.findIndex(
    (component, index) => component !== MINIMUM_NODE_VERSION[index],
  );
  return difference === -1 ||
    current[difference] > MINIMUM_NODE_VERSION[difference];
}

function ensureSupportedNodeVersion(): void {
  if (!_isSupportedNodeVersionForTest(process.versions.node)) {
    throw new Error(
      `native stdio requires Node.js ${MINIMUM_NODE_VERSION.join('.')} or newer; ` +
      `current version is ${process.versions.node}`,
    );
  }
}

function spawnDriver(request: RequestSpec): NativeLifecycleDriver {
  ensureSupportedNodeVersion();
  return _spawnStreamingDriverForTest(request, getNative(), nodeStreamFactory);
}

export function spawnBindingSandboxProcess(
  request: RequestSpec,
): MxcSandboxProcess {
  const driver = spawnDriver(request);
  try {
    return _createMxcSandboxProcess(driver);
  } catch (error) {
    destroyStream(driver.standardInput);
    destroyStream(driver.standardOutput);
    destroyStream(driver.standardError);
    try {
      driver.shutdown();
    } catch {
      // Preserve the construction failure while still releasing native state.
    } finally {
      void driver.free().catch(() => {});
    }
    throw error;
  }
}
