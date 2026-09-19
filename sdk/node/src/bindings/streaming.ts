// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import type { Readable, Writable } from 'node:stream';
import koffi, { type KoffiFunc } from 'koffi';
import {
  createMxcSandboxProcess,
  type MxcSandboxProcess,
  type NativeLifecycleDriver,
  type NativeLifecycleStatus,
} from '../sandbox-process.js';
import { loadMxcFfi, type MxcNativeLibrary } from '../native-library.js';
import type { RequestSpec } from './request.js';
import { bindNativeFunction } from './native-function.js';
import {
  adoptNativeStdio,
  minimumWindowsNativeStdioNodeVersion,
  nodeStreamFactory,
  supportsNativeStdio,
  type NativeHandle,
  type NativeStdioHandles,
  type NativeStreamFactory,
} from './native-stdio.js';
import {
  AbiErrorDetailType,
  decodeString,
  nativeStatusError,
  parseStringArray,
  type AbiErrorDetail,
} from './native-error.js';

type Pointer = unknown;
type NativeLibraryHandle = MxcNativeLibrary['handle'];
type NativeFreeCompletion = (error: Error | null) => void;
type NativeWaitCompletion = (error: Error | null, status: number) => void;

const AbiSandbox = koffi.opaque('MxcSandbox');
const AbiNativeStdioType = koffi.struct('MxcNodeNativeStdio', {
  stdin_handle: 'intptr_t',
  stdout_handle: 'intptr_t',
  stderr_handle: 'intptr_t',
});

export interface StreamingNativeFacade {
  spawn(
    request: string,
    outHandle: Pointer[],
    error: AbiErrorDetail,
  ): number;
  id(handle: Pointer): number;
  takeNativeStdio(handle: Pointer, stdio: NativeStdioHandles): number;
  closeNativePipe(handle: NativeHandle): void;
  tryWait(
    handle: Pointer,
    outExit: number[],
    outRunning: number[],
    outTimedOut: number[],
  ): number;
  wait(
    handle: Pointer,
    outExit: number[],
    outTimedOut: number[],
    completion: NativeWaitCompletion,
  ): void;
  kill(handle: Pointer): number;
  killForTimeout(handle: Pointer): number;
  warningsJson(handle: Pointer, out: Pointer[]): number;
  outputMetadataJson(handle: Pointer, out: Pointer[]): number;
  free(handle: Pointer, completion: NativeFreeCompletion): void;
  freeError(error: AbiErrorDetail): void;
  freeString(value: Pointer): void;
}

function bindSandboxFunctions(
  handle: NativeLibraryHandle,
): StreamingNativeFacade {
  const pointer = koffi.pointer(AbiSandbox);
  const free = bindNativeFunction<KoffiFunc<(sandbox: Pointer) => void>>(
    handle,
    {
      symbol: 'mxc_sandbox_free',
      result: 'void',
      parameters: [pointer],
    },
  );
  const wait = bindNativeFunction<KoffiFunc<(
    sandbox: Pointer,
    outExit: number[],
    outTimedOut: number[],
  ) => number>>(handle, {
    symbol: 'mxc_sandbox_wait',
    result: 'int32_t',
    parameters: [
      pointer,
      koffi.out(koffi.pointer('int32_t')),
      koffi.out(koffi.pointer('int32_t')),
    ],
  });
  return {
    spawn: bindNativeFunction(handle, {
      symbol: 'mxc_spawn_request',
      result: 'int32_t',
      parameters: [
        'const char *',
        koffi.out(koffi.pointer(AbiSandbox, 2)),
        koffi.out(koffi.pointer(AbiErrorDetailType)),
      ],
    }),
    id: bindNativeFunction(handle, {
      symbol: 'mxc_sandbox_id',
      result: 'uint32_t',
      parameters: [pointer],
    }),
    takeNativeStdio: bindNativeFunction(handle, {
      symbol: 'mxc_sandbox_take_native_stdio',
      result: 'int32_t',
      parameters: [pointer, koffi.out(koffi.pointer(AbiNativeStdioType))],
    }),
    closeNativePipe: bindNativeFunction(handle, {
      symbol: 'mxc_native_pipe_close',
      result: 'void',
      parameters: ['intptr_t'],
    }),
    tryWait: bindNativeFunction(handle, {
      symbol: 'mxc_sandbox_try_wait',
      result: 'int32_t',
      parameters: [
        pointer,
        koffi.out(koffi.pointer('int32_t')),
        koffi.out(koffi.pointer('int32_t')),
        koffi.out(koffi.pointer('int32_t')),
      ],
    }),
    wait(sandbox, outExit, outTimedOut, completion) {
      wait.async(sandbox, outExit, outTimedOut, completion);
    },
    kill: bindNativeFunction(handle, {
      symbol: 'mxc_sandbox_kill',
      result: 'int32_t',
      parameters: [pointer],
    }),
    killForTimeout: bindNativeFunction(handle, {
      symbol: 'mxc_sandbox_kill_for_timeout',
      result: 'int32_t',
      parameters: [pointer],
    }),
    warningsJson: bindNativeFunction(handle, {
      symbol: 'mxc_sandbox_warnings_json',
      result: 'int32_t',
      parameters: [pointer, koffi.out(koffi.pointer('char', 2))],
    }),
    outputMetadataJson: bindNativeFunction(handle, {
      symbol: 'mxc_sandbox_output_metadata_json',
      result: 'int32_t',
      parameters: [pointer, koffi.out(koffi.pointer('char', 2))],
    }),
    free(sandbox, completion) {
      free.async(sandbox, completion);
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
  } as StreamingNativeFacade;
}

let sharedNative: StreamingNativeFacade | undefined;

function getNative(): StreamingNativeFacade {
  return sharedNative ??= bindSandboxFunctions(loadMxcFfi().handle);
}

function throwIfFailed(status: number, message: string): void {
  if (status !== 0) throw nativeStatusError(status, {}, message);
}

function destroyStream(stream: Readable | Writable | null): void {
  if (stream !== null && !stream.destroyed) stream.destroy();
}

function freeSandboxAsync(
  native: StreamingNativeFacade,
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
  private waitPromise: Promise<{ exitCode: number; timedOut: boolean }> | undefined;

  constructor(
    private readonly native: StreamingNativeFacade,
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

  wait(): Promise<{ exitCode: number; timedOut: boolean }> {
    return this.waitPromise ??= new Promise((resolve, reject) => {
      const exit = [0];
      const timedOut = [0];
      this.native.wait(this.handle, exit, timedOut, (error, status) => {
        if (error !== null) {
          reject(error);
          return;
        }
        try {
          throwIfFailed(status, 'waiting for sandbox process failed');
          resolve({
            exitCode: exit[0],
            timedOut: timedOut[0] !== 0,
          });
        } catch (failure) {
          reject(failure);
        }
      });
    });
  }

  warnings(): readonly string[] {
    return parseStringArray(
      this.readOwnedJson('warningsJson'),
    );
  }

  outputMetadata(): unknown | undefined {
    const json = this.readOwnedJson('outputMetadataJson');
    return json === undefined ? undefined : JSON.parse(json);
  }

  kill(): void {
    throwIfFailed(
      this.native.kill(this.handle),
      'killing sandbox process failed',
    );
  }

  killForTimeout(): void {
    throwIfFailed(
      this.native.killForTimeout(this.handle),
      'killing timed-out sandbox process failed',
    );
  }

  free(): Promise<void> {
    return this.freePromise ??= (this.waitPromise ?? Promise.resolve())
      .catch(() => {})
      .then(() => freeSandboxAsync(this.native, this.handle));
  }

  private readOwnedJson(
    method: 'warningsJson' | 'outputMetadataJson',
  ): string | undefined {
    const out: Pointer[] = [null];
    throwIfFailed(
      this.native[method](this.handle, out),
      'reading sandbox process data failed',
    );
    try {
      return decodeString(out[0]);
    } finally {
      if (out[0] !== null) this.native.freeString(out[0]);
    }
  }
}

function beginFailedSpawnCleanup(
  native: StreamingNativeFacade,
  handle: Pointer,
): void {
  void freeSandboxAsync(native, handle).catch(() => {});
}

/** Internal constructor with injectable native and stream dependencies. */
export function createStreamingDriver(
  request: RequestSpec,
  native: StreamingNativeFacade,
  factory: NativeStreamFactory,
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
    const stdio = {} as NativeStdioHandles;
    throwIfFailed(
      native.takeNativeStdio(handle, stdio),
      'taking native stdio failed',
    );
    const adopted = adoptNativeStdio(
      stdio,
      factory,
      (nativeHandle) => native.closeNativePipe(nativeHandle),
    );
    input = adopted.standardInput;
    output = adopted.standardOutput;
    errorOutput = adopted.standardError;

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

function ensureSupportedNodeVersion(): void {
  if (!supportsNativeStdio(nodeStreamFactory.platform, process.versions.node)) {
    throw new Error(
      `native stdio on Windows requires Node.js ` +
      `${minimumWindowsNativeStdioNodeVersion()} or newer; ` +
      `current version is ${process.versions.node}`,
    );
  }
}

function spawnDriver(request: RequestSpec): NativeLifecycleDriver {
  ensureSupportedNodeVersion();
  return createStreamingDriver(request, getNative(), nodeStreamFactory);
}

export function spawnBindingSandboxProcess(
  request: RequestSpec,
): MxcSandboxProcess {
  const driver = spawnDriver(request);
  try {
    return createMxcSandboxProcess(driver, request.policy.timeoutMs);
  } catch (error) {
    destroyStream(driver.standardInput);
    destroyStream(driver.standardOutput);
    destroyStream(driver.standardError);
    void driver.free().catch(() => {});
    throw error;
  }
}
