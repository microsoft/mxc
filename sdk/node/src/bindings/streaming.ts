// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import type { Readable, Writable } from 'node:stream';
import koffi, { type KoffiFunc } from 'koffi';
import { MxcError } from '../errors.js';
import {
  MxcSandboxProcess,
  type NativeLifecycleDriver,
  type NativeLifecycleStatus,
} from '../sandbox-process.js';
import { loadMxcFfi, type MxcNativeLibrary } from '../native-library.js';
import type { RequestSpec } from './request.js';
import { bindNativeFunction } from './native-function.js';
import {
  createNativeStdioStreams,
  destroyNativeStreams,
  nativeStdioNodeRequirement,
  nativeStdioPlatformName,
  nodeStreamFactory,
  supportsNativeStdio,
  type NativeHandle,
  type NativeStdioHandles,
  type NativeStdioStreams,
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
  stateAwareExec(
    request: string,
    experimental: number,
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

function bindStreamingNativeFacade(
  handle: NativeLibraryHandle,
): StreamingNativeFacade {
  const sandboxPointer = koffi.pointer(AbiSandbox);

  // Koffi exposes asynchronous invocation on the bound function object, so
  // wait and free keep their raw bindings behind callback-shaped facade methods.
  const freeAsyncBinding = bindNativeFunction<
    KoffiFunc<(sandbox: Pointer) => void>
  >(
    handle,
    {
      symbol: 'mxc_sandbox_free',
      result: 'void',
      parameters: [sandboxPointer],
    },
  );

  const waitAsyncBinding = bindNativeFunction<KoffiFunc<(
    sandbox: Pointer,
    outExit: number[],
    outTimedOut: number[],
  ) => number>>(handle, {
    symbol: 'mxc_sandbox_wait',
    result: 'int32_t',
    parameters: [
      sandboxPointer,
      koffi.out(koffi.pointer('int32_t')),
      koffi.out(koffi.pointer('int32_t')),
    ],
  });

  const native: StreamingNativeFacade = {
    spawn: bindNativeFunction(handle, {
      symbol: 'mxc_spawn_request',
      result: 'int32_t',
      parameters: [
        'const char *',
        koffi.out(koffi.pointer(AbiSandbox, 2)),
        koffi.out(koffi.pointer(AbiErrorDetailType)),
      ],
    }),

    stateAwareExec: bindNativeFunction(handle, {
      symbol: 'mxc_state_aware_exec',
      result: 'int32_t',
      parameters: [
        'const char *',
        'int32_t',
        koffi.out(koffi.pointer(AbiSandbox, 2)),
        koffi.out(koffi.pointer(AbiErrorDetailType)),
      ],
    }),
    id: bindNativeFunction(handle, {
      symbol: 'mxc_sandbox_id',
      result: 'uint32_t',
      parameters: [sandboxPointer],
    }),

    takeNativeStdio: bindNativeFunction(handle, {
      symbol: 'mxc_sandbox_take_native_stdio',
      result: 'int32_t',
      parameters: [
        sandboxPointer,
        koffi.out(koffi.pointer(AbiNativeStdioType)),
      ],
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
        sandboxPointer,
        koffi.out(koffi.pointer('int32_t')),
        koffi.out(koffi.pointer('int32_t')),
        koffi.out(koffi.pointer('int32_t')),
      ],
    }),

    wait(sandbox, outExit, outTimedOut, completion) {
      waitAsyncBinding.async(sandbox, outExit, outTimedOut, completion);
    },

    kill: bindNativeFunction(handle, {
      symbol: 'mxc_sandbox_kill',
      result: 'int32_t',
      parameters: [sandboxPointer],
    }),

    killForTimeout: bindNativeFunction(handle, {
      symbol: 'mxc_sandbox_kill_for_timeout',
      result: 'int32_t',
      parameters: [sandboxPointer],
    }),

    warningsJson: bindNativeFunction(handle, {
      symbol: 'mxc_sandbox_warnings_json',
      result: 'int32_t',
      parameters: [sandboxPointer, koffi.out(koffi.pointer('char', 2))],
    }),

    outputMetadataJson: bindNativeFunction(handle, {
      symbol: 'mxc_sandbox_output_metadata_json',
      result: 'int32_t',
      parameters: [sandboxPointer, koffi.out(koffi.pointer('char', 2))],
    }),

    free(sandbox, completion) {
      freeAsyncBinding.async(sandbox, completion);
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
  };

  return native;
}

let sharedNative: StreamingNativeFacade | undefined;
let stateAwareSandboxProcessFactory:
  | ((
      requestJson: string,
      experimental: boolean,
      timeoutMs?: number,
    ) => MxcSandboxProcess)
  | undefined;

function getNative(): StreamingNativeFacade {
  return sharedNative ??= bindStreamingNativeFacade(loadMxcFfi().handle);
}

function throwIfFailed(status: number, message: string): void {
  if (status !== 0) throw nativeStatusError(status, {}, message);
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
  private readonly pollExit = [0];
  private readonly pollRunning = [1];
  private readonly pollTimedOut = [0];

  constructor(
    private readonly native: StreamingNativeFacade,
    private readonly handle: Pointer,
    readonly id: number,
    readonly standardInput: Writable | null,
    readonly standardOutput: Readable | null,
    readonly standardError: Readable | null,
  ) {}

  poll(): NativeLifecycleStatus {
    this.pollExit[0] = 0;
    this.pollRunning[0] = 1;
    this.pollTimedOut[0] = 0;
    throwIfFailed(
      this.native.tryWait(
        this.handle,
        this.pollExit,
        this.pollRunning,
        this.pollTimedOut,
      ),
      'polling sandbox process failed',
    );
    return {
      exitCode: this.pollExit[0],
      running: this.pollRunning[0] !== 0,
      timedOut: this.pollTimedOut[0] !== 0,
    };
  }

  wait(): Promise<{ exitCode: number; timedOut: boolean }> {
    return new Promise((resolve, reject) => {
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
    if (json === undefined) return undefined;
    try {
      return JSON.parse(json);
    } catch (error) {
      throw new MxcError({
        code: 'backend_error',
        message: 'native runtime returned malformed output metadata',
        details: {
          cause: error instanceof Error ? error.message : String(error),
        },
      });
    }
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
    return freeSandboxAsync(this.native, this.handle);
  }

  private readOwnedJson(
    method: 'warningsJson' | 'outputMetadataJson',
  ): string | undefined {
    const out: Pointer[] = [null];
    const description = method === 'warningsJson'
      ? 'reading sandbox process warnings failed'
      : 'reading sandbox process output metadata failed';
    throwIfFailed(
      this.native[method](this.handle, out),
      description,
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
function createStreamingDriverFromSpawn(
  native: StreamingNativeFacade,
  factory: NativeStreamFactory,
  spawn: (outHandle: Pointer[], error: AbiErrorDetail) => number,
): NativeLifecycleDriver {
  const outHandle: Pointer[] = [null];
  const error = {} as AbiErrorDetail;
  const status = spawn(outHandle, error);
  if (status !== 0) {
    try {
      throw nativeStatusError(status, error);
    } finally {
      native.freeError(error);
    }
  }

  const handle = outHandle[0];
  if (handle === null || handle === undefined) {
    throw new MxcError(
      'backend_error',
      'native runtime returned a null lifecycle handle',
    );
  }

  let streams: NativeStdioStreams | undefined;
  try {
    const stdio = {} as NativeStdioHandles;
    throwIfFailed(
      native.takeNativeStdio(handle, stdio),
      'taking native stdio failed',
    );
    streams = createNativeStdioStreams(
      stdio,
      factory,
      (nativeHandle) => native.closeNativePipe(nativeHandle),
    );

    const id = native.id(handle);
    return new KoffiLifecycleDriver(
      native,
      handle,
      id,
      streams.standardInput,
      streams.standardOutput,
      streams.standardError,
    );
  } catch (error) {
    if (streams !== undefined) destroyNativeStreams(streams);
    beginFailedSpawnCleanup(native, handle);
    throw error;
  }
}

/** Internal constructor with injectable native and stream dependencies. */
export function createStreamingDriver(
  request: RequestSpec,
  native: StreamingNativeFacade,
  factory: NativeStreamFactory,
): NativeLifecycleDriver {
  return createStreamingDriverFromSpawn(
    native,
    factory,
    (outHandle, error) => native.spawn(
      JSON.stringify(request),
      outHandle,
      error,
    ),
  );
}

function ensureSupportedNodeVersion(): void {
  const platform = nodeStreamFactory.platform;
  const requirement = nativeStdioNodeRequirement(platform);
  if (
    requirement === undefined ||
    supportsNativeStdio(platform, process.versions.node)
  ) return;

  const platformName = nativeStdioPlatformName(platform);
  throw new MxcError({
    code: 'backend_unavailable',
    message: `native stdio on ${platformName} requires Node.js ` +
      `${requirement}; ` +
      `current version is ${process.versions.node}`,
    remediation: `Use Node.js ${requirement} on ${platformName}.`,
  });
}

function spawnDriver(request: RequestSpec): NativeLifecycleDriver {
  ensureSupportedNodeVersion();
  return createStreamingDriver(request, getNative(), nodeStreamFactory);
}

export function spawnBindingSandboxProcess(
  request: RequestSpec,
): MxcSandboxProcess {
  const driver = spawnDriver(request);
  return createSandboxProcess(driver, request.policy.timeoutMs);
}

/** Internal state-aware constructor with injectable native dependencies. */
export function createStateAwareStreamingDriver(
  requestJson: string,
  experimental: boolean,
  native: StreamingNativeFacade,
  factory: NativeStreamFactory,
): NativeLifecycleDriver {
  return createStreamingDriverFromSpawn(
    native,
    factory,
    (outHandle, error) => native.stateAwareExec(
      requestJson,
      experimental ? 1 : 0,
      outHandle,
      error,
    ),
  );
}

function createSandboxProcess(
  driver: NativeLifecycleDriver,
  timeoutMs?: number,
): MxcSandboxProcess {
  try {
    return new MxcSandboxProcess(driver, timeoutMs);
  } catch (error) {
    destroyNativeStreams(driver);
    void driver.free().catch(() => {});
    throw error;
  }
}

export function _setStateAwareBindingSandboxProcessFactory(
  factory?: (
    requestJson: string,
    experimental: boolean,
    timeoutMs?: number,
  ) => MxcSandboxProcess,
): void {
  stateAwareSandboxProcessFactory = factory;
}

export function spawnStateAwareBindingSandboxProcess(
  requestJson: string,
  experimental: boolean,
  timeoutMs?: number,
): MxcSandboxProcess {
  if (stateAwareSandboxProcessFactory !== undefined) {
    return stateAwareSandboxProcessFactory(
      requestJson,
      experimental,
      timeoutMs,
    );
  }

  ensureSupportedNodeVersion();
  const native = getNative();
  const driver = createStateAwareStreamingDriver(
    requestJson,
    experimental,
    native,
    nodeStreamFactory,
  );
  return createSandboxProcess(driver, timeoutMs);
}
