// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import koffi, { type KoffiFunc } from 'koffi';
import { MxcError } from '../v1/errors.js';
import { MxcPtyProcess } from '../v1/mxc-pty-process.js';
import { loadMxcFfi, type MxcNativeLibrary } from '../native-library.js';
import { bindNativeFunction } from './native-function.js';
import {
  AbiErrorDetailType,
  nativeStatusError,
  type AbiErrorDetail,
} from './native-error.js';
import {
  destroyNativeStreams,
  nodeStreamFactory,
  type NativeStreamFactory,
} from './native-stdio.js';
import type { OneShotRequest } from '../generated/v1_0_0/wire.js';
import {
  AbiSandbox,
  createNativeLifecycleDriver,
  getStreamingNative,
  type LifecycleNativeFacade,
} from './streaming.js';

type Pointer = unknown;
type NativeLibraryHandle = MxcNativeLibrary['handle'];
type NativeCompletion = (error: Error | null, status: number) => void;

export interface PtyNativeFacade {
  spawnPty(
    request: string,
    experimental: number,
    rows: number,
    columns: number,
    outHandle: Pointer[],
    error: AbiErrorDetail,
    completion: NativeCompletion,
  ): void;
  execPty(
    request: string,
    experimental: number,
    rows: number,
    columns: number,
    outHandle: Pointer[],
    error: AbiErrorDetail,
    completion: NativeCompletion,
  ): void;
  resize(handle: Pointer, rows: number, columns: number): number;
}

function bindPtyNativeFacade(handle: NativeLibraryHandle): PtyNativeFacade {
  const sandboxPointer = koffi.pointer(AbiSandbox);
  const spawn = bindNativeFunction<KoffiFunc<(
    request: string,
    experimental: number,
    rows: number,
    columns: number,
    outHandle: Pointer[],
    error: AbiErrorDetail,
  ) => number>>(handle, {
    symbol: 'mxc_spawn_pty_json',
    result: 'int32_t',
    parameters: [
      'const char *',
      'int32_t',
      'uint16_t',
      'uint16_t',
      koffi.out(koffi.pointer(AbiSandbox, 2)),
      koffi.out(koffi.pointer(AbiErrorDetailType)),
    ],
  });
  const exec = bindNativeFunction<KoffiFunc<(
    request: string,
    experimental: number,
    rows: number,
    columns: number,
    outHandle: Pointer[],
    error: AbiErrorDetail,
  ) => number>>(handle, {
    symbol: 'mxc_state_aware_exec_pty',
    result: 'int32_t',
    parameters: [
      'const char *',
      'int32_t',
      'uint16_t',
      'uint16_t',
      koffi.out(koffi.pointer(AbiSandbox, 2)),
      koffi.out(koffi.pointer(AbiErrorDetailType)),
    ],
  });
  return {
    spawnPty(request, experimental, rows, columns, outHandle, error, completion) {
      spawn.async(request, experimental, rows, columns, outHandle, error, completion);
    },
    execPty(
      request,
      experimental,
      rows,
      columns,
      outHandle,
      error,
      completion,
    ) {
      exec.async(
        request,
        experimental,
        rows,
        columns,
        outHandle,
        error,
        completion,
      );
    },
    resize: bindNativeFunction(handle, {
      symbol: 'mxc_sandbox_pty_resize',
      result: 'int32_t',
      parameters: [sandboxPointer, 'uint16_t', 'uint16_t'],
    }),
  };
}

let sharedNative: PtyNativeFacade | undefined;

function getPtyNative(): PtyNativeFacade {
  return sharedNative ??= bindPtyNativeFacade(loadMxcFfi().handle);
}

function throwIfFailed(status: number, message: string): void {
  if (status !== 0) throw nativeStatusError(status, {}, message);
}

/** Internal constructor with injectable native and stream dependencies. */
export async function createPty(
  request: OneShotRequest,
  experimental: boolean,
  rows: number,
  columns: number,
  ptyNative: PtyNativeFacade,
  lifecycleNative: LifecycleNativeFacade,
  factory: NativeStreamFactory,
): Promise<MxcPtyProcess> {
  const requestJson = JSON.stringify(request);
  return createPtyFromJson(
    request.process.timeout,
    rows,
    columns,
    (outHandle, error, completion) => ptyNative.spawnPty(
      requestJson,
      experimental ? 1 : 0,
      rows,
      columns,
      outHandle,
      error,
      completion,
    ),
    ptyNative,
    lifecycleNative,
    factory,
  );
}

async function createPtyFromJson(
  timeoutMs: number | undefined,
  rows: number,
  columns: number,
  spawn: (
    outHandle: Pointer[],
    error: AbiErrorDetail,
    completion: NativeCompletion,
  ) => void,
  ptyNative: PtyNativeFacade,
  lifecycleNative: LifecycleNativeFacade,
  factory: NativeStreamFactory,
): Promise<MxcPtyProcess> {
  const outHandle: Pointer[] = [null];
  const error = {} as AbiErrorDetail;
  const status = await new Promise<number>((resolve, reject) => {
    spawn(outHandle, error, (callError, nativeStatus) => {
      if (callError !== null) reject(callError);
      else resolve(nativeStatus);
    });
  });
  if (status !== 0) {
    try {
      throw nativeStatusError(status, error);
    } finally {
      lifecycleNative.freeError(error);
    }
  }

  const handle = outHandle[0];
  if (handle === null || handle === undefined) {
    throw new MxcError(
      'backend_error',
      'native runtime returned a null PTY handle',
    );
  }

  const driver = createNativeLifecycleDriver(
    lifecycleNative,
    factory,
    handle,
  );
  if (driver.standardError !== null) {
    destroyNativeStreams(driver);
    await driver.free().catch(() => {});
    throw new MxcError(
      'backend_error',
      'native runtime returned a separate PTY stderr stream',
    );
  }
  try {
    return new MxcPtyProcess(
      driver,
      (size) => throwIfFailed(
        ptyNative.resize(handle, size.rows, size.columns),
        'resizing sandbox PTY failed',
      ),
      timeoutMs,
    );
  } catch (failure) {
    destroyNativeStreams(driver);
    await driver.free().catch(() => {});
    throw failure;
  }
}

function execStateAwareBindingSandboxWithPtyNative(
  requestJson: string,
  experimental: boolean,
  rows: number,
  columns: number,
  timeoutMs?: number,
): Promise<MxcPtyProcess> {
  const ptyNative = getPtyNative();
  return createPtyFromJson(
    timeoutMs,
    rows,
    columns,
    (outHandle, error, completion) => ptyNative.execPty(
      requestJson,
      experimental ? 1 : 0,
      rows,
      columns,
      outHandle,
      error,
      completion,
    ),
    ptyNative,
    getStreamingNative(),
    nodeStreamFactory,
  );
}

type ExecStateAwarePtyImplementation = typeof execStateAwareBindingSandboxWithPtyNative;

let execStateAwarePtyImplementation = execStateAwareBindingSandboxWithPtyNative;

/** @internal Replaces the native state-aware PTY spawn for unit tests. */
export function _setExecStateAwareBindingSandboxWithPtyImplementation(
  implementation?: ExecStateAwarePtyImplementation,
): void {
  execStateAwarePtyImplementation =
    implementation ?? execStateAwareBindingSandboxWithPtyNative;
}

export function execStateAwareBindingSandboxWithPty(
  requestJson: string,
  experimental: boolean,
  rows: number,
  columns: number,
  timeoutMs?: number,
): Promise<MxcPtyProcess> {
  return execStateAwarePtyImplementation(
    requestJson,
    experimental,
    rows,
    columns,
    timeoutMs,
  );
}

function spawnBindingSandboxWithPtyNative(
  request: OneShotRequest,
  experimental: boolean,
  rows: number,
  columns: number,
): Promise<MxcPtyProcess> {
  return createPty(
    request,
    experimental,
    rows,
    columns,
    getPtyNative(),
    getStreamingNative(),
    nodeStreamFactory,
  );
}

type SpawnPtyImplementation = (
  request: OneShotRequest,
  experimental: boolean,
  rows: number,
  columns: number,
) => Promise<MxcPtyProcess>;

let spawnPtyImplementation = spawnBindingSandboxWithPtyNative;

/** @internal Replaces the native PTY spawn for one process's unit tests. */
export function _setSpawnBindingSandboxWithPtyImplementation(
  implementation?: SpawnPtyImplementation,
): void {
  spawnPtyImplementation = implementation ?? spawnBindingSandboxWithPtyNative;
}

export function spawnBindingSandboxWithPty(
  request: OneShotRequest,
  experimental: boolean,
  rows: number,
  columns: number,
): Promise<MxcPtyProcess> {
  return spawnPtyImplementation(request, experimental, rows, columns);
}
