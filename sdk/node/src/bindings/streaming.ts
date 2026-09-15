// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import koffi, { type KoffiFunc } from 'koffi';
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
import {
  _createMxcSandboxProcess,
  type MxcSandboxProcess,
  type NativeStreamingDriver,
  type NativeStreamingEvent,
} from '../sandbox-process.js';

type Pointer = unknown;
type NativeLibraryHandle = MxcNativeLibrary['handle'];
type RegisteredCallback = ReturnType<typeof koffi.register>;

const STDOUT = 1;
const STDERR = 2;
const EVENT_STDOUT = 1;
const EVENT_STDERR = 2;
const EVENT_STDOUT_EOF = 3;
const EVENT_STDERR_EOF = 4;
const EVENT_STDIN_COMPLETE = 5;
const EVENT_EXIT = 6;
const EVENT_ERROR = 7;
const EVENT_SHUTDOWN = 8;

const AbiCoordinator = koffi.opaque('MxcNodeIoCoordinator');
const AbiEventCallback = koffi.pointer(koffi.proto(
  'void MxcIoEventCallback(void *userData, int32 event, uint32 operation, const uint8 *data, size_t length, int64 value, int32 flag)',
));

function bindCoordinatorFunctions(handle: NativeLibraryHandle) {
  const pointer = koffi.pointer(AbiCoordinator);
  return {
    spawn: bindNativeFunction<KoffiFunc<(
      request: string,
      callback: RegisteredCallback,
      userData: Pointer,
      coordinator: Pointer[],
      error: AbiErrorDetail,
    ) => number>>(handle, {
      symbol: 'mxc_io_spawn_request_callback',
      result: 'int32_t',
      parameters: [
        'const char *',
        AbiEventCallback,
        'void *',
        koffi.out(koffi.pointer(AbiCoordinator, 2)),
        koffi.out(koffi.pointer(AbiErrorDetailType)),
      ],
    }),

    stateAwareExec: bindNativeFunction<KoffiFunc<(
      request: string,
      experimental: number,
      callback: RegisteredCallback,
      userData: Pointer,
      coordinator: Pointer[],
      error: AbiErrorDetail,
    ) => number>>(handle, {
      symbol: 'mxc_io_state_aware_exec_callback',
      result: 'int32_t',
      parameters: [
        'const char *',
        'int32_t',
        AbiEventCallback,
        'void *',
        koffi.out(koffi.pointer(AbiCoordinator, 2)),
        koffi.out(koffi.pointer(AbiErrorDetailType)),
      ],
    }),

    id: bindNativeFunction<(coordinator: Pointer) => number>(handle, {
      symbol: 'mxc_io_id',
      result: 'uint32_t',
      parameters: [pointer],
    }),

    hasStdin: bindNativeFunction<(coordinator: Pointer) => number>(handle, {
      symbol: 'mxc_io_has_stdin',
      result: 'int32_t',
      parameters: [pointer],
    }),

    hasStdout: bindNativeFunction<(coordinator: Pointer) => number>(handle, {
      symbol: 'mxc_io_has_stdout',
      result: 'int32_t',
      parameters: [pointer],
    }),

    hasStderr: bindNativeFunction<(coordinator: Pointer) => number>(handle, {
      symbol: 'mxc_io_has_stderr',
      result: 'int32_t',
      parameters: [pointer],
    }),

    requestRead: bindNativeFunction<
      (coordinator: Pointer, stream: number) => number
    >(handle, {
      symbol: 'mxc_io_request_read',
      result: 'int32_t',
      parameters: [pointer, 'int32_t'],
    }),

    closeOutput: bindNativeFunction<
      (coordinator: Pointer, stream: number) => number
    >(handle, {
      symbol: 'mxc_io_close_output',
      result: 'int32_t',
      parameters: [pointer, 'int32_t'],
    }),

    startWrite: bindNativeFunction<KoffiFunc<(
      coordinator: Pointer,
      buffer: Buffer,
      length: number,
      operation: number[],
    ) => number>>(handle, {
      symbol: 'mxc_io_start_write',
      result: 'int32_t',
      parameters: [
        pointer,
        'const uint8_t *',
        'size_t',
        koffi.out(koffi.pointer('uint32_t')),
      ],
    }),

    startFlush: bindNativeFunction<KoffiFunc<(
      coordinator: Pointer,
      operation: number[],
    ) => number>>(handle, {
      symbol: 'mxc_io_start_flush',
      result: 'int32_t',
      parameters: [pointer, koffi.out(koffi.pointer('uint32_t'))],
    }),

    closeStdin: bindNativeFunction<(coordinator: Pointer) => number>(handle, {
      symbol: 'mxc_io_close_stdin',
      result: 'int32_t',
      parameters: [pointer],
    }),

    requestKill: bindNativeFunction<(coordinator: Pointer) => number>(handle, {
      symbol: 'mxc_io_request_kill',
      result: 'int32_t',
      parameters: [pointer],
    }),

    requestShutdown: bindNativeFunction<
      (coordinator: Pointer) => number
    >(handle, {
      symbol: 'mxc_io_request_shutdown',
      result: 'int32_t',
      parameters: [pointer],
    }),

    warningsJson: bindNativeFunction<KoffiFunc<(
      coordinator: Pointer,
      out: Pointer[],
    ) => number>>(handle, {
      symbol: 'mxc_io_warnings_json',
      result: 'int32_t',
      parameters: [pointer, koffi.out(koffi.pointer('char', 2))],
    }),

    outputMetadataJson: bindNativeFunction<KoffiFunc<(
      coordinator: Pointer,
      out: Pointer[],
    ) => number>>(handle, {
      symbol: 'mxc_io_output_metadata_json',
      result: 'int32_t',
      parameters: [pointer, koffi.out(koffi.pointer('char', 2))],
    }),

    free: bindNativeFunction<(coordinator: Pointer) => void>(handle, {
      symbol: 'mxc_io_free',
      result: 'void',
      parameters: [pointer],
    }),

    freeError: bindNativeFunction<(error: AbiErrorDetail) => void>(handle, {
      symbol: 'mxc_error_detail_free',
      result: 'void',
      parameters: [koffi.pointer(AbiErrorDetailType)],
    }),

    freeString: bindNativeFunction<(value: Pointer) => void>(handle, {
      symbol: 'mxc_string_free',
      result: 'void',
      parameters: ['char *'],
    }),
  };
}

type NativeCoordinator = ReturnType<typeof bindCoordinatorFunctions>;
let sharedNative: NativeCoordinator | undefined;
let sandboxProcessFactory:
  | ((request: RequestSpec) => MxcSandboxProcess)
  | undefined;
let stateAwareSandboxProcessFactory:
  | ((requestJson: string, experimental: boolean) => MxcSandboxProcess)
  | undefined;

function getNative(): NativeCoordinator {
  return sharedNative ??= bindCoordinatorFunctions(loadMxcFfi().handle);
}

function throwIfFailed(status: number, message: string): void {
  if (status !== 0) throw nativeStatusError(status, {}, message);
}

class KoffiStreamingDriver implements NativeStreamingDriver {
  readonly id: number;
  readonly hasStdin: boolean;
  readonly hasStdout: boolean;
  readonly hasStderr: boolean;
  private handler?: (event: NativeStreamingEvent) => void;
  private readonly queued: NativeStreamingEvent[] = [];
  private shutdownRequested = false;
  private freed = false;

  constructor(
    private readonly native: NativeCoordinator,
    private readonly handle: Pointer,
    private readonly callback: RegisteredCallback,
  ) {
    this.id = native.id(handle);
    this.hasStdin = native.hasStdin(handle) !== 0;
    this.hasStdout = native.hasStdout(handle) !== 0;
    this.hasStderr = native.hasStderr(handle) !== 0;
  }

  setEventHandler(handler: (event: NativeStreamingEvent) => void): void {
    this.handler = handler;
    for (const event of this.queued.splice(0)) handler(event);
  }

  onEvent(event: NativeStreamingEvent): void {
    if (this.handler === undefined) this.queued.push(event);
    else this.handler(event);
    if (event.type === 'shutdown') setImmediate(() => this.freeNative());
  }

  warnings(): readonly string[] {
    return parseStringArray(this.readJson(
      (out) => this.native.warningsJson(this.handle, out),
      'retrieving sandbox warnings failed',
    ));
  }

  outputMetadata(): unknown | undefined {
    const json = this.readJson(
      (out) => this.native.outputMetadataJson(this.handle, out),
      'retrieving sandbox output metadata failed',
    );
    return json === undefined ? undefined : JSON.parse(json);
  }

  requestRead(stream: 'stdout' | 'stderr'): void {
    throwIfFailed(
      this.native.requestRead(this.handle, stream === 'stdout' ? STDOUT : STDERR),
      `requesting sandbox ${stream} failed`,
    );
  }

  startWrite(buffer: Buffer): number {
    const operation = [0];
    throwIfFailed(
      this.native.startWrite(this.handle, buffer, buffer.length, operation),
      'queueing sandbox stdin failed',
    );
    return operation[0]!;
  }

  startFlush(): number {
    const operation = [0];
    throwIfFailed(
      this.native.startFlush(this.handle, operation),
      'queueing sandbox stdin flush failed',
    );
    return operation[0]!;
  }

  closeStdin(): void {
    throwIfFailed(
      this.native.closeStdin(this.handle),
      'closing sandbox stdin failed',
    );
  }

  closeOutput(stream: 'stdout' | 'stderr'): void {
    throwIfFailed(
      this.native.closeOutput(this.handle, stream === 'stdout' ? STDOUT : STDERR),
      `closing sandbox ${stream} failed`,
    );
  }

  kill(): void {
    throwIfFailed(
      this.native.requestKill(this.handle),
      'requesting sandbox termination failed',
    );
  }

  shutdown(): void {
    if (this.shutdownRequested) return;
    this.shutdownRequested = true;
    throwIfFailed(
      this.native.requestShutdown(this.handle),
      'requesting sandbox shutdown failed',
    );
  }

  private readJson(
    call: (out: Pointer[]) => number,
    message: string,
  ): string | undefined {
    const out = [null] as Pointer[];
    throwIfFailed(call(out), message);
    try {
      return decodeString(out[0]);
    } finally {
      if (out[0] !== null) this.native.freeString(out[0]);
    }
  }

  private freeNative(): void {
    if (this.freed) return;
    this.freed = true;
    try {
      koffi.unregister(this.callback);
    } finally {
      this.native.free(this.handle);
    }
  }
}

function decodeEvent(
  event: number,
  operation: number,
  data: Pointer,
  length: number,
  value: number | bigint,
  flag: number,
): NativeStreamingEvent {
  const scalar = Number(value);
  switch (event) {
    case EVENT_STDOUT:
    case EVENT_STDERR: {
      const bytes = data && length > 0
        ? Buffer.from(koffi.decode(
            data,
            koffi.array('uint8', length, 'Typed'),
          ) as Uint8Array)
        : Buffer.alloc(0);
      return {
        type: event === EVENT_STDOUT ? 'stdout' : 'stderr',
        data: bytes,
      };
    }
    case EVENT_STDOUT_EOF:
      return { type: 'stdout-eof' };
    case EVENT_STDERR_EOF:
      return { type: 'stderr-eof' };
    case EVENT_STDIN_COMPLETE:
      return {
        type: 'stdin-complete',
        operation,
        written: scalar,
        succeeded: flag !== 0,
      };
    case EVENT_EXIT:
      return {
        type: 'exit',
        result: { exitCode: scalar, timedOut: flag !== 0 },
      };
    case EVENT_SHUTDOWN:
      return { type: 'shutdown' };
    default:
      return {
        type: 'error',
        error: new Error('native sandbox I/O coordinator failed'),
      };
  }
}

function spawnDriver(
  invoke: (
    native: NativeCoordinator,
    callback: RegisteredCallback,
    outHandle: Pointer[],
    error: AbiErrorDetail,
  ) => number,
  fallback: string,
): NativeStreamingDriver {
  const native = getNative();
  const outHandle = [null] as Pointer[];
  const error: AbiErrorDetail = {
    message: null,
    operation: null,
    nativeCode: null,
    remediation: null,
  };
  let driver: KoffiStreamingDriver | undefined;
  let cleanupHandle: Pointer | null = null;
  const queued: NativeStreamingEvent[] = [];
  let callback!: RegisteredCallback;
  callback = koffi.register((
    _userData: Pointer,
    event: number,
    operation: number,
    data: Pointer,
    length: number,
    value: number | bigint,
    flag: number,
  ) => {
    try {
      const decoded = decodeEvent(event, operation, data, length, value, flag);
      if (driver !== undefined) {
        driver.onEvent(decoded);
      } else if (cleanupHandle !== null && decoded.type === 'shutdown') {
        const handle = cleanupHandle;
        cleanupHandle = null;
        setImmediate(() => {
          koffi.unregister(callback);
          native.free(handle);
        });
      } else {
        queued.push(decoded);
      }
    } catch {
      // Exceptions cannot safely cross the native callback boundary.
    }
  }, AbiEventCallback);

  try {
    const status = invoke(native, callback, outHandle, error);
    if (status !== 0 || outHandle[0] === null) {
      throw nativeStatusError(status || 12, error, fallback);
    }
    driver = new KoffiStreamingDriver(native, outHandle[0], callback);
    for (const event of queued) driver.onEvent(event);
    return driver;
  } catch (errorValue) {
    if (outHandle[0] === null) {
      koffi.unregister(callback);
    } else {
      // Shutdown completes asynchronously through the registered callback.
      cleanupHandle = outHandle[0];
      native.requestShutdown(cleanupHandle);
    }
    throw errorValue;
  } finally {
    native.freeError(error);
  }
}

export function _setBindingSandboxProcessFactory(
  factory?: (request: RequestSpec) => MxcSandboxProcess,
): void {
  sandboxProcessFactory = factory;
}

export function _setStateAwareBindingSandboxProcessFactory(
  factory?: (requestJson: string, experimental: boolean) => MxcSandboxProcess,
): void {
  stateAwareSandboxProcessFactory = factory;
}

export function spawnBindingSandboxProcess(
  request: RequestSpec,
): MxcSandboxProcess {
  if (sandboxProcessFactory !== undefined) {
    return sandboxProcessFactory(request);
  }
  return _createMxcSandboxProcess(spawnDriver(
    (native, callback, outHandle, error) => native.spawn(
      JSON.stringify(request),
      callback,
      null,
      outHandle,
      error,
    ),
    'spawning sandbox failed',
  ));
}

export function spawnStateAwareBindingSandboxProcess(
  requestJson: string,
  experimental: boolean,
): MxcSandboxProcess {
  if (stateAwareSandboxProcessFactory !== undefined) {
    return stateAwareSandboxProcessFactory(requestJson, experimental);
  }
  return _createMxcSandboxProcess(spawnDriver(
    (native, callback, outHandle, error) => native.stateAwareExec(
      requestJson,
      experimental ? 1 : 0,
      callback,
      null,
      outHandle,
      error,
    ),
    'starting state-aware sandbox exec failed',
  ));
}
