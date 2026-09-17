// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Binds the native streaming ABI, then wraps its sandbox and stream handles in
// the lifetime-safe interfaces consumed by MxcSandboxProcess.

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
import type {
  SandboxProcessBinding,
  SandboxProcessWaitResult,
  SandboxReadableBinding,
  SandboxWritableBinding,
} from './streaming-types.js';
import {
  _createMxcSandboxProcess,
  type MxcSandboxProcess,
} from '../sandbox-process.js';

type Pointer = unknown;
type TakeReadResult = { stream: Pointer; closer: Pointer | null } | null;

type SpawnFunction = KoffiFunc<(request: string, handle: Pointer[], error: AbiErrorDetail) => number>;
type ReadFunction = KoffiFunc<(stream: Pointer, buffer: Buffer, cap: number, outRead: number[]) => number>;
type WriteFunction = KoffiFunc<(stream: Pointer, buffer: Buffer, len: number, outWritten: number[]) => number>;
type FlushFunction = KoffiFunc<(stream: Pointer) => number>;

// Small operation set consumed by the handle-lifetime adapters below.
interface StreamingApi {
  spawn: SpawnFunction;
  freeError(error: AbiErrorDetail): void;
  takeStdin(handle: Pointer): Pointer | null;
  takeStdout(handle: Pointer): TakeReadResult;
  takeStderr(handle: Pointer): TakeReadResult;
  id(handle: Pointer): number;
  warnings(handle: Pointer): string[];
  outputMetadata(handle: Pointer): unknown | undefined;
  tryWait(handle: Pointer): SandboxProcessWaitResult & { running: boolean };
  wait(handle: Pointer): SandboxProcessWaitResult;
  kill(handle: Pointer): void;
  freeSandbox(handle: Pointer): void;
  read: ReadFunction;
  write: WriteFunction;
  flush: FlushFunction;
  closeCloser(closer: Pointer): void;
  freeRead(stream: Pointer): void;
  freeWrite(stream: Pointer): void;
  freeCloser(closer: Pointer): void;
}

let sharedApi: StreamingApi | undefined;
let sandboxProcessFactory: ((request: RequestSpec, timeoutMs?: number) => MxcSandboxProcess)
  | undefined;
const AbiSandbox = koffi.opaque('MxcNodeSandbox');
const AbiReadStream = koffi.opaque('MxcNodeReadStream');
const AbiWriteStream = koffi.opaque('MxcNodeWriteStream');
const AbiStreamCloser = koffi.opaque('MxcNodeStreamCloser');

type NativeLibraryHandle = MxcNativeLibrary['handle'];

// Sandbox creation, status, metadata, and terminal lifecycle.
function bindSandboxFunctions(handle: NativeLibraryHandle) {
  const spawn = bindNativeFunction<
    (request: string, sandbox: Pointer[], error: AbiErrorDetail) => number
  >(handle, {
    symbol: 'mxc_spawn_request',
    result: 'int32_t',
    parameters: [
      'const char *',
      koffi.out(koffi.pointer(AbiSandbox, 2)),
      koffi.out(koffi.pointer(AbiErrorDetailType)),
    ],
  });

  const tryWait = bindNativeFunction<
    (sandbox: Pointer, exitCode: number[], running: number[], timedOut: number[]) => number
  >(handle, {
    symbol: 'mxc_sandbox_try_wait',
    result: 'int32_t',
    parameters: [
      koffi.pointer(AbiSandbox),
      koffi.out(koffi.pointer('int32_t')),
      koffi.out(koffi.pointer('int32_t')),
      koffi.out(koffi.pointer('int32_t')),
    ],
  });

  const wait = bindNativeFunction<
    (sandbox: Pointer, exitCode: number[], timedOut: number[]) => number
  >(handle, {
    symbol: 'mxc_sandbox_wait',
    result: 'int32_t',
    parameters: [
      koffi.pointer(AbiSandbox),
      koffi.out(koffi.pointer('int32_t')),
      koffi.out(koffi.pointer('int32_t')),
    ],
  });

  const id = bindNativeFunction<(sandbox: Pointer) => number>(handle, {
    symbol: 'mxc_sandbox_id',
    result: 'uint32_t',
    parameters: [koffi.pointer(AbiSandbox)],
  });

  const kill = bindNativeFunction<(sandbox: Pointer) => number>(handle, {
    symbol: 'mxc_sandbox_kill',
    result: 'int32_t',
    parameters: [koffi.pointer(AbiSandbox)],
  });

  const warningsJson = bindNativeFunction<
    (sandbox: Pointer, out: Pointer[]) => number
  >(handle, {
    symbol: 'mxc_sandbox_warnings_json',
    result: 'int32_t',
    parameters: [
      koffi.pointer(AbiSandbox),
      koffi.out(koffi.pointer('char', 2)),
    ],
  });

  const outputJson = bindNativeFunction<
    (sandbox: Pointer, out: Pointer[]) => number
  >(handle, {
    symbol: 'mxc_sandbox_output_metadata_json',
    result: 'int32_t',
    parameters: [
      koffi.pointer(AbiSandbox),
      koffi.out(koffi.pointer('char', 2)),
    ],
  });

  const freeSandbox = bindNativeFunction<(sandbox: Pointer) => void>(handle, {
    symbol: 'mxc_sandbox_free',
    result: 'void',
    parameters: [koffi.pointer(AbiSandbox)],
  });

  return {
    spawn,
    tryWait,
    wait,
    id,
    kill,
    warningsJson,
    outputJson,
    freeSandbox,
  };
}

// Pipe acquisition, asynchronous I/O, interruption, and disposal.
function bindStreamFunctions(handle: NativeLibraryHandle) {
  const takeStdin = bindNativeFunction<
    (sandbox: Pointer) => Pointer | null
  >(handle, {
    symbol: 'mxc_sandbox_take_stdin',
    result: koffi.pointer(AbiWriteStream),
    parameters: [koffi.pointer(AbiSandbox)],
  });

  const takeStdout = bindNativeFunction<
    (sandbox: Pointer) => Pointer | null
  >(handle, {
    symbol: 'mxc_sandbox_take_stdout',
    result: koffi.pointer(AbiReadStream),
    parameters: [koffi.pointer(AbiSandbox)],
  });

  const takeStderr = bindNativeFunction<
    (sandbox: Pointer) => Pointer | null
  >(handle, {
    symbol: 'mxc_sandbox_take_stderr',
    result: koffi.pointer(AbiReadStream),
    parameters: [koffi.pointer(AbiSandbox)],
  });

  const stdoutCloser = bindNativeFunction<
    (sandbox: Pointer) => Pointer | null
  >(handle, {
    symbol: 'mxc_sandbox_stdout_closer',
    result: koffi.pointer(AbiStreamCloser),
    parameters: [koffi.pointer(AbiSandbox)],
  });

  const stderrCloser = bindNativeFunction<
    (sandbox: Pointer) => Pointer | null
  >(handle, {
    symbol: 'mxc_sandbox_stderr_closer',
    result: koffi.pointer(AbiStreamCloser),
    parameters: [koffi.pointer(AbiSandbox)],
  });

  const read = bindNativeFunction<
    (stream: Pointer, buffer: Buffer, cap: number, outRead: number[]) => number
  >(handle, {
    symbol: 'mxc_stream_read',
    result: 'int32_t',
    parameters: [
      koffi.pointer(AbiReadStream),
      'uint8_t *',
      'size_t',
      koffi.out(koffi.pointer('size_t')),
    ],
  });

  const write = bindNativeFunction<
    (stream: Pointer, buffer: Buffer, len: number, outWritten: number[]) => number
  >(handle, {
    symbol: 'mxc_stream_write',
    result: 'int32_t',
    parameters: [
      koffi.pointer(AbiWriteStream),
      'const uint8_t *',
      'size_t',
      koffi.out(koffi.pointer('size_t')),
    ],
  });

  const flush = bindNativeFunction<(stream: Pointer) => number>(handle, {
    symbol: 'mxc_stream_flush',
    result: 'int32_t',
    parameters: [koffi.pointer(AbiWriteStream)],
  });

  const closeCloser = bindNativeFunction<(closer: Pointer) => number>(handle, {
    symbol: 'mxc_stream_closer_close',
    result: 'int32_t',
    parameters: [koffi.pointer(AbiStreamCloser)],
  });

  const freeRead = bindNativeFunction<(stream: Pointer) => void>(handle, {
    symbol: 'mxc_read_stream_free',
    result: 'void',
    parameters: [koffi.pointer(AbiReadStream)],
  });

  const freeWrite = bindNativeFunction<(stream: Pointer) => void>(handle, {
    symbol: 'mxc_write_stream_free',
    result: 'void',
    parameters: [koffi.pointer(AbiWriteStream)],
  });

  const freeCloser = bindNativeFunction<(closer: Pointer) => void>(handle, {
    symbol: 'mxc_stream_closer_free',
    result: 'void',
    parameters: [koffi.pointer(AbiStreamCloser)],
  });

  return {
    takeStdin,
    takeStdout,
    takeStderr,
    stdoutCloser,
    stderrCloser,
    read,
    write,
    flush,
    closeCloser,
    freeRead,
    freeWrite,
    freeCloser,
  };
}

// Deallocators for values whose ownership crosses the native boundary.
function bindOwnedValueFunctions(handle: NativeLibraryHandle) {
  const errorFree = bindNativeFunction<(error: AbiErrorDetail) => void>(handle, {
    symbol: 'mxc_error_detail_free',
    result: 'void',
    parameters: [koffi.pointer(AbiErrorDetailType)],
  });

  const stringFree = bindNativeFunction<(value: Pointer) => void>(handle, {
    symbol: 'mxc_string_free',
    result: 'void',
    parameters: ['char *'],
  });

  return { errorFree, stringFree };
}

function bindStreamingFunctions() {
  const { handle } = loadMxcFfi();
  return {
    ...bindSandboxFunctions(handle),
    ...bindStreamFunctions(handle),
    ...bindOwnedValueFunctions(handle),
  };
}

type BoundStreamingFunctions = ReturnType<typeof bindStreamingFunctions>;

function throwIfFailed(status: number, message: string): void {
  if (status !== 0) {
    throw nativeStatusError(status, {}, message);
  }
}

function readOwnedJson(
  native: BoundStreamingFunctions,
  call: (out: Pointer[]) => number,
  message: string,
): string | undefined {
  const out = [null] as Pointer[];
  throwIfFailed(call(out), message);
  try {
    return decodeString(out[0]);
  } finally {
    if (out[0] !== null) {
      native.stringFree(out[0]);
    }
  }
}

function takeReadable(
  sandbox: Pointer,
  take: (sandbox: Pointer) => Pointer | null,
  takeCloser: (sandbox: Pointer) => Pointer | null,
): TakeReadResult {
  const stream = take(sandbox);
  if (stream === null) {
    return null;
  }
  return { stream, closer: takeCloser(sandbox) };
}

function readTryWait(
  native: BoundStreamingFunctions,
  sandbox: Pointer,
): SandboxProcessWaitResult & { running: boolean } {
  const exitCode = [0];
  const running = [0];
  const timedOut = [0];
  throwIfFailed(
    native.tryWait(sandbox, exitCode, running, timedOut),
    'querying sandbox status failed',
  );
  return {
    exitCode: exitCode[0]!,
    running: running[0] !== 0,
    timedOut: timedOut[0] !== 0,
  };
}

function readWait(
  native: BoundStreamingFunctions,
  sandbox: Pointer,
): SandboxProcessWaitResult {
  const exitCode = [0];
  const timedOut = [0];
  throwIfFailed(
    native.wait(sandbox, exitCode, timedOut),
    'waiting on sandbox failed',
  );
  return {
    exitCode: exitCode[0]!,
    timedOut: timedOut[0] !== 0,
  };
}

function createStreamingApi(): StreamingApi {
  const native = bindStreamingFunctions();

  return {
    spawn: native.spawn,
    freeError: native.errorFree,
    takeStdin: native.takeStdin,
    takeStdout: (sandbox) =>
      takeReadable(sandbox, native.takeStdout, native.stdoutCloser),
    takeStderr: (sandbox) =>
      takeReadable(sandbox, native.takeStderr, native.stderrCloser),
    id: native.id,
    warnings: (sandbox) => parseStringArray(
      readOwnedJson(
        native,
        (out) => native.warningsJson(sandbox, out),
        'retrieving sandbox warnings failed',
      ),
    ),
    outputMetadata: (sandbox) => {
      const json = readOwnedJson(
        native,
        (out) => native.outputJson(sandbox, out),
        'retrieving sandbox output metadata failed',
      );
      return json === undefined ? undefined : JSON.parse(json);
    },
    tryWait: (sandbox) => readTryWait(native, sandbox),
    wait: (sandbox) => readWait(native, sandbox),
    kill: (sandbox) => {
      throwIfFailed(native.kill(sandbox), 'killing sandbox failed');
    },
    freeSandbox: native.freeSandbox,
    read: native.read,
    write: native.write,
    flush: native.flush,
    closeCloser: (closer) => {
      throwIfFailed(
        native.closeCloser(closer),
        'closing sandbox output stream failed',
      );
    },
    freeRead: native.freeRead,
    freeWrite: native.freeWrite,
    freeCloser: native.freeCloser,
  };
}

function getStreamingApi(): StreamingApi {
  return sharedApi ??= createStreamingApi();
}

function callAsync<T>(
  invoke: (callback: (error: unknown, status: number) => void) => void,
  readResult: (status: number) => T,
): Promise<T> {
  return new Promise((resolve, reject) => {
    invoke((error, status) => {
      if (error) {
        reject(error);
        return;
      }
      try {
        resolve(readResult(status));
      } catch (failure) {
        reject(failure);
      }
    });
  });
}

class StreamingReadableBinding implements SandboxReadableBinding {
  private active = 0;
  private freed = false;
  private freePending = false;
  private closerClosed = false;

  constructor(
    private readonly api: StreamingApi,
    private readonly stream: Pointer,
    private readonly closer: Pointer | null,
    private readonly label: string,
  ) {}

  read(buffer: Buffer): Promise<number> {
    const outRead = [0];
    this.active += 1;
    return callAsync(
      (callback) => this.api.read.async(this.stream, buffer, buffer.length, outRead, callback),
      (status) => {
        if (status !== 0) throw nativeStatusError(status, {}, `reading sandbox ${this.label} failed`);
        return outRead[0]!;
      },
    ).finally(() => {
      this.active -= 1;
      this.finishFree();
    });
  }

  close(): void {
    if (this.closer === null || this.closerClosed) return;
    this.closerClosed = true;
    this.api.closeCloser(this.closer);
  }

  free(): void {
    this.freePending = true;
    this.finishFree();
  }

  private finishFree(): void {
    if (!this.freePending || this.active !== 0 || this.freed) return;
    this.freed = true;
    if (this.closer !== null) this.api.freeCloser(this.closer);
    this.api.freeRead(this.stream);
  }
}

class StreamingWritableBinding implements SandboxWritableBinding {
  private active = 0;
  private freed = false;
  private freePending = false;

  constructor(private readonly api: StreamingApi, private readonly stream: Pointer) {}

  write(buffer: Buffer): Promise<number> {
    const outWritten = [0];
    this.active += 1;
    return callAsync(
      (callback) => this.api.write.async(this.stream, buffer, buffer.length, outWritten, callback),
      (status) => {
        if (status !== 0) throw nativeStatusError(status, {}, 'writing sandbox stdin failed');
        return outWritten[0]!;
      },
    ).finally(() => {
      this.active -= 1;
      this.finishFree();
    });
  }

  flush(): Promise<void> {
    this.active += 1;
    return callAsync(
      (callback) => this.api.flush.async(this.stream, callback),
      (status) => {
        if (status !== 0) throw nativeStatusError(status, {}, 'flushing sandbox stdin failed');
      },
    ).finally(() => {
      this.active -= 1;
      this.finishFree();
    });
  }

  free(): void {
    this.freePending = true;
    this.finishFree();
  }

  private finishFree(): void {
    if (!this.freePending || this.active !== 0 || this.freed) return;
    this.freed = true;
    this.api.freeWrite(this.stream);
  }
}

class StreamingProcessBinding implements SandboxProcessBinding {
  private stdinTaken = false;
  private stdoutTaken = false;
  private stderrTaken = false;
  private freed = false;

  constructor(
    private readonly api: StreamingApi,
    private readonly handle: Pointer,
    readonly id: number,
    readonly warnings: readonly string[],
  ) {}

  takeStdin(): SandboxWritableBinding | null {
    if (this.stdinTaken) return null;
    this.stdinTaken = true;
    const stream = this.api.takeStdin(this.handle);
    return stream === null ? null : new StreamingWritableBinding(this.api, stream);
  }

  takeStdout(): SandboxReadableBinding | null {
    if (this.stdoutTaken) return null;
    this.stdoutTaken = true;
    const stream = this.api.takeStdout(this.handle);
    return stream === null ? null : new StreamingReadableBinding(this.api, stream.stream, stream.closer, 'stdout');
  }

  takeStderr(): SandboxReadableBinding | null {
    if (this.stderrTaken) return null;
    this.stderrTaken = true;
    const stream = this.api.takeStderr(this.handle);
    return stream === null ? null : new StreamingReadableBinding(this.api, stream.stream, stream.closer, 'stderr');
  }

  tryWait(): SandboxProcessWaitResult & { running: boolean } {
    return this.api.tryWait(this.handle);
  }

  wait(): SandboxProcessWaitResult {
    return this.api.wait(this.handle);
  }

  outputMetadata(): unknown | undefined {
    return this.api.outputMetadata(this.handle);
  }

  kill(): void {
    this.api.kill(this.handle);
  }

  free(): void {
    if (this.freed) return;
    this.freed = true;
    this.api.freeSandbox(this.handle);
  }
}

/**
 * Spawn the low-level handle adapter. The Node stream/process facade is added
 * by the next layer so this binding module remains independently buildable.
 */
export function spawnStreamingProcessBinding(
  request: RequestSpec,
): SandboxProcessBinding {
  const api = getStreamingApi();
  const outHandle = [null] as Pointer[];
  const error = {} as AbiErrorDetail;
  let spawned = false;
  try {
    spawned = true;
    const status = api.spawn(JSON.stringify(request), outHandle, error);
    if (status !== 0 || outHandle[0] === null) {
      throw nativeStatusError(status || 12, error, 'spawning sandbox failed');
    }
    return new StreamingProcessBinding(
      api,
      outHandle[0],
      api.id(outHandle[0]),
      api.warnings(outHandle[0]),
    );
  } catch (errorValue) {
    if (outHandle[0] !== null) api.freeSandbox(outHandle[0]);
    throw errorValue;
  } finally {
    if (spawned) api.freeError(error);
  }
}

export function _setBindingSandboxProcessFactory(
  factory?: (request: RequestSpec, timeoutMs?: number) => MxcSandboxProcess,
): void {
  sandboxProcessFactory = factory;
}

export function spawnBindingSandboxProcess(
  request: RequestSpec,
  timeoutMs?: number,
): MxcSandboxProcess {
  if (sandboxProcessFactory !== undefined) {
    return sandboxProcessFactory(request, timeoutMs);
  }
  return _createMxcSandboxProcess(
    spawnStreamingProcessBinding(request),
    timeoutMs,
  );
}
