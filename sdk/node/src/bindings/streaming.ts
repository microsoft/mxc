// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Owns native sandbox and stream handles and adapts them to MxcSandboxProcess.

import koffi, { type KoffiFunc } from 'koffi';
import { loadMxcFfi } from '../native-library.js';
import type { RequestSpec } from './request.js';
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
  type SandboxProcessBinding,
  type SandboxProcessWaitResult,
  type SandboxReadableBinding,
  type SandboxWritableBinding,
} from '../sandbox-process.js';

type Pointer = unknown;
type TakeReadResult = { stream: Pointer; closer: Pointer | null } | null;

type SpawnFunction = KoffiFunc<(request: string, handle: Pointer[], error: AbiErrorDetail) => number>;
type ReadFunction = KoffiFunc<(stream: Pointer, buffer: Buffer, cap: number, outRead: number[]) => number>;
type WriteFunction = KoffiFunc<(stream: Pointer, buffer: Buffer, len: number, outWritten: number[]) => number>;
type FlushFunction = KoffiFunc<(stream: Pointer) => number>;

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

function createStreamingApi(): StreamingApi {
  const native = loadMxcFfi();
  const { handle } = native;
  const spawn = handle.func('mxc_spawn_request', 'int32_t', [
    'const char *',
    koffi.out(koffi.pointer(AbiSandbox, 2)),
    koffi.out(koffi.pointer(AbiErrorDetailType)),
  ]) as SpawnFunction;
  const errorFree = handle.func('mxc_error_detail_free', 'void', [koffi.pointer(AbiErrorDetailType)]) as (error: AbiErrorDetail) => void;
  const warningsJson = handle.func('mxc_sandbox_warnings_json', 'int32_t', [
    koffi.pointer(AbiSandbox),
    koffi.out(koffi.pointer('char', 2)),
  ]) as (sandbox: Pointer, out: Pointer[]) => number;
  const outputJson = handle.func('mxc_sandbox_output_metadata_json', 'int32_t', [
    koffi.pointer(AbiSandbox),
    koffi.out(koffi.pointer('char', 2)),
  ]) as (sandbox: Pointer, out: Pointer[]) => number;
  const stringFree = handle.func('mxc_string_free', 'void', ['char *']) as (value: Pointer) => void;
  const stdoutCloser = handle.func('mxc_sandbox_stdout_closer', koffi.pointer(AbiStreamCloser), [koffi.pointer(AbiSandbox)]) as (sandbox: Pointer) => Pointer | null;
  const stderrCloser = handle.func('mxc_sandbox_stderr_closer', koffi.pointer(AbiStreamCloser), [koffi.pointer(AbiSandbox)]) as (sandbox: Pointer) => Pointer | null;
  const read = handle.func('mxc_stream_read', 'int32_t', [
    koffi.pointer(AbiReadStream),
    'uint8_t *',
    'size_t',
    koffi.out(koffi.pointer('size_t')),
  ]) as ReadFunction;
  const write = handle.func('mxc_stream_write', 'int32_t', [
    koffi.pointer(AbiWriteStream),
    'const uint8_t *',
    'size_t',
    koffi.out(koffi.pointer('size_t')),
  ]) as WriteFunction;
  const flush = handle.func('mxc_stream_flush', 'int32_t', [koffi.pointer(AbiWriteStream)]) as FlushFunction;
  const closeCloser = handle.func('mxc_stream_closer_close', 'int32_t', [koffi.pointer(AbiStreamCloser)]) as (closer: Pointer) => number;
  const tryWait = handle.func('mxc_sandbox_try_wait', 'int32_t', [
    koffi.pointer(AbiSandbox),
    koffi.out(koffi.pointer('int32_t')),
    koffi.out(koffi.pointer('int32_t')),
    koffi.out(koffi.pointer('int32_t')),
  ]) as (sandbox: Pointer, exitCode: number[], running: number[], timedOut: number[]) => number;
  const wait = handle.func('mxc_sandbox_wait', 'int32_t', [
    koffi.pointer(AbiSandbox),
    koffi.out(koffi.pointer('int32_t')),
    koffi.out(koffi.pointer('int32_t')),
  ]) as (sandbox: Pointer, exitCode: number[], timedOut: number[]) => number;
  const takeStdout = handle.func('mxc_sandbox_take_stdout', koffi.pointer(AbiReadStream), [koffi.pointer(AbiSandbox)]) as (sandbox: Pointer) => Pointer | null;
  const takeStderr = handle.func('mxc_sandbox_take_stderr', koffi.pointer(AbiReadStream), [koffi.pointer(AbiSandbox)]) as (sandbox: Pointer) => Pointer | null;
  const takeStdin = handle.func('mxc_sandbox_take_stdin', koffi.pointer(AbiWriteStream), [koffi.pointer(AbiSandbox)]) as (sandbox: Pointer) => Pointer | null;
  const id = handle.func('mxc_sandbox_id', 'uint32_t', [koffi.pointer(AbiSandbox)]) as (sandbox: Pointer) => number;
  const kill = handle.func('mxc_sandbox_kill', 'int32_t', [koffi.pointer(AbiSandbox)]) as (sandbox: Pointer) => number;
  const freeSandbox = handle.func('mxc_sandbox_free', 'void', [koffi.pointer(AbiSandbox)]) as (sandbox: Pointer) => void;
  const freeRead = handle.func('mxc_read_stream_free', 'void', [koffi.pointer(AbiReadStream)]) as (stream: Pointer) => void;
  const freeWrite = handle.func('mxc_write_stream_free', 'void', [koffi.pointer(AbiWriteStream)]) as (stream: Pointer) => void;
  const freeCloser = handle.func('mxc_stream_closer_free', 'void', [koffi.pointer(AbiStreamCloser)]) as (closer: Pointer) => void;

  const readJson = (call: (out: Pointer[]) => number, message: string): string | undefined => {
    const out = [null] as Pointer[];
    const status = call(out);
    if (status !== 0) throw nativeStatusError(status, {}, message);
    try {
      return decodeString(out[0]);
    } finally {
      if (out[0] !== null) stringFree(out[0]);
    }
  };

  return {
    spawn,
    freeError: errorFree,
    takeStdin,
    takeStdout: (sandbox) => {
      const stream = takeStdout(sandbox);
      return stream === null ? null : { stream, closer: stdoutCloser(sandbox) };
    },
    takeStderr: (sandbox) => {
      const stream = takeStderr(sandbox);
      return stream === null ? null : { stream, closer: stderrCloser(sandbox) };
    },
    id,
    warnings: (sandbox) => parseStringArray(
      readJson((out) => warningsJson(sandbox, out), 'retrieving sandbox warnings failed'),
    ),
    outputMetadata: (sandbox) => {
      const json = readJson((out) => outputJson(sandbox, out), 'retrieving sandbox output metadata failed');
      return json === undefined ? undefined : JSON.parse(json);
    },
    tryWait: (sandbox) => {
      const exitCode = [0];
      const running = [0];
      const timedOut = [0];
      const status = tryWait(sandbox, exitCode, running, timedOut);
      if (status !== 0) throw nativeStatusError(status, {}, 'querying sandbox status failed');
      return { exitCode: exitCode[0]!, running: running[0] !== 0, timedOut: timedOut[0] !== 0 };
    },
    wait: (sandbox) => {
      const exitCode = [0];
      const timedOut = [0];
      const status = wait(sandbox, exitCode, timedOut);
      if (status !== 0) throw nativeStatusError(status, {}, 'waiting on sandbox failed');
      return { exitCode: exitCode[0]!, timedOut: timedOut[0] !== 0 };
    },
    kill: (sandbox) => {
      const status = kill(sandbox);
      if (status !== 0) throw nativeStatusError(status, {}, 'killing sandbox failed');
    },
    freeSandbox,
    read,
    write,
    flush,
    closeCloser: (closer) => {
      const status = closeCloser(closer);
      if (status !== 0) throw nativeStatusError(status, {}, 'closing sandbox output stream failed');
    },
    freeRead,
    freeWrite,
    freeCloser,
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

function spawnRealBinding(request: RequestSpec, timeoutMs?: number): MxcSandboxProcess {
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
    const binding = new StreamingProcessBinding(api, outHandle[0], api.id(outHandle[0]), api.warnings(outHandle[0]));
    return _createMxcSandboxProcess(binding, timeoutMs);
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
  return (sandboxProcessFactory ?? spawnRealBinding)(request, timeoutMs);
}
