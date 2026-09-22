// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import assert from 'node:assert';
import { PassThrough, type Readable, type Writable } from 'node:stream';
import { describe, it } from 'node:test';
import {
  createStreamingDriver,
  type StreamingNativeFacade,
} from '../../src/bindings/streaming.js';
import {
  createNodeStreamFactory,
  supportsNativeStdio,
  type NodeStreamDependencies,
  type NativeStreamFactory,
} from '../../src/bindings/native-stdio.js';

class FakeNative implements StreamingNativeFacade {
  readonly handle = {};
  readonly closedHandles: Array<number | bigint> = [];
  readonly freedStrings: unknown[] = [];
  closeFailureHandle: number | bigint | undefined;
  spawnStatus = 0;
  takeStatus = 0;
  killCount = 0;
  timeoutKillCount = 0;
  waitCount = 0;
  freeCount = 0;
  freeErrorCount = 0;
  warningsStatus = 0;
  outputMetadataStatus = 0;
  deferWait = false;
  pendingWait:
    | {
      exit: number[];
      timedOut: number[];
      completion: (error: Error | null, status: number) => void;
    }
    | undefined;
  stdinHandle: number | bigint = 11;
  stdoutHandle: number | bigint = 12;
  stderrHandle: number | bigint = 13;

  spawn(_request: string, outHandle: unknown[], _error: unknown): number {
    outHandle[0] = this.handle;
    return this.spawnStatus;
  }

  id(): number {
    return 23;
  }

  takeNativeStdio(_handle: unknown, stdio: {
    stdin_handle: number | bigint;
    stdout_handle: number | bigint;
    stderr_handle: number | bigint;
  }): number {
    stdio.stdin_handle = this.stdinHandle;
    stdio.stdout_handle = this.stdoutHandle;
    stdio.stderr_handle = this.stderrHandle;
    return this.takeStatus;
  }

  closeNativePipe(handle: number | bigint): void {
    this.closedHandles.push(handle);
    if (handle === this.closeFailureHandle) {
      throw new Error(`closing ${handle} failed`);
    }
  }

  tryWait(
    _handle: unknown,
    exit: number[],
    running: number[],
    timedOut: number[],
  ): number {
    exit[0] = 0;
    running[0] = 1;
    timedOut[0] = 0;
    return 0;
  }

  wait(
    _handle: unknown,
    exit: number[],
    timedOut: number[],
    completion: (error: Error | null, status: number) => void,
  ): void {
    this.waitCount += 1;
    if (this.deferWait) {
      this.pendingWait = { exit, timedOut, completion };
      return;
    }
    queueMicrotask(() => {
      exit[0] = 0;
      timedOut[0] = 0;
      completion(null, 0);
    });
  }

  completeWait(exitCode = 0, timedOut = false): void {
    const pending = this.pendingWait;
    assert.notStrictEqual(pending, undefined);
    this.pendingWait = undefined;
    pending!.exit[0] = exitCode;
    pending!.timedOut[0] = timedOut ? 1 : 0;
    pending!.completion(null, 0);
  }

  kill(): number {
    this.killCount += 1;
    return 0;
  }

  killForTimeout(): number {
    this.timeoutKillCount += 1;
    return 0;
  }

  warningsJson(_handle: unknown, out: unknown[]): number {
    out[0] = null;
    return this.warningsStatus;
  }

  outputMetadataJson(_handle: unknown, out: unknown[]): number {
    out[0] = null;
    return this.outputMetadataStatus;
  }

  free(_handle: unknown, completion: (error: Error | null) => void): void {
    this.freeCount += 1;
    queueMicrotask(() => completion(null));
  }

  freeError(): void {
    this.freeErrorCount += 1;
  }

  freeString(value: unknown): void {
    this.freedStrings.push(value);
  }
}

class FakeStreams implements NativeStreamFactory {
  readonly readableHandles: Array<number | bigint> = [];
  readonly writableHandles: Array<number | bigint> = [];
  readonly readableStreams: PassThrough[] = [];
  readonly writableStreams: PassThrough[] = [];
  failHandle: number | bigint | undefined;

  constructor(readonly platform: NodeJS.Platform = 'linux') {}

  readable(handle: number | bigint): Readable {
    if (handle === this.failHandle) {
      throw new Error('readable construction failed');
    }
    this.readableHandles.push(handle);
    const stream = new PassThrough();
    this.readableStreams.push(stream);
    return stream;
  }

  writable(handle: number | bigint): Writable {
    if (handle === this.failHandle) {
      throw new Error('writable construction failed');
    }
    this.writableHandles.push(handle);
    const stream = new PassThrough();
    this.writableStreams.push(stream);
    return stream;
  }
}

describe('native streaming binding ownership', () => {
  it('passes raw Windows handles directly to the stream factory', async () => {
    const native = new FakeNative();
    native.stdinHandle = 0x100000001n;
    native.stdoutHandle = 0x100000002n;
    native.stderrHandle = 0x100000003n;
    const streams = new FakeStreams('win32');

    const driver = createStreamingDriver(
      {} as never,
      native,
      streams,
    );

    assert.deepStrictEqual(streams.writableHandles, [0x100000001n]);
    assert.deepStrictEqual(
      streams.readableHandles,
      [0x100000002n, 0x100000003n],
    );
    assert.deepStrictEqual(native.closedHandles, []);
    await driver.free();
  });

  it('creates one owning stream per endpoint with the correct direction', async () => {
    const native = new FakeNative();
    const streams = new FakeStreams();

    const driver = createStreamingDriver(
      {} as never,
      native,
      streams,
    );

    assert.strictEqual(driver.id, 23);
    assert.deepStrictEqual(streams.writableHandles, [11]);
    assert.deepStrictEqual(streams.readableHandles, [12, 13]);
    assert.deepStrictEqual(native.closedHandles, []);
    await driver.free();
    assert.strictEqual(native.freeCount, 1);
  });

  it('waits off-thread and returns the native terminal result', async () => {
    const native = new FakeNative();
    native.deferWait = true;
    const driver = createStreamingDriver(
      {} as never,
      native,
      new FakeStreams(),
    );

    const wait = driver.wait();
    await Promise.resolve();

    assert.strictEqual(native.waitCount, 1);

    native.completeWait(31, true);

    assert.deepStrictEqual(await wait, { exitCode: 31, timedOut: true });
    await driver.free();
    assert.strictEqual(native.freeCount, 1);
  });

  it('treats platform-specific missing endpoint sentinels as absent', async () => {
    const unixNative = new FakeNative();
    unixNative.stdinHandle = -1;
    unixNative.stderrHandle = -1n;
    const unixStreams = new FakeStreams();
    const unixDriver = createStreamingDriver(
      {} as never,
      unixNative,
      unixStreams,
    );

    assert.strictEqual(unixDriver.standardInput, null);
    assert.strictEqual(unixDriver.standardError, null);
    assert.deepStrictEqual(unixStreams.readableHandles, [12]);
    await unixDriver.free();

    const windowsNative = new FakeNative();
    windowsNative.stdinHandle = 0n;
    windowsNative.stderrHandle = 0;
    const windowsStreams = new FakeStreams('win32');
    const windowsDriver = createStreamingDriver(
      {} as never,
      windowsNative,
      windowsStreams,
    );

    assert.strictEqual(windowsDriver.standardInput, null);
    assert.strictEqual(windowsDriver.standardError, null);
    assert.deepStrictEqual(windowsStreams.readableHandles, [12]);
    await windowsDriver.free();
  });

  it('closes the failed and remaining handles when stream construction fails', async () => {
    const native = new FakeNative();
    const streams = new FakeStreams();
    streams.failHandle = 12;

    assert.throws(
      () => createStreamingDriver({} as never, native, streams),
      /readable construction failed/,
    );

    assert.deepStrictEqual(native.closedHandles, [12, 13]);
    assert.strictEqual(streams.writableStreams[0].destroyed, true);
    await new Promise((resolve) => setImmediate(resolve));
    assert.strictEqual(native.freeCount, 1);
  });

  it('continues rollback when closing one remaining raw handle fails', async () => {
    const native = new FakeNative();
    native.closeFailureHandle = 12;
    const streams = new FakeStreams();
    streams.failHandle = 12;

    assert.throws(
      () => createStreamingDriver({} as never, native, streams),
      /rollback was incomplete/,
    );

    assert.deepStrictEqual(native.closedHandles, [12, 13]);
    assert.strictEqual(streams.writableStreams[0].destroyed, true);
    await new Promise((resolve) => setImmediate(resolve));
    assert.strictEqual(native.freeCount, 1);
  });

  it('frees the sandbox when native stdio transfer fails', async () => {
    const native = new FakeNative();
    native.takeStatus = 12;

    assert.throws(
      () => createStreamingDriver(
        {} as never,
        native,
        new FakeStreams(),
      ),
      /taking native stdio failed/,
    );

    await new Promise((resolve) => setImmediate(resolve));
    assert.strictEqual(native.freeCount, 1);
  });

  it('frees native error detail when spawn fails', () => {
    const native = new FakeNative();
    native.spawnStatus = 12;

    assert.throws(
      () => createStreamingDriver(
        {} as never,
        native,
        new FakeStreams(),
      ),
      /native runtime failed/,
    );

    assert.strictEqual(native.freeErrorCount, 1);
    assert.strictEqual(native.freeCount, 0);
  });

  it('surfaces native process-data read failures', async () => {
    const native = new FakeNative();
    native.warningsStatus = 12;
    native.outputMetadataStatus = 12;
    const driver = createStreamingDriver(
      {} as never,
      native,
      new FakeStreams(),
    );

    assert.throws(
      () => driver.warnings(),
      /reading sandbox process warnings failed/,
    );
    assert.throws(
      () => driver.outputMetadata(),
      /reading sandbox process output metadata failed/,
    );
    await driver.free();
  });
});

describe('native Node stream construction', () => {
  it('constructs owning Windows streams from the full native handle', () => {
    const calls: Array<{
      readonly direction: 'readable' | 'writable';
      readonly path: string;
      readonly options: unknown;
    }> = [];
    const dependencies: NodeStreamDependencies = {
      createReadStream(path, options) {
        calls.push({ direction: 'readable', path, options });
        return new PassThrough();
      },
      createWriteStream(path, options) {
        calls.push({ direction: 'writable', path, options });
        return new PassThrough();
      },
      createSocket() {
        throw new Error('Windows must not construct fd-backed sockets');
      },
    };
    const factory = createNodeStreamFactory('win32', dependencies);

    factory.writable(0x100000001n);
    factory.readable(0x100000002);

    assert.deepStrictEqual(calls, [
      {
        direction: 'writable',
        path: '',
        options: { autoClose: true, windowsHandle: 0x100000001n },
      },
      {
        direction: 'readable',
        path: '',
        options: { autoClose: true, windowsHandle: 0x100000002n },
      },
    ]);
  });

  it('constructs directional owning Unix sockets from validated descriptors', () => {
    const socketOptions: unknown[] = [];
    const dependencies: NodeStreamDependencies = {
      createReadStream() {
        throw new Error('Unix must not construct Windows read streams');
      },
      createWriteStream() {
        throw new Error('Unix must not construct Windows write streams');
      },
      createSocket(options) {
        socketOptions.push(options);
        return new PassThrough();
      },
    };
    const factory = createNodeStreamFactory('linux', dependencies);

    factory.writable(11n);
    factory.readable(12);

    assert.deepStrictEqual(socketOptions, [
      { fd: 11, readable: false, writable: true },
      { fd: 12, readable: true, writable: false },
    ]);
    assert.throws(
      () => factory.readable(Number.MAX_SAFE_INTEGER + 1),
      /invalid file descriptor/,
    );
  });
});

describe('native streaming Node version support', () => {
  it('enforces the platform-specific native stdio runtime ranges', () => {
    assert.strictEqual(supportsNativeStdio('win32', '24.20.9'), false);
    assert.strictEqual(supportsNativeStdio('win32', '24.21.0'), true);
    assert.strictEqual(supportsNativeStdio('win32', '24.21.1'), true);
    assert.strictEqual(supportsNativeStdio('win32', '25.0.0'), false);
    assert.strictEqual(supportsNativeStdio('win32', '25.9.0'), false);
    assert.strictEqual(supportsNativeStdio('win32', '26.7.0'), false);
    assert.strictEqual(supportsNativeStdio('win32', '26.8.0'), true);
    assert.strictEqual(supportsNativeStdio('win32', '27.0.0'), true);
    assert.strictEqual(supportsNativeStdio('win32', '23.99.99'), false);
    assert.strictEqual(supportsNativeStdio('win32', 'v24.21.0'), true);
    assert.strictEqual(supportsNativeStdio('win32', 'v26.8.0'), true);
    assert.strictEqual(supportsNativeStdio('win32', '26.8'), false);
    assert.strictEqual(supportsNativeStdio('win32', 'invalid'), false);
    assert.strictEqual(supportsNativeStdio('win32', '24.21beta'), false);
    assert.strictEqual(supportsNativeStdio('win32', '24.21.0.1'), false);
    assert.strictEqual(supportsNativeStdio('linux', '23.99.99'), false);
    assert.strictEqual(supportsNativeStdio('linux', '24.0.0'), true);
    assert.strictEqual(supportsNativeStdio('linux', '25.0.0'), true);
    assert.strictEqual(supportsNativeStdio('darwin', '23.99.99'), false);
    assert.strictEqual(supportsNativeStdio('darwin', '24.0.0'), true);
  });
});
