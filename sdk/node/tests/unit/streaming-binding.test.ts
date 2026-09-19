// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import assert from 'node:assert';
import { PassThrough, type Readable, type Writable } from 'node:stream';
import { describe, it } from 'node:test';
import {
  _isSupportedNodeVersionForTest,
  _spawnStreamingDriverForTest,
  type _NativeStreamFactory,
  type _StreamingNativeFacade,
} from '../../src/bindings/streaming.js';

class FakeNative implements _StreamingNativeFacade {
  readonly handle = {};
  readonly closedHandles: Array<number | bigint> = [];
  readonly freedStrings: unknown[] = [];
  spawnStatus = 0;
  takeStatus = 0;
  killCount = 0;
  freeCount = 0;
  freeErrorCount = 0;
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

  wait(_handle: unknown, exit: number[], timedOut: number[]): number {
    exit[0] = 0;
    timedOut[0] = 0;
    return 0;
  }

  kill(): number {
    this.killCount += 1;
    return 0;
  }

  warningsJson(_handle: unknown, out: unknown[]): number {
    out[0] = null;
    return 0;
  }

  outputMetadataJson(_handle: unknown, out: unknown[]): number {
    out[0] = null;
    return 0;
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

class FakeStreams implements _NativeStreamFactory {
  readonly readableHandles: Array<number | bigint> = [];
  readonly writableHandles: Array<number | bigint> = [];
  failHandle: number | bigint | undefined;

  constructor(readonly platform: NodeJS.Platform = 'linux') {}

  readable(handle: number | bigint): Readable {
    if (handle === this.failHandle) {
      throw new Error('readable construction failed');
    }
    this.readableHandles.push(handle);
    return new PassThrough();
  }

  writable(handle: number | bigint): Writable {
    if (handle === this.failHandle) {
      throw new Error('writable construction failed');
    }
    this.writableHandles.push(handle);
    return new PassThrough();
  }
}

describe('native streaming binding ownership', () => {
  it('passes raw Windows handles directly to the stream factory', async () => {
    const native = new FakeNative();
    native.stdinHandle = 0x100000001n;
    native.stdoutHandle = 0x100000002n;
    native.stderrHandle = 0x100000003n;
    const streams = new FakeStreams('win32');

    const driver = _spawnStreamingDriverForTest(
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

  it('adopts each endpoint once with the correct direction', async () => {
    const native = new FakeNative();
    const streams = new FakeStreams();

    const driver = _spawnStreamingDriverForTest(
      {} as never,
      native,
      streams,
    );

    assert.strictEqual(driver.id, 23);
    assert.deepStrictEqual(streams.writableHandles, [11]);
    assert.deepStrictEqual(streams.readableHandles, [12, 13]);
    assert.deepStrictEqual(native.closedHandles, []);
    await driver.free();
    await driver.free();
    assert.strictEqual(native.freeCount, 1);
  });

  it('treats platform-specific missing endpoint sentinels as absent', async () => {
    const unixNative = new FakeNative();
    unixNative.stdinHandle = -1;
    unixNative.stderrHandle = -1n;
    const unixStreams = new FakeStreams();
    const unixDriver = _spawnStreamingDriverForTest(
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
    const windowsDriver = _spawnStreamingDriverForTest(
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
      () => _spawnStreamingDriverForTest({} as never, native, streams),
      /readable construction failed/,
    );

    assert.deepStrictEqual(native.closedHandles, [12, 13]);
    await new Promise((resolve) => setImmediate(resolve));
    assert.strictEqual(native.freeCount, 1);
  });

  it('frees native error detail when spawn fails', () => {
    const native = new FakeNative();
    native.spawnStatus = 12;

    assert.throws(
      () => _spawnStreamingDriverForTest(
        {} as never,
        native,
        new FakeStreams(),
      ),
      /native runtime failed/,
    );

    assert.strictEqual(native.freeErrorCount, 1);
    assert.strictEqual(native.freeCount, 0);
  });
});

describe('native streaming Node version support', () => {
  it('requires Node 24.21.0 or newer', () => {
    assert.strictEqual(_isSupportedNodeVersionForTest('24.20.9'), false);
    assert.strictEqual(_isSupportedNodeVersionForTest('24.21.0'), true);
    assert.strictEqual(_isSupportedNodeVersionForTest('24.21.1'), true);
    assert.strictEqual(_isSupportedNodeVersionForTest('25.0.0'), true);
    assert.strictEqual(_isSupportedNodeVersionForTest('23.99.99'), false);
  });
});
