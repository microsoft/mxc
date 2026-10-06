// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import assert from 'node:assert';
import { PassThrough, type Readable, type Writable } from 'node:stream';
import { describe, it } from 'node:test';
import {
  createPty,
  type PtyNativeFacade,
} from '../../src/bindings/pty.js';
import type { LifecycleNativeFacade } from '../../src/bindings/streaming.js';
import type {
  NativeHandle,
  NativeStdioHandles,
  NativeStreamFactory,
} from '../../src/bindings/native-stdio.js';

class FakePtyNative implements PtyNativeFacade, LifecycleNativeFacade {
  readonly handle = {};
  spawnRows = 0;
  spawnColumns = 0;
  resizedRows = 0;
  resizedColumns = 0;
  killed = false;
  freed = false;

  spawnPty(
    _request: string,
    _experimental: number,
    rows: number,
    columns: number,
    outHandle: unknown[],
    _error: unknown,
    completion: (error: Error | null, status: number) => void,
  ): void {
    this.spawnRows = rows;
    this.spawnColumns = columns;
    outHandle[0] = this.handle;
    queueMicrotask(() => completion(null, 0));
  }

  execPty(
    _request: string,
    _experimental: number,
    rows: number,
    columns: number,
    outHandle: unknown[],
    _error: unknown,
    completion: (error: Error | null, status: number) => void,
  ): void {
    this.spawnPty('', 0, rows, columns, outHandle, _error, completion);
  }

  id(): number {
    return 42;
  }

  takeNativeStdio(_handle: unknown, stdio: NativeStdioHandles): number {
    stdio.stdin_handle = 11;
    stdio.stdout_handle = 12;
    stdio.stderr_handle = -1;
    return 0;
  }

  closeNativePipe(): void {}

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

  wait(): void {
    throw new Error('wait should not run in this test');
  }

  kill(): number {
    this.killed = true;
    return 0;
  }

  killForTimeout(): number {
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

  free(
    _handle: unknown,
    completion: (error: Error | null) => void,
  ): void {
    this.freed = true;
    queueMicrotask(() => completion(null));
  }

  freeError(): void {}
  freeString(): void {}

  resize(_handle: unknown, rows: number, columns: number): number {
    this.resizedRows = rows;
    this.resizedColumns = columns;
    return 0;
  }

}

class FakeStreams implements NativeStreamFactory {
  readonly platform: NodeJS.Platform = 'linux';
  readonly input = new PassThrough();
  readonly output = new PassThrough();

  readable(handle: NativeHandle): Readable {
    assert.strictEqual(handle, 12);
    return this.output;
  }

  writable(handle: NativeHandle): Writable {
    assert.strictEqual(handle, 11);
    return this.input;
  }
}

describe('PTY native binding', () => {
  it('creates merged terminal streams and forwards resize', async () => {
    const native = new FakePtyNative();
    const streams = new FakeStreams();
    const terminal = await createPty(
      {
        version: '1.0.0',
        process: { commandLine: 'cmd' },
        containment: 'process',
      },
      false,
      30,
      100,
      native,
      native,
      streams,
    );

    assert.strictEqual(terminal.id, 42);
    assert.strictEqual(terminal.input, streams.input);
    assert.strictEqual(terminal.output, streams.output);
    assert.strictEqual(terminal.standardError, null);
    assert.strictEqual(native.spawnRows, 30);
    assert.strictEqual(native.spawnColumns, 100);

    terminal.resize({ rows: 40, columns: 120 });
    assert.strictEqual(native.resizedRows, 40);
    assert.strictEqual(native.resizedColumns, 120);

    terminal.dispose();
    assert.throws(
      () => terminal.resize({ rows: 50, columns: 130 }),
      /disposed/,
    );
    assert.strictEqual(native.resizedRows, 40);
    assert.strictEqual(native.resizedColumns, 120);
    await new Promise((resolve) => setImmediate(resolve));
    assert.strictEqual(native.killed, true);
    assert.strictEqual(native.freed, true);
  });
});
