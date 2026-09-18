// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import assert from 'node:assert';
import { once } from 'node:events';
import { describe, it } from 'node:test';
import {
  _createMxcSandboxProcess,
  type NativeStreamingDriver,
  type NativeStreamingEvent,
} from '../../src/sandbox-process.js';

class FakeDriver implements NativeStreamingDriver {
  readonly writes: string[] = [];
  readonly closedOutputs: string[] = [];
  warningValues = ['relaxed'];
  metadata: unknown = { tag: 'done' };
  stdinClosed = false;
  killed = false;
  shutdownCalled = false;
  stdoutChunks: (Buffer | null)[] = [Buffer.from('out'), null];
  stderrChunks: (Buffer | null)[] = [Buffer.from('err'), null];
  outputDelayMs = 0;
  private handler?: (event: NativeStreamingEvent) => void;
  private nextOperation = 1;

  constructor(
    readonly id = 7,
    readonly hasStdin = true,
    readonly hasStdout = true,
    readonly hasStderr = true,
  ) {}

  setEventHandler(handler: (event: NativeStreamingEvent) => void): void {
    this.handler = handler;
  }

  warnings(): readonly string[] {
    return this.warningValues;
  }

  outputMetadata(): unknown {
    return this.metadata;
  }

  requestRead(stream: 'stdout' | 'stderr'): void {
    const chunks = stream === 'stdout' ? this.stdoutChunks : this.stderrChunks;
    const chunk = chunks.shift();
    if (chunk === undefined) return;
    const deliver = () => {
      this.emit(chunk === null
        ? { type: `${stream}-eof` }
        : { type: stream, data: chunk } as NativeStreamingEvent);
    };
    if (this.outputDelayMs === 0) queueMicrotask(deliver);
    else setTimeout(deliver, this.outputDelayMs);
  }

  startWrite(buffer: Buffer): number {
    this.writes.push(buffer.toString('utf8'));
    return this.completeStdin(buffer.length);
  }

  startFlush(): number {
    return this.completeStdin(0);
  }

  closeStdin(): void {
    this.stdinClosed = true;
  }

  closeOutput(stream: 'stdout' | 'stderr'): void {
    this.closedOutputs.push(stream);
  }

  kill(): void {
    this.killed = true;
  }

  shutdown(): void {
    this.shutdownCalled = true;
  }

  exit(result = { exitCode: 7, timedOut: false }): void {
    this.emit({ type: 'exit', result });
  }

  fail(error: Error): void {
    this.emit({ type: 'error', error });
  }

  private completeStdin(written: number): number {
    const operation = this.nextOperation++;
    queueMicrotask(() => this.emit({
      type: 'stdin-complete',
      operation,
      written,
      succeeded: true,
    }));
    return operation;
  }

  private emit(event: NativeStreamingEvent): void {
    this.handler?.(event);
  }
}

describe('native streaming process', () => {
  it('surfaces callback output as a Node readable stream', async () => {
    const driver = new FakeDriver();
    const proc = _createMxcSandboxProcess(driver);
    const chunks: Buffer[] = [];
    proc.standardOutput!.on('data', (chunk) => chunks.push(Buffer.from(chunk)));

    await once(proc.standardOutput!, 'end');

    assert.strictEqual(Buffer.concat(chunks).toString('utf8'), 'out');
    proc.dispose();
  });

  it('writes stdin and exposes terminal metadata after exit', async () => {
    const driver = new FakeDriver();
    const proc = _createMxcSandboxProcess(driver);
    proc.standardInput!.end('hello');
    await once(proc.standardInput!, 'finish');
    const wait = proc.waitAsync();
    driver.exit();

    assert.deepStrictEqual(await wait, { exitCode: 7, timedOut: false });
    assert.deepStrictEqual(driver.writes, ['hello']);
    assert.strictEqual(driver.stdinClosed, true);
    assert.deepStrictEqual(proc.outputMetadata, { tag: 'done' });
    assert.strictEqual(driver.shutdownCalled, true);
  });

  it('writes every byte of a chunk larger than the native queue limit', async () => {
    const driver = new FakeDriver();
    const proc = _createMxcSandboxProcess(driver);
    const input = Buffer.alloc(100_000, 'x');
    proc.standardInput!.end(input);

    await once(proc.standardInput!, 'finish');

    assert.strictEqual(driver.writes.join('').length, input.length);
    proc.dispose();
  });

  it('refreshes warnings after terminal completion', async () => {
    const driver = new FakeDriver();
    const proc = _createMxcSandboxProcess(driver);
    assert.deepStrictEqual(proc.warnings, ['relaxed']);
    driver.warningValues = ['relaxed', 'cleanup warning'];
    const wait = proc.waitAsync();
    driver.exit();

    await wait;

    assert.deepStrictEqual(proc.warnings, ['relaxed', 'cleanup warning']);
  });

  it('drains untaken output while waiting', async () => {
    const driver = new FakeDriver();
    const proc = _createMxcSandboxProcess(driver);
    const wait = proc.waitAsync();
    driver.exit();

    await wait;

    assert.throws(() => proc.standardOutput, /drained internally by wait/);
    assert.strictEqual(driver.stdinClosed, true);
  });

  it('waits for trailing output after the exit event', async () => {
    const driver = new FakeDriver();
    driver.stdoutChunks = [];
    const proc = _createMxcSandboxProcess(driver);
    let output = '';
    proc.standardOutput!.on('data', (chunk) => {
      output += chunk.toString();
    });
    const wait = proc.waitAsync();
    driver.exit();
    await new Promise((resolve) => setImmediate(resolve));

    driver.stdoutChunks.push(Buffer.from('trailing'), null);
    driver.requestRead('stdout');

    assert.deepStrictEqual(await wait, { exitCode: 7, timedOut: false });
    assert.strictEqual(output, 'trailing');
  });

  it('bounds output draining when EOF never arrives', async () => {
    const driver = new FakeDriver();
    driver.stdoutChunks = [];
    const proc = _createMxcSandboxProcess(driver);
    proc.standardOutput!.resume();
    const wait = proc.waitAsync();
    driver.exit();

    assert.deepStrictEqual(await wait, { exitCode: 7, timedOut: false });
    assert.ok(driver.closedOutputs.includes('stdout'));
  });

  it('resets the drain grace period while output remains active', async () => {
    const driver = new FakeDriver();
    driver.outputDelayMs = 20;
    driver.stdoutChunks = [
      ...Array.from({ length: 20 }, () => Buffer.alloc(1024, 'x')),
      null,
    ];
    const proc = _createMxcSandboxProcess(driver);
    let bytes = 0;
    proc.standardOutput!.on('data', (chunk) => {
      bytes += chunk.length;
    });
    const wait = proc.waitAsync();
    driver.exit();

    await wait;
    assert.strictEqual(bytes, 20 * 1024);
    assert.strictEqual(bytes, 20 * 1024);
  });

  it('kills through the native driver', () => {
    const driver = new FakeDriver();
    const proc = _createMxcSandboxProcess(driver);

    proc.kill();

    assert.strictEqual(driver.killed, true);
    proc.dispose();
  });

  it('rejects wait and closes streams after a native error', async () => {
    const driver = new FakeDriver();
    const proc = _createMxcSandboxProcess(driver);
    const wait = proc.waitAsync();

    driver.fail(new Error('native failure'));

    await assert.rejects(wait, /native failure/);
    assert.strictEqual(driver.shutdownCalled, true);
  });

  it('does not overwrite a terminal error with a racing exit result', async () => {
    const driver = new FakeDriver();
    driver.stdoutChunks = [];
    const proc = _createMxcSandboxProcess(driver);
    proc.standardOutput!.resume();
    const wait = proc.waitAsync();
    driver.exit({ exitCode: 9, timedOut: false });
    driver.fail(new Error('late output failure'));

    await assert.rejects(wait, /late output failure/);
    await assert.rejects(proc.waitAsync(), /late output failure/);
    assert.strictEqual(proc.outputMetadata, undefined);
  });

  it('rejects stream acquisition after disposal', () => {
    const proc = _createMxcSandboxProcess(new FakeDriver());
    proc.dispose();

    assert.throws(() => proc.standardInput, /disposed/);
    assert.throws(() => proc.standardOutput, /disposed/);
    assert.throws(() => proc.standardError, /disposed/);
  });

  it('runs registered cleanup on terminal completion', async () => {
    const driver = new FakeDriver();
    const proc = _createMxcSandboxProcess(driver);
    let cleaned = false;
    proc._registerCleanup(() => {
      cleaned = true;
    });
    const wait = proc.waitAsync();
    driver.exit();

    await wait;

    assert.strictEqual(cleaned, true);
  });

  it('shuts down the driver when initial warning retrieval fails', () => {
    const driver = new FakeDriver();
    driver.warnings = () => {
      throw new Error('warning retrieval failed');
    };

    assert.throws(
      () => _createMxcSandboxProcess(driver),
      /warning retrieval failed/,
    );
    assert.strictEqual(driver.shutdownCalled, true);
  });
});
