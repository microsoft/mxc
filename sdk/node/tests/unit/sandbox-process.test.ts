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
  closeStdinAttempts = 0;
  closeStdinFailures = 0;
  closeOutputAttempts = 0;
  killed = false;
  shutdownCalled = false;
  shutdownAttempts = 0;
  shutdownFailures = 0;
  abortCalled = false;
  stdoutChunks: (Buffer | null)[] = [Buffer.from('out'), null];
  stderrChunks: (Buffer | null)[] = [Buffer.from('err'), null];
  outputDelayMs = 0;
  requestReadFailures = 0;
  closeOutputFailures = 0;
  writeBackpressureAttempts = 0;
  writeAttempts = 0;
  writeSucceeded = true;
  maxWriteCompletion?: number;
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
    if (this.requestReadFailures > 0) {
      this.requestReadFailures -= 1;
      throw new Error(`requesting ${stream} failed`);
    }
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
    this.writeAttempts += 1;
    if (this.writeBackpressureAttempts > 0) {
      this.writeBackpressureAttempts -= 1;
      return 0;
    }
    const written = Math.min(
      buffer.length,
      this.maxWriteCompletion ?? buffer.length,
    );
    this.writes.push(buffer.subarray(0, written).toString('utf8'));
    return this.completeStdin(written);
  }

  startFlush(): number {
    return this.completeStdin(0);
  }

  closeStdin(): void {
    this.closeStdinAttempts += 1;
    if (this.closeStdinFailures > 0) {
      this.closeStdinFailures -= 1;
      throw new Error('closing stdin failed');
    }
    this.stdinClosed = true;
  }

  closeOutput(stream: 'stdout' | 'stderr'): void {
    this.closeOutputAttempts += 1;
    if (this.closeOutputFailures > 0) {
      this.closeOutputFailures -= 1;
      throw new Error(`closing ${stream} failed`);
    }
    this.closedOutputs.push(stream);
  }

  kill(): void {
    this.killed = true;
  }

  shutdown(): void {
    this.shutdownAttempts += 1;
    if (this.shutdownFailures > 0) {
      this.shutdownFailures -= 1;
      throw new Error('shutdown request failed');
    }
    this.shutdownCalled = true;
  }

  abort(): void {
    this.abortCalled = true;
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
      succeeded: this.writeSucceeded,
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
    assert.strictEqual(proc.standardInput?.writableEnded, true);
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

  it('continues partial native writes without duplicating bytes', async () => {
    const driver = new FakeDriver();
    driver.maxWriteCompletion = 3;
    const proc = _createMxcSandboxProcess(driver);
    const input = 'partial-native-completion';
    proc.standardInput!.end(input);

    await once(proc.standardInput!, 'finish');

    assert.strictEqual(driver.writes.join(''), input);
    assert.strictEqual(driver.writeAttempts, Math.ceil(input.length / 3));
    proc.dispose();
  });

  it('retries writes when the native queue applies backpressure', async () => {
    const driver = new FakeDriver();
    driver.writeBackpressureAttempts = 2;
    const proc = _createMxcSandboxProcess(driver);
    proc.standardInput!.end('retry');

    await once(proc.standardInput!, 'finish');

    assert.strictEqual(driver.writeAttempts, 3);
    assert.deepStrictEqual(driver.writes, ['retry']);
    proc.dispose();
  });

  it('stops retrying a backpressured write when the process exits', async () => {
    const driver = new FakeDriver();
    driver.writeBackpressureAttempts = Number.MAX_SAFE_INTEGER;
    const proc = _createMxcSandboxProcess(driver);
    const input = proc.standardInput!;
    const write = new Promise<Error | null | undefined>((resolve) => {
      input.write('blocked', resolve);
    });
    await new Promise((resolve) => setImmediate(resolve));

    driver.exit();

    assert.match((await write)?.message ?? '', /process exited/);
    const attemptsAfterExit = driver.writeAttempts;
    await new Promise((resolve) => setTimeout(resolve, 50));
    assert.strictEqual(driver.writeAttempts, attemptsAfterExit);
    await proc.waitAsync();
  });

  it('surfaces a failed native write completion', async () => {
    const driver = new FakeDriver();
    driver.writeSucceeded = false;
    const proc = _createMxcSandboxProcess(driver);
    const input = proc.standardInput!;

    await assert.rejects(
      new Promise<void>((resolve, reject) => {
        input.write('rejected', (error) => {
          if (error) reject(error);
          else resolve();
        });
      }),
      /stdin operation failed/,
    );
    proc.dispose();
  });

  it('surfaces a close failure after flushing stdin', async () => {
    const driver = new FakeDriver();
    driver.closeStdinFailures = 1;
    const proc = _createMxcSandboxProcess(driver);
    const input = proc.standardInput!;
    const finish = once(input, 'finish');

    input.end();
    await assert.rejects(finish, /closing stdin failed/);
    await new Promise((resolve) => setImmediate(resolve));
    assert.strictEqual(driver.closeStdinAttempts, 2);
    assert.strictEqual(driver.stdinClosed, true);
    proc.dispose();
  });

  it('fails the process when direct stdin destruction cannot close native stdin', async () => {
    const driver = new FakeDriver();
    driver.closeStdinFailures = 1;
    const proc = _createMxcSandboxProcess(driver);
    const input = proc.standardInput!;
    const closed = new Promise<void>((resolve) => {
      input.once('close', resolve);
    });

    input.destroy();
    await closed;

    await assert.rejects(proc.waitAsync(), /closing stdin failed/);
    assert.strictEqual(driver.shutdownCalled, true);
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

  it('finalizes an exited process even when wait is not called', async () => {
    const driver = new FakeDriver();
    const proc = _createMxcSandboxProcess(driver);

    driver.exit();
    for (let attempt = 0; attempt < 10 && !driver.shutdownCalled; attempt += 1) {
      await new Promise((resolve) => setImmediate(resolve));
    }

    assert.strictEqual(driver.shutdownCalled, true);
    assert.strictEqual(driver.stdinClosed, true);
    assert.throws(() => proc.standardOutput, /drained internally by waitAsync/);
    assert.deepStrictEqual(
      await proc.waitAsync(),
      { exitCode: 7, timedOut: false },
    );
  });

  it('rejects wait when an internal output read fails', async () => {
    const driver = new FakeDriver();
    driver.requestReadFailures = 1;
    const proc = _createMxcSandboxProcess(driver);

    const wait = proc.waitAsync();
    driver.exit();

    await assert.rejects(wait, /requesting stdout failed/);
    assert.strictEqual(driver.shutdownCalled, true);
  });

  it('rejects wait when closing an internally drained output fails', async () => {
    const driver = new FakeDriver();
    driver.stdoutChunks = [];
    driver.closeOutputFailures = 1;
    const proc = _createMxcSandboxProcess(driver);

    const wait = proc.waitAsync();
    driver.exit();

    await assert.rejects(wait, /closing stdout failed/);
    assert.strictEqual(driver.shutdownCalled, true);
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
    const wait = proc.waitAsync();
    driver.exit();

    assert.deepStrictEqual(await wait, { exitCode: 7, timedOut: false });
    assert.ok(driver.closedOutputs.includes('stdout'));
  });

  it('does not truncate caller-owned output while the consumer is paused', async () => {
    const driver = new FakeDriver();
    const proc = _createMxcSandboxProcess(driver);
    const output = proc.standardOutput!;
    let completed = false;
    const wait = proc.waitAsync().then((result) => {
      completed = true;
      return result;
    });
    driver.exit();

    await new Promise((resolve) => setTimeout(resolve, 300));
    assert.strictEqual(completed, false);
    assert.ok(!driver.closedOutputs.includes('stdout'));

    let observed = '';
    output.on('data', (chunk) => {
      observed += chunk.toString();
    });
    output.resume();

    assert.deepStrictEqual(await wait, { exitCode: 7, timedOut: false });
    assert.strictEqual(observed, 'out');
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
  });

  it('preserves caller-buffered output after wait completes', async () => {
    const driver = new FakeDriver();
    const proc = _createMxcSandboxProcess(driver);
    const output = proc.standardOutput!;
    output.on('readable', () => {});
    const wait = proc.waitAsync();
    driver.exit();

    await wait;

    assert.strictEqual(output.destroyed, false);
    const ended = once(output, 'end');
    assert.strictEqual(output.read()?.toString(), 'out');
    await ended;
    assert.ok(!driver.closedOutputs.includes('stdout'));
  });

  it('lets the caller close owned output when native EOF never arrives', async () => {
    const driver = new FakeDriver();
    driver.stdoutChunks = [Buffer.from('partial')];
    const proc = _createMxcSandboxProcess(driver);
    const output = proc.standardOutput!;
    output.on('readable', () => {});
    const wait = proc.waitAsync();
    driver.exit();

    await new Promise((resolve) => setImmediate(resolve));

    assert.strictEqual(output.destroyed, false);
    assert.strictEqual(output.read()?.toString(), 'partial');
    output.destroy();
    await wait;
    assert.ok(driver.closedOutputs.includes('stdout'));
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

  it('ignores a late exit after a native failure aborts the handle', async () => {
    const driver = new FakeDriver();
    driver.shutdownFailures = 1;
    const proc = _createMxcSandboxProcess(driver);
    const wait = proc.waitAsync();

    driver.fail(new Error('native failure'));
    await assert.rejects(wait, /native failure/);
    assert.strictEqual(driver.abortCalled, true);
    const closeStdinAttempts = driver.closeStdinAttempts;

    driver.exit();

    assert.strictEqual(driver.closeStdinAttempts, closeStdinAttempts);
  });

  it('rejects wait and shuts down when closing untaken stdin fails', async () => {
    const driver = new FakeDriver();
    driver.closeStdinFailures = 1;
    const proc = _createMxcSandboxProcess(driver);

    const wait = proc.waitAsync();

    await assert.rejects(wait, /closing stdin failed/);
    assert.strictEqual(driver.shutdownCalled, true);
  });

  it('runs cleanup registered after a native error immediately', () => {
    const driver = new FakeDriver();
    const proc = _createMxcSandboxProcess(driver);
    let cleaned = false;

    driver.fail(new Error('native failure'));
    proc._registerCleanup(() => {
      cleaned = true;
    });

    assert.strictEqual(cleaned, true);
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

  it('runs cleanup registered during terminal cleanup', async () => {
    const driver = new FakeDriver();
    const proc = _createMxcSandboxProcess(driver);
    let nestedCleanupRan = false;
    proc._registerCleanup(() => {
      proc._registerCleanup(() => {
        nestedCleanupRan = true;
      });
    });
    const wait = proc.waitAsync();
    driver.exit();

    await wait;

    assert.strictEqual(nestedCleanupRan, true);
  });

  it('runs every cleanup and rejects wait when cleanup fails', async () => {
    const driver = new FakeDriver();
    const proc = _createMxcSandboxProcess(driver);
    let secondCleanupRan = false;
    proc._registerCleanup(() => {
      throw new Error('cleanup failed');
    });
    proc._registerCleanup(() => {
      secondCleanupRan = true;
    });
    const wait = proc.waitAsync();

    driver.exit();

    await assert.rejects(wait, /cleanup failed/);
    assert.strictEqual(secondCleanupRan, true);
    assert.strictEqual(driver.shutdownCalled, true);
  });

  it('preserves a native failure when cleanup also fails', async () => {
    const driver = new FakeDriver();
    const proc = _createMxcSandboxProcess(driver);
    let secondCleanupRan = false;
    proc._registerCleanup(() => {
      throw new Error('cleanup failed');
    });
    proc._registerCleanup(() => {
      secondCleanupRan = true;
    });
    const wait = proc.waitAsync();

    driver.fail(new Error('native failure'));

    await assert.rejects(wait, /native failure/);
    assert.strictEqual(secondCleanupRan, true);
    assert.strictEqual(driver.shutdownCalled, true);
  });

  it('retries shutdown once before surfacing its failure', async () => {
    const driver = new FakeDriver();
    driver.shutdownFailures = 1;
    const proc = _createMxcSandboxProcess(driver);
    const wait = proc.waitAsync();

    driver.exit();

    await assert.rejects(wait, /shutdown request failed/);
    assert.strictEqual(driver.shutdownAttempts, 2);
    assert.strictEqual(driver.shutdownCalled, true);
  });

  it('shuts down before dispose surfaces a cleanup failure', () => {
    const driver = new FakeDriver();
    const proc = _createMxcSandboxProcess(driver);
    proc._registerCleanup(() => {
      throw new Error('cleanup failed');
    });

    assert.throws(() => proc.dispose(), /cleanup failed/);
    assert.strictEqual(driver.shutdownCalled, true);
    assert.doesNotThrow(() => proc.dispose());
  });

  it('aborts when dispose cannot request shutdown', () => {
    const driver = new FakeDriver();
    driver.shutdownFailures = 1;
    const proc = _createMxcSandboxProcess(driver);

    assert.throws(() => proc.dispose(), /shutdown request failed/);
    assert.strictEqual(driver.abortCalled, true);
    assert.doesNotThrow(() => proc.dispose());
  });

  it('surfaces native stdin close failures during disposal', () => {
    const driver = new FakeDriver();
    driver.closeStdinFailures = 1;
    const proc = _createMxcSandboxProcess(driver);
    void proc.standardInput;

    assert.throws(() => proc.dispose(), /closing stdin failed/);
    assert.strictEqual(driver.closeStdinAttempts, 2);
    assert.strictEqual(driver.stdinClosed, true);
    assert.strictEqual(driver.shutdownCalled, true);
  });

  it('surfaces native output close failures during disposal', () => {
    const driver = new FakeDriver();
    driver.closeOutputFailures = 1;
    const proc = _createMxcSandboxProcess(driver);
    void proc.standardOutput;

    assert.throws(() => proc.dispose(), /closing stdout failed/);
    assert.strictEqual(driver.closeOutputAttempts, 2);
    assert.deepStrictEqual(driver.closedOutputs, ['stdout']);
    assert.strictEqual(driver.shutdownCalled, true);
  });

  it('ignores late native errors after dispose aborts the handle', () => {
    const driver = new FakeDriver();
    driver.shutdownFailures = 1;
    const proc = _createMxcSandboxProcess(driver);

    assert.throws(() => proc.dispose(), /shutdown request failed/);
    driver.fail(new Error('late native failure'));

    assert.strictEqual(driver.shutdownAttempts, 1);
    assert.strictEqual(driver.abortCalled, true);
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

  it('aborts the driver when initial warning retrieval and shutdown fail', () => {
    const driver = new FakeDriver();
    driver.warnings = () => {
      throw new Error('warning retrieval failed');
    };
    driver.shutdownFailures = 1;

    assert.throws(
      () => _createMxcSandboxProcess(driver),
      /warning retrieval failed/,
    );
    assert.strictEqual(driver.shutdownAttempts, 1);
    assert.strictEqual(driver.abortCalled, true);
  });
});
