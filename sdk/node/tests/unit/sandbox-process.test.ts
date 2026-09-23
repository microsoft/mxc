// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import assert from 'node:assert';
import { once } from 'node:events';
import { PassThrough } from 'node:stream';
import { describe, it } from 'node:test';
import {
  MxcSandboxProcess,
  type LifecycleScheduler,
  type NativeLifecycleDriver,
  type NativeLifecycleStatus,
} from '../../src/sandbox-process.js';

class FakeDriver implements NativeLifecycleDriver {
  readonly standardInput = new PassThrough();
  readonly standardOutput = new PassThrough();
  readonly standardError = new PassThrough();
  warningValues = ['initial warning'];
  metadata: unknown = undefined;
  status: NativeLifecycleStatus = {
    exitCode: 0,
    running: true,
    timedOut: false,
  };
  pollError: Error | undefined;
  timeoutKillError: Error | undefined;
  completeOnTimeoutKill: NativeLifecycleStatus | undefined;
  completeOnPoll: number | undefined;
  pollCount = 0;
  killCount = 0;
  timeoutKillCount = 0;
  waitCount = 0;
  warningsCount = 0;
  metadataCount = 0;
  freeCount = 0;
  deferWait = false;
  freeError: Error | undefined;
  waitInFlight = false;
  readonly serializedCallsDuringWait: string[] = [];
  private completeDeferredWait:
    | ((result: { exitCode: number; timedOut: boolean }) => void)
    | undefined;

  constructor(readonly id = 17) {}

  poll(): NativeLifecycleStatus {
    if (this.pollError !== undefined) throw this.pollError;
    this.pollCount += 1;
    if (this.pollCount === this.completeOnPoll) this.complete(23, false);
    return this.status;
  }

  async wait(): Promise<{ exitCode: number; timedOut: boolean }> {
    this.waitCount += 1;
    if (this.deferWait) {
      this.waitInFlight = true;
      return new Promise((resolve) => {
        this.completeDeferredWait = resolve;
      });
    }
    return {
      exitCode: this.status.exitCode,
      timedOut: this.status.timedOut,
    };
  }

  warnings(): readonly string[] {
    this.recordSerializedCall('warnings');
    this.warningsCount += 1;
    return this.warningValues;
  }

  outputMetadata(): unknown {
    this.recordSerializedCall('outputMetadata');
    this.metadataCount += 1;
    return this.metadata;
  }

  kill(): void {
    this.killCount += 1;
  }

  killForTimeout(): void {
    this.timeoutKillCount += 1;
    if (this.completeOnTimeoutKill !== undefined) {
      this.status = this.completeOnTimeoutKill;
    }
    if (this.timeoutKillError !== undefined) throw this.timeoutKillError;
  }

  async free(): Promise<void> {
    this.recordSerializedCall('free');
    this.freeCount += 1;
    if (this.freeError !== undefined) throw this.freeError;
  }

  complete(exitCode = 0, timedOut = false): void {
    this.status = { exitCode, running: false, timedOut };
  }

  resolveWait(exitCode = this.status.exitCode, timedOut = this.status.timedOut): void {
    this.waitInFlight = false;
    this.completeDeferredWait?.({ exitCode, timedOut });
    this.completeDeferredWait = undefined;
  }

  private recordSerializedCall(operation: string): void {
    if (this.waitInFlight) this.serializedCallsDuringWait.push(operation);
  }
}

class ManualScheduler implements LifecycleScheduler {
  private time = 0;
  private nextId = 1;
  private readonly tasks = new Map<number, {
    readonly due: number;
    readonly callback: () => void;
  }>();
  readonly scheduledDelays: number[] = [];

  now(): number {
    return this.time;
  }

  schedule(callback: () => void, delayMs: number): unknown {
    this.scheduledDelays.push(delayMs);
    const id = this.nextId++;
    this.tasks.set(id, { due: this.time + delayMs, callback });
    return id;
  }

  cancel(handle: unknown): void {
    this.tasks.delete(handle as number);
  }

  advance(delayMs: number): void {
    this.time += delayMs;
    const ready = [...this.tasks.entries()]
      .filter(([, task]) => task.due <= this.time)
      .sort((left, right) => left[1].due - right[1].due);
    for (const [id, task] of ready) {
      if (!this.tasks.delete(id)) continue;
      task.callback();
    }
  }
}

describe('native sandbox process', () => {
  it('exposes the transferred Node streams directly', async () => {
    const driver = new FakeDriver();
    const proc = new MxcSandboxProcess(driver);
    assert.strictEqual(proc.standardInput, driver.standardInput);
    assert.strictEqual(proc.standardOutput, driver.standardOutput);
    assert.strictEqual(proc.standardError, driver.standardError);

    const data = once(proc.standardOutput!, 'data');
    driver.standardOutput.write('native output');
    assert.strictEqual((await data)[0].toString(), 'native output');

    proc.dispose();
  });

  it('closes untaken stdin and drains untaken output while waiting', async () => {
    const driver = new FakeDriver();
    const proc = new MxcSandboxProcess(driver);
    const inputEnded = once(driver.standardInput, 'finish');
    const wait = proc.waitAsync();

    driver.standardOutput.end(Buffer.alloc(128 * 1024));
    driver.standardError.end(Buffer.alloc(128 * 1024));
    driver.complete(4);

    assert.deepStrictEqual(await wait, { exitCode: 4, timedOut: false });
    await inputEnded;
    assert.strictEqual(driver.standardOutput.readableFlowing, true);
    assert.strictEqual(driver.standardError.readableFlowing, true);
  });

  it('refreshes warnings and metadata after terminal completion', async () => {
    const driver = new FakeDriver();
    const proc = new MxcSandboxProcess(driver);
    assert.deepStrictEqual(proc.warnings, ['initial warning']);
    driver.warningValues = ['cleanup warning'];
    driver.metadata = { source: 'native' };
    driver.complete(9, true);

    assert.deepStrictEqual(await proc.waitAsync(), {
      exitCode: 9,
      timedOut: true,
    });
    assert.deepStrictEqual(proc.warnings, ['cleanup warning']);
    assert.deepStrictEqual(proc.outputMetadata, { source: 'native' });
    assert.strictEqual(driver.waitCount, 1);
    assert.strictEqual(driver.freeCount, 1);
  });

  it('does not reject successful completion for an expected stdin closure', async () => {
    const driver = new FakeDriver();
    const proc = new MxcSandboxProcess(driver);
    const error = Object.assign(new Error('write EPIPE'), { code: 'EPIPE' });

    driver.standardInput.emit('error', error);
    driver.complete(7);

    assert.deepStrictEqual(await proc.waitAsync(), {
      exitCode: 7,
      timedOut: false,
    });
  });

  it('accepts the Windows EOF code as an expected stdin closure', async () => {
    const driver = new FakeDriver();
    const proc = new MxcSandboxProcess(driver);
    const error = Object.assign(new Error('stdin reached EOF'), { code: 'EOF' });

    driver.standardInput.emit('error', error);
    driver.complete(7);

    assert.deepStrictEqual(await proc.waitAsync(), {
      exitCode: 7,
      timedOut: false,
    });
  });

  it('still rejects unexpected stdin failures', async () => {
    const driver = new FakeDriver();
    const proc = new MxcSandboxProcess(driver);
    const error = Object.assign(new Error('stdin failed'), { code: 'EIO' });

    driver.standardInput.emit('error', error);

    await assert.rejects(proc.waitAsync(), /stdin failed/);
  });

  it('does not destroy caller-owned output when the process exits', async () => {
    const driver = new FakeDriver();
    const proc = new MxcSandboxProcess(driver);
    const output = proc.standardOutput!;
    output.pause();
    driver.standardOutput.write('trailing output');
    driver.complete();

    await proc.waitAsync();

    assert.strictEqual(output.destroyed, false);
    assert.strictEqual(output.read()?.toString(), 'trailing output');
  });

  it('forwards kill while the process is running', () => {
    const driver = new FakeDriver();
    const proc = new MxcSandboxProcess(driver);

    proc.kill();

    assert.strictEqual(driver.killCount, 1);
    proc.dispose();
    assert.strictEqual(driver.killCount, 1);
  });

  it('rejects wait when lifecycle polling fails', async () => {
    const driver = new FakeDriver();
    const proc = new MxcSandboxProcess(driver);
    driver.pollError = new Error('poll failed');

    await assert.rejects(proc.waitAsync(), /poll failed/);
    assert.strictEqual(driver.waitCount, 0);
    assert.strictEqual(driver.freeCount, 1);
  });

  it('disposes streams and native lifecycle ownership exactly once', async () => {
    const driver = new FakeDriver();
    const proc = new MxcSandboxProcess(driver);
    const wait = proc.waitAsync();

    proc.dispose();
    proc.dispose();

    await assert.rejects(wait, /disposed before completion/);
    assert.strictEqual(driver.killCount, 1);
    assert.strictEqual(driver.freeCount, 1);
    assert.strictEqual(driver.standardInput.destroyed, true);
    assert.strictEqual(driver.standardOutput.destroyed, true);
    assert.strictEqual(driver.standardError.destroyed, true);
    assert.throws(() => proc.standardOutput, /disposed/);
  });

  it('reports asynchronous native cleanup failures during disposal', async () => {
    const driver = new FakeDriver();
    driver.freeError = new Error('native free callback failed');
    const reported: Error[] = [];
    const proc = new MxcSandboxProcess(
      driver,
      undefined,
      undefined,
      (error) => reported.push(error),
    );

    proc.dispose();
    await new Promise<void>((resolve) => setImmediate(resolve));

    assert.deepStrictEqual(
      reported.map((error) => error.message),
      ['native free callback failed'],
    );
  });

  it('polls lifecycle state at a fixed 100 ms interval', () => {
    const driver = new FakeDriver();
    const scheduler = new ManualScheduler();
    const proc = new MxcSandboxProcess(driver, undefined, scheduler);

    scheduler.advance(100);
    scheduler.advance(100);

    assert.deepStrictEqual(
      scheduler.scheduledDelays,
      [100, 100, 100],
    );
    proc.dispose();
  });

  it('schedules polling against an earlier timeout deadline', async () => {
    const driver = new FakeDriver();
    const scheduler = new ManualScheduler();
    const proc = new MxcSandboxProcess(driver, 35, scheduler);
    const wait = proc.waitAsync();

    assert.deepStrictEqual(scheduler.scheduledDelays, [35]);
    scheduler.advance(35);

    assert.deepStrictEqual(await wait, { exitCode: 0, timedOut: true });
    assert.strictEqual(driver.timeoutKillCount, 1);
  });

  it('enforces the request timeout and reports a timed-out result', async () => {
    const driver = new FakeDriver();
    const scheduler = new ManualScheduler();
    const proc = new MxcSandboxProcess(driver, 1, scheduler);

    const wait = proc.waitAsync();
    scheduler.advance(100);
    const result = await wait;

    assert.deepStrictEqual(result, { exitCode: 0, timedOut: true });
    assert.strictEqual(driver.killCount, 0);
    assert.strictEqual(driver.timeoutKillCount, 1);
    assert.strictEqual(driver.waitCount, 1);
  });

  it('observes an exit racing the timeout before killing', async () => {
    const driver = new FakeDriver();
    driver.completeOnPoll = 3;
    const scheduler = new ManualScheduler();
    const proc = new MxcSandboxProcess(driver, 1, scheduler);

    const wait = proc.waitAsync();
    scheduler.advance(100);
    const result = await wait;

    assert.deepStrictEqual(result, { exitCode: 23, timedOut: false });
    assert.strictEqual(driver.killCount, 0);
    assert.strictEqual(driver.timeoutKillCount, 0);
    assert.strictEqual(driver.waitCount, 1);
  });

  it('reaps a timeout exit that races a failed timeout kill', async () => {
    const driver = new FakeDriver();
    driver.timeoutKillError = new Error('process already exited');
    driver.completeOnTimeoutKill = {
      exitCode: -1,
      running: false,
      timedOut: true,
    };
    const scheduler = new ManualScheduler();
    const proc = new MxcSandboxProcess(driver, 1, scheduler);

    const wait = proc.waitAsync();
    scheduler.advance(100);
    const result = await wait;

    assert.deepStrictEqual(result, { exitCode: -1, timedOut: true });
    assert.strictEqual(driver.timeoutKillCount, 1);
    assert.strictEqual(driver.waitCount, 1);
  });

  it('does not issue control calls after terminal wait starts', async () => {
    const driver = new FakeDriver();
    driver.deferWait = true;
    const scheduler = new ManualScheduler();
    const proc = new MxcSandboxProcess(driver, undefined, scheduler);
    const wait = proc.waitAsync();
    driver.complete(5);

    scheduler.advance(100);
    assert.strictEqual(driver.waitCount, 1);
    proc.kill();

    assert.strictEqual(driver.killCount, 0);
    driver.resolveWait(5, false);
    assert.deepStrictEqual(await wait, { exitCode: 5, timedOut: false });
  });

  it('keeps stream failures during terminal wait separate from process completion', async () => {
    const driver = new FakeDriver();
    driver.deferWait = true;
    const scheduler = new ManualScheduler();
    const proc = new MxcSandboxProcess(driver, undefined, scheduler);
    const wait = proc.waitAsync();
    driver.complete(5);

    scheduler.advance(100);
    assert.strictEqual(driver.waitCount, 1);
    driver.standardOutput.emit('error', new Error('stdout failed'));

    assert.strictEqual(
      driver.warningsCount,
      1,
      'terminal getters must not overlap the in-flight native wait',
    );
    assert.deepStrictEqual(driver.serializedCallsDuringWait, []);
    driver.resolveWait(5, false);

    assert.deepStrictEqual(await wait, { exitCode: 5, timedOut: false });
    assert.strictEqual(driver.warningsCount, 2);
    assert.strictEqual(driver.metadataCount, 1);
    assert.strictEqual(driver.freeCount, 1);
    assert.deepStrictEqual(driver.serializedCallsDuringWait, []);
  });
});
