// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import assert from 'node:assert';
import { once } from 'node:events';
import { PassThrough } from 'node:stream';
import { describe, it } from 'node:test';
import {
  _createMxcSandboxProcess,
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
  killCount = 0;
  shutdownCount = 0;
  freeCount = 0;

  constructor(readonly id = 17) {}

  poll(): NativeLifecycleStatus {
    if (this.pollError !== undefined) throw this.pollError;
    return this.status;
  }

  warnings(): readonly string[] {
    return this.warningValues;
  }

  outputMetadata(): unknown {
    return this.metadata;
  }

  kill(): void {
    this.killCount += 1;
  }

  shutdown(): void {
    this.shutdownCount += 1;
  }

  async free(): Promise<void> {
    this.freeCount += 1;
  }

  complete(exitCode = 0, timedOut = false): void {
    this.status = { exitCode, running: false, timedOut };
  }
}

describe('native sandbox process', () => {
  it('exposes the transferred Node streams directly', async () => {
    const driver = new FakeDriver();
    const proc = _createMxcSandboxProcess(driver);
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
    const proc = _createMxcSandboxProcess(driver);
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
    const proc = _createMxcSandboxProcess(driver);
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
    assert.strictEqual(driver.shutdownCount, 1);
    assert.strictEqual(driver.freeCount, 1);
  });

  it('does not destroy caller-owned output when the process exits', async () => {
    const driver = new FakeDriver();
    const proc = _createMxcSandboxProcess(driver);
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
    const proc = _createMxcSandboxProcess(driver);

    proc.kill();

    assert.strictEqual(driver.killCount, 1);
    proc.dispose();
  });

  it('rejects wait when lifecycle polling fails', async () => {
    const driver = new FakeDriver();
    const proc = _createMxcSandboxProcess(driver);
    driver.pollError = new Error('poll failed');

    await assert.rejects(proc.waitAsync(), /poll failed/);
    assert.strictEqual(driver.shutdownCount, 1);
    assert.strictEqual(driver.freeCount, 1);
  });

  it('runs all registered cleanup and preserves the first failure', async () => {
    const driver = new FakeDriver();
    const proc = _createMxcSandboxProcess(driver);
    let secondRan = false;
    proc._registerCleanup(() => {
      throw new Error('cleanup failed');
    });
    proc._registerCleanup(() => {
      secondRan = true;
    });
    driver.complete();

    await assert.rejects(proc.waitAsync(), /cleanup failed/);
    assert.strictEqual(secondRan, true);
  });

  it('disposes streams and native lifecycle ownership exactly once', async () => {
    const driver = new FakeDriver();
    const proc = _createMxcSandboxProcess(driver);
    const wait = proc.waitAsync();

    proc.dispose();
    proc.dispose();

    await assert.rejects(wait, /disposed before completion/);
    assert.strictEqual(driver.shutdownCount, 1);
    assert.strictEqual(driver.freeCount, 1);
    assert.strictEqual(driver.standardInput.destroyed, true);
    assert.strictEqual(driver.standardOutput.destroyed, true);
    assert.strictEqual(driver.standardError.destroyed, true);
    assert.throws(() => proc.standardOutput, /disposed/);
  });
});
