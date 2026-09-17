// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import assert from 'node:assert';
import { getEventListeners, once } from 'node:events';
import { afterEach, describe, it } from 'node:test';
import { spawnSandbox, spawnSandboxFromConfig } from '../../src/sandbox.js';
import {
  _createMxcSandboxProcess,
  type SandboxProcessBinding,
  type SandboxReadableBinding,
  type SandboxWritableBinding,
} from '../../src/sandbox-process.js';
import { _setBindingSandboxProcessFactory } from '../../src/bindings/streaming.js';
import type { RequestSpec } from '../../src/bindings/request.js';

class FakeReadable implements SandboxReadableBinding {
  constructor(private readonly chunks: (Buffer | null)[], private readonly events: string[]) {}
  read(buffer: Buffer): Promise<number> {
    const next = this.chunks.shift() ?? null;
    if (next !== null) next.copy(buffer);
    return Promise.resolve(next === null ? 0 : next.length);
  }
  close(): void {
    this.events.push('close-read');
  }
  free(): void {
    this.events.push('free-read');
  }
}

class DeferredReadable implements SandboxReadableBinding {
  private releaseRead?: () => void;
  private delivered = false;

  read(buffer: Buffer): Promise<number> {
    if (this.delivered) return Promise.resolve(0);
    return new Promise((resolve) => {
      this.releaseRead = () => {
        this.delivered = true;
        const chunk = Buffer.from('trailing');
        chunk.copy(buffer);
        resolve(chunk.length);
      };
    });
  }

  release(): void {
    this.releaseRead?.();
  }

  close(): void {}
  free(): void {}
}

class CloseableBlockedReadable implements SandboxReadableBinding {
  closed = false;
  freed = false;
  private completeRead?: (count: number) => void;

  read(): Promise<number> {
    return new Promise((resolve) => {
      this.completeRead = resolve;
    });
  }

  close(): void {
    this.closed = true;
    this.completeRead?.(0);
  }

  free(): void {
    this.freed = true;
  }
}

class FakeWritable implements SandboxWritableBinding {
  readonly writes: string[] = [];
  flushed = false;
  freed = false;

  write(buffer: Buffer): Promise<number> {
    this.writes.push(buffer.toString('utf8'));
    return Promise.resolve(buffer.length);
  }
  flush(): Promise<void> {
    this.flushed = true;
    return Promise.resolve();
  }
  free(): void {
    this.freed = true;
  }
}

class DeferredPartialWritable extends FakeWritable {
  private resolveWrite?: (written: number) => void;

  override write(buffer: Buffer): Promise<number> {
    this.writes.push(buffer.toString('utf8'));
    return new Promise((resolve) => {
      this.resolveWrite = resolve;
    });
  }

  release(written: number): void {
    this.resolveWrite?.(written);
  }
}

class FakeBinding implements SandboxProcessBinding {
  warningValues = ['relaxed'];
  warningReads = 0;
  outputMetadataReads = 0;
  readonly stdoutEvents: string[] = [];
  readonly stderrEvents: string[] = [];
  stdin = new FakeWritable();
  stdout: SandboxReadableBinding = new FakeReadable([Buffer.from('out'), null], this.stdoutEvents);
  stderr: SandboxReadableBinding = new FakeReadable([Buffer.from('err'), null], this.stderrEvents);
  killed = false;
  freed = false;
  waitCalls = 0;
  polls = 0;

  constructor(
    readonly id: number,
    private readonly runningPolls: number,
    private readonly waitResult = { exitCode: 7, timedOut: false },
    private readonly metadata: unknown = { tag: 'done' },
  ) {}

  warnings(): readonly string[] {
    this.warningReads += 1;
    return this.warningValues;
  }
  takeStdin(): SandboxWritableBinding | null {
    return this.stdin;
  }
  takeStdout(): SandboxReadableBinding | null {
    return this.stdout;
  }
  takeStderr(): SandboxReadableBinding | null {
    return this.stderr;
  }
  tryWait() {
    this.polls += 1;
    return {
      running: this.polls <= this.runningPolls,
      exitCode: 0,
      timedOut: false,
    };
  }
  wait() {
    this.waitCalls += 1;
    return this.waitResult;
  }
  outputMetadata(): unknown {
    this.outputMetadataReads += 1;
    return this.metadata;
  }
  kill(): void {
    this.killed = true;
  }
  free(): void {
    this.freed = true;
  }
}

afterEach(() => _setBindingSandboxProcessFactory());

describe('native streaming spawn APIs', () => {
  it('routes the existing policy entry point through the binding request adapter', () => {
    let seen: RequestSpec | undefined;
    _setBindingSandboxProcessFactory((request) => {
      seen = request;
      return _createMxcSandboxProcess(new FakeBinding(42, 0));
    });

    const proc = spawnSandbox('echo hello', { version: '0.9.0-alpha' }, { experimental: true }, 'C:\\work', 'sample');

    assert.strictEqual(proc.id, 42);
    assert.deepStrictEqual(proc.warnings, ['relaxed']);
    assert.strictEqual(seen?.policy.version, '0.9.0-alpha');
    assert.strictEqual(seen?.command, 'echo hello');
    assert.deepStrictEqual(seen?.containment, { type: 'process' });
    assert.strictEqual(seen?.containerName, 'sample');
    assert.strictEqual(seen?.workingDirectory, 'C:\\work');
    assert.strictEqual(seen?.environment, undefined);
    assert.strictEqual(seen?.inheritDefaultEnv, false);
    assert.strictEqual(seen?.experimental, true);
    proc.dispose();
  });

  it('routes the existing config entry point through the binding request adapter', () => {
    let seen: RequestSpec | undefined;
    _setBindingSandboxProcessFactory((request) => {
      seen = request;
      return _createMxcSandboxProcess(new FakeBinding(43, 0));
    });

    const proc = spawnSandboxFromConfig({
      version: '0.9.0-alpha',
      containment: 'wslc',
      process: {
        commandLine: 'echo configured',
        env: ['FROM_CONFIG=value', 'OVERRIDE=old'],
      },
    }, {
      experimental: true,
      inheritDefaultEnv: true,
    }, 'C:\\work', {
      FROM_CALLER: 'yes',
      OVERRIDE: 'new',
    });

    assert.strictEqual(proc.id, 43);
    assert.strictEqual(seen?.command, 'echo configured');
    assert.strictEqual(seen?.containment.type, 'wslc');
    assert.strictEqual(seen?.workingDirectory, 'C:\\work');
    assert.deepStrictEqual(seen?.environment, {
      FROM_CONFIG: 'value',
      FROM_CALLER: 'yes',
      OVERRIDE: 'new',
    });
    assert.strictEqual(seen?.inheritDefaultEnv, true);
    proc.dispose();
  });

  it('surfaces stdout as a Node readable stream', async () => {
    const proc = _createMxcSandboxProcess(new FakeBinding(8, 0));
    const chunks: Buffer[] = [];
    proc.standardOutput!.on('data', (chunk) => chunks.push(Buffer.from(chunk)));
    await once(proc.standardOutput!, 'end');

    assert.strictEqual(Buffer.concat(chunks).toString('utf8'), 'out');
    proc.dispose();
  });

  it('writes to stdin and exposes terminal metadata after wait', async () => {
    const binding = new FakeBinding(9, 1);
    const proc = _createMxcSandboxProcess(binding);
    proc.standardInput!.end('hello');
    await once(proc.standardInput!, 'finish');

    assert.deepStrictEqual(binding.stdin.writes, ['hello']);
    assert.strictEqual(binding.stdin.flushed, true);
    assert.deepStrictEqual(await proc.waitAsync(), { exitCode: 7, timedOut: false });
    assert.deepStrictEqual(proc.outputMetadata, { tag: 'done' });
    assert.strictEqual(binding.freed, true);
  });

  it('refreshes warnings before releasing the terminal handle', async () => {
    const binding = new FakeBinding(12, 0);
    const proc = _createMxcSandboxProcess(binding);
    assert.deepStrictEqual(proc.warnings, ['relaxed']);
    binding.warningValues = ['relaxed', 'cleanup warning'];

    await proc.waitAsync();

    assert.deepStrictEqual(proc.warnings, ['relaxed', 'cleanup warning']);
    assert.strictEqual(binding.freed, true);
  });

  it('drains untaken output streams while waiting', async () => {
    const binding = new FakeBinding(5, 1);
    const proc = _createMxcSandboxProcess(binding);

    await proc.waitAsync();
    await new Promise((resolve) => setImmediate(resolve));

    assert.throws(() => proc.standardOutput, /drained internally by wait/);
    assert.ok(binding.stdoutEvents.includes('free-read'));
    assert.ok(binding.stderrEvents.includes('free-read'));
  });

  it('waits for an owned output stream to deliver its final chunk', async () => {
    const binding = new FakeBinding(16, 0);
    const deferred = new DeferredReadable();
    binding.stdout = deferred;
    const proc = _createMxcSandboxProcess(binding);
    let output = '';
    proc.standardOutput!.on('data', (chunk) => {
      output += chunk.toString();
    });
    let settled = false;
    const wait = proc.waitAsync().then((result) => {
      settled = true;
      return result;
    });

    await new Promise((resolve) => setImmediate(resolve));
    assert.strictEqual(settled, false);
    deferred.release();

    assert.deepStrictEqual(await wait, { exitCode: 7, timedOut: false });
    assert.strictEqual(output, 'trailing');
  });

  it('bounds terminal output draining when an inherited handle never reaches EOF', async () => {
    const binding = new FakeBinding(19, 0);
    const blocked = new CloseableBlockedReadable();
    binding.stdout = blocked;
    const proc = _createMxcSandboxProcess(binding);
    proc.standardOutput!.resume();

    assert.deepStrictEqual(await proc.waitAsync(), { exitCode: 7, timedOut: false });
    assert.strictEqual(blocked.closed, true);
    assert.strictEqual(blocked.freed, true);
  });

  it('does not access the native process handle after disposal races finalization', async () => {
    const binding = new FakeBinding(20, 0);
    const deferred = new DeferredReadable();
    binding.stdout = deferred;
    const proc = _createMxcSandboxProcess(binding);
    proc.standardOutput!.resume();
    const wait = proc.waitAsync();
    await new Promise((resolve) => setImmediate(resolve));

    proc.dispose();
    deferred.release();

    await assert.rejects(wait, /disposed/);
    await new Promise((resolve) => setImmediate(resolve));
    assert.strictEqual(binding.warningReads, 1);
    assert.strictEqual(binding.outputMetadataReads, 0);
    assert.strictEqual(binding.freed, true);
  });

  it('enforces the policy timeout by killing before the final wait', async () => {
    const binding = new FakeBinding(3, Number.MAX_SAFE_INTEGER, { exitCode: -1, timedOut: false });
    const proc = _createMxcSandboxProcess(binding, 0.001);

    const result = await proc.waitAsync();

    assert.deepStrictEqual(result, { exitCode: -1, timedOut: true });
    assert.strictEqual(binding.killed, true);
    assert.strictEqual(binding.waitCalls, 1);
  });

  it('does not report a timeout when completion wins the deadline recheck', async () => {
    class DeadlineRaceBinding extends FakeBinding {
      override tryWait() {
        this.polls += 1;
        return {
          running: this.polls < 2,
          exitCode: 0,
          timedOut: false,
        };
      }
    }
    const binding = new DeadlineRaceBinding(13, 0, { exitCode: 0, timedOut: false });
    const proc = _createMxcSandboxProcess(binding, 0.001);

    const result = await proc.waitAsync();

    assert.deepStrictEqual(result, { exitCode: 0, timedOut: false });
    assert.strictEqual(binding.killed, false);
  });

  it('accepts an empty stdin write without calling the native binding', async () => {
    const binding = new FakeBinding(14, 0);
    const proc = _createMxcSandboxProcess(binding);

    proc.standardInput!.write(Buffer.alloc(0));
    proc.standardInput!.end();
    await once(proc.standardInput!, 'finish');

    assert.deepStrictEqual(binding.stdin.writes, []);
    proc.dispose();
  });

  it('does not continue a partial stdin write after destruction', async () => {
    const binding = new FakeBinding(15, 0);
    const stdin = new DeferredPartialWritable();
    binding.stdin = stdin;
    const proc = _createMxcSandboxProcess(binding);
    const input = proc.standardInput!;
    input.on('error', () => {});

    const writeResult = new Promise<Error | undefined>((resolve) => {
      input.write('hello', (error) => resolve(error ?? undefined));
    });
    input.destroy();
    stdin.release(1);

    const error = await writeResult;
    assert.match(error?.message ?? '', /stdin closed before the write completed/);
    assert.deepStrictEqual(stdin.writes, ['hello']);
    assert.strictEqual(stdin.freed, true);
    proc.dispose();
  });

  it('rejects stream acquisition after disposal', () => {
    const proc = _createMxcSandboxProcess(new FakeBinding(15, 0));
    proc.dispose();

    assert.throws(() => proc.standardInput, /disposed/);
    assert.throws(() => proc.standardOutput, /disposed/);
    assert.throws(() => proc.standardError, /disposed/);
  });

  it('rejects new native operations after terminal handle release', async () => {
    const proc = _createMxcSandboxProcess(new FakeBinding(17, 0));
    await proc.waitAsync();

    assert.throws(() => proc.standardInput, /terminal completion/);
    assert.throws(() => proc.kill(), /terminal completion/);
  });

  it('releases the native handle when initial warning retrieval fails', () => {
    const binding = new FakeBinding(18, 0);
    binding.warnings = () => {
      throw new Error('warning retrieval failed');
    };

    assert.throws(() => _createMxcSandboxProcess(binding), /warning retrieval failed/);
    assert.strictEqual(binding.freed, true);
  });

  it('removes the abort listener after terminal completion', async () => {
    const controller = new AbortController();
    _setBindingSandboxProcessFactory(() =>
      _createMxcSandboxProcess(new FakeBinding(4, 0)));

    const proc = spawnSandbox(
      'echo hello',
      { version: '0.9.0-alpha' },
      { signal: controller.signal },
    );
    assert.strictEqual(getEventListeners(controller.signal, 'abort').length, 1);

    await proc.waitAsync();

    assert.strictEqual(getEventListeners(controller.signal, 'abort').length, 0);
    proc.dispose();
  });
});
