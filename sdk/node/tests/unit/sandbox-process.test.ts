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

class FakeBinding implements SandboxProcessBinding {
  readonly warnings = ['relaxed'];
  readonly stdoutEvents: string[] = [];
  readonly stderrEvents: string[] = [];
  readonly stdin = new FakeWritable();
  readonly stdout = new FakeReadable([Buffer.from('out'), null], this.stdoutEvents);
  readonly stderr = new FakeReadable([Buffer.from('err'), null], this.stderrEvents);
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
    proc.stdout!.on('data', (chunk) => chunks.push(Buffer.from(chunk)));
    await once(proc.stdout!, 'end');

    assert.strictEqual(Buffer.concat(chunks).toString('utf8'), 'out');
    proc.dispose();
  });

  it('writes to stdin and exposes terminal metadata after wait', async () => {
    const binding = new FakeBinding(9, 1);
    const proc = _createMxcSandboxProcess(binding);
    proc.stdin!.end('hello');
    await once(proc.stdin!, 'finish');

    assert.deepStrictEqual(binding.stdin.writes, ['hello']);
    assert.strictEqual(binding.stdin.flushed, true);
    assert.deepStrictEqual(await proc.wait(), { exitCode: 7, timedOut: false });
    assert.deepStrictEqual(proc.outputMetadata, { tag: 'done' });
  });

  it('drains untaken output streams while waiting', async () => {
    const binding = new FakeBinding(5, 1);
    const proc = _createMxcSandboxProcess(binding);

    await proc.wait();
    await new Promise((resolve) => setImmediate(resolve));

    assert.throws(() => proc.stdout, /drained internally by wait/);
    assert.ok(binding.stdoutEvents.includes('free-read'));
    assert.ok(binding.stderrEvents.includes('free-read'));
  });

  it('enforces the policy timeout by killing before the final wait', async () => {
    const binding = new FakeBinding(3, Number.MAX_SAFE_INTEGER, { exitCode: -1, timedOut: false });
    const proc = _createMxcSandboxProcess(binding, 0.001);

    const result = await proc.wait();

    assert.deepStrictEqual(result, { exitCode: -1, timedOut: true });
    assert.strictEqual(binding.killed, true);
    assert.strictEqual(binding.waitCalls, 1);
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

    await proc.wait();

    assert.strictEqual(getEventListeners(controller.signal, 'abort').length, 0);
    proc.dispose();
  });
});
