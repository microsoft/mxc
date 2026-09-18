// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import assert from 'node:assert';
import { once } from 'node:events';
import { readFileSync } from 'node:fs';
import { afterEach, describe, it } from 'node:test';
import type pty from 'node-pty';
import {
  _setPtySpawnImplementation,
  spawnSandbox,
  spawnSandboxFromConfig,
} from '../../src/sandbox.js';
import {
  _createMxcSandboxProcess,
  MxcSandboxProcess,
  type NativeStreamingDriver,
  type NativeStreamingEvent,
} from '../../src/sandbox-process.js';
import { _setBindingSandboxProcessFactory } from '../../src/bindings/streaming.js';
import type { RequestSpec } from '../../src/bindings/request.js';

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

class ImmediateExitDriver extends FakeDriver {
  override setEventHandler(handler: (event: NativeStreamingEvent) => void): void {
    super.setEventHandler(handler);
    this.exit();
  }
}

class ImmediateErrorDriver extends FakeDriver {
  override setEventHandler(handler: (event: NativeStreamingEvent) => void): void {
    super.setEventHandler(handler);
    this.fail(new Error('immediate native failure'));
  }
}

afterEach(() => {
  _setBindingSandboxProcessFactory();
  _setPtySpawnImplementation();
});

describe('native streaming process', () => {
  it('routes the default spawn mode through the attached PTY worker', () => {
    let request: RequestSpec | undefined;
    let exitListener: (() => void) | undefined;
    const fakePty = {
      onExit(listener: () => void) {
        exitListener = listener;
        return { dispose() {} };
      },
      kill() {},
    } as unknown as pty.IPty;

    _setPtySpawnImplementation((file, args, options) => {
      assert.strictEqual(file, process.execPath);
      assert.strictEqual(options.cwd, 'C:\\host-work');
      assert.strictEqual(options.cols, 160);
      const payloadIndex = args.indexOf('--payload-file');
      assert.notStrictEqual(payloadIndex, -1);
      request = JSON.parse(
        readFileSync(args[payloadIndex + 1], 'utf8'),
      ) as RequestSpec;
      return fakePty;
    });

    const proc = spawnSandboxFromConfig({
      version: '0.9.0-alpha',
      process: { commandLine: 'echo attached' },
    }, { ptyOptions: { cols: 160 } }, 'C:\\host-work', { FROM_CALLER: 'yes' });

    assert.strictEqual(proc, fakePty);
    assert.strictEqual(request?.command, 'echo attached');
    assert.deepStrictEqual(request?.containment, { type: 'process' });
    assert.deepStrictEqual(request?.environment, { FROM_CALLER: 'yes' });
    exitListener?.();
  });

  it('retains the executor PTY path for orderly-cancellation compatibility', () => {
    const controller = new AbortController();
    let spawnedFile: string | undefined;
    let spawnedArgs: string[] | undefined;
    const fakePty = {
      onExit() {
        return { dispose() {} };
      },
    } as unknown as pty.IPty;
    _setPtySpawnImplementation((file, args) => {
      spawnedFile = file;
      spawnedArgs = args;
      return fakePty;
    });

    const proc = spawnSandboxFromConfig({
      version: '0.9.0-alpha',
      process: { commandLine: 'echo attached' },
    }, {
      executablePath: process.execPath,
      signal: controller.signal,
      skipPlatformCheck: true,
    });

    assert.strictEqual(proc, fakePty);
    assert.strictEqual(spawnedFile, process.execPath);
    assert.ok(spawnedArgs?.includes('--config-base64'));
    assert.ok(!spawnedArgs?.includes('--payload-file'));
  });

  it('routes usePty false through callback streaming', () => {
    let request: RequestSpec | undefined;
    _setBindingSandboxProcessFactory((value) => {
      request = value;
      return _createMxcSandboxProcess(new FakeDriver(42));
    });

    const proc = spawnSandbox(
      'echo hello',
      { version: '0.9.0-alpha' },
      { experimental: true, usePty: false },
      'C:\\work',
      'sample',
      { FROM_CALLER: 'yes' },
    );

    assert.ok(proc instanceof MxcSandboxProcess);
    assert.strictEqual(proc.id, 42);
    assert.strictEqual(request?.command, 'echo hello');
    assert.strictEqual(request?.workingDirectory, 'C:\\work');
    assert.deepStrictEqual(request?.environment, { FROM_CALLER: 'yes' });
    proc.dispose();
  });

  it('kills callback streaming when the abort signal fires', () => {
    const controller = new AbortController();
    const driver = new FakeDriver(43);
    _setBindingSandboxProcessFactory(
      () => _createMxcSandboxProcess(driver),
    );
    const proc = spawnSandbox(
      'echo hello',
      { version: '0.9.0-alpha' },
      { signal: controller.signal, usePty: false },
    );

    assert.ok(proc instanceof MxcSandboxProcess);
    controller.abort();

    assert.strictEqual(driver.killed, true);
    proc.dispose();
  });

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

    assert.throws(() => proc.standardOutput, /after terminal completion/);
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

  it('supports the ChildProcess-compatible pipe and close-event surface', async () => {
    const driver = new FakeDriver(23);
    const proc = _createMxcSandboxProcess(driver);
    const exit = once(proc, 'exit');
    const close = once(proc, 'close');

    const chunks: Buffer[] = [];
    proc.stdout!.on('data', (chunk) => chunks.push(Buffer.from(chunk)));
    assert.strictEqual(proc.stdin, proc.standardInput);
    assert.strictEqual(proc.stderr, proc.standardError);
    proc.stderr!.resume();

    driver.exit();

    assert.deepStrictEqual(await exit, [7, null]);
    assert.deepStrictEqual(await close, [7, null]);
    assert.strictEqual(Buffer.concat(chunks).toString('utf8'), 'out');
    assert.strictEqual(proc.exitCode, 7);
    assert.strictEqual(driver.shutdownCalled, true);
  });

  it('appends warnings and capture-denials metadata to compatibility stderr', async () => {
    const driver = new FakeDriver(24);
    driver.metadata = { captureDenials: { outputPath: 'denials.json' } };
    const proc = _createMxcSandboxProcess(driver);
    let stderr = '';
    proc.stderr!.on('data', (chunk) => {
      stderr += chunk.toString();
    });
    const close = once(proc, 'close');

    driver.exit();
    await close;

    assert.match(stderr, /err/);
    assert.match(stderr, /relaxed/);
    assert.match(stderr, /"outputPath":"denials\.json"/);
  });

  it('drains unclaimed output for completion-only consumers', async () => {
    const driver = new FakeDriver(25);
    const proc = _createMxcSandboxProcess(driver);
    const close = once(proc, 'close');

    await new Promise((resolve) => setImmediate(resolve));
    await new Promise((resolve) => setImmediate(resolve));
    assert.ok(proc.stdout);
    assert.ok(proc.stderr);
    driver.exit();

    assert.deepStrictEqual(await close, [7, null]);
    assert.strictEqual(driver.stdoutChunks.length, 0);
    assert.strictEqual(driver.stderrChunks.length, 0);
  });

  it('supports EventEmitter completion listener aliases', async () => {
    const driver = new FakeDriver(26);
    const proc = _createMxcSandboxProcess(driver);
    const events: string[] = [];
    proc.addListener('exit', () => events.push('exit'));
    proc.prependOnceListener('close', () => events.push('close'));

    driver.exit();
    await new Promise((resolve) => setImmediate(resolve));

    assert.deepStrictEqual(events, ['exit', 'close']);
  });

  it('keeps stdin available after registering completion listeners', async () => {
    const driver = new FakeDriver(27);
    const proc = _createMxcSandboxProcess(driver);
    proc.on('close', () => {});

    await new Promise((resolve) => setImmediate(resolve));

    assert.ok(proc.stdin);
    assert.strictEqual(driver.stdinClosed, false);
    proc.dispose();
  });

  it('releases the native coordinator after an unobserved exit', async () => {
    const driver = new FakeDriver(28);
    const proc = _createMxcSandboxProcess(driver);

    driver.exit();
    await new Promise((resolve) => setImmediate(resolve));

    assert.strictEqual(proc.exitCode, 7);
    assert.strictEqual(driver.shutdownCalled, true);
  });

  it('keeps pipes claimable when native exit is reported during construction', () => {
    const proc = _createMxcSandboxProcess(new ImmediateExitDriver());

    assert.ok(proc.stdout);
    assert.ok(proc.stderr);
    proc.dispose();
  });

  it('delivers native failures to an error-only listener', async () => {
    const driver = new FakeDriver(29);
    const proc = _createMxcSandboxProcess(driver);
    const error = once(proc, 'error');

    driver.fail(new Error('native failure'));

    const [received] = await error;
    assert.match((received as Error).message, /native failure/);
    assert.strictEqual(driver.shutdownCalled, true);
  });

  it('replays an immediate native failure to error and close listeners', async () => {
    const proc = _createMxcSandboxProcess(new ImmediateErrorDriver());
    const error = new Promise<Error>((resolve) => proc.once('error', resolve));
    const close = new Promise<[number | null, number | null]>((resolve) => {
      proc.once('close', (code, signal) => resolve([code, signal]));
    });

    assert.match((await error).message, /immediate native failure/);
    assert.deepStrictEqual(await close, [null, null]);
  });

  it('accepts a ChildProcess-style signal argument when killing', () => {
    const driver = new FakeDriver(30);
    const proc = _createMxcSandboxProcess(driver);

    assert.strictEqual(proc.kill(0), true);
    assert.strictEqual(driver.killed, false);
    assert.strictEqual(proc.kill('SIGTERM'), true);
    assert.strictEqual(driver.killed, true);
    proc.dispose();
  });

  it('finalizes when a claimed output stream remains unread', async () => {
    const driver = new FakeDriver(31);
    const proc = _createMxcSandboxProcess(driver);
    assert.ok(proc.stdout);
    const wait = proc.waitAsync();

    driver.exit();

    assert.deepStrictEqual(await wait, { exitCode: 7, timedOut: false });
    assert.strictEqual(driver.shutdownCalled, true);
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
