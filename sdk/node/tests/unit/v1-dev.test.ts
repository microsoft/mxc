// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import assert from 'node:assert/strict';
import { PassThrough, Readable } from 'node:stream';
import { afterEach, it } from 'node:test';
import { _setBindingRawRunAsyncImplementation } from '../../src/bindings/run.js';
import {
  _setBindingRawSandboxProcessFactory,
  _setStateAwareBindingSandboxProcessFactory,
} from '../../src/bindings/streaming.js';
import {
  _setSpawnBindingSandboxWithPtyJsonImplementation,
  _setExecStateAwareBindingSandboxWithPtyImplementation,
} from '../../src/bindings/pty.js';
import { _setBindingStateAwareAsyncImplementation } from '../../src/bindings/state-aware.js';
import { MxcProcess, type NativeLifecycleDriver } from '../../src/v1/container-process.js';
import { captureProcessOutput } from '../../src/v1/capture.js';
import { MxcPtyProcess } from '../../src/v1/mxc-pty-process.js';
import { runInContainer } from '../../src/v1/lifecycle.js';
import type { ContainerId } from '../../src/v1/lifecycle-types.js';
import * as dev from '../../src/v1/dev/index.js';

afterEach(() => {
  _setBindingRawRunAsyncImplementation();
  _setBindingRawSandboxProcessFactory();
  _setStateAwareBindingSandboxProcessFactory();
  _setSpawnBindingSandboxWithPtyJsonImplementation();
  _setExecStateAwareBindingSandboxWithPtyImplementation();
  _setBindingStateAwareAsyncImplementation();
});

function fakeProcess(stdout = 'out', stderr = 'err'): MxcProcess {
  const standardOutput = new PassThrough();
  const standardError = new PassThrough();
  const driver: NativeLifecycleDriver = {
    id: 42,
    standardInput: null,
    standardOutput,
    standardError,
    poll: () => ({ exitCode: 7, timedOut: false, running: false }),
    wait: async () => ({ exitCode: 7, timedOut: false }),
    warnings: () => ['warning'],
    outputMetadata: () => undefined,
    kill: () => {},
    killForTimeout: () => {},
    free: async () => {},
  };
  const process = new MxcProcess(driver);
  standardOutput.end(stdout);
  standardError.end(stderr);
  return process;
}

function fakeTerminal(): MxcPtyProcess {
  return new MxcPtyProcess({
    id: 43, standardInput: null, standardOutput: null, standardError: null,
    poll: () => ({ exitCode: 0, timedOut: false, running: true }),
    wait: async () => ({ exitCode: 0, timedOut: false }),
    warnings: () => [], outputMetadata: () => undefined,
    kill: () => {}, killForTimeout: () => {}, free: async () => {},
  }, () => {});
}

it('one-shot capture passes the original JSON and independent authorization', async () => {
  const json = ' { "version":"1.1.0-alpha","process":{"commandLine":"echo","timeout":1e2} } ';
  let received: [string, boolean] | undefined;
  _setBindingRawRunAsyncImplementation(async (request, experimental) => {
    received = [request, experimental];
    return {
      stdout: 'out',
      stderr: 'err',
      exitCode: 7,
      timedOut: false,
      warnings: ['warning'],
    };
  });
  const result = await dev.runJson(json, { experimental: true });
  assert.deepStrictEqual(received, [json, true]);
  assert.deepStrictEqual(result, {
    stdout: 'out', stderr: 'err', exitCode: 7, timedOut: false, warnings: ['warning'],
  });
});

it('one-shot live modes pass the exact request and timeout to their bindings', async () => {
  const json = '{"version":"1.0.0","containment":"seatbelt","process":{"commandLine":"echo","timeout":120}}';
  let pipeArgs: unknown[] = [];
  let ptyArgs: unknown[] = [];
  const pipe = fakeProcess();
  _setBindingRawSandboxProcessFactory(async (...args) => {
    pipeArgs = args;
    return pipe;
  });
  _setSpawnBindingSandboxWithPtyJsonImplementation(async (...args) => {
    ptyArgs = args;
    return fakeTerminal();
  });
  const spawned = await dev.spawnJson(json, { experimental: true });
  const terminal = await dev.spawnWithPtyJson(json, { size: { rows: 30, columns: 90 } });
  assert.strictEqual(spawned, pipe);
  assert.deepStrictEqual(pipeArgs, [json, true, 120]);
  assert.deepStrictEqual(ptyArgs, [json, false, 30, 90, 120]);
  spawned.dispose();
  terminal.dispose();
});

it('state-aware execution captures streams and preserves container ownership', async () => {
  const json = '{"version":"1.0.0","phase":"exec","sandboxId":"iso:abc","process":{"commandLine":"echo","timeout":250}}';
  let received: unknown[] = [];
  const proc = fakeProcess();
  _setStateAwareBindingSandboxProcessFactory((...args) => {
    received = args;
    return proc;
  });
  const output = await dev.runInContainerJson(json, { experimental: true });
  assert.deepStrictEqual(received, [json, true, 250]);
  assert.deepStrictEqual(output, {
    stdout: 'out', stderr: 'err', exitCode: 7, timedOut: false, warnings: ['warning'],
  });
  assert.throws(() => proc.standardOutput, /disposed/);
});

it('typed and raw captured execs return partial output when pipes stay open after timeout', {
  timeout: 2000,
}, async () => {
  _setStateAwareBindingSandboxProcessFactory(() => {
    const stdout = new PassThrough();
    const stderr = new PassThrough();
    stdout.write('partial out');
    stderr.write('partial err');
    const driver: NativeLifecycleDriver = {
      id: 42,
      standardInput: null,
      standardOutput: stdout,
      standardError: stderr,
      poll: () => ({ exitCode: -1, timedOut: true, running: false }),
      wait: async () => ({ exitCode: -1, timedOut: true }),
      warnings: () => [],
      outputMetadata: () => undefined,
      kill: () => {},
      killForTimeout: () => {},
      free: async () => {},
    };
    return new MxcProcess(driver);
  });
  const json = '{"version":"1.0.0","phase":"exec","sandboxId":"iso:abc","process":{"commandLine":"echo"}}';
  const requests = [
    dev.runInContainerJson(json),
    runInContainer('iso:abc' as ContainerId<'isolation_session'>, { command: 'echo' }),
  ];
  for (const result of await Promise.all(requests)) {
    assert.deepStrictEqual(result, {
      stdout: 'partial out',
      stderr: 'partial err',
      exitCode: -1,
      timedOut: true,
      warnings: [],
    });
  }
});

it('settles capture before a pending native read permits stream close', {
  timeout: 2000,
}, async () => {
  for (const waitFails of [false, true]) {
    let finishDestroy: (() => void) | undefined;
    const output = new Readable({
      read() {},
      destroy(_error, callback) {
        finishDestroy = () => callback(null);
      },
    });
    output.push('partial output');
    const driver: NativeLifecycleDriver = {
      id: 42,
      standardInput: null,
      standardOutput: output,
      standardError: null,
      poll: () => ({ exitCode: -1, timedOut: true, running: false }),
      wait: async () => {
        if (waitFails) throw new Error('native wait failed');
        return { exitCode: -1, timedOut: true };
      },
      warnings: () => [],
      outputMetadata: () => undefined,
      kill: () => {},
      killForTimeout: () => {},
      free: async () => {},
    };
    const proc = new MxcProcess(driver);
    try {
      if (waitFails) {
        await assert.rejects(captureProcessOutput(proc), /native wait failed/);
      } else {
        assert.deepStrictEqual(await captureProcessOutput(proc), {
          result: { exitCode: -1, timedOut: true },
          stdout: 'partial output',
          stderr: '',
        });
      }
      assert.strictEqual(output.destroyed, true);
      assert.strictEqual(output.closed, false);
    } finally {
      finishDestroy?.();
      proc.dispose();
    }
  }
});

it('preserves the capture failure when process disposal also fails', async () => {
  let cleanupAttempted = false;
  _setStateAwareBindingSandboxProcessFactory(() => {
    const output = new Readable({
      read() { this.destroy(new Error('capture read failed')); },
    });
    const driver: NativeLifecycleDriver = {
      id: 42,
      standardInput: null,
      standardOutput: output,
      standardError: null,
      poll: () => ({ exitCode: 0, timedOut: false, running: true }),
      wait: async () => ({ exitCode: 0, timedOut: false }),
      warnings: () => [],
      outputMetadata: () => undefined,
      kill: () => {},
      killForTimeout: () => {},
      free: async () => {},
    };
    const proc = new MxcProcess(driver);
    proc.dispose = () => {
      cleanupAttempted = true;
      throw new Error('dispose failed');
    };
    return proc;
  });
  const json = '{"version":"1.0.0","phase":"exec","sandboxId":"iso:abc","process":{"commandLine":"echo"}}';
  await assert.rejects(dev.runInContainerJson(json), /capture read failed/);
  assert.strictEqual(cleanupAttempted, true);
});

it('typed and raw capture reject read failures while process wait is pending', {
  timeout: 2000,
}, async () => {
  const releaseFree: Array<() => void> = [];
  _setStateAwareBindingSandboxProcessFactory(() => {
    const output = new Readable({
      read() { this.destroy(new Error('capture read failed')); },
    });
    const driver: NativeLifecycleDriver = {
      id: 42,
      standardInput: null,
      standardOutput: output,
      standardError: null,
      poll: () => ({ exitCode: 0, timedOut: false, running: true }),
      wait: async () => ({ exitCode: 0, timedOut: false }),
      warnings: () => [],
      outputMetadata: () => undefined,
      kill: () => {},
      killForTimeout: () => {},
      free: () => new Promise<void>((resolve) => {
        releaseFree.push(resolve);
      }),
    };
    return new MxcProcess(driver);
  });
  const json = '{"version":"1.0.0","phase":"exec","sandboxId":"iso:abc","process":{"commandLine":"echo"}}';
  try {
    await Promise.all([
      assert.rejects(dev.runInContainerJson(json), /capture read failed/),
      assert.rejects(
        runInContainer('iso:abc' as ContainerId<'isolation_session'>, { command: 'echo' }),
        /capture read failed/,
      ),
    ]);
  } finally {
    for (const release of releaseFree) release();
  }
});

it('successful stream EOF does not finish capture before process exit', async () => {
  let running = true;
  let captured = false;
  const output = new PassThrough();
  const driver: NativeLifecycleDriver = {
    id: 42,
    standardInput: null,
    standardOutput: output,
    standardError: null,
    poll: () => ({ exitCode: 0, timedOut: false, running }),
    wait: async () => ({ exitCode: 0, timedOut: false }),
    warnings: () => [],
    outputMetadata: () => undefined,
    kill: () => {},
    killForTimeout: () => {},
    free: async () => {},
  };
  const proc = new MxcProcess(driver);
  try {
    const result = captureProcessOutput(proc).then((value) => {
      captured = true;
      return value;
    });
    const ended = new Promise<void>((resolve) => output.once('end', resolve));
    output.end('finished');
    await ended;
    assert.strictEqual(captured, false);
    running = false;
    assert.deepStrictEqual(await result, {
      result: { exitCode: 0, timedOut: false },
      stdout: 'finished',
      stderr: '',
    });
  } finally {
    proc.dispose();
  }
});

it('state-aware pipe and PTY spawns forward exact JSON and terminal controls', async () => {
  const json = ' { "version":"1.1.0-alpha","phase":"exec","sandboxId":"iso:abc","process":{"commandLine":"echo","timeout":300} } ';
  let pipeArgs: unknown[] = [];
  let ptyArgs: unknown[] = [];
  _setStateAwareBindingSandboxProcessFactory((...args) => {
    pipeArgs = args;
    return fakeProcess();
  });
  _setExecStateAwareBindingSandboxWithPtyImplementation(async (...args) => {
    ptyArgs = args;
    return fakeTerminal();
  });
  const proc = await dev.spawnInContainerJson(json, { experimental: true });
  const pty = await dev.spawnInContainerWithPtyJson(json, {
    experimental: true,
    size: { rows: 25, columns: 100 },
  });
  assert.deepStrictEqual(pipeArgs, [json, true, 300]);
  assert.deepStrictEqual(ptyArgs, [json, true, 25, 100, 300]);
  proc.dispose();
  pty.dispose();
});

it('all lifecycle phases return the unchanged native response and dry-run flag', async () => {
  const received: Array<{ requestJson: string; dryRun: boolean; experimental: boolean }> = [];
  const reply = '{"result":{"sandboxId":"wsb:123","metadata":{"future":17}}}';
  _setBindingStateAwareAsyncImplementation(async (request) => {
    received.push(request);
    return reply;
  });
  const phases = [
    ['provision', dev.provisionContainerJson, dev.validateProvisionJson],
    ['start', dev.startContainerJson, dev.validateStartJson],
    ['stop', dev.stopContainerJson, dev.validateStopJson],
    ['deprovision', dev.deprovisionContainerJson, dev.validateDeprovisionJson],
  ] as const;
  for (const [phase, execute, validate] of phases) {
    const json = ` { "version":"1.1.0-alpha","phase":"${phase}","sandboxId":"wsb:123" } `;
    assert.strictEqual(await execute(json, { experimental: true }), reply);
    assert.strictEqual(await validate(json, { experimental: true }), reply);
    assert.deepStrictEqual(received.slice(-2), [
      { requestJson: json, experimental: true, dryRun: false },
      { requestJson: json, experimental: true, dryRun: true },
    ]);
  }
  const exec = '{"version":"1.0.0","phase":"exec","sandboxId":"iso:abc","process":{"commandLine":"echo"}}';
  assert.strictEqual(await dev.validateProcessJson(exec), reply);
  assert.deepStrictEqual(received.at(-1), { requestJson: exec, experimental: false, dryRun: true });
});

it('rejects phase mismatches, malformed options and invalid Unicode before native calls', async () => {
  _setBindingStateAwareAsyncImplementation(async () => {
    assert.fail('native must not be called');
  });
  const start = '{"version":"1.0.0","phase":"start","sandboxId":"iso:abc"}';
  await assert.rejects(dev.stopContainerJson(start), { code: 'malformed_request' });
  await assert.rejects(dev.spawnInContainerJson(start), { code: 'malformed_request' });
  await assert.rejects(dev.runJson(start), { code: 'malformed_request' });
  await assert.rejects(dev.validateProcessJson(start), { code: 'malformed_request' });
  // @ts-expect-error Deliberately exercise runtime validation of invalid options.
  await assert.rejects(dev.startContainerJson(start, { experimental: 'yes' }),
    { code: 'malformed_request' });
  // @ts-expect-error Deliberately exercise runtime validation of an invalid PTY size.
  await assert.rejects(dev.spawnWithPtyJson(start, { size: null }),
    { code: 'malformed_request' });
  await assert.rejects(dev.spawnWithPtyJson(start, {
    // @ts-expect-error Unknown PTY size fields must fail at runtime too.
    size: { rows: 24, columns: 80, extra: true },
  }), { code: 'malformed_request' });
  await assert.rejects(dev.startContainerJson(start + '\uD800'), { code: 'malformed_request' });
});
