// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import assert from 'node:assert';
import { EventEmitter } from 'node:events';
import { afterEach, describe, it } from 'node:test';
import { MxcError } from '../../src/errors.js';
import { spawnSandboxAsync } from '../../src/sandbox.js';
import {
  _setBindingRunWorkerFactory,
  type BindingRunWorkerLike,
  type BindingRunWorkerMessage,
} from '../../src/bindings/run-worker.js';
import type { RequestSpec } from '../../src/bindings/request.js';

class FakeWorker extends EventEmitter implements BindingRunWorkerLike {
  reply(message: BindingRunWorkerMessage): void {
    queueMicrotask(() => this.emit('message', message));
  }
}

afterEach(() => _setBindingRunWorkerFactory());

describe('in-process async run routing', () => {
  it('converts the existing config flow at the native boundary', async () => {
    let bindingRequest: RequestSpec | undefined;
    _setBindingRunWorkerFactory((data) => {
      bindingRequest = data.request;
      const worker = new FakeWorker();
      worker.reply({
        ok: true,
        result: {
          stdout: 'out',
          stderr: 'err',
          exitCode: 7,
          timedOut: false,
          warnings: [],
        },
      });
      return worker;
    });

    const result = await spawnSandboxAsync(
      'echo hello',
      { version: '0.9.0-alpha' },
      { experimental: true, inheritDefaultEnv: true },
      'C:\\work',
      'sample',
    );

    assert.deepStrictEqual(result, { stdout: 'out', stderr: 'err', exitCode: 7 });
    assert.strictEqual(bindingRequest?.policy.version, '0.9.0-alpha');
    assert.strictEqual(bindingRequest?.command, 'echo hello');
    assert.strictEqual(bindingRequest?.containerName, 'sample');
    assert.strictEqual(bindingRequest?.workingDirectory, 'C:\\work');
    assert.deepStrictEqual(bindingRequest?.environment, {});
    assert.strictEqual(bindingRequest?.inheritDefaultEnv, true);
    assert.strictEqual(bindingRequest?.experimental, true);
  });

  it('rejects executor-only options instead of falling back', async () => {
    const policy = { version: '0.9.0-alpha' };
    for (const options of [
      { usePty: true },
      { dryRun: true },
      { executablePath: 'wxc-exec.exe' },
    ]) {
      await assert.rejects(
        spawnSandboxAsync('echo hello', policy, options),
        /does not support executor-only option/,
      );
    }
  });

  it('surfaces buffered diagnostics', async () => {
    _setBindingRunWorkerFactory(() => {
      const worker = new FakeWorker();
      worker.reply({
        ok: true,
        result: {
          stdout: '',
          stderr: 'native stderr',
          exitCode: 0,
          timedOut: false,
          warnings: ['policy was relaxed'],
          outputMetadata: {
            captureDenials: { kind: 'captureDenials', outputPath: 'denials.json' },
          },
        },
      });
      return worker;
    });

    const result = await spawnSandboxAsync('echo hello', { version: '0.9.0-alpha' });
    assert.strictEqual(
      result.stderr,
      'native stderr\npolicy was relaxed\n'
        + '{"kind":"captureDenials","outputPath":"denials.json"}\n',
    );
  });

  it('rejects timed-out execution', async () => {
    _setBindingRunWorkerFactory(() => {
      const worker = new FakeWorker();
      worker.reply({
        ok: true,
        result: {
          stdout: '',
          stderr: '',
          exitCode: -1,
          timedOut: true,
          warnings: [],
        },
      });
      return worker;
    });

    await assert.rejects(
      spawnSandboxAsync('sleep 30', { version: '0.9.0-alpha', timeoutMs: 1 }),
      (error: unknown) =>
        error instanceof MxcError
        && error.code === 'backend_error'
        && error.message.includes('timed out'),
    );
  });

  it('rejects testing-only policy instead of falling back', async () => {
    await assert.rejects(
      spawnSandboxAsync('echo hello', {
        version: '0.8.0-alpha',
        network: { proxy: { builtinTestServer: true } },
      }),
      /not supported by the in-process Node SDK/,
    );
  });
});
