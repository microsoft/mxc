// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import assert from 'node:assert';
import { EventEmitter } from 'node:events';
import { afterEach, describe, it } from 'node:test';
import { spawnSandboxAsync, type SandboxSpawnOptions } from '../../src/sandbox.js';
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
      { experimental: true },
      'C:\\work',
      'sample',
    );

    assert.deepStrictEqual(result, { stdout: 'out', stderr: 'err', exitCode: 7 });
    assert.strictEqual(bindingRequest?.policy.version, '0.9.0-alpha');
    assert.strictEqual(bindingRequest?.command, 'echo hello');
    assert.strictEqual(bindingRequest?.containerName, 'sample');
    assert.strictEqual(bindingRequest?.workingDirectory, 'C:\\work');
    assert.deepStrictEqual(bindingRequest?.environment, {});
    assert.strictEqual(bindingRequest?.experimental, true);
  });

  it('rejects executor-only options instead of falling back', async () => {
    const policy = { version: '0.9.0-alpha' };
    for (const options of [
      { usePty: true } as unknown as SandboxSpawnOptions,
      { dryRun: true } as unknown as SandboxSpawnOptions,
      { executablePath: 'wxc-exec.exe' } as unknown as SandboxSpawnOptions,
    ]) {
      await assert.rejects(
        spawnSandboxAsync('echo hello', policy, options),
        /no longer supports legacy option/,
      );
    }
  });

  it('rejects testing-only policy instead of falling back', async () => {
    await assert.rejects(
      spawnSandboxAsync('echo hello', {
        version: '0.9.0-alpha',
        network: { proxy: { builtinTestServer: true } },
      } as unknown as { version: string }),
      /not supported by the in-process Node SDK/,
    );
  });
});
