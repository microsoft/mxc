// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import assert from 'node:assert';
import { EventEmitter } from 'node:events';
import { afterEach, describe, it } from 'node:test';
import { spawnSandboxAsync } from '../../src/sandbox.js';
import {
  _setBindingRunWorkerFactory,
  type BindingRunWorkerLike,
  type BindingRunWorkerMessage,
} from '../../src/bindings/run-worker.js';
import type { BindingSandboxRequest } from '../../src/bindings/request.js';

class FakeWorker extends EventEmitter implements BindingRunWorkerLike {
  reply(message: BindingRunWorkerMessage): void {
    queueMicrotask(() => this.emit('message', message));
  }
}

afterEach(() => _setBindingRunWorkerFactory());

describe('in-process async run routing', () => {
  it('uses mxc_ffi for a compatible request', async () => {
    let bindingRequest: BindingSandboxRequest | undefined;
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
    assert.deepStrictEqual(bindingRequest, {
      policy: { version: '0.9.0-alpha' },
      command: 'echo hello',
      containment: { type: 'process' },
      containerName: 'sample',
      workingDirectory: 'C:\\work',
      environment: {},
      experimental: true,
    });
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

  it('rejects testing-only policy instead of falling back', async () => {
    await assert.rejects(
      spawnSandboxAsync('echo hello', {
        version: '0.9.0-alpha',
        network: { proxy: { builtinTestServer: true } },
      }),
      /testing-feature gate/,
    );
  });
});
