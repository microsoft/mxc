// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import assert from 'node:assert';
import { EventEmitter } from 'node:events';
import { afterEach, describe, it } from 'node:test';
import { MxcError } from '../../src/errors.js';
import {
  _setBindingRunWorkerFactory,
  runBindingRequestAsync,
  type BindingRunWorkerLike,
  type BindingRunWorkerMessage,
} from '../../src/bindings/run-worker.js';
import type { RequestSpec } from '../../src/bindings/request.js';

const request: RequestSpec = {
  policy: { version: '0.9.0-alpha' },
  command: 'echo hello',
  containment: { type: 'process' },
  environment: {},
  inheritDefaultEnv: false,
  experimental: false,
};

class FakeWorker extends EventEmitter implements BindingRunWorkerLike {
  reply(message: BindingRunWorkerMessage): void {
    queueMicrotask(() => this.emit('message', message));
  }

  fail(error: Error): void {
    queueMicrotask(() => this.emit('error', error));
  }
}

afterEach(() => _setBindingRunWorkerFactory());

describe('mxc_ffi run worker', () => {
  it('resolves a native result asynchronously', async () => {
    const worker = new FakeWorker();
    _setBindingRunWorkerFactory(() => {
      worker.reply({
        ok: true,
        result: {
          stdout: 'ok',
          stderr: '',
          exitCode: 0,
          timedOut: false,
          warnings: [],
        },
      });
      return worker;
    });

    assert.strictEqual((await runBindingRequestAsync(request)).stdout, 'ok');
  });

  it('reconstructs typed native errors', async () => {
    const worker = new FakeWorker();
    _setBindingRunWorkerFactory(() => {
      worker.reply({
        ok: false,
        error: { code: 'policy_validation', message: 'denied' },
      });
      return worker;
    });

    await assert.rejects(runBindingRequestAsync(request), (error) =>
      error instanceof MxcError && error.code === 'policy_validation');
  });

  it('rejects worker failures', async () => {
    const worker = new FakeWorker();
    _setBindingRunWorkerFactory(() => {
      worker.fail(new Error('worker failed'));
      return worker;
    });

    await assert.rejects(runBindingRequestAsync(request), /worker failed/);
  });
});
