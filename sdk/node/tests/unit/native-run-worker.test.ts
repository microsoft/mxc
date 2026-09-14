// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import assert from 'node:assert';
import { EventEmitter } from 'node:events';
import { afterEach, describe, it } from 'node:test';
import { MxcError } from '../../src/errors.js';
import {
  _setNativeRunWorkerFactory,
  runNativeRequestAsync,
  type NativeRunWorkerLike,
  type NativeRunWorkerMessage,
} from '../../src/native-run-worker.js';

class FakeWorker extends EventEmitter implements NativeRunWorkerLike {
  reply(message: NativeRunWorkerMessage): void {
    queueMicrotask(() => this.emit('message', message));
  }

  fail(error: Error): void {
    queueMicrotask(() => this.emit('error', error));
  }
}

afterEach(() => _setNativeRunWorkerFactory());

describe('native run worker', () => {
  it('resolves a native result asynchronously', async () => {
    const worker = new FakeWorker();
    _setNativeRunWorkerFactory(() => {
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

    assert.strictEqual((await runNativeRequestAsync('{}')).stdout, 'ok');
  });

  it('reconstructs typed native errors', async () => {
    const worker = new FakeWorker();
    _setNativeRunWorkerFactory(() => {
      worker.reply({
        ok: false,
        error: { code: 'policy_validation', message: 'denied' },
      });
      return worker;
    });

    await assert.rejects(runNativeRequestAsync('{}'), (error) =>
      error instanceof MxcError && error.code === 'policy_validation');
  });

  it('rejects worker failures', async () => {
    const worker = new FakeWorker();
    _setNativeRunWorkerFactory(() => {
      worker.fail(new Error('worker failed'));
      return worker;
    });

    await assert.rejects(runNativeRequestAsync('{}'), /worker failed/);
  });
});
