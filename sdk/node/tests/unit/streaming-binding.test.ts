// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import assert from 'node:assert';
import { describe, it } from 'node:test';
import {
  _spawnStreamingDriverForTest,
  type _StreamingCallbackFacade,
  type _StreamingNativeFacade,
} from '../../src/bindings/streaming.js';

type NativeCallback = Parameters<_StreamingCallbackFacade['register']>[0];

async function verifySpawnCleanup(
  requestShutdownResult: number | 'throw',
): Promise<void> {
  const handle = {};
  let callback: NativeCallback | undefined;
  let unregisterCount = 0;
  let shutdownCount = 0;
  let freeCount = 0;
  let freeErrorCount = 0;
  const callbacks: _StreamingCallbackFacade = {
    register(value) {
      callback = value;
      return {} as ReturnType<_StreamingCallbackFacade['register']>;
    },
    unregister() {
      unregisterCount += 1;
      callback = undefined;
    },
  };
  const native = {
    spawn(
      _request: string,
      _callback: unknown,
      _userData: unknown,
      outHandle: unknown[],
    ) {
      outHandle[0] = handle;
      return 0;
    },
    id() {
      throw new Error('reading coordinator id failed');
    },
    requestShutdown() {
      shutdownCount += 1;
      if (requestShutdownResult === 'throw') {
        throw new Error('shutdown invocation failed');
      }
      return requestShutdownResult;
    },
    free(_handle: unknown, completion: (error: Error | null) => void) {
      freeCount += 1;
      completion(null);
    },
    freeError() {
      freeErrorCount += 1;
    },
  } as unknown as _StreamingNativeFacade;

  assert.throws(
    () => _spawnStreamingDriverForTest({} as never, native, callbacks),
    /reading coordinator id failed/,
  );
  assert.strictEqual(shutdownCount, 1);
  assert.strictEqual(freeErrorCount, 1);
  assert.strictEqual(freeCount, requestShutdownResult === 0 ? 0 : 1);
  assert.strictEqual(unregisterCount, requestShutdownResult === 0 ? 0 : 1);

  callback?.(null, 8, 0, null, 0, 0, 0);
  await new Promise((resolve) => setImmediate(resolve));

  assert.strictEqual(unregisterCount, 1);
  assert.strictEqual(freeCount, 1);
}

describe('native streaming binding ownership', () => {
  it('cleans up exactly once when initialization fails after spawn', async () => {
    await verifySpawnCleanup(0);
  });

  it('does not double-free when initialization and shutdown fail', async () => {
    await verifySpawnCleanup(1);
  });

  it('frees the handle when the shutdown invocation throws', async () => {
    await verifySpawnCleanup('throw');
  });

  it('reports callback unregister failure after native free completes', () => {
    const handle = {};
    let callback: NativeCallback | undefined;
    let freeCount = 0;
    const scheduled: Array<() => void> = [];
    const originalSetImmediate = globalThis.setImmediate;
    globalThis.setImmediate = ((value: () => void) => {
      scheduled.push(value);
      return {} as NodeJS.Immediate;
    }) as typeof setImmediate;
    try {
      const callbacks: _StreamingCallbackFacade = {
        register(value) {
          callback = value;
          return {} as ReturnType<_StreamingCallbackFacade['register']>;
        },
        unregister() {
          throw new Error('unregister failed');
        },
      };
      const native = {
        spawn(
          _request: string,
          _callback: unknown,
          _userData: unknown,
          outHandle: unknown[],
        ) {
          outHandle[0] = handle;
          return 0;
        },
        id() {
          return 7;
        },
        hasStdin() {
          return 0;
        },
        hasStdout() {
          return 0;
        },
        hasStderr() {
          return 0;
        },
        free(_handle: unknown, completion: (error: Error | null) => void) {
          freeCount += 1;
          completion(null);
        },
        freeError() {},
      } as unknown as _StreamingNativeFacade;
      const driver = _spawnStreamingDriverForTest({} as never, native, callbacks);
      driver.setEventHandler(() => {});

      callback?.(null, 8, 0, null, 0, 0, 0);
      assert.strictEqual(scheduled.length, 1);
      scheduled.shift()!();

      assert.strictEqual(freeCount, 1);
      assert.strictEqual(scheduled.length, 1);
      assert.throws(scheduled.shift()!, /unregister failed/);
    } finally {
      globalThis.setImmediate = originalSetImmediate;
    }
  });
});
