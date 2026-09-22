// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import assert from 'node:assert';
import { describe, it } from 'node:test';
import {
  runBindingStateAwareRequestWithNative,
  type BindingStateAwareRequest,
  type StateAwareNativeFacade,
  type StateAwareNativeResult,
} from '../../src/bindings/state-aware.js';
import { MxcError } from '../../src/errors.js';

class FakeStateAwareNative implements StateAwareNativeFacade {
  readonly calls: Array<{
    request: string;
    dryRun: number;
    experimental: number;
  }> = [];
  callbackError: Error | null = null;
  nativeStatus = 0;
  resultStatus = 0;
  freeCount = 0;

  run(
    request: string,
    dryRun: number,
    experimental: number,
    result: StateAwareNativeResult,
    completion: (error: Error | null, status: number) => void,
  ): void {
    this.calls.push({ request, dryRun, experimental });
    result.status = this.resultStatus;
    queueMicrotask(() => completion(this.callbackError, this.nativeStatus));
  }

  free(): void {
    this.freeCount += 1;
  }
}

const REQUEST: BindingStateAwareRequest = {
  requestJson: '{"phase":"start"}',
  dryRun: true,
  experimental: true,
};

describe('state-aware native binding ownership', () => {
  it('forwards flags and frees the populated result exactly once', async () => {
    const native = new FakeStateAwareNative();

    assert.strictEqual(
      await runBindingStateAwareRequestWithNative(REQUEST, native),
      '{}',
    );
    assert.deepStrictEqual(native.calls, [{
      request: REQUEST.requestJson,
      dryRun: 1,
      experimental: 1,
    }]);
    assert.strictEqual(native.freeCount, 1);
  });

  it('frees a populated result when native status decoding fails', async () => {
    const native = new FakeStateAwareNative();
    native.nativeStatus = 12;

    await assert.rejects(
      () => runBindingStateAwareRequestWithNative(REQUEST, native),
      (error: unknown) =>
        error instanceof MxcError &&
        error.code === 'backend_error',
    );
    assert.strictEqual(native.freeCount, 1);
  });

  it('frees a populated result when the result reports failure', async () => {
    const native = new FakeStateAwareNative();
    native.resultStatus = 12;

    await assert.rejects(
      () => runBindingStateAwareRequestWithNative(REQUEST, native),
      (error: unknown) =>
        error instanceof MxcError &&
        error.code === 'backend_error',
    );
    assert.strictEqual(native.freeCount, 1);
  });

  it('does not free a result when the asynchronous call itself fails', async () => {
    const native = new FakeStateAwareNative();
    native.callbackError = new Error('callback failed');

    await assert.rejects(
      () => runBindingStateAwareRequestWithNative(REQUEST, native),
      /callback failed/,
    );
    assert.strictEqual(native.freeCount, 0);
  });
});
