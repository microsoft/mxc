// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import assert from 'node:assert';
import { describe, it } from 'node:test';
import {
  runBindingStateAwareAttachedRequestWithNative,
  runBindingStateAwareRequestWithNative,
  type BindingStateAwareRequest,
  type StateAwareAttachedNativeFacade,
  type StateAwareAttachedOutcome,
  type StateAwareNativeFacade,
  type StateAwareNativeResult,
} from '../../src/bindings/state-aware.js';
import type { AbiErrorDetail } from '../../src/bindings/native-error.js';
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

class FakeStateAwareAttachedNative implements StateAwareAttachedNativeFacade {
  readonly calls: Array<{ request: string; experimental: number }> = [];
  nativeStatus = 0;
  freeCount = 0;
  outcome: StateAwareAttachedOutcome = { timed_out: 0, exit_code: 7 };

  execAttached(
    request: string,
    experimental: number,
    outcome: StateAwareAttachedOutcome,
    _error: AbiErrorDetail,
  ): number {
    this.calls.push({ request, experimental });
    outcome.timed_out = this.outcome.timed_out;
    outcome.exit_code = this.outcome.exit_code;
    return this.nativeStatus;
  }

  freeError(): void {
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

describe('state-aware attached native binding ownership', () => {
  it('forwards the request and maps the terminal outcome', () => {
    const native = new FakeStateAwareAttachedNative();
    native.outcome = { timed_out: 1, exit_code: 0 };

    assert.deepStrictEqual(
      runBindingStateAwareAttachedRequestWithNative(
        '{"phase":"exec"}',
        true,
        native,
      ),
      { exitCode: 0, timedOut: true },
    );
    assert.deepStrictEqual(native.calls, [{
      request: '{"phase":"exec"}',
      experimental: 1,
    }]);
    assert.strictEqual(native.freeCount, 1);
  });

  it('decodes native failures and frees error detail', () => {
    const native = new FakeStateAwareAttachedNative();
    native.nativeStatus = 12;

    assert.throws(
      () => runBindingStateAwareAttachedRequestWithNative(
        '{"phase":"exec"}',
        false,
        native,
      ),
      (error: unknown) =>
        error instanceof MxcError &&
        error.code === 'backend_error',
    );
    assert.strictEqual(native.freeCount, 1);
  });
});
