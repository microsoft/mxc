// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import assert from 'node:assert';
import { describe, it } from 'node:test';
import {
  runBindingStateAwareRequestWithNative,
  type BindingStateAwareRequest,
  type StateAwareNativeFacade,
  type StateAwareNativeResult,
  type TypedStateAwareNativeResult,
} from '../../src/bindings/state-aware.js';
import {
  MXC_STATE_AWARE_START,
  type MxcTypedStateAwareRequest,
} from '../../src/bindings/typed-abi.js';
import { MxcError } from '../../src/errors.js';

class FakeStateAwareNative implements StateAwareNativeFacade {
  readonly jsonCalls: Array<{
    request: string;
    dryRun: number;
    experimental: number;
  }> = [];
  readonly typedCalls: Array<{
    request: MxcTypedStateAwareRequest;
    dryRun: number;
  }> = [];
  callbackError: Error | null = null;
  nativeStatus = 0;
  resultStatus = 0;
  freeJsonCount = 0;
  freeTypedCount = 0;

  runJson(
    request: string,
    dryRun: number,
    experimental: number,
    result: StateAwareNativeResult,
    completion: (error: Error | null, status: number) => void,
  ): void {
    this.jsonCalls.push({ request, dryRun, experimental });
    result.status = this.resultStatus;
    queueMicrotask(() => completion(this.callbackError, this.nativeStatus));
  }

  runTyped(
    request: MxcTypedStateAwareRequest,
    dryRun: number,
    result: TypedStateAwareNativeResult,
    completion: (error: Error | null, status: number) => void,
  ): void {
    this.typedCalls.push({ request, dryRun });
    result.status = this.resultStatus;
    result.sandboxIdUtf8 = null;
    queueMicrotask(() => completion(this.callbackError, this.nativeStatus));
  }

  freeJson(): void {
    this.freeJsonCount += 1;
  }

  freeTyped(): void {
    this.freeTypedCount += 1;
  }
}

const REQUEST: BindingStateAwareRequest = {
  requestJson: '{"version":"1.0.0","phase":"start","sandboxId":"iso:abc"}',
  dryRun: true,
  experimental: true,
};

const JSON_REQUEST: BindingStateAwareRequest = {
  requestJson: '{"version":"1.1.0-alpha","phase":"provision","containment":"windows_sandbox"}',
  dryRun: true,
  experimental: true,
};

describe('state-aware native binding ownership', () => {
  it('marshals stable lifecycle requests to typed FFI and frees the result once', async () => {
    const native = new FakeStateAwareNative();

    assert.strictEqual(
      await runBindingStateAwareRequestWithNative(REQUEST, native),
      '{"result":{}}',
    );
    assert.strictEqual(native.jsonCalls.length, 0);
    assert.strictEqual(native.typedCalls.length, 1);
    assert.strictEqual(native.typedCalls[0]!.dryRun, 1);
    assert.strictEqual(native.typedCalls[0]!.request.operation, MXC_STATE_AWARE_START);
    assert.strictEqual(native.typedCalls[0]!.request.experimental, 1);
    assert.strictEqual(native.freeTypedCount, 1);
  });

  it('keeps Windows Sandbox lifecycle on the explicit JSON FFI lane', async () => {
    const native = new FakeStateAwareNative();

    assert.strictEqual(
      await runBindingStateAwareRequestWithNative(JSON_REQUEST, native),
      '{}',
    );
    assert.deepStrictEqual(native.jsonCalls, [{
      request: JSON_REQUEST.requestJson,
      dryRun: 1,
      experimental: 1,
    }]);
    assert.strictEqual(native.typedCalls.length, 0);
    assert.strictEqual(native.freeJsonCount, 1);
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
    assert.strictEqual(native.freeTypedCount, 1);
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
    assert.strictEqual(native.freeTypedCount, 1);
  });

  it('does not free a result when the asynchronous call itself fails', async () => {
    const native = new FakeStateAwareNative();
    native.callbackError = new Error('callback failed');

    await assert.rejects(
      () => runBindingStateAwareRequestWithNative(REQUEST, native),
      /callback failed/,
    );
    assert.strictEqual(native.freeTypedCount, 0);
  });
});
