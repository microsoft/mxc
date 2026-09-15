// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { afterEach, beforeEach, describe, it } from 'node:test';
import assert from 'node:assert';
import { EventEmitter } from 'node:events';

import {
  _setBindingTelemetryWorkerFactory,
  runTelemetryConsentQueryAsync,
  runTelemetryConsentRequestAsync,
  runTelemetryConsentWithdrawAsync,
  type BindingTelemetryWorkerLike,
  type TelemetryWorkerData,
  type TelemetryWorkerMessage,
} from '../../src/bindings/telemetry-worker.js';
import {
  TELEMETRY_CONSENT_DECISION_YES,
  TELEMETRY_CONSENT_PRESENTER_ERROR,
} from '../../src/bindings/telemetry.js';

class FakeWorker extends EventEmitter implements BindingTelemetryWorkerLike {
  reply(message: TelemetryWorkerMessage): void {
    queueMicrotask(() => this.emit('message', message));
  }

  fail(error: Error): void {
    queueMicrotask(() => this.emit('error', error));
  }

  exit(code: number): void {
    queueMicrotask(() => this.emit('exit', code));
  }
}

function waitFor(condition: () => boolean, timeoutMs = 3_000): Promise<void> {
  const started = Date.now();
  return new Promise((resolve, reject) => {
    const timer = setInterval(() => {
      if (condition()) {
        clearInterval(timer);
        resolve();
        return;
      }
      if (Date.now() - started > timeoutMs) {
        clearInterval(timer);
        reject(new Error(`condition did not become true within ${timeoutMs}ms`));
      }
    }, 5);
  });
}

describe('telemetry worker bindings', () => {
  let worker: FakeWorker;
  let workerData: TelemetryWorkerData | undefined;

  beforeEach(() => {
    worker = new FakeWorker();
    workerData = undefined;
    _setBindingTelemetryWorkerFactory((data) => {
      workerData = data;
      return worker;
    });
  });

  afterEach(() => {
    _setBindingTelemetryWorkerFactory();
  });

  it('returns read-only consent snapshots from the worker', async () => {
    const promise = runTelemetryConsentQueryAsync();
    worker.reply({
      kind: 'snapshot',
      snapshot: {
        consent: 'granted',
        statusJson: '{"storedState":"granted","effectiveState":"granted","reason":null,"policy":"allowed"}',
        policy: 'allowed',
        needsPrompt: false,
      },
    });
    assert.deepStrictEqual(await promise, {
      consent: 'granted',
      statusJson: '{"storedState":"granted","effectiveState":"granted","reason":null,"policy":"allowed"}',
      policy: 'allowed',
      needsPrompt: false,
    });
  });

  it('returns withdrawal payloads from the worker', async () => {
    const promise = runTelemetryConsentWithdrawAsync();
    worker.reply({
      kind: 'payload',
      payload: '{"result":"withdrawn","storedState":"denied","effectiveState":"denied","reason":null,"policy":"unrestricted"}',
    });
    assert.strictEqual(
      await promise,
      '{"result":"withdrawn","storedState":"denied","effectiveState":"denied","reason":null,"policy":"unrestricted"}',
    );
  });

  it('relays an async presenter decision through the shared callback buffer', async () => {
    const promise = runTelemetryConsentRequestAsync('en-US', async (promptJson, signal) => {
      assert.match(promptJson, /"locale":"en-US"/);
      assert.strictEqual(signal.aborted, false);
      await Promise.resolve();
      return TELEMETRY_CONSENT_DECISION_YES;
    });
    await waitFor(() => workerData?.operation === 'request');
    const decision = new Int32Array((workerData as Extract<TelemetryWorkerData, { operation: 'request' }>).decisionShared);

    worker.reply({
      kind: 'present',
      promptJson: '{"resourceVersion":1,"locale":"en-US","title":{"id":"title","text":"Help improve MXC"},"body":{"id":"body","text":"body"},"affirmativeLabel":{"id":"yes","text":"Yes"},"negativeLabel":{"id":"no","text":"No"},"learnMoreLabel":{"id":"learn","text":"Learn more"},"learnMoreUrl":"https://example.microsoft.com/privacy"}',
    });

    await waitFor(() => Atomics.load(decision, 0) === 1);
    assert.strictEqual(Atomics.load(decision, 1), TELEMETRY_CONSENT_DECISION_YES);

    worker.reply({
      kind: 'payload',
      payload: '{"result":"granted","storedState":"granted","effectiveState":"granted","reason":null,"policy":"allowed"}',
    });

    assert.strictEqual(
      await promise,
      '{"result":"granted","storedState":"granted","effectiveState":"granted","reason":null,"policy":"allowed"}',
    );
  });

  it('preserves the original presenter failure instead of the native fallback error', async () => {
    const promise = runTelemetryConsentRequestAsync(undefined, () => {
      throw new Error('UI unavailable');
    });
    await waitFor(() => workerData?.operation === 'request');
    const decision = new Int32Array((workerData as Extract<TelemetryWorkerData, { operation: 'request' }>).decisionShared);

    worker.reply({
      kind: 'present',
      promptJson: '{"resourceVersion":1,"locale":"en-US","title":{"id":"title","text":"Help improve MXC"},"body":{"id":"body","text":"body"},"affirmativeLabel":{"id":"yes","text":"Yes"},"negativeLabel":{"id":"no","text":"No"},"learnMoreLabel":{"id":"learn","text":"Learn more"},"learnMoreUrl":"https://example.microsoft.com/privacy"}',
    });

    await waitFor(() => Atomics.load(decision, 0) === 1);
    assert.strictEqual(Atomics.load(decision, 1), TELEMETRY_CONSENT_PRESENTER_ERROR);

    worker.reply({
      kind: 'error',
      error: { code: 'backend_error', message: 'requesting telemetry consent failed' },
    });

    await assert.rejects(promise, /UI unavailable/);
  });

  it('aborts the presenter signal and wakes the native callback on worker exit', async () => {
    let observedSignal: AbortSignal | undefined;
    const promise = runTelemetryConsentRequestAsync(undefined, async (_promptJson, signal) => {
      observedSignal = signal;
      await new Promise(() => {});
      return TELEMETRY_CONSENT_DECISION_YES;
    });
    await waitFor(() => workerData?.operation === 'request');
    const decision = new Int32Array((workerData as Extract<TelemetryWorkerData, { operation: 'request' }>).decisionShared);

    worker.reply({
      kind: 'present',
      promptJson: '{"resourceVersion":1,"locale":"en-US","title":{"id":"title","text":"Help improve MXC"},"body":{"id":"body","text":"body"},"affirmativeLabel":{"id":"yes","text":"Yes"},"negativeLabel":{"id":"no","text":"No"},"learnMoreLabel":{"id":"learn","text":"Learn more"},"learnMoreUrl":"https://example.microsoft.com/privacy"}',
    });
    await waitFor(() => observedSignal !== undefined);

    worker.exit(9);

    await assert.rejects(promise, /worker exited before returning a result/);
    assert.strictEqual(observedSignal?.aborted, true);
    assert.strictEqual(Atomics.load(decision, 0), 1);
    assert.strictEqual(Atomics.load(decision, 1), TELEMETRY_CONSENT_PRESENTER_ERROR);
  });
});
