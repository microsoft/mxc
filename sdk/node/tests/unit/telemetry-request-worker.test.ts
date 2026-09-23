// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { afterEach, beforeEach, describe, it } from 'node:test';
import assert from 'node:assert';
import { EventEmitter } from 'node:events';

import {
  _setBindingTelemetryWorkerFactory,
  runTelemetryConsentRequestAsync,
  type BindingTelemetryWorkerLike,
  type TelemetryRequestWorkerData,
  type TelemetryRequestWorkerMessage,
} from '../../src/bindings/telemetry-request-worker.js';
import {
  TELEMETRY_CONSENT_DECISION_YES,
  TELEMETRY_CONSENT_PRESENTER_ERROR,
} from '../../src/bindings/telemetry.js';

class FakeWorker extends EventEmitter implements BindingTelemetryWorkerLike {
  terminated = false;
  unreferenced = false;

  reply(message: TelemetryRequestWorkerMessage): void {
    queueMicrotask(() => this.emit('message', message));
  }

  fail(error: Error): void {
    queueMicrotask(() => this.emit('error', error));
  }

  exit(code: number): void {
    queueMicrotask(() => this.emit('exit', code));
  }

  unref(): void {
    this.unreferenced = true;
  }

  terminate(): void {
    this.terminated = true;
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

describe('telemetry consent request worker', () => {
  let worker: FakeWorker;
  let workerData: TelemetryRequestWorkerData | undefined;

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

  it('relays an async presenter decision through the shared callback buffer', async () => {
    const promise = runTelemetryConsentRequestAsync('en-US', async (promptJson, signal) => {
      assert.match(promptJson, /"locale":"en-US"/);
      assert.strictEqual(signal.aborted, false);
      await Promise.resolve();
      return TELEMETRY_CONSENT_DECISION_YES;
    });
    await waitFor(() => workerData !== undefined);
    const decision = new Int32Array(workerData!.decisionShared);

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
    await waitFor(() => workerData !== undefined);
    const decision = new Int32Array(workerData!.decisionShared);

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
    await waitFor(() => workerData !== undefined);
    const decision = new Int32Array(workerData!.decisionShared);

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

  it('aborts the presenter and preserves a worker error', async () => {
    let observedSignal: AbortSignal | undefined;
    const promise = runTelemetryConsentRequestAsync(undefined, async (_promptJson, signal) => {
      observedSignal = signal;
      await new Promise(() => {});
      return TELEMETRY_CONSENT_DECISION_YES;
    });
    await waitFor(() => workerData !== undefined);
    const decision = new Int32Array(workerData!.decisionShared);

    worker.reply({
      kind: 'present',
      promptJson: '{"resourceVersion":1,"locale":"en-US","title":{"id":"title","text":"Help improve MXC"},"body":{"id":"body","text":"body"},"affirmativeLabel":{"id":"yes","text":"Yes"},"negativeLabel":{"id":"no","text":"No"},"learnMoreLabel":{"id":"learn","text":"Learn more"},"learnMoreUrl":"https://example.microsoft.com/privacy"}',
    });
    await waitFor(() => observedSignal !== undefined);

    worker.fail(new Error('worker crashed'));

    await assert.rejects(promise, /worker crashed/);
    assert.strictEqual(observedSignal?.aborted, true);
    assert.strictEqual(Atomics.load(decision, 0), 1);
    assert.strictEqual(Atomics.load(decision, 1), TELEMETRY_CONSENT_PRESENTER_ERROR);
  });

  it('rejects unexpected worker messages', async () => {
    const promise = runTelemetryConsentRequestAsync(
      undefined,
      () => TELEMETRY_CONSENT_DECISION_YES,
    );
    await waitFor(() => workerData !== undefined);

    worker.reply({ kind: 'unknown' } as unknown as TelemetryRequestWorkerMessage);

    await assert.rejects(promise, /unexpected message/);
  });

  it('terminates a worker that stops making native progress', async () => {
    const promise = runTelemetryConsentRequestAsync(
      undefined,
      () => TELEMETRY_CONSENT_DECISION_YES,
      10,
    );
    await waitFor(() => workerData !== undefined);

    await assert.rejects(promise, /timed out/);
    assert.strictEqual(worker.terminated, true);
    assert.strictEqual(worker.unreferenced, true);
  });

  it('pauses the native deadline while the presenter is deciding', async () => {
    let resolvePresenter: ((decision: number) => void) | undefined;
    const promise = runTelemetryConsentRequestAsync(
      undefined,
      () => new Promise<number>((resolve) => {
        resolvePresenter = resolve;
      }),
      100,
    );
    await waitFor(() => workerData !== undefined);

    worker.reply({
      kind: 'present',
      promptJson: '{"resourceVersion":1,"locale":"en-US","title":{"id":"title","text":"Help improve MXC"},"body":{"id":"body","text":"body"},"affirmativeLabel":{"id":"yes","text":"Yes"},"negativeLabel":{"id":"no","text":"No"},"learnMoreLabel":{"id":"learn","text":"Learn more"},"learnMoreUrl":"https://example.microsoft.com/privacy"}',
    });
    await waitFor(() => resolvePresenter !== undefined);
    await new Promise((resolve) => setTimeout(resolve, 150));
    assert.strictEqual(worker.terminated, false);

    resolvePresenter!(TELEMETRY_CONSENT_DECISION_YES);
    const decision = new Int32Array(workerData!.decisionShared);
    await waitFor(() => Atomics.load(decision, 0) === 1);
    worker.reply({ kind: 'payload', payload: '{"result":"granted"}' });

    assert.strictEqual(await promise, '{"result":"granted"}');
  });

  it('fails closed before committing a decision after the deadline is exhausted', async (t) => {
    t.mock.timers.enable({ apis: ['Date'] });
    const promise = runTelemetryConsentRequestAsync(
      undefined,
      () => TELEMETRY_CONSENT_DECISION_YES,
      100,
    );
    const rejection = assert.rejects(promise, /timed out/);
    await waitFor(() => workerData !== undefined);

    t.mock.timers.tick(100);
    worker.reply({
      kind: 'present',
      promptJson: '{"resourceVersion":1,"locale":"en-US","title":{"id":"title","text":"Help improve MXC"},"body":{"id":"body","text":"body"},"affirmativeLabel":{"id":"yes","text":"Yes"},"negativeLabel":{"id":"no","text":"No"},"learnMoreLabel":{"id":"learn","text":"Learn more"},"learnMoreUrl":"https://example.microsoft.com/privacy"}',
    });

    const decision = new Int32Array(workerData!.decisionShared);
    await waitFor(() => Atomics.load(decision, 0) === 1);
    assert.strictEqual(Atomics.load(decision, 1), TELEMETRY_CONSENT_PRESENTER_ERROR);
    await rejection;
    assert.strictEqual(worker.terminated, true);
    assert.strictEqual(worker.unreferenced, true);
  });
});
