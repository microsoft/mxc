// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { afterEach, beforeEach, describe, it } from 'node:test';
import assert from 'node:assert';
import { EventEmitter } from 'node:events';

import {
  queryTelemetryConsentAsync,
  requestTelemetryConsent,
  withdrawTelemetryConsentAsync,
  _resetTelemetryFailureReporting,
  _setTelemetryPlatform,
  type TelemetryConsentPrompt,
} from '../../src/telemetry.js';
import {
  _setBindingTelemetryAsyncImplementation,
  TELEMETRY_CONSENT_DECISION_YES,
  TELEMETRY_CONSENT_PRESENTER_ERROR,
  type TelemetryAsyncImplementation,
} from '../../src/bindings/telemetry.js';
import {
  _setBindingTelemetryWorkerFactory,
  type BindingTelemetryWorkerLike,
  type TelemetryRequestWorkerData,
  type TelemetryRequestWorkerMessage,
} from '../../src/bindings/telemetry-request-worker.js';
import { MxcError } from '../../src/errors.js';

class FakeWorker extends EventEmitter implements BindingTelemetryWorkerLike {
  reply(message: TelemetryRequestWorkerMessage): void {
    queueMicrotask(() => this.emit('message', message));
  }

  unref(): void {}

  terminate(): void {}
}

const prompt: TelemetryConsentPrompt = {
  resourceVersion: 1,
  locale: 'en-US',
  title: { id: 'telemetry.consent.title', text: 'Help improve Microsoft eXecution Container (MXC)' },
  body: { id: 'telemetry.consent.body', text: 'canonical body' },
  affirmativeLabel: { id: 'telemetry.consent.yes', text: 'Yes' },
  negativeLabel: { id: 'telemetry.consent.no', text: 'No' },
  learnMoreLabel: { id: 'telemetry.consent.learnMore', text: 'Privacy Statement' },
  learnMoreUrl: 'https://go.microsoft.com/fwlink/?linkid=521839',
};
const promptJson = JSON.stringify(prompt);
const grantedStatusJson =
  '{"storedState":"granted","effectiveState":"granted","reason":null,"policy":"allowed"}';
const withdrawnJson =
  '{"result":"withdrawn","storedState":"denied","effectiveState":"denied","reason":null,"policy":"unrestricted"}';

function setAsyncImplementation(
  overrides: Partial<TelemetryAsyncImplementation>,
): void {
  _setBindingTelemetryAsyncImplementation({
    readConsentStatusJson: overrides.readConsentStatusJson ?? (async () => grantedStatusJson),
    withdrawConsentJson: overrides.withdrawConsentJson ?? (async () => withdrawnJson),
  });
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

describe('telemetry consent', () => {
  beforeEach(() => {
    _setTelemetryPlatform('win32');
    setAsyncImplementation({});
  });

  afterEach(() => {
    _setBindingTelemetryAsyncImplementation();
    _setBindingTelemetryWorkerFactory();
    _setTelemetryPlatform(null);
  });

  it('parses typed stored/effective status from a consistent native snapshot', async () => {
    assert.deepStrictEqual(await queryTelemetryConsentAsync(), {
      state: 'granted',
      storedState: 'granted',
      effectiveState: 'granted',
      needsPrompt: false,
      policy: 'allowed',
    });
  });

  it('fails closed when the native status payload is invalid', async () => {
    setAsyncImplementation({
      readConsentStatusJson: async () => '{"storedState":"granted"}',
    });

    const query = await queryTelemetryConsentAsync();
    assert.deepStrictEqual({
      ...query,
      error: undefined,
    }, {
      state: 'undetermined',
      storedState: 'undetermined',
      effectiveState: 'undetermined',
      needsPrompt: false,
      policy: 'blocked',
      error: undefined,
    });
    assert.match(query.error ?? '', /unrecognised telemetry consent output/);
  });

  it('deduplicates variable fail-closed details by operation and safe result', async () => {
    _resetTelemetryFailureReporting();
    const warnings: string[] = [];
    const originalWarn = console.warn;
    let call = 0;
    console.warn = (...args: unknown[]) => warnings.push(args.map(String).join(' '));
    try {
      setAsyncImplementation({
        readConsentStatusJson: async () =>
          call++ === 0 ? 'not json' : '{"storedState":1}',
      });
      assert.strictEqual((await queryTelemetryConsentAsync()).effectiveState, 'undetermined');
      assert.strictEqual((await queryTelemetryConsentAsync()).effectiveState, 'undetermined');
    } finally {
      console.warn = originalWarn;
    }
    assert.strictEqual(warnings.length, 1);
    assert.ok(warnings[0]?.includes('fail-closed'));
  });

  it('maps a typed presenter decision onto the native callback result', async () => {
    let requestData: TelemetryRequestWorkerData | undefined;
    const worker = new FakeWorker();
    _setBindingTelemetryWorkerFactory((data) => {
      requestData = data;
      return worker;
    });

    const promise = requestTelemetryConsent((value) => {
      assert.deepStrictEqual(value, prompt);
      return 'yes';
    }, 'en-US');
    await waitFor(() => requestData !== undefined);
    const decision = new Int32Array(requestData!.decisionShared);

    worker.reply({ kind: 'present', promptJson });
    await waitFor(() => Atomics.load(decision, 0) === 1);
    assert.strictEqual(Atomics.load(decision, 1), TELEMETRY_CONSENT_DECISION_YES);
    worker.reply({
      kind: 'payload',
      payload: '{"result":"granted","storedState":"granted","effectiveState":"granted","reason":null,"policy":"allowed"}',
    });

    assert.deepStrictEqual(await promise, {
      action: 'request',
      result: 'granted',
      storedState: 'granted',
      effectiveState: 'granted',
      needsPrompt: false,
      policy: 'allowed',
    });
    assert.strictEqual(requestData!.locale, 'en-US');
  });

  it('rejects invalid presenter decisions and returns the original failure', async () => {
    let requestData: TelemetryRequestWorkerData | undefined;
    const worker = new FakeWorker();
    _setBindingTelemetryWorkerFactory((data) => {
      requestData = data;
      return worker;
    });

    const promise = requestTelemetryConsent(() => 'maybe' as unknown as 'yes');
    await waitFor(() => requestData !== undefined);
    const decision = new Int32Array(requestData!.decisionShared);

    worker.reply({ kind: 'present', promptJson });
    await waitFor(() => Atomics.load(decision, 0) === 1);
    assert.strictEqual(Atomics.load(decision, 1), TELEMETRY_CONSENT_PRESENTER_ERROR);
    worker.reply({
      kind: 'error',
      error: { code: 'backend_error', message: 'requesting telemetry consent failed' },
    });

    await assert.rejects(promise, /invalid decision/);
  });

  it('rejects locales containing embedded NUL characters', async () => {
    let called = false;
    _setBindingTelemetryWorkerFactory(() => {
      called = true;
      return new FakeWorker();
    });
    await assert.rejects(
      requestTelemetryConsent(() => 'yes', 'en-US\0dev'),
      /embedded NUL/,
    );
    assert.strictEqual(called, false);
  });

  it('parses and withdraws through the native binding', async () => {
    assert.strictEqual((await queryTelemetryConsentAsync()).effectiveState, 'granted');
    assert.deepStrictEqual(await withdrawTelemetryConsentAsync(), {
      action: 'withdraw',
      result: 'withdrawn',
      storedState: 'denied',
      effectiveState: 'denied',
      needsPrompt: false,
      policy: 'unrestricted',
    });
  });

  it('rejects withdrawal responses with invalid results', async () => {
    setAsyncImplementation({
      withdrawConsentJson: async () =>
        '{"result":"status","storedState":"denied","effectiveState":"denied","reason":null,"policy":"blocked"}',
    });
    await assert.rejects(withdrawTelemetryConsentAsync(), /unrecognised telemetry consent output/);
  });

  it('preserves typed native withdrawal failures', async () => {
    const nativeError = new MxcError({
      code: 'backend_error',
      message: 'consent store write failed',
      details: { ffiStatus: 103 },
    });
    setAsyncImplementation({
      withdrawConsentJson: async () => {
        throw nativeError;
      },
    });

    await assert.rejects(
      withdrawTelemetryConsentAsync(),
      (error) => error === nativeError,
    );
  });
});

describe('telemetry consent is Windows-only', () => {
  afterEach(() => {
    _setBindingTelemetryAsyncImplementation();
    _setBindingTelemetryWorkerFactory();
    _setTelemetryPlatform(null);
  });

  for (const platform of ['linux', 'darwin'] as const) {
    it(`does not query or present consent on ${platform}`, async () => {
      _setTelemetryPlatform(platform);
      let called = false;
      setAsyncImplementation({
        readConsentStatusJson: async () => {
          called = true;
          return grantedStatusJson;
        },
        withdrawConsentJson: async () => {
          called = true;
          return withdrawnJson;
        },
      });
      _setBindingTelemetryWorkerFactory(() => {
        called = true;
        return new FakeWorker();
      });

      const request = await requestTelemetryConsent(
        () => {
          called = true;
          return 'yes';
        },
        'en-US\0dev',
      );
      assert.strictEqual(request.result, 'notApplicable');
      assert.strictEqual((await queryTelemetryConsentAsync()).state, 'not-applicable');
      assert.strictEqual((await withdrawTelemetryConsentAsync()).result, 'notApplicable');
      assert.strictEqual(called, false);
    });
  }
});
