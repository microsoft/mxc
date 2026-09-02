// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert';
import {
  getTelemetryConsent,
  queryTelemetryConsent,
  queryTelemetryConsentAsync,
  needsTelemetryConsentPrompt,
  getTelemetryPolicy,
  requestTelemetryConsent,
  withdrawTelemetryConsent,
  withdrawTelemetryConsentAsync,
  _setTelemetryConsentAsyncRunner,
  _setTelemetryConsentRunner,
  _setTelemetryConsentProtocolRunner,
  _setTelemetryPlatform,
  _resetTelemetryFailureReporting,
  type TelemetryConsentPrompt,
} from '../../src/telemetry.js';

const prompt: TelemetryConsentPrompt = {
  resourceVersion: 1,
  locale: 'en-US',
  title: { id: 'telemetry.consent.title', text: 'Help improve Microsoft Products' },
  body: { id: 'telemetry.consent.body', text: 'canonical body' },
  affirmativeLabel: { id: 'telemetry.consent.yes', text: 'Yes' },
  negativeLabel: { id: 'telemetry.consent.no', text: 'No' },
  learnMoreLabel: { id: 'telemetry.consent.learnMore', text: 'Privacy Statement' },
  learnMoreUrl: 'https://go.microsoft.com/fwlink/?linkid=521839',
};

function status(
  effectiveState: 'granted' | 'denied' | 'undetermined' | 'not-applicable',
  policy: 'unrestricted' | 'allowed' | 'blocked' | 'not-applicable' = 'unrestricted',
  needsPrompt = false,
): string {
  return JSON.stringify({
    action: 'status',
    result: 'status',
    storedState: effectiveState,
    effectiveState,
    needsPrompt,
    policy,
  });
}

describe('telemetry consent', () => {
  beforeEach(() => {
    _setTelemetryPlatform('win32');
  });

  afterEach(() => {
    _setTelemetryConsentRunner(null);
    _setTelemetryConsentAsyncRunner(null);
    _setTelemetryConsentProtocolRunner(null);
    _setTelemetryPlatform(null);
  });

  it('parses typed stored/effective status', () => {
    _setTelemetryConsentRunner(() => status('granted', 'allowed'));
    assert.deepStrictEqual(queryTelemetryConsent(), {
      state: 'granted',
      storedState: 'granted',
      effectiveState: 'granted',
      needsPrompt: false,
      policy: 'allowed',
    });
    assert.strictEqual(getTelemetryConsent(), 'granted');
    assert.strictEqual(getTelemetryPolicy(), 'allowed');
  });

  it('passes status through the typed JSON maintenance envelope', () => {
    let args: readonly string[] = [];
    _setTelemetryConsentRunner((value) => {
      args = value;
      return status('undetermined', 'unrestricted', true);
    });
    assert.strictEqual(needsTelemetryConsentPrompt(), true);
    assert.strictEqual(args[0], '--config-base64');
    const request = JSON.parse(Buffer.from(args[1]!, 'base64').toString('utf8'));
    assert.deepStrictEqual(request, { command: 'telemetryConsent', action: 'status' });
  });

  it('coalesces convenience getters for one turn without caching explicit queries', async () => {
    let calls = 0;
    _setTelemetryConsentRunner(() => {
      calls += 1;
      return status('granted', 'allowed');
    });

    assert.strictEqual(getTelemetryConsent(), 'granted');
    assert.strictEqual(getTelemetryPolicy(), 'allowed');
    assert.strictEqual(needsTelemetryConsentPrompt(), false);
    assert.strictEqual(calls, 1);

    assert.strictEqual(queryTelemetryConsent().effectiveState, 'granted');
    assert.strictEqual(calls, 2);

    await Promise.resolve();
    assert.strictEqual(getTelemetryConsent(), 'granted');
    assert.strictEqual(calls, 3);
  });

  it('deduplicates each fail-closed diagnostic category', async () => {
    _resetTelemetryFailureReporting();
    const warnings: string[] = [];
    const originalWarn = console.warn;
    console.warn = (...args: unknown[]) => warnings.push(args.map(String).join(' '));
    try {
      _setTelemetryConsentRunner(() => 'not json');
      _setTelemetryConsentAsyncRunner(async () => 'not json');
      assert.strictEqual(getTelemetryConsent(), 'undetermined');
      assert.strictEqual(getTelemetryPolicy(), 'blocked');
      assert.strictEqual(needsTelemetryConsentPrompt(), false);
      assert.strictEqual(queryTelemetryConsent().effectiveState, 'undetermined');
      assert.strictEqual(queryTelemetryConsent().effectiveState, 'undetermined');
      assert.strictEqual((await queryTelemetryConsentAsync()).effectiveState, 'undetermined');
    } finally {
      console.warn = originalWarn;
    }
    assert.strictEqual(warnings.length, 2);
    assert.ok(warnings.every((warning) => /fail-closed/.test(warning)));
  });

  it('never reports a prompt alongside blocked policy', () => {
    _setTelemetryConsentRunner(() => status('undetermined', 'blocked', true));
    assert.strictEqual(needsTelemetryConsentPrompt(), false);
  });

  it('fails status queries closed for mismatched actions and invalid results', async () => {
    _setTelemetryConsentRunner(() => JSON.stringify({
      action: 'request',
      result: 'status',
      storedState: 'granted',
      effectiveState: 'granted',
      needsPrompt: false,
      policy: 'allowed',
    }));
    const syncQuery = queryTelemetryConsent();
    assert.strictEqual(syncQuery.storedState, 'undetermined');
    assert.strictEqual(syncQuery.effectiveState, 'undetermined');
    assert.strictEqual(syncQuery.policy, 'blocked');
    assert.strictEqual(syncQuery.needsPrompt, false);
    assert.match(syncQuery.error ?? '', /unrecognised telemetry consent output/);

    _setTelemetryConsentAsyncRunner(async () => JSON.stringify({
      action: 'status',
      result: 'withdrawn',
      storedState: 'granted',
      effectiveState: 'granted',
      needsPrompt: false,
      policy: 'allowed',
    }));
    const asyncQuery = await queryTelemetryConsentAsync();
    assert.strictEqual(asyncQuery.effectiveState, 'undetermined');
    assert.strictEqual(asyncQuery.policy, 'blocked');
    assert.strictEqual(asyncQuery.needsPrompt, false);
  });

  it('binds a synchronous presenter decision to the canonical prompt', async () => {
    let observedLocale: string | undefined;
    _setTelemetryConsentProtocolRunner(async (locale, presenter) => {
      observedLocale = locale;
      const decision = await presenter(prompt);
      assert.strictEqual(decision, 'yes');
      return {
        action: 'request',
        result: 'granted',
        storedState: 'granted',
        effectiveState: 'granted',
        needsPrompt: false,
        policy: 'unrestricted',
      };
    });

    const outcome = await requestTelemetryConsent((value) => {
      assert.deepStrictEqual(value, prompt);
      return 'yes';
    }, 'en-US');
    assert.strictEqual(observedLocale, 'en-US');
    assert.strictEqual(outcome.result, 'granted');
  });

  it('invalidates convenience query state around a consent request', async () => {
    let currentState: 'denied' | 'granted' = 'denied';
    let queryCalls = 0;
    _setTelemetryConsentRunner(() => {
      queryCalls += 1;
      return status(currentState);
    });
    _setTelemetryConsentProtocolRunner(async () => {
      currentState = 'granted';
      return {
        action: 'request',
        result: 'granted',
        storedState: 'granted',
        effectiveState: 'granted',
        needsPrompt: false,
        policy: 'unrestricted',
      };
    });

    assert.strictEqual(getTelemetryConsent(), 'denied');
    await requestTelemetryConsent(() => 'yes');
    assert.strictEqual(getTelemetryConsent(), 'granted');
    assert.strictEqual(queryCalls, 2);
  });

  it('supports an asynchronous presenter and propagates presenter failure', async () => {
    _setTelemetryConsentProtocolRunner(async (_locale, presenter) => {
      await presenter(prompt);
      throw new Error('should not continue');
    });
    await assert.rejects(
      requestTelemetryConsent(async () => {
        await Promise.resolve();
        throw new Error('UI unavailable');
      }),
      /UI unavailable/,
    );
  });

  it('withdraws through the typed JSON maintenance envelope', () => {
    let args: readonly string[] = [];
    _setTelemetryConsentRunner((value) => {
      args = value;
      return JSON.stringify({
        action: 'withdraw',
        result: 'withdrawn',
        storedState: 'denied',
        effectiveState: 'denied',
        needsPrompt: false,
        policy: 'blocked',
      });
    });
    const outcome = withdrawTelemetryConsent();
    assert.strictEqual(outcome.result, 'withdrawn');
    const request = JSON.parse(Buffer.from(args[1]!, 'base64').toString('utf8'));
    assert.deepStrictEqual(request, { command: 'telemetryConsent', action: 'withdraw' });
  });

  it('queries and withdraws through the non-blocking runner', async () => {
    const actions: string[] = [];
    _setTelemetryConsentAsyncRunner(async (args) => {
      const request = JSON.parse(Buffer.from(args[1]!, 'base64').toString('utf8'));
      actions.push(request.action);
      return request.action === 'status'
        ? status('granted', 'allowed')
        : JSON.stringify({
          action: 'withdraw',
          result: 'withdrawn',
          storedState: 'denied',
          effectiveState: 'denied',
          needsPrompt: false,
          policy: 'unrestricted',
        });
    });

    assert.strictEqual((await queryTelemetryConsentAsync()).effectiveState, 'granted');
    assert.strictEqual((await withdrawTelemetryConsentAsync()).result, 'withdrawn');
    assert.deepStrictEqual(actions, ['status', 'withdraw']);
  });

  it('rejects withdrawal responses with mismatched actions or invalid results', async () => {
    _setTelemetryConsentRunner(() => JSON.stringify({
      action: 'status',
      result: 'withdrawn',
      storedState: 'denied',
      effectiveState: 'denied',
      needsPrompt: false,
      policy: 'blocked',
    }));
    assert.throws(withdrawTelemetryConsent, /unrecognised telemetry consent output/);

    _setTelemetryConsentAsyncRunner(async () => JSON.stringify({
      action: 'withdraw',
      result: 'status',
      storedState: 'denied',
      effectiveState: 'denied',
      needsPrompt: false,
      policy: 'blocked',
    }));
    await assert.rejects(
      withdrawTelemetryConsentAsync(),
      /unrecognised telemetry consent output/,
    );
  });
});

describe('telemetry consent is Windows-only', () => {
  afterEach(() => {
    _setTelemetryConsentRunner(null);
    _setTelemetryConsentAsyncRunner(null);
    _setTelemetryConsentProtocolRunner(null);
    _setTelemetryPlatform(null);
  });

  for (const platform of ['linux', 'darwin'] as const) {
    it(`does not query or present consent on ${platform}`, async () => {
      _setTelemetryPlatform(platform);
      let called = false;
      _setTelemetryConsentRunner(() => {
        called = true;
        throw new Error('must not run');
      });
      _setTelemetryConsentProtocolRunner(async () => {
        called = true;
        throw new Error('must not run');
      });

      assert.strictEqual(getTelemetryConsent(), 'not-applicable');
      const request = await requestTelemetryConsent(() => {
        called = true;
        return 'yes';
      });
      assert.strictEqual(request.result, 'notApplicable');
      assert.strictEqual(withdrawTelemetryConsent().result, 'notApplicable');
      assert.strictEqual((await queryTelemetryConsentAsync()).state, 'not-applicable');
      assert.strictEqual((await withdrawTelemetryConsentAsync()).result, 'notApplicable');
      assert.strictEqual(called, false);
    });
  }
});
