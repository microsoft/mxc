// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert';
import {
  queryTelemetryConsentAsync,
  requestTelemetryConsent,
  withdrawTelemetryConsentAsync,
  _setTelemetryConsentAsyncRunner,
  _setTelemetryConsentProtocolRunner,
  _setTelemetryPlatform,
  _resetTelemetryFailureReporting,
  type TelemetryConsentPrompt,
} from '../../src/telemetry.js';

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
    _setTelemetryConsentAsyncRunner(null);
    _setTelemetryConsentProtocolRunner(null);
    _setTelemetryPlatform(null);
  });

  it('parses typed stored/effective status', async () => {
    _setTelemetryConsentAsyncRunner(async () => status('granted', 'allowed'));
    assert.deepStrictEqual(await queryTelemetryConsentAsync(), {
      state: 'granted',
      storedState: 'granted',
      effectiveState: 'granted',
      needsPrompt: false,
      policy: 'allowed',
    });
  });

  it('queries status through the dedicated consent command', async () => {
    let args: readonly string[] = [];
    _setTelemetryConsentAsyncRunner(async (value) => {
      args = value;
      return status('undetermined', 'unrestricted', true);
    });
    assert.strictEqual((await queryTelemetryConsentAsync()).needsPrompt, true);
    assert.deepStrictEqual(args, ['--telemetry-consent', 'status']);
    assert.ok(!args.includes('--config-base64'));
  });

  it('deduplicates each fail-closed diagnostic category', async () => {
    _resetTelemetryFailureReporting();
    const warnings: string[] = [];
    const originalWarn = console.warn;
    console.warn = (...args: unknown[]) => warnings.push(args.map(String).join(' '));
    try {
      _setTelemetryConsentAsyncRunner(async () => 'not json');
      assert.strictEqual((await queryTelemetryConsentAsync()).effectiveState, 'undetermined');
      assert.strictEqual((await queryTelemetryConsentAsync()).effectiveState, 'undetermined');
      _setTelemetryConsentAsyncRunner(async () => 'different invalid output');
      assert.strictEqual((await queryTelemetryConsentAsync()).effectiveState, 'undetermined');
    } finally {
      console.warn = originalWarn;
    }
    assert.strictEqual(warnings.length, 2);
    assert.ok(warnings.every((warning) => /fail-closed/.test(warning)));
  });

  it('never reports a prompt alongside blocked policy', async () => {
    _setTelemetryConsentAsyncRunner(async () => status('undetermined', 'blocked', true));
    assert.strictEqual((await queryTelemetryConsentAsync()).needsPrompt, false);
  });

  it('fails status queries closed for mismatched actions and invalid results', async () => {
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

  it('queries and withdraws through the non-blocking runner', async () => {
    const actions: string[] = [];
    _setTelemetryConsentAsyncRunner(async (args) => {
      assert.deepStrictEqual(args.slice(0, 1), ['--telemetry-consent']);
      const action = args[1]!;
      actions.push(action);
      return action === 'status'
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
    _setTelemetryConsentAsyncRunner(null);
    _setTelemetryConsentProtocolRunner(null);
    _setTelemetryPlatform(null);
  });

  for (const platform of ['linux', 'darwin'] as const) {
    it(`does not query or present consent on ${platform}`, async () => {
      _setTelemetryPlatform(platform);
      let called = false;
      _setTelemetryConsentAsyncRunner(async () => {
        called = true;
        throw new Error('must not run');
      });
      _setTelemetryConsentProtocolRunner(async () => {
        called = true;
        throw new Error('must not run');
      });

      const request = await requestTelemetryConsent(() => {
        called = true;
        return 'yes';
      });
      assert.strictEqual(request.result, 'notApplicable');
      assert.strictEqual((await queryTelemetryConsentAsync()).state, 'not-applicable');
      assert.strictEqual((await withdrawTelemetryConsentAsync()).result, 'notApplicable');
      assert.strictEqual(called, false);
    });
  }
});
