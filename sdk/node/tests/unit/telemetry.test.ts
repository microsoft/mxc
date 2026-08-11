// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert';
import {
  getTelemetryConsent,
  queryTelemetryConsent,
  needsTelemetryConsentPrompt,
  getTelemetryPolicy,
  requestTelemetryConsent,
  withdrawTelemetryConsent,
  _setTelemetryConsentRunner,
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
  affirmativeLabel: { id: 'telemetry.consent.yes', text: 'Yes, send optional diagnostic data' },
  negativeLabel: { id: 'telemetry.consent.no', text: 'No, do not send' },
  learnMoreLabel: { id: 'telemetry.consent.learnMore', text: 'Microsoft Privacy Statement' },
  learnMoreUrl: 'https://privacy.microsoft.com/privacystatement',
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

  it('fails closed on malformed output and reports the failure once', () => {
    _resetTelemetryFailureReporting();
    const warnings: string[] = [];
    const originalWarn = console.warn;
    console.warn = (...args: unknown[]) => warnings.push(args.map(String).join(' '));
    try {
      _setTelemetryConsentRunner(() => 'not json');
      assert.strictEqual(getTelemetryConsent(), 'undetermined');
      assert.strictEqual(getTelemetryPolicy(), 'blocked');
      assert.strictEqual(needsTelemetryConsentPrompt(), false);
    } finally {
      console.warn = originalWarn;
    }
    assert.strictEqual(warnings.length, 1);
    assert.match(warnings[0]!, /fail-closed/);
  });

  it('never reports a prompt alongside blocked policy', () => {
    _setTelemetryConsentRunner(() => status('undetermined', 'blocked', true));
    assert.strictEqual(needsTelemetryConsentPrompt(), false);
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
});

describe('telemetry consent is Windows-only', () => {
  afterEach(() => {
    _setTelemetryConsentRunner(null);
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
      assert.strictEqual(called, false);
    });
  }
});
