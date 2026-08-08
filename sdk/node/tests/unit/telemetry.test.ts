// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert';
import {
  getTelemetryConsent,
  queryTelemetryConsent,
  needsTelemetryConsentPrompt,
  getTelemetryPolicy,
  setTelemetryConsent,
  _setTelemetryConsentRunner,
  _setTelemetryPlatform,
  _resetTelemetryFailureReporting,
} from '../../src/telemetry.js';

describe('telemetry consent', () => {
  // Every test in this block exercises the Windows behaviour via the injected
  // runner; pin the platform so the Windows-only guards don't short-circuit
  // them on a Linux/macOS CI agent. The non-Windows guards get their own
  // block below.
  beforeEach(() => {
    _setTelemetryPlatform('win32');
  });

  afterEach(() => {
    _setTelemetryConsentRunner(null);
    _setTelemetryPlatform(null);
  });

  it('getTelemetryConsent parses a granted response', () => {
    _setTelemetryConsentRunner(() => '{"consent":"granted","needsPrompt":false,"policy":"unrestricted"}');
    assert.strictEqual(getTelemetryConsent(), 'granted');
  });

  it('getTelemetryConsent parses a denied response', () => {
    _setTelemetryConsentRunner(() => '{"consent":"denied","needsPrompt":false,"policy":"unrestricted"}');
    assert.strictEqual(getTelemetryConsent(), 'denied');
  });

  it('getTelemetryConsent parses a not-applicable response from the runner', () => {
    _setTelemetryConsentRunner(() => '{"consent":"not-applicable","needsPrompt":false,"policy":"unrestricted"}');
    assert.strictEqual(getTelemetryConsent(), 'not-applicable');
  });

  it('getTelemetryConsent fails closed to undetermined on malformed output', () => {
    _setTelemetryConsentRunner(() => 'not json at all');
    assert.strictEqual(getTelemetryConsent(), 'undetermined');
  });

  it('getTelemetryConsent fails closed to undetermined on an unrecognised consent value', () => {
    _setTelemetryConsentRunner(() => '{"consent":"maybe"}');
    assert.strictEqual(getTelemetryConsent(), 'undetermined');
  });

  it('getTelemetryConsent never throws when the runner throws (e.g. missing/blocked binary)', () => {
    _setTelemetryConsentRunner(() => {
      throw new Error('ENOENT: spawn wxc-exec.exe');
    });
    assert.doesNotThrow(() => getTelemetryConsent());
    assert.strictEqual(getTelemetryConsent(), 'undetermined');
  });

  it('getTelemetryConsent passes --telemetry-consent-status', () => {
    let capturedArgs: readonly string[] | undefined;
    _setTelemetryConsentRunner((args) => {
      capturedArgs = args;
      return '{"consent":"undetermined","needsPrompt":true,"policy":"unrestricted"}';
    });
    getTelemetryConsent();
    assert.deepStrictEqual(capturedArgs, ['--telemetry-consent-status']);
  });

  it('needsTelemetryConsentPrompt surfaces the native needsPrompt for every consent state', () => {
    _setTelemetryConsentRunner(() => '{"consent":"undetermined","needsPrompt":true,"policy":"unrestricted"}');
    assert.strictEqual(needsTelemetryConsentPrompt(), true);

    _setTelemetryConsentRunner(() => '{"consent":"granted","needsPrompt":false,"policy":"unrestricted"}');
    assert.strictEqual(needsTelemetryConsentPrompt(), false);

    _setTelemetryConsentRunner(() => '{"consent":"denied","needsPrompt":false,"policy":"unrestricted"}');
    assert.strictEqual(needsTelemetryConsentPrompt(), false);

    _setTelemetryConsentRunner(() => '{"consent":"not-applicable","needsPrompt":false,"policy":"unrestricted"}');
    assert.strictEqual(needsTelemetryConsentPrompt(), false);
  });

  it('setTelemetryConsent(true) passes --telemetry-consent-grant and a source', () => {
    let capturedArgs: readonly string[] | undefined;
    _setTelemetryConsentRunner((args) => {
      capturedArgs = args;
      return '{"consent":"granted","needsPrompt":false,"policy":"unrestricted"}';
    });
    setTelemetryConsent(true, 'prompt');
    assert.deepStrictEqual(capturedArgs, [
      '--telemetry-consent-grant',
      '--telemetry-consent-source',
      'prompt',
    ]);
  });

  it('setTelemetryConsent(false) passes --telemetry-consent-revoke', () => {
    let capturedArgs: readonly string[] | undefined;
    _setTelemetryConsentRunner((args) => {
      capturedArgs = args;
      return '{"consent":"denied","needsPrompt":false,"policy":"unrestricted"}';
    });
    setTelemetryConsent(false);
    assert.deepStrictEqual(capturedArgs, [
      '--telemetry-consent-revoke',
      '--telemetry-consent-source',
      'sdk',
    ]);
  });

  it('setTelemetryConsent throws when the runner throws (e.g. missing/blocked binary)', () => {
    _setTelemetryConsentRunner(() => {
      throw new Error('spawn failed');
    });
    assert.throws(() => setTelemetryConsent(true), /failed to persist telemetry consent/);
  });

  it('setTelemetryConsent throws when the reported state does not match the request', () => {
    // Simulates a host where wxc-exec refuses the grant/revoke and always
    // reports not-applicable.
    _setTelemetryConsentRunner(() => '{"consent":"not-applicable","needsPrompt":false,"policy":"unrestricted"}');
    assert.throws(() => setTelemetryConsent(true), /failed to persist telemetry consent/);
  });

  it('queryTelemetryConsent reports no error on a clean read', () => {
    _setTelemetryConsentRunner(() => '{"consent":"granted","needsPrompt":false,"policy":"unrestricted"}');
    assert.deepStrictEqual(queryTelemetryConsent(), {
      state: 'granted',
      needsPrompt: false,
      policy: 'unrestricted',
    });
  });

  it('queryTelemetryConsent surfaces the runner failure that forced undetermined', () => {
    _setTelemetryConsentRunner(() => {
      throw new Error('ENOENT: spawn wxc-exec.exe');
    });
    const result = queryTelemetryConsent();
    assert.strictEqual(result.state, 'undetermined');
    assert.strictEqual(result.needsPrompt, false);
    assert.match(result.error ?? '', /ENOENT/);
  });

  it('the built-in runner never reports not-applicable on Windows', () => {
    // Regression guard: the default runner used to synthesise a
    // 'not-applicable' payload when it could not locate wxc-exec. Every public
    // entry point already returns early off Windows, so that branch is only
    // reachable on a Windows host with a broken install — where reporting
    // 'not-applicable' tells the host this machine never collects telemetry
    // and hides the failure instead of surfacing it via `error`.
    //
    // Uses the real runner (no injection). Where the binary is present this
    // spawns a read-only status query; where it is absent the runner throws
    // and we fall closed to 'undetermined'. Either way 'not-applicable' is the
    // one answer that must never come back on win32.
    _setTelemetryConsentRunner(null);
    const result = queryTelemetryConsent();
    assert.notStrictEqual(result.state, 'not-applicable');
    assert.notStrictEqual(result.policy, 'not-applicable');
    if (result.error !== undefined) {
      assert.strictEqual(result.state, 'undetermined');
      assert.strictEqual(result.policy, 'blocked');
      assert.strictEqual(result.needsPrompt, false);
    }
  });

  it('a fail-closed read is reported to the console exactly once per distinct failure', () => {
    // The three convenience getters discard the `error` field entirely, so
    // without this a broken install is completely silent. Deduplicated because
    // a host may poll these getters to render a settings toggle.
    _resetTelemetryFailureReporting();
    const warnings: string[] = [];
    const originalWarn = console.warn;
    console.warn = (...args: unknown[]) => {
      warnings.push(args.map(String).join(' '));
    };
    try {
      _setTelemetryConsentRunner(() => {
        throw new Error('ENOENT: spawn wxc-exec.exe');
      });
      getTelemetryConsent();
      getTelemetryPolicy();
      needsTelemetryConsentPrompt();
    } finally {
      console.warn = originalWarn;
    }
    assert.strictEqual(warnings.length, 1, `expected one warning, got: ${JSON.stringify(warnings)}`);
    assert.match(warnings[0]!, /fail-closed/);
    assert.match(warnings[0]!, /ENOENT/);
  });

  it('reporting a fail-closed read never throws even if console.warn does', () => {
    // The reporter runs on the path whose entire purpose is to guarantee the
    // caller cannot crash, so it must not be able to introduce a failure.
    _resetTelemetryFailureReporting();
    const originalWarn = console.warn;
    console.warn = () => {
      throw new Error('console is unavailable');
    };
    try {
      _setTelemetryConsentRunner(() => {
        throw new Error('ENOENT: spawn wxc-exec.exe');
      });
      assert.doesNotThrow(() => getTelemetryConsent());
      assert.strictEqual(getTelemetryConsent(), 'undetermined');
    } finally {
      console.warn = originalWarn;
    }
  });

  it('queryTelemetryConsent surfaces malformed output that forced undetermined', () => {
    _setTelemetryConsentRunner(() => 'not json at all');
    const result = queryTelemetryConsent();
    assert.strictEqual(result.state, 'undetermined');
    assert.strictEqual(result.needsPrompt, false);
    assert.match(result.error ?? '', /unrecognised/);
  });

  it('queryTelemetryConsent reports no error for a genuine undetermined store', () => {
    _setTelemetryConsentRunner(() => '{"consent":"undetermined","needsPrompt":true,"policy":"unrestricted"}');
    assert.deepStrictEqual(queryTelemetryConsent(), {
      state: 'undetermined',
      needsPrompt: true,
      policy: 'unrestricted',
    });
  });

  it('queryTelemetryConsent does not mistake garbage containing "undetermined" for a real read', () => {
    // Regression: the error was once inferred by searching raw stdout for the
    // literal '"undetermined"'. Unparseable output that happens to contain
    // that substring then masqueraded as a genuine undecided store, with no
    // error and no warning.
    _setTelemetryConsentRunner(() => 'garbage "undetermined"');
    const result = queryTelemetryConsent();
    assert.strictEqual(result.state, 'undetermined');
    assert.strictEqual(result.policy, 'blocked');
    assert.match(result.error ?? '', /unrecognised/);
  });

  it('queryTelemetryConsent surfaces a policy parse failure even when consent parsed cleanly', () => {
    // Regression: a valid consent value paired with an unrecognised policy
    // silently fell back to 'blocked' with no error, because the old
    // substring check only ever fired when the *consent* value was
    // unreadable.
    _setTelemetryConsentRunner(() => '{"consent":"undetermined","needsPrompt":true,"policy":"nonsense"}');
    const result = queryTelemetryConsent();
    assert.strictEqual(result.state, 'undetermined');
    assert.strictEqual(result.policy, 'blocked');
    assert.strictEqual(result.needsPrompt, false);
    assert.match(result.error ?? '', /policy/);
  });

  it('needsTelemetryConsentPrompt reports the native answer rather than deriving it', () => {
    // The prompt policy lives in Rust (ConsentState::needs_prompt). The SDK
    // must not second-guess it by re-deriving `state === 'undetermined'`,
    // otherwise the policy would have to be changed in four languages.
    _setTelemetryConsentRunner(() => '{"consent":"undetermined","needsPrompt":false,"policy":"unrestricted"}');
    assert.strictEqual(needsTelemetryConsentPrompt(), false);

    _setTelemetryConsentRunner(() => '{"consent":"granted","needsPrompt":true,"policy":"unrestricted"}');
    assert.strictEqual(needsTelemetryConsentPrompt(), true);
  });

  it('needsTelemetryConsentPrompt fails closed when the binary omits needsPrompt', () => {
    // A wxc-exec older than this SDK. Never prompt on a guess: the answer
    // could not be persisted by that binary's SDK contract anyway.
    _setTelemetryConsentRunner(() => '{"consent":"undetermined"}');
    assert.strictEqual(needsTelemetryConsentPrompt(), false);
    assert.strictEqual(getTelemetryConsent(), 'undetermined');
  });

  it('getTelemetryPolicy reports the native answer', () => {
    for (const state of ['unrestricted', 'allowed', 'blocked'] as const) {
      _setTelemetryConsentRunner(() => `{"consent":"denied","needsPrompt":false,"policy":"${state}"}`);
      assert.strictEqual(getTelemetryPolicy(), state);
    }
  });

  it('getTelemetryPolicy fails closed to blocked when the field is absent or unrecognised', () => {
    // A wxc-exec older than this SDK, or a corrupted payload. Reporting the
    // permissive 'unrestricted' on a guess would let a host claim telemetry is
    // administratively permitted when it may not be.
    _setTelemetryConsentRunner(() => '{"consent":"denied","needsPrompt":false}');
    assert.strictEqual(getTelemetryPolicy(), 'blocked');

    _setTelemetryConsentRunner(() => '{"consent":"denied","needsPrompt":false,"policy":"whatever"}');
    assert.strictEqual(getTelemetryPolicy(), 'blocked');
  });

  it('getTelemetryPolicy fails closed to blocked when the runner fails', () => {
    _setTelemetryConsentRunner(() => {
      throw new Error('ENOENT: spawn wxc-exec.exe');
    });
    assert.strictEqual(getTelemetryPolicy(), 'blocked');

    _setTelemetryConsentRunner(() => 'not json at all');
    assert.strictEqual(getTelemetryPolicy(), 'blocked');
  });

  it('an administrative block suppresses the prompt without erasing the user decision', () => {
    // The CLI already suppresses `needsPrompt` under a blocking policy; the
    // SDK must pass that through verbatim and still report the user's own
    // recorded state, so a host can explain the situation accurately.
    _setTelemetryConsentRunner(() => '{"consent":"granted","needsPrompt":false,"policy":"blocked"}');
    assert.strictEqual(needsTelemetryConsentPrompt(), false);
    assert.strictEqual(getTelemetryConsent(), 'granted');
    assert.strictEqual(getTelemetryPolicy(), 'blocked');
  });

  it('never reports needsPrompt alongside a blocked policy', () => {
    // A wxc-exec older than this SDK omits the policy field, so we default it
    // to 'blocked' — but it would still report needsPrompt:true on a fresh
    // store. Passing that pair through would have the host prompt for a
    // decision it simultaneously claims cannot take effect.
    _setTelemetryConsentRunner(() => '{"consent":"undetermined","needsPrompt":true}');
    const query = queryTelemetryConsent();
    assert.strictEqual(query.policy, 'blocked');
    assert.strictEqual(query.needsPrompt, false);
    assert.strictEqual(needsTelemetryConsentPrompt(), false);

    // Same coercion when the policy field is present but blocking and the
    // native layer somehow disagrees with itself.
    _setTelemetryConsentRunner(
      () => '{"consent":"undetermined","needsPrompt":true,"policy":"blocked"}',
    );
    assert.strictEqual(needsTelemetryConsentPrompt(), false);
  });

  it('queryTelemetryConsent answers all three questions from a single spawn', () => {
    // The convenience getters each spawn wxc-exec, so a startup path that
    // needs more than one field must use this instead of calling them in
    // sequence. Guards that the snapshot really is a single invocation.
    let calls = 0;
    _setTelemetryConsentRunner(() => {
      calls += 1;
      return '{"consent":"granted","needsPrompt":false,"policy":"allowed"}';
    });

    const query = queryTelemetryConsent();
    assert.strictEqual(calls, 1);
    assert.strictEqual(query.state, 'granted');
    assert.strictEqual(query.needsPrompt, false);
    assert.strictEqual(query.policy, 'allowed');
  });
});

describe('telemetry consent is Windows-only', () => {
  afterEach(() => {
    _setTelemetryConsentRunner(null);
    _setTelemetryPlatform(null);
  });

  for (const platform of ['linux', 'darwin'] as const) {
    it(`getTelemetryConsent returns not-applicable on ${platform} even if the runner fails`, () => {
      _setTelemetryPlatform(platform);
      _setTelemetryConsentRunner(() => {
        throw new Error('this must never be called');
      });
      assert.strictEqual(getTelemetryConsent(), 'not-applicable');
    });

    it(`needsTelemetryConsentPrompt is false on ${platform} even if the runner fails`, () => {
      // The load-bearing assertion: MXC must never drive a host into showing
      // a telemetry consent prompt on a platform where it collects nothing.
      _setTelemetryPlatform(platform);
      _setTelemetryConsentRunner(() => {
        throw new Error('this must never be called');
      });
      assert.strictEqual(needsTelemetryConsentPrompt(), false);
    });

    it(`setTelemetryConsent throws on ${platform} without spawning anything`, () => {
      _setTelemetryPlatform(platform);
      let called = false;
      _setTelemetryConsentRunner(() => {
        called = true;
        return '{"consent":"granted","needsPrompt":false,"policy":"unrestricted"}';
      });
      assert.throws(() => setTelemetryConsent(true), /only.*on Windows/);
      assert.strictEqual(called, false);
    });

    it(`getTelemetryPolicy is not-applicable on ${platform} even if the runner fails`, () => {
      // Administrative policy is only meaningful where telemetry can be
      // collected. Reporting 'blocked' here would wrongly imply an
      // administrator had acted.
      _setTelemetryPlatform(platform);
      _setTelemetryConsentRunner(() => {
        throw new Error('this must never be called');
      });
      assert.strictEqual(getTelemetryPolicy(), 'not-applicable');
    });
  }
});

