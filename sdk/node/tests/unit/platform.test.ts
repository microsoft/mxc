// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert';
import * as os from 'os';
import * as path from 'path';
import {
  getPlatformSupport,
  _resetPlatformSupportCache,
  _setProbeRunner,
  _parseBwrapVersion,
  _probeBubblewrap,
  _setBwrapVersionRunner,
  _probeBubblewrapNetwork,
  _setLinuxProbeRunner,
  findWxcExecutable,
} from '../../src/platform.js';

const isWindows = os.platform() === 'win32';

const allUiCapabilities = {
  canBlockClipboardRead: true,
  canBlockClipboardWrite: true,
  canBlockInputInjection: true,
  canBlockInputMethodChanges: true,
  canBlockExternalUiObjects: true,
  canBlockGlobalUiNamespace: true,
  canBlockDesktopSwitching: true,
  canBlockLogoffOrShutdown: true,
  canBlockSystemParameterChanges: true,
  canBlockDisplaySettingsChanges: true,
};

describe('getPlatformSupport probe integration', () => {
  beforeEach(() => {
    _resetPlatformSupportCache();
  });

  afterEach(() => {
    _setProbeRunner(null);
    _resetPlatformSupportCache();
  });

  it('returns isolationTier when probe succeeds', { skip: !isWindows }, () => {
    let calls = 0;
    _setProbeRunner(() => {
      calls += 1;
      return JSON.stringify({
        tier: 'appcontainer-bfs',
        needsDaclAugmentation: false,
        warnings: ['BaseContainer API not present'],
        probes: { baseContainerApiPresent: false, bfscfgPresent: true },
      });
    });
    const support = getPlatformSupport();
    if (!support.isSupported) {
      // Host build doesn't satisfy the version gate; the probe path is
      // not taken on this machine. Skip the assertion.
      return;
    }
    assert.strictEqual(support.isolationTier, 'appcontainer-bfs');
    assert.deepStrictEqual(support.isolationWarnings, ['BaseContainer API not present']);
    assert.strictEqual(calls, 1);
  });

  it('omits isolationTier when probe throws', { skip: !isWindows }, () => {
    _setProbeRunner(() => {
      throw new Error('boom');
    });
    const support = getPlatformSupport();
    assert.strictEqual(support.isolationTier, undefined);
    assert.strictEqual(support.isolationWarnings, undefined);
  });

  it('omits isolationTier when probe returns malformed JSON', { skip: !isWindows }, () => {
    _setProbeRunner(() => 'not json');
    const support = getPlatformSupport();
    assert.strictEqual(support.isolationTier, undefined);
    assert.strictEqual(support.isolationWarnings, undefined);
  });

  it('rejects unknown tier strings via type narrowing', { skip: !isWindows }, () => {
    _setProbeRunner(() =>
      JSON.stringify({
        tier: 'future-tier',
        warnings: [],
        probes: { baseContainerApiPresent: true, bfscfgPresent: true },
      }),
    );
    const support = getPlatformSupport();
    assert.strictEqual(support.isolationTier, undefined);
  });

  it('caches the platform-support result', { skip: !isWindows }, () => {
    let calls = 0;
    _setProbeRunner(() => {
      calls += 1;
      return JSON.stringify({
        tier: 'appcontainer-bfs',
        warnings: [],
        probes: { baseContainerApiPresent: false, bfscfgPresent: true },
      });
    });
    const a = getPlatformSupport();
    const b = getPlatformSupport();
    assert.strictEqual(a, b, 'cached object identity');
    if (a.isSupported) {
      assert.strictEqual(calls, 1, 'probe should be invoked exactly once');
    }
  });

  it('still returns base PlatformSupport shape on non-Windows', { skip: isWindows }, () => {
    const support = getPlatformSupport();
    assert.strictEqual(support.isolationTier, undefined);
    assert.strictEqual(support.isolationWarnings, undefined);
    assert.strictEqual(support.uiCapabilities, undefined);
    assert.ok(Array.isArray(support.availableMethods));
  });

  // Partial-JSON tests: the probe binary's output is parsed permissively
  // — a future schema bump that adds fields must not break older SDKs,
  // and a downlevel probe that omits fields must not crash callers.
  // `populateIsolationFromProbe` is the single point of contact; the
  // tests below stress it via `_setProbeRunner`.
  it('handles probe JSON with only `tier`', { skip: !isWindows }, () => {
    _setProbeRunner(() => JSON.stringify({ tier: 'appcontainer-dacl' }));
    const support = getPlatformSupport();
    if (!support.isSupported) return;
    assert.strictEqual(support.isolationTier, 'appcontainer-dacl');
    assert.strictEqual(
      support.isolationWarnings,
      undefined,
      'missing warnings array must leave isolationWarnings undefined',
    );
  });

  it('handles probe JSON with only `warnings`', { skip: !isWindows }, () => {
    _setProbeRunner(() => JSON.stringify({ warnings: ['msg-1', 'msg-2'] }));
    const support = getPlatformSupport();
    if (!support.isSupported) return;
    // No `tier` field → isolationTier stays unset; warnings still
    // surface so callers can observe degraded-detection state.
    assert.strictEqual(support.isolationTier, undefined);
    assert.deepStrictEqual(support.isolationWarnings, ['msg-1', 'msg-2']);
  });

  it('handles empty probe JSON object', { skip: !isWindows }, () => {
    _setProbeRunner(() => JSON.stringify({}));
    const support = getPlatformSupport();
    if (!support.isSupported) return;
    assert.strictEqual(support.isolationTier, undefined);
    assert.strictEqual(support.isolationWarnings, undefined);
  });

  it('filters non-string entries out of warnings array', { skip: !isWindows }, () => {
    _setProbeRunner(() =>
      JSON.stringify({
        tier: 'appcontainer-bfs',
        warnings: ['ok', 42, null, { not: 'a string' }, 'ok2'],
      }),
    );
    const support = getPlatformSupport();
    if (!support.isSupported) return;
    assert.deepStrictEqual(support.isolationWarnings, ['ok', 'ok2']);
  });

  it('omits isolationWarnings when filtered warnings array is empty', { skip: !isWindows }, () => {
    _setProbeRunner(() =>
      JSON.stringify({
        tier: 'appcontainer-bfs',
        warnings: [42, null], // every entry is non-string → empty after filter
      }),
    );
    const support = getPlatformSupport();
    if (!support.isSupported) return;
    assert.strictEqual(support.isolationTier, 'appcontainer-bfs');
    assert.strictEqual(support.isolationWarnings, undefined);
  });

  it('treats probe JSON that is a non-object (number, string, null) as unparseable', { skip: !isWindows }, () => {
    for (const payload of ['42', '"a string"', 'null']) {
      _resetPlatformSupportCache();
      _setProbeRunner(() => payload);
      const support = getPlatformSupport();
      assert.strictEqual(support.isolationTier, undefined, `payload=${payload}`);
      assert.strictEqual(support.isolationWarnings, undefined, `payload=${payload}`);
    }
  });

  it('surfaces portable UI capabilities from probes', { skip: !isWindows }, () => {
    _setProbeRunner(() =>
      JSON.stringify({
        tier: 'appcontainer-dacl',
        probes: {
          baseContainerApiPresent: false,
          bfscfgPresent: false,
          uiCapabilities: allUiCapabilities,
        },
      }),
    );
    const support = getPlatformSupport();
    if (!support.isSupported) return;
    assert.deepStrictEqual(support.uiCapabilities, allUiCapabilities);
  });

  it('reports input-injection blocking unsupported from probe capabilities', { skip: !isWindows }, () => {
    _setProbeRunner(() =>
      JSON.stringify({
        tier: 'appcontainer-dacl',
        probes: {
          baseContainerApiPresent: false,
          bfscfgPresent: false,
          uiCapabilities: {
            ...allUiCapabilities,
            canBlockInputInjection: false,
          },
        },
      }),
    );
    const support = getPlatformSupport();
    if (!support.isSupported) return;
    assert.strictEqual(support.uiCapabilities?.canBlockInputInjection, false);
    assert.strictEqual(support.uiCapabilities?.canBlockInputMethodChanges, true);
  });

  it('reports input-method and input-injection blocking unsupported from probe capabilities', { skip: !isWindows }, () => {
    _setProbeRunner(() =>
      JSON.stringify({
        tier: 'appcontainer-dacl',
        probes: {
          baseContainerApiPresent: false,
          bfscfgPresent: false,
          uiCapabilities: {
            ...allUiCapabilities,
            canBlockInputInjection: false,
            canBlockInputMethodChanges: false,
          },
        },
      }),
    );
    const support = getPlatformSupport();
    if (!support.isSupported) return;
    assert.strictEqual(support.uiCapabilities?.canBlockInputInjection, false);
    assert.strictEqual(support.uiCapabilities?.canBlockInputMethodChanges, false);
    assert.strictEqual(support.uiCapabilities?.canBlockClipboardRead, true);
    assert.strictEqual(support.uiCapabilities?.canBlockDisplaySettingsChanges, true);
  });

  it('omits UI capabilities when probes block is absent', { skip: !isWindows }, () => {
    _setProbeRunner(() => JSON.stringify({ tier: 'appcontainer-dacl' }));
    const support = getPlatformSupport();
    if (!support.isSupported) return;
    assert.strictEqual(support.uiCapabilities, undefined);
  });

  it('omits UI capabilities when probe omits them', { skip: !isWindows }, () => {
    _setProbeRunner(() =>
      JSON.stringify({
        tier: 'appcontainer-dacl',
        probes: {
          baseContainerApiPresent: false,
          bfscfgPresent: false,
        },
      }),
    );
    const support = getPlatformSupport();
    if (!support.isSupported) return;
    assert.strictEqual(support.uiCapabilities, undefined);
  });

  it('omits UI capabilities when probe returns a partial capability object', { skip: !isWindows }, () => {
    _setProbeRunner(() =>
      JSON.stringify({
        tier: 'appcontainer-dacl',
        probes: {
          baseContainerApiPresent: false,
          bfscfgPresent: false,
          uiCapabilities: {
            canBlockClipboardRead: true,
          },
        },
      }),
    );
    const support = getPlatformSupport();
    if (!support.isSupported) return;
    assert.strictEqual(support.uiCapabilities, undefined);
  });
});

// findWxcExecutable failure-mode: the SDK's default probe runner calls
// findWxcExecutable() and throws if it returns null. Tests below
// confirm the function never throws — only ever returns a string path
// or `null` — even under hostile inputs to its env-var search seam.
describe('findWxcExecutable failure modes', () => {
  let prevBinDir: string | undefined;

  beforeEach(() => {
    prevBinDir = process.env.MXC_BIN_DIR;
  });

  afterEach(() => {
    if (prevBinDir === undefined) {
      delete process.env.MXC_BIN_DIR;
    } else {
      process.env.MXC_BIN_DIR = prevBinDir;
    }
  });

  it('returns a string or null and never throws under a nonexistent MXC_BIN_DIR', () => {
    // Point MXC_BIN_DIR at a path that definitely doesn't exist. The
    // function should silently fall through to its standard search,
    // returning either a real path (dev machine with binaries built)
    // or null (CI sans binaries). Both are acceptable — the contract
    // we care about is "does not throw".
    process.env.MXC_BIN_DIR = path.join(
      os.tmpdir(),
      `mxc-sdk-unit-no-such-dir-${process.pid}`,
    );
    const result = findWxcExecutable();
    assert.ok(result === null || typeof result === 'string', `got: ${result}`);
  });

  it('returns a string or null when MXC_BIN_DIR is empty', () => {
    process.env.MXC_BIN_DIR = '';
    const result = findWxcExecutable();
    assert.ok(result === null || typeof result === 'string');
  });
});

// IsolationSession availability is now reported by the native probe
// (`wxc-exec --probe` -> probes.isolationSessionAvailable). These tests stub
// the probe runner so the gate can be exercised deterministically without
// depending on the host's actual build.
describe('isolation_session availability gate', () => {
  beforeEach(() => {
    _resetPlatformSupportCache();
  });

  afterEach(() => {
    _setProbeRunner(null);
    _resetPlatformSupportCache();
  });

  it('includes isolation_session when the probe reports it available', { skip: !isWindows }, () => {
    _setProbeRunner(() =>
      JSON.stringify({ tier: 'base-container', probes: { isolationSessionAvailable: true } }),
    );
    const support = getPlatformSupport();
    assert.ok(support.isSupported, 'Windows is supported regardless of iso gate');
    assert.ok(
      support.availableMethods.includes('isolation_session'),
      `expected isolation_session present, got: ${support.availableMethods.join(',')}`,
    );
  });

  it('omits isolation_session when the probe reports it unavailable', { skip: !isWindows }, () => {
    _setProbeRunner(() =>
      JSON.stringify({ tier: 'base-container', probes: { isolationSessionAvailable: false } }),
    );
    const support = getPlatformSupport();
    assert.ok(
      !support.availableMethods.includes('isolation_session'),
      `expected isolation_session absent, got: ${support.availableMethods.join(',')}`,
    );
  });

  it('omits isolation_session when the probes block omits the field', { skip: !isWindows }, () => {
    _setProbeRunner(() => JSON.stringify({ tier: 'base-container', probes: {} }));
    const support = getPlatformSupport();
    assert.ok(!support.availableMethods.includes('isolation_session'));
  });

  it('omits isolation_session when the probe fails', { skip: !isWindows }, () => {
    _setProbeRunner(() => {
      throw new Error('probe failed');
    });
    const support = getPlatformSupport();
    assert.ok(support.isSupported, 'Windows support is independent of the probe');
    assert.ok(!support.availableMethods.includes('isolation_session'));
  });

  it('always reports processcontainer as the default on Windows (no build gate)', { skip: !isWindows }, () => {
    // The runtime gate lives in the native binary; the SDK reports Windows
    // support regardless of isolation-session availability.
    _setProbeRunner(() => JSON.stringify({ probes: { isolationSessionAvailable: false } }));
    const support = getPlatformSupport();
    assert.ok(support.isSupported);
    assert.strictEqual(support.availableMethods[0], 'processcontainer');
  });
});

// The Bubblewrap probe gates on version, not just presence: `--clearenv`
// (emitted unconditionally by the Rust argument builder) only exists in
// bwrap 0.5.0+. Mirrors the Rust tests in
// `src/backends/bubblewrap/common/src/bwrap_version.rs`.
describe('bwrap version parsing', () => {
  it('parses the standard `bwrap --version` output', () => {
    assert.deepStrictEqual(_parseBwrapVersion('bubblewrap 0.11.2\n'), [0, 11, 2]);
  });

  it('parses distro-patched and short version strings', () => {
    assert.deepStrictEqual(_parseBwrapVersion('bubblewrap 0.4.1-1'), [0, 4, 1]);
    assert.deepStrictEqual(_parseBwrapVersion('bubblewrap 0.6'), [0, 6, 0]);
  });

  it('honors the Debian `+really` marker', () => {
    // `X+reallyY` ships upstream Y, not X, so Y is the effective version.
    assert.deepStrictEqual(_parseBwrapVersion('bubblewrap 0.11.0+really0.10.0'), [0, 10, 0]);
    assert.deepStrictEqual(_parseBwrapVersion('bubblewrap 0.11.0+really0.10.0-1'), [0, 10, 0]);
  });

  it('returns null when no version token is present', () => {
    assert.strictEqual(_parseBwrapVersion(''), null);
    assert.strictEqual(_parseBwrapVersion('bwrap: command not found'), null);
  });

  it('fails closed on a stray number in unrelated output', () => {
    // Regression: searching for any numeric token let unrelated output clear
    // the gate — "some other tool 999" parsed as 999.0.0. Anchoring on the
    // `bubblewrap` package name is what keeps this fail-closed.
    assert.strictEqual(_parseBwrapVersion('some other tool 999'), null);
    assert.strictEqual(_parseBwrapVersion('bwrap 0.11.2'), null);
  });

  it('rejects components that overflow the Rust parser\'s u32', () => {
    // Shared contract with `bwrap_version.rs`: an out-of-range component is a
    // malformed banner, not a very new bwrap. Without this the SDK gate would
    // admit a banner the backend's gate rejects.
    assert.strictEqual(_parseBwrapVersion('bubblewrap 99999999999999999999.0.0'), null);
    assert.strictEqual(_parseBwrapVersion('bubblewrap 0.4294967296.0'), null);
    assert.deepStrictEqual(_parseBwrapVersion('bubblewrap 4294967295.0.0'), [4294967295, 0, 0]);
  });

  it('rejects junk after the patch component', () => {
    // Regression: components past the patch were dropped unchecked, so
    // "0.5.0.invalid" cleared the gate as 0.5.0.
    assert.strictEqual(_parseBwrapVersion('bubblewrap 0.5.0.invalid'), null);
    // A numeric fourth component is a plausible distro build, not junk.
    assert.deepStrictEqual(_parseBwrapVersion('bubblewrap 0.6.0.1'), [0, 6, 0]);
  });

  it('fails closed on a present but non-numeric component', () => {
    // "0.6.invalid" must not be read as 0.6.0 — only an absent component
    // defaults to 0.
    assert.strictEqual(_parseBwrapVersion('bubblewrap 0.6.invalid'), null);
    assert.strictEqual(_parseBwrapVersion('bubblewrap 0.beta.1'), null);
    assert.strictEqual(_parseBwrapVersion('bubblewrap 0.6.'), null);
    assert.deepStrictEqual(_parseBwrapVersion('bubblewrap 1'), [1, 0, 0]);
  });
});

// The minimum-version comparison itself, driven through the injectable
// runner. Without these the SDK gate could drift from the Rust gate in
// `src/backends/bubblewrap/common/src/bwrap_version.rs` unnoticed.
describe('bwrap minimum-version gate', () => {
  afterEach(() => {
    _setBwrapVersionRunner(null);
    _resetPlatformSupportCache();
  });

  const withVersion = (stdout: string) =>
    _setBwrapVersionRunner(() => ({ kind: 'output', stdout }));

  it('accepts a version exactly at the floor', () => {
    withVersion('bubblewrap 0.5.0\n');
    assert.deepStrictEqual(_probeBubblewrap(), { available: true });
  });

  it('accepts a version above the floor', () => {
    withVersion('bubblewrap 0.11.2\n');
    assert.deepStrictEqual(_probeBubblewrap(), { available: true });
  });

  it('rejects a version below the floor and names it', () => {
    // 0.4.1 has --ro-bind-try but not --clearenv.
    withVersion('bubblewrap 0.4.1\n');
    const probe = _probeBubblewrap();
    assert.strictEqual(probe.available, false);
    assert.match(probe.reason, /0\.4\.1 is too old/);
    assert.match(probe.reason, /0\.5\.0 or newer/);
  });

  it('rejects the release immediately below the floor', () => {
    withVersion('bubblewrap 0.4.99\n');
    assert.strictEqual(_probeBubblewrap().available, false);
  });

  it('does not let a `+really` version smuggle a below-floor bwrap past the gate', () => {
    // Regression: reading the leading version accepted this as 0.5.0, even
    // though the installed bwrap is 0.4.1 and has no `--clearenv`.
    withVersion('bubblewrap 0.5.0+really0.4.1\n');
    const probe = _probeBubblewrap();
    assert.strictEqual(probe.available, false);
    assert.match(probe.reason, /0\.4\.1 is too old/);
  });

  it('fails closed on unparsable probe output', () => {
    withVersion('something else entirely\n');
    const probe = _probeBubblewrap();
    assert.strictEqual(probe.available, false);
    assert.match(probe.reason, /could not determine/);
  });

  it('fails closed when unrelated output contains a number', () => {
    withVersion('some other tool 999\n');
    const probe = _probeBubblewrap();
    assert.strictEqual(probe.available, false);
    assert.match(probe.reason, /could not determine/);
  });

  it('reports a missing binary as not installed', () => {
    _setBwrapVersionRunner(() => ({ kind: 'notFound' }));
    const probe = _probeBubblewrap();
    assert.strictEqual(probe.available, false);
    assert.match(probe.reason, /not installed or not on PATH/);
  });

  it('reports a present but broken binary distinctly from a missing one', () => {
    // A permissions/loader failure must not tell the user to install a
    // package they already have; the status and stderr must survive.
    _setBwrapVersionRunner(() => ({
      kind: 'failed',
      status: 126,
      detail: 'bwrap: permission denied',
    }));
    const probe = _probeBubblewrap();
    assert.strictEqual(probe.available, false);
    assert.match(probe.reason, /is present but/);
    assert.match(probe.reason, /126/);
    assert.match(probe.reason, /permission denied/);
    assert.doesNotMatch(probe.reason, /not installed/);
  });

  it('reports a timed-out probe as a failure rather than hanging', () => {
    // `getPlatformSupport()` is synchronous, so a hung `bwrap --version` must
    // surface as a bounded failure with the timeout named.
    _setBwrapVersionRunner(() => ({
      kind: 'failed',
      status: null,
      detail: 'timed out after 5000ms',
    }));
    const probe = _probeBubblewrap();
    assert.strictEqual(probe.available, false);
    assert.match(probe.reason, /timed out after 5000ms/);
  });

  it('describes a failure that has no exit status without claiming it never ran', () => {
    // A signal-terminated run also has a null status, so the wording must not
    // assert the process could not be executed.
    _setBwrapVersionRunner(() => ({
      kind: 'failed',
      status: null,
      detail: 'EACCES: permission denied',
    }));
    const probe = _probeBubblewrap();
    assert.strictEqual(probe.available, false);
    assert.match(probe.reason, /failed without an exit status/);
  });

  it('omits bubblewrap from getPlatformSupport below the floor', { skip: os.platform() !== 'linux' }, () => {
    withVersion('bubblewrap 0.4.1\n');
    _resetPlatformSupportCache();
    assert.ok(!getPlatformSupport().availableMethods.includes('bubblewrap'));
  });

  it('includes bubblewrap in getPlatformSupport at the floor', { skip: os.platform() !== 'linux' }, () => {
    withVersion('bubblewrap 0.5.0\n');
    _resetPlatformSupportCache();
    assert.ok(getPlatformSupport().availableMethods.includes('bubblewrap'));
  });
});

describe('_probeBubblewrapNetwork', () => {
  afterEach(() => {
    _setLinuxProbeRunner(null);
    _resetPlatformSupportCache();
  });

  it('reports supported when the probe advertises proxyEnforcement', () => {
    _setLinuxProbeRunner(() =>
      JSON.stringify([{ backend: 'bubblewrap', capabilities: ['proxyEnforcement'] }]),
    );
    assert.deepStrictEqual(_probeBubblewrapNetwork(), {
      proxyEnforcement: 'supported',
      warnings: [],
    });
  });

  it('reports unsupported with the probe reason when the capability is absent', () => {
    _setLinuxProbeRunner(() =>
      JSON.stringify([{ backend: 'bubblewrap', warnings: ['slirp4netns not found'] }]),
    );
    const result = _probeBubblewrapNetwork();
    assert.strictEqual(result.proxyEnforcement, 'unsupported');
    assert.deepStrictEqual(result.warnings, ['slirp4netns not found']);
  });

  it('ignores capabilities reported for other backends', () => {
    _setLinuxProbeRunner(() =>
      JSON.stringify([
        { backend: 'lxc', capabilities: ['proxyEnforcement'] },
        { backend: 'bubblewrap', capabilities: [] },
      ]),
    );
    assert.strictEqual(_probeBubblewrapNetwork().proxyEnforcement, 'unsupported');
  });

  it('fails closed when the probe binary cannot run', () => {
    _setLinuxProbeRunner(() => {
      throw new Error('lxc-exec not found');
    });
    const result = _probeBubblewrapNetwork();
    assert.strictEqual(result.proxyEnforcement, 'unsupported');
    assert.match(result.warnings[0], /lxc-exec not found/);
  });

  it('fails closed on malformed JSON', () => {
    _setLinuxProbeRunner(() => 'not json');
    assert.strictEqual(_probeBubblewrapNetwork().proxyEnforcement, 'unsupported');
  });

  it('fails closed when the payload is not an array', () => {
    _setLinuxProbeRunner(() => JSON.stringify({ backend: 'bubblewrap' }));
    assert.strictEqual(_probeBubblewrapNetwork().proxyEnforcement, 'unsupported');
  });

  it('fails closed when bubblewrap is absent from the payload', () => {
    _setLinuxProbeRunner(() => JSON.stringify([{ backend: 'lxc' }]));
    const result = _probeBubblewrapNetwork();
    assert.strictEqual(result.proxyEnforcement, 'unsupported');
    assert.match(result.warnings[0], /did not report bubblewrap/);
  });
});
