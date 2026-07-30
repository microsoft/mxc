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
  _setWindowsBuildQuery,
  _parseBwrapVersion,
  _probeBubblewrap,
  _setBwrapVersionRunner,
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

// IsolationSession availability is gated on Windows Insider Preview build
// 26300.8553+. These tests stub the build-query seam so the gate can be
// exercised deterministically without depending on the host's actual build.
describe('isolation_session availability gate', () => {
  beforeEach(() => {
    _resetPlatformSupportCache();
  });

  afterEach(() => {
    _setWindowsBuildQuery(null);
    _resetPlatformSupportCache();
  });

  it('omits isolation_session when minor build is below 8553', { skip: !isWindows }, () => {
    _setWindowsBuildQuery(() => ({ major: 26300, minor: 8552 }));
    const support = getPlatformSupport();
    assert.ok(support.isSupported, 'Windows is supported regardless of iso gate');
    assert.ok(
      !support.availableMethods.includes('isolation_session'),
      `expected isolation_session absent, got: ${support.availableMethods.join(',')}`,
    );
  });

  it('includes isolation_session when build is exactly 26300.8553', { skip: !isWindows }, () => {
    _setWindowsBuildQuery(() => ({ major: 26300, minor: 8553 }));
    const support = getPlatformSupport();
    assert.ok(support.availableMethods.includes('isolation_session'));
  });

  it('includes isolation_session when minor is newer (26300.9999)', { skip: !isWindows }, () => {
    _setWindowsBuildQuery(() => ({ major: 26300, minor: 9999 }));
    const support = getPlatformSupport();
    assert.ok(support.availableMethods.includes('isolation_session'));
  });

  it('omits isolation_session when major is newer than 26300 (gate is pinned to the Insider Preview)', { skip: !isWindows }, () => {
    _setWindowsBuildQuery(() => ({ major: 26400, minor: 0 }));
    const support = getPlatformSupport();
    assert.ok(!support.availableMethods.includes('isolation_session'));
  });

  it('omits isolation_session when the registry query returns null', { skip: !isWindows }, () => {
    _setWindowsBuildQuery(() => null);
    const support = getPlatformSupport();
    assert.ok(!support.availableMethods.includes('isolation_session'));
  });

  it('always reports processcontainer as the default on Windows (no build gate)', { skip: !isWindows }, () => {
    // Even on a hypothetical sub-24H2 build the SDK now reports support;
    // the runtime gate has moved into the native binary.
    _setWindowsBuildQuery(() => ({ major: 22000, minor: 0 }));
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
    assert.deepStrictEqual(_parseBwrapVersion('bubblewrap 0.11.0+really0.10.0'), [0, 11, 0]);
    assert.deepStrictEqual(_parseBwrapVersion('bubblewrap 0.6'), [0, 6, 0]);
  });

  it('returns null when no version token is present', () => {
    assert.strictEqual(_parseBwrapVersion(''), null);
    assert.strictEqual(_parseBwrapVersion('bwrap: command not found'), null);
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

  it('fails closed on unparsable probe output', () => {
    withVersion('something else entirely\n');
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

  it('describes a spawn failure that has no exit status', () => {
    _setBwrapVersionRunner(() => ({
      kind: 'failed',
      status: null,
      detail: 'EACCES: permission denied',
    }));
    const probe = _probeBubblewrap();
    assert.strictEqual(probe.available, false);
    assert.match(probe.reason, /could not be executed/);
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
