// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert';
import * as os from 'os';
import * as fs from 'fs';
import * as path from 'path';
import {
  getPlatformSupport,
  _resetPlatformSupportCache,
  _setProbeRunner,
  _setWindowsBuildQuery,
  findWxcExecutable,
  findLxcExecutable,
  findSeatbeltExecutable,
  getPlatformPackageName,
  getExecutableBinaryName,
  isSupportedPlatformTuple,
  getRustTargetTriple,
  _setPlatformPackageDir,
  _setDevMode,
  _setHostId,
  _setSdkRequire,
  _setSdkPackageRoot,
  _validatePlatformPackageDir,
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

// Per-platform binary package discovery (#512). Tests default to PRODUCTION
// resolution mode (_setDevMode(false)) so the injected platform package is the
// trusted source; dev-mode and fail-closed behavior are exercised explicitly.
describe('per-platform binary package discovery', () => {
  let prevBinDir: string | undefined;
  const tempDirs: string[] = [];

  function makeTempDir(): string {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mxc-sdk-platpkg-'));
    tempDirs.push(dir);
    return dir;
  }

  // Stage a fake, executable binary so verifyExecutable() accepts it on every OS
  // (it checks X_OK on non-Windows for non-.exe binaries).
  function stageBinary(dir: string, name: string): string {
    const p = path.join(dir, name);
    fs.writeFileSync(p, '#!/bin/sh\nexit 0\n', { mode: 0o755 });
    return p;
  }

  beforeEach(() => {
    prevBinDir = process.env.MXC_BIN_DIR;
    delete process.env.MXC_BIN_DIR;
    _setDevMode(false);
  });

  afterEach(() => {
    _setPlatformPackageDir(undefined);
    _setDevMode(null);
    _setHostId(null);
    _setSdkRequire(undefined);
    _setSdkPackageRoot(undefined);
    if (prevBinDir === undefined) {
      delete process.env.MXC_BIN_DIR;
    } else {
      process.env.MXC_BIN_DIR = prevBinDir;
    }
    // Iterate a copy and tolerate per-dir failures (EBUSY/EPERM on Windows) so a
    // single rmSync throw cannot leak the remaining temp dirs.
    for (const d of tempDirs.splice(0)) {
      try {
        fs.rmSync(d, { recursive: true, force: true });
      } catch {
        // best-effort cleanup
      }
    }
  });

  it('getPlatformPackageName matches the current host os/arch', () => {
    const arch = os.arch() === 'arm64' ? 'arm64' : 'x64';
    assert.strictEqual(
      getPlatformPackageName(),
      `@microsoft/mxc-sdk-${process.platform}-${arch}`,
    );
  });

  it('getExecutableBinaryName returns the right binary per OS', () => {
    assert.strictEqual(getExecutableBinaryName('win32'), 'wxc-exec.exe');
    assert.strictEqual(getExecutableBinaryName('linux'), 'lxc-exec');
    assert.strictEqual(getExecutableBinaryName('darwin'), 'mxc-exec-mac');
  });

  it('isSupportedPlatformTuple covers the shipped set and rejects 32-bit', () => {
    for (const t of ['win32-x64', 'win32-arm64', 'linux-x64', 'linux-arm64', 'darwin-arm64', 'darwin-x64']) {
      const [p, a] = t.split('-');
      assert.strictEqual(isSupportedPlatformTuple(p as NodeJS.Platform, a), true, t);
    }
    assert.strictEqual(isSupportedPlatformTuple('win32', 'ia32'), false, '32-bit');
    assert.strictEqual(isSupportedPlatformTuple('freebsd', 'x64'), false, 'unsupported OS');
  });

  it('findWxcExecutable prefers the platform package (production)', () => {
    const dir = makeTempDir();
    const expected = stageBinary(dir, 'wxc-exec.exe');
    _setPlatformPackageDir(dir);
    assert.strictEqual(findWxcExecutable(), expected);
  });

  it('findLxcExecutable prefers the platform package (production)', () => {
    const dir = makeTempDir();
    const expected = stageBinary(dir, 'lxc-exec');
    _setPlatformPackageDir(dir);
    assert.strictEqual(findLxcExecutable(), expected);
  });

  it('findSeatbeltExecutable prefers the platform package (production)', () => {
    const dir = makeTempDir();
    const expected = stageBinary(dir, 'mxc-exec-mac');
    _setPlatformPackageDir(dir);
    assert.strictEqual(findSeatbeltExecutable(), expected);
  });

  it('production fails closed: empty platform package resolves to null (no fallthrough)', () => {
    // The package dir exists but has no binary. In production the resolver must
    // NOT fall through to bin/<arch> or src/target — it returns null.
    const dir = makeTempDir();
    _setPlatformPackageDir(dir);
    assert.strictEqual(findWxcExecutable(), null);
    assert.strictEqual(findSeatbeltExecutable(), null);
  });

  it('production fails closed: absent platform package resolves to null', () => {
    _setPlatformPackageDir(null);
    assert.strictEqual(findWxcExecutable(), null);
  });

  it('MXC_BIN_DIR override wins over the platform package', () => {
    const overrideDir = makeTempDir();
    const archDir = path.join(overrideDir, os.arch() === 'arm64' ? 'arm64' : 'x64');
    fs.mkdirSync(archDir, { recursive: true });
    const expected = stageBinary(archDir, 'wxc-exec.exe');

    // Also stage a binary in the platform package to prove precedence.
    const ppDir = makeTempDir();
    stageBinary(ppDir, 'wxc-exec.exe');
    _setPlatformPackageDir(ppDir);

    process.env.MXC_BIN_DIR = overrideDir;
    assert.strictEqual(findWxcExecutable(), expected);
  });

  it('MXC_BIN_DIR is honored in dev mode too', () => {
    const overrideDir = makeTempDir();
    const archDir = path.join(overrideDir, os.arch() === 'arm64' ? 'arm64' : 'x64');
    fs.mkdirSync(archDir, { recursive: true });
    const expected = stageBinary(archDir, 'wxc-exec.exe');

    _setDevMode(true);
    _setPlatformPackageDir(null);
    process.env.MXC_BIN_DIR = overrideDir;
    assert.strictEqual(findWxcExecutable(), expected);
  });

  it('reports darwin-x64 (Intel macOS) as a supported tuple', () => {
    _setHostId({ platform: 'darwin', arch: 'x64' });
    _resetPlatformSupportCache();
    const support = getPlatformSupport();
    // sandbox-exec presence varies by host; assert the tuple gate did NOT reject it.
    assert.ok(!/not a supported MXC target/i.test(support.reason ?? ''));
    _resetPlatformSupportCache();
  });

  it('reports a 32-bit host (win32-ia32) as unsupported', () => {
    _setHostId({ platform: 'win32', arch: 'ia32' });
    _resetPlatformSupportCache();
    const support = getPlatformSupport();
    assert.strictEqual(support.isSupported, false);
    assert.match(support.reason ?? '', /not a supported MXC target/i);
    _resetPlatformSupportCache();
  });

  it('reports darwin-arm64 (Apple Silicon) as supported', () => {
    _setHostId({ platform: 'darwin', arch: 'arm64' });
    _resetPlatformSupportCache();
    const support = getPlatformSupport();
    // sandbox-exec presence varies by host; assert the tuple gate did NOT reject it.
    assert.ok(!/not a supported MXC target/i.test(support.reason ?? ''));
    _resetPlatformSupportCache();
  });

  it('_validatePlatformPackageDir accepts a matching package and rejects mismatches', () => {
    const dir = makeTempDir();
    const pkgPath = path.join(dir, 'package.json');
    const name = getPlatformPackageName();

    // Correct name + version (0.7.0 = current meta) → validated.
    fs.writeFileSync(pkgPath, JSON.stringify({ name, version: '0.7.0' }));
    assert.strictEqual(_validatePlatformPackageDir(pkgPath), dir);

    // Wrong name → rejected.
    fs.writeFileSync(pkgPath, JSON.stringify({ name: '@evil/squatter', version: '0.7.0' }));
    assert.strictEqual(_validatePlatformPackageDir(pkgPath), null);

    // Wrong version → rejected.
    fs.writeFileSync(pkgPath, JSON.stringify({ name, version: '9.9.9' }));
    assert.strictEqual(_validatePlatformPackageDir(pkgPath), null);
  });

  // --- Hermetic resolver tests (round-2 P1-2): drive the real resolution paths
  // against fixtures via the _setSdkRequire / _setSdkPackageRoot seams. ---

  const META_VERSION = '0.7.0';

  // Build a fake installed layout: <tmp>/node_modules/@microsoft/mxc-sdk (root)
  // with a sibling platform package at the host-tuple path (where the fallback
  // looks); the manifest's `name` is configurable to test squatter rejection.
  //
  // These tests exercise findWxcExecutable() (the Windows resolver), so they pin
  // the host to win32 — otherwise on a Linux/macOS CI worker getPlatformPackageName
  // / getExecutableBinaryName would describe lxc-exec/mxc-exec-mac while the
  // lookup wants wxc-exec.exe, and the staged sibling binary name would mismatch.
  function fakeInstall(opts: { siblingName?: string; siblingVersion?: string; withBinary?: boolean } = {}) {
    _setHostId({ platform: 'win32', arch: os.arch() === 'arm64' ? 'arm64' : 'x64' });
    const tmp = makeTempDir();
    const root = path.join(tmp, 'node_modules', '@microsoft', 'mxc-sdk');
    fs.mkdirSync(root, { recursive: true });
    fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify({ name: '@microsoft/mxc-sdk', version: META_VERSION }));

    // The sibling dir path is always the real host tuple; only the manifest name varies.
    const sibDir = path.join(tmp, 'node_modules', '@microsoft', getPlatformPackageName().replace('@microsoft/', ''));
    fs.mkdirSync(sibDir, { recursive: true });
    fs.writeFileSync(
      path.join(sibDir, 'package.json'),
      JSON.stringify({ name: opts.siblingName ?? getPlatformPackageName(), version: opts.siblingVersion ?? META_VERSION }),
    );
    let binary: string | undefined;
    if (opts.withBinary) {
      binary = stageBinary(sibDir, getExecutableBinaryName());
    }
    return { tmp, root, sibDir, binary };
  }

  it('P0-1: resolves the platform package via the sibling fallback when createRequire is null', () => {
    const { root, binary } = fakeInstall({ withBinary: true });
    _setSdkRequire(null); // simulate a bundled/transpiled-CJS consumer
    _setSdkPackageRoot(root);
    _setPlatformPackageDir(undefined); // use real resolution incl. the fallback
    _setDevMode(null); // real isDevMode → production (root is under node_modules)
    assert.strictEqual(findWxcExecutable(), binary);
  });

  it('P0-2: a planted ../src/Cargo.toml under node_modules does NOT enable dev fallbacks', () => {
    const { tmp, root } = fakeInstall(); // no binary in the (validated) package
    // Spoof the dev marker in the install tree.
    fs.mkdirSync(path.join(tmp, 'node_modules', '@microsoft', 'src'), { recursive: true });
    fs.writeFileSync(path.join(tmp, 'node_modules', '@microsoft', 'src', 'Cargo.toml'), '');
    // Stage a binary in a dev-only candidate path that must be IGNORED in production.
    const devStaged = path.join(root, 'platform-packages', `${process.platform}-${os.arch() === 'arm64' ? 'arm64' : 'x64'}`);
    fs.mkdirSync(devStaged, { recursive: true });
    stageBinary(devStaged, getExecutableBinaryName());

    _setSdkRequire(null);
    _setSdkPackageRoot(root);
    _setPlatformPackageDir(undefined);
    _setDevMode(null); // real isDevMode — must be production despite the planted Cargo.toml
    assert.strictEqual(findWxcExecutable(), null);
  });

  it('P1-2: dev mode prefers a locally-staged binary over the installed package', () => {
    // Pin the host to win32 so findWxcExecutable() (which looks for wxc-exec.exe)
    // matches the staged binary name on any CI worker, not just a Windows one.
    _setHostId({ platform: 'win32', arch: os.arch() === 'arm64' ? 'arm64' : 'x64' });
    const tmp = makeTempDir();
    const root = path.join(tmp, 'repo', 'sdk');
    fs.mkdirSync(root, { recursive: true });
    fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify({ name: '@microsoft/mxc-sdk', version: META_VERSION }));
    fs.mkdirSync(path.join(tmp, 'repo', 'src'), { recursive: true });
    fs.writeFileSync(path.join(tmp, 'repo', 'src', 'Cargo.toml'), ''); // dev marker (not under node_modules)

    const localDir = path.join(root, 'platform-packages', `win32-${os.arch() === 'arm64' ? 'arm64' : 'x64'}`);
    fs.mkdirSync(localDir, { recursive: true });
    const localBin = stageBinary(localDir, getExecutableBinaryName());

    const installedDir = makeTempDir();
    stageBinary(installedDir, getExecutableBinaryName());

    _setSdkRequire(null);
    _setSdkPackageRoot(root);
    _setDevMode(null); // real → dev (root not under node_modules, Cargo.toml present)
    _setPlatformPackageDir(installedDir); // installed package also has a binary
    assert.strictEqual(findWxcExecutable(), localBin, 'local staged binary must win in dev mode');
  });

  it('P1-2: dev mode prefers src/target/<triple> over the installed package', () => {
    // Round-3 P2: assert the src/target ordering explicitly — a fresh local Rust
    // build must beat a downloaded tarball so a build failure isn't masked.
    _setHostId({ platform: 'win32', arch: os.arch() === 'arm64' ? 'arm64' : 'x64' });
    const tmp = makeTempDir();
    const root = path.join(tmp, 'repo', 'sdk');
    fs.mkdirSync(root, { recursive: true });
    fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify({ name: '@microsoft/mxc-sdk', version: META_VERSION }));
    fs.mkdirSync(path.join(tmp, 'repo', 'src'), { recursive: true });
    fs.writeFileSync(path.join(tmp, 'repo', 'src', 'Cargo.toml'), ''); // dev marker

    const triple = getRustTargetTriple('win32', os.arch() === 'arm64' ? 'arm64' : 'x64');
    const releaseDir = path.join(tmp, 'repo', 'src', 'target', triple, 'release');
    fs.mkdirSync(releaseDir, { recursive: true });
    const localBin = stageBinary(releaseDir, getExecutableBinaryName());

    const installedDir = makeTempDir();
    stageBinary(installedDir, getExecutableBinaryName());

    _setSdkRequire(null);
    _setSdkPackageRoot(root);
    _setDevMode(null);
    _setPlatformPackageDir(installedDir);
    assert.strictEqual(findWxcExecutable(), localBin, 'src/target build must win over installed package in dev');
  });

  it('P1-2: an installed package with a mismatched name/version is rejected end-to-end', () => {
    const { root } = fakeInstall({ siblingName: '@evil/squatter', withBinary: true });
    _setSdkRequire(null);
    _setSdkPackageRoot(root);
    _setPlatformPackageDir(undefined);
    _setDevMode(null);
    assert.strictEqual(findWxcExecutable(), null, 'a squatting package must not be executed');
  });

  it('P1-1 (round-3): sibling fallback fails closed when the meta version is unreadable', () => {
    // Bundled consumer: createRequire null AND no readable meta package.json, so
    // getSdkVersion() === null. A sibling package with the right NAME but an
    // unverifiable version must NOT be trusted — resolver returns null (the
    // consumer must use MXC_BIN_DIR instead).
    _setHostId({ platform: 'win32', arch: os.arch() === 'arm64' ? 'arm64' : 'x64' });
    const tmp = makeTempDir();
    const root = path.join(tmp, 'node_modules', '@microsoft', 'mxc-sdk');
    fs.mkdirSync(root, { recursive: true }); // NOTE: no package.json at root → version unreadable

    const sibDir = path.join(tmp, 'node_modules', '@microsoft', getPlatformPackageName().replace('@microsoft/', ''));
    fs.mkdirSync(sibDir, { recursive: true });
    fs.writeFileSync(
      path.join(sibDir, 'package.json'),
      JSON.stringify({ name: getPlatformPackageName(), version: '0.0.0-attacker' }),
    );
    stageBinary(sibDir, getExecutableBinaryName());

    _setSdkRequire(null);
    _setSdkPackageRoot(root);
    _setPlatformPackageDir(undefined);
    _setDevMode(null); // real → production (root under node_modules)
    assert.strictEqual(findWxcExecutable(), null, 'name-only match with unreadable meta version must fail closed');
  });

  it('P0-4 (round-3): production never executes a planted bin/<arch> or src/target binary', () => {
    // The fail-closed guarantee must hold even when an attacker stages a
    // competing binary in the legacy bin/<arch> and src/target dev paths: in a
    // production (installed) layout with NO valid platform package, the resolver
    // returns null rather than the planted binary.
    _setHostId({ platform: 'win32', arch: os.arch() === 'arm64' ? 'arm64' : 'x64' });
    const tmp = makeTempDir();
    const root = path.join(tmp, 'node_modules', '@microsoft', 'mxc-sdk');
    fs.mkdirSync(root, { recursive: true });
    fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify({ name: '@microsoft/mxc-sdk', version: META_VERSION }));

    const arch = os.arch() === 'arm64' ? 'arm64' : 'x64';
    // Plant a competing binary in the legacy bin/<arch> path.
    const legacyBin = path.join(root, 'bin', arch);
    fs.mkdirSync(legacyBin, { recursive: true });
    stageBinary(legacyBin, 'wxc-exec.exe');
    // Plant another in src/target/<triple>/{release,debug}.
    const triple = getRustTargetTriple('win32', arch);
    for (const cfg of ['release', 'debug']) {
      const d = path.join(root, '..', 'src', 'target', triple, cfg);
      fs.mkdirSync(d, { recursive: true });
      stageBinary(d, 'wxc-exec.exe');
    }

    _setSdkRequire(null);
    _setSdkPackageRoot(root);
    _setPlatformPackageDir(null); // no valid platform package installed
    _setDevMode(false); // production
    assert.strictEqual(findWxcExecutable(), null, 'planted fallback binaries must never be executed in production');
  });
});
