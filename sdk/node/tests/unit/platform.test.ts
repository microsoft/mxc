// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert';
import * as fs from 'node:fs';
import * as os from 'os';
import * as path from 'path';
import { Worker } from 'node:worker_threads';
import {
  getPlatformSupport,
  _resetPlatformSupportCache,
  _setProbeRunner,
  _parseBwrapVersion,
  _probeBubblewrap,
  _mapBwrapHelperResult,
  _bwrapProbeDeadlines,
  _runBwrapVersionCommand,
  _setBwrapProbeWorkerFactory,
  _setBwrapVersionRunner,
  _setLxcAvailabilityProbe,
  _setPlatformDiagnosticLogger,
  findWxcExecutable,
  _resetWxcExecutableCache,
  _setWxcExecutableVerifier,
} from '../../src/platform.js';

const isWindows = os.platform() === 'win32';

function readPidFileEventually(pidFile: string, timeoutMs = 5000): number {
  const pollBuffer = new Int32Array(new SharedArrayBuffer(4));
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      return Number.parseInt(fs.readFileSync(pidFile, 'utf8'), 10);
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== 'ENOENT') throw err;
      Atomics.wait(pollBuffer, 0, 0, 10);
    }
  }
  throw new Error(`probe did not write ${pidFile} within ${timeoutMs}ms`);
}

function isProcessGoneError(err: unknown): boolean {
  const code = (err as NodeJS.ErrnoException).code;
  return code === 'ENOENT' || code === 'ESRCH';
}

function assertProcessTerminated(pid: number, message: string): void {
  try {
    const stat = fs.readFileSync(`/proc/${pid}/stat`, 'utf8');
    const state = stat.slice(stat.lastIndexOf(') ') + 2, stat.lastIndexOf(') ') + 3);
    assert.strictEqual(state, 'Z', message);
  } catch (err) {
    if (!isProcessGoneError(err)) throw err;
  }
}

function directZombieChildren(): Set<number> {
  const zombies = new Set<number>();
  if (os.platform() !== 'linux') return zombies;
  for (const entry of fs.readdirSync('/proc')) {
    if (!/^\d+$/.test(entry)) continue;
    try {
      const status = fs.readFileSync(`/proc/${entry}/status`, 'utf8');
      if (
        status.match(/^PPid:\s+(\d+)$/m)?.[1] === String(process.pid) &&
        status.match(/^State:\s+(\w)/m)?.[1] === 'Z'
      ) {
        zombies.add(Number(entry));
      }
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== 'ENOENT') throw err;
    }
  }
  return zombies;
}

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
    _resetWxcExecutableCache();
  });

  afterEach(() => {
    if (prevBinDir === undefined) {
      delete process.env.MXC_BIN_DIR;
    } else {
      process.env.MXC_BIN_DIR = prevBinDir;
    }
    _setWxcExecutableVerifier(null);
    _resetWxcExecutableCache();
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

  it('does not cache a failed executable lookup', () => {
    process.env.MXC_BIN_DIR = path.join(
      os.tmpdir(),
      `mxc-sdk-unit-no-such-dir-${process.pid}`,
    );
    _setWxcExecutableVerifier(() => false);
    assert.strictEqual(findWxcExecutable(), null);

    _setWxcExecutableVerifier((candidate) => candidate.startsWith(process.env.MXC_BIN_DIR!));
    assert.ok(findWxcExecutable()?.startsWith(process.env.MXC_BIN_DIR));
  });

  it('honors an MXC_BIN_DIR override configured after a cached lookup', () => {
    delete process.env.MXC_BIN_DIR;
    _setWxcExecutableVerifier(() => true);
    const initial = findWxcExecutable();
    assert.ok(initial);

    const override = path.join(os.tmpdir(), `mxc-sdk-unit-override-${process.pid}`);
    process.env.MXC_BIN_DIR = override;

    const resolved = findWxcExecutable();
    assert.ok(resolved?.startsWith(override));
    assert.notStrictEqual(resolved, initial);
  });

  it('honors an MXC_BIN_DIR executable staged after caching a fallback', () => {
    const override = path.join(os.tmpdir(), `mxc-sdk-unit-override-${process.pid}`);
    const overrideExecutable = path.join(
      override,
      os.arch() === 'arm64' ? 'arm64' : 'x64',
      'wxc-exec.exe',
    );
    process.env.MXC_BIN_DIR = override;

    let overrideAvailable = false;
    _setWxcExecutableVerifier((candidate) =>
      candidate === overrideExecutable ? overrideAvailable : true,
    );

    const fallback = findWxcExecutable();
    assert.ok(fallback);
    assert.notStrictEqual(fallback, overrideExecutable);

    overrideAvailable = true;
    assert.strictEqual(findWxcExecutable(), overrideExecutable);
  });

  it('revalidates a cached executable before returning it', () => {
    let cachedPath: string | null = null;
    _setWxcExecutableVerifier((candidate) => candidate !== cachedPath);
    cachedPath = findWxcExecutable();
    assert.ok(cachedPath);

    const resolved = findWxcExecutable();
    assert.ok(resolved);
    assert.notStrictEqual(resolved, cachedPath);
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

describe('hyperlight availability gate', () => {
  beforeEach(() => {
    _resetPlatformSupportCache();
  });

  afterEach(() => {
    _setProbeRunner(null);
    _resetPlatformSupportCache();
  });

  it('includes hyperlight when the probe reports it available', { skip: !isWindows }, () => {
    _setProbeRunner(() =>
      JSON.stringify({ tier: 'base-container', probes: { hyperlightAvailable: true } }),
    );
    const support = getPlatformSupport();
    assert.ok(
      support.availableMethods.includes('hyperlight'),
      `expected hyperlight present, got: ${support.availableMethods.join(',')}`,
    );
  });

  it('omits hyperlight when the probe reports it unavailable', { skip: !isWindows }, () => {
    _setProbeRunner(() =>
      JSON.stringify({ tier: 'base-container', probes: { hyperlightAvailable: false } }),
    );
    const support = getPlatformSupport();
    assert.ok(
      !support.availableMethods.includes('hyperlight'),
      `expected hyperlight absent, got: ${support.availableMethods.join(',')}`,
    );
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

describe('bwrap subprocess helpers', () => {
  it('publishes a worker result only after the anchor closes', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mxc-bwrap-anchor-order-'));
    const anchorPath = path.join(dir, 'delayed-anchor.js');
    fs.writeFileSync(
      anchorPath,
      "process.stdout.write('{\"kind\":\"notFound\"}\\n');\n" +
        'setTimeout(() => process.exit(0), 300);\n',
    );
    const shared = new SharedArrayBuffer(12 + 1024);
    const header = new Int32Array(shared, 0, 3);
    const worker = new Worker(
      new URL('../../src/bwrap-probe-worker.js', import.meta.url),
      {
        workerData: {
          shared,
          anchorPath,
          helperPath: anchorPath,
          probeTimeoutMs: 1000,
          publishTimeoutMs: 900,
          outputLimit: 1024,
        },
      },
    );
    worker.on('error', () => {});
    try {
      const started = Date.now();
      const waitResult = Atomics.wait(header, 0, 0, 1000);
      const elapsed = Date.now() - started;
      assert.notStrictEqual(waitResult, 'timed-out');
      assert.ok(elapsed >= 200, `worker published after ${elapsed}ms, before anchor close`);
    } finally {
      worker.unref();
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('ignores anchor stderr so diagnostics cannot stall cleanup', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mxc-bwrap-anchor-stderr-'));
    const anchorPath = path.join(dir, 'noisy-anchor.js');
    fs.writeFileSync(
      anchorPath,
      "const fs = require('node:fs');\n" +
        "fs.writeSync(2, Buffer.alloc(2 * 1024 * 1024, 'x'));\n" +
        "process.stdout.write('{\"kind\":\"notFound\"}\\n');\n",
    );
    const shared = new SharedArrayBuffer(12 + 1024);
    const header = new Int32Array(shared, 0, 3);
    const worker = new Worker(
      new URL('../../src/bwrap-probe-worker.js', import.meta.url),
      {
        workerData: {
          shared,
          anchorPath,
          helperPath: anchorPath,
          probeTimeoutMs: 1000,
          publishTimeoutMs: 900,
          outputLimit: 1024,
        },
      },
    );
    worker.on('error', () => {});
    try {
      const waitResult = Atomics.wait(header, 0, 0, 2000);
      assert.notStrictEqual(waitResult, 'timed-out');
      const length = Atomics.load(header, 1);
      assert.deepStrictEqual(
        JSON.parse(Buffer.from(shared, 12, length).toString()),
        { kind: 'notFound' },
      );
    } finally {
      worker.unref();
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('maps bounded helper results', () => {
    assert.deepStrictEqual(_mapBwrapHelperResult({ kind: 'timeout' }, 50), {
      kind: 'failed',
      status: null,
      detail: 'timed out after 50ms',
    });
    assert.deepStrictEqual(_mapBwrapHelperResult({ kind: 'overflow' }), {
      kind: 'failed',
      status: null,
      detail: 'probe output exceeded the 65536-byte cap',
    });
    assert.deepStrictEqual(
      _mapBwrapHelperResult({ kind: 'notFound' }),
      { kind: 'notFound' },
    );
    assert.deepStrictEqual(
      _mapBwrapHelperResult({
        kind: 'completed',
        status: 124,
        signal: null,
        stdout: '',
        stderr: 'wrapper failed\n',
      }),
      { kind: 'failed', status: 124, detail: 'wrapper failed' },
    );
    assert.deepStrictEqual(
      _mapBwrapHelperResult({
        kind: 'completed',
        status: 126,
        signal: null,
        stdout: '',
        stderr: '',
      }),
      { kind: 'failed', status: 126, detail: '' },
    );
  });

  it(
    'reaps the detached anchor after repeated probes',
    { skip: os.platform() !== 'linux' },
    () => {
      const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mxc-bwrap-reap-'));
      const originalPath = process.env.PATH;
      const existingZombies = directZombieChildren();
      try {
        process.env.PATH = dir;
        for (let i = 0; i < 5; i += 1) {
          assert.deepStrictEqual(_runBwrapVersionCommand(1000), { kind: 'notFound' });
        }

        const pollBuffer = new Int32Array(new SharedArrayBuffer(4));
        const deadline = Date.now() + 5000;
        while (Date.now() < deadline) {
          const newZombies = [...directZombieChildren()].filter(
            (pid) => !existingZombies.has(pid),
          );
          if (newZombies.length === 0) return;
          Atomics.wait(pollBuffer, 0, 0, 10);
        }
        const newZombies = [...directZombieChildren()].filter(
          (pid) => !existingZombies.has(pid),
        );
        assert.deepStrictEqual(newZombies, [], 'probe anchors must be reaped');
      } finally {
        if (originalPath === undefined) {
          delete process.env.PATH;
        } else {
          process.env.PATH = originalPath;
        }
        fs.rmSync(dir, { recursive: true, force: true });
      }
    },
  );

  it(
    'bounds actual subprocess output at 64 KiB',
    { skip: os.platform() !== 'linux' },
    () => {
      const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mxc-bwrap-overflow-'));
      const originalPath = process.env.PATH;
      try {
        const wrapper = path.join(dir, 'bwrap');
        fs.writeFileSync(
          wrapper,
          '#!/bin/sh\n' +
            "dd if=/dev/zero bs=70000 count=1 2>/dev/null | tr '\\000' x\n",
        );
        fs.chmodSync(wrapper, 0o755);
        process.env.PATH = `${dir}${path.delimiter}${originalPath ?? ''}`;

        assert.deepStrictEqual(_runBwrapVersionCommand(3000), {
          kind: 'failed',
          status: null,
          detail: 'probe output exceeded the 65536-byte cap',
        });
      } finally {
        if (originalPath === undefined) {
          delete process.env.PATH;
        } else {
          process.env.PATH = originalPath;
        }
        fs.rmSync(dir, { recursive: true, force: true });
      }
    },
  );

  it(
    'forwards a multi-chunk helper result without truncating its JSON',
    { skip: os.platform() !== 'linux' },
    () => {
      const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mxc-bwrap-large-result-'));
      const originalPath = process.env.PATH;
      try {
        const wrapper = path.join(dir, 'bwrap');
        fs.writeFileSync(
          wrapper,
          '#!/bin/sh\n' +
            "printf 'bubblewrap 0.5.0 '\n" +
            "dd if=/dev/zero bs=60000 count=1 2>/dev/null | tr '\\000' x\n",
        );
        fs.chmodSync(wrapper, 0o755);
        process.env.PATH = `${dir}${path.delimiter}${originalPath ?? ''}`;

        const result = _runBwrapVersionCommand(3000);
        assert.strictEqual(result.kind, 'output');
        if (result.kind === 'output') {
          assert.ok(result.stdout.startsWith('bubblewrap 0.5.0 '));
          assert.ok(result.stdout.length > 60000);
        }
      } finally {
        if (originalPath === undefined) {
          delete process.env.PATH;
        } else {
          process.env.PATH = originalPath;
        }
        fs.rmSync(dir, { recursive: true, force: true });
      }
    },
  );

  it(
    'bounds a wrapper whose background descendant retains stdout and stderr',
    { skip: os.platform() !== 'linux' },
    () => {
      const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mxc-bwrap-descendant-'));
      const originalPath = process.env.PATH;
      const originalPidFile = process.env.MXC_TEST_DESCENDANT_PID_FILE;
      const pidFile = path.join(dir, 'descendant.pid');
      let descendantPid: number | undefined;
      try {
        const wrapper = path.join(dir, 'bwrap');
        fs.writeFileSync(
          wrapper,
          '#!/bin/sh\n' +
            '(sleep 30) &\n' +
            'echo "$!" > "$MXC_TEST_DESCENDANT_PID_FILE"\n' +
            "exec /bin/echo 'bubblewrap 0.5.0'\n",
        );
        fs.chmodSync(wrapper, 0o755);
        process.env.PATH = `${dir}${path.delimiter}${originalPath ?? ''}`;
        process.env.MXC_TEST_DESCENDANT_PID_FILE = pidFile;

        const result = _runBwrapVersionCommand(1000);
        assert.deepStrictEqual(result, {
          kind: 'failed',
          status: null,
          detail: 'timed out after 1000ms',
        });
        descendantPid = readPidFileEventually(pidFile);
        const pollBuffer = new Int32Array(new SharedArrayBuffer(4));
        const deadline = Date.now() + 1000;
        let terminated = false;
        while (Date.now() < deadline) {
          try {
            const stat = fs.readFileSync(`/proc/${descendantPid}/stat`, 'utf8');
            const state = stat.slice(stat.lastIndexOf(') ') + 2, stat.lastIndexOf(') ') + 3);
            if (state === 'Z') {
              terminated = true;
              break;
            }
            Atomics.wait(pollBuffer, 0, 0, 10);
          } catch (err) {
            if (isProcessGoneError(err)) {
              terminated = true;
              break;
            }
            throw err;
          }
        }
        assert.ok(terminated, 'probe must terminate the background descendant');
      } finally {
        if (descendantPid !== undefined) {
          try {
            process.kill(descendantPid, 'SIGKILL');
          } catch (err) {
            if ((err as NodeJS.ErrnoException).code !== 'ESRCH') throw err;
          }
        }
        if (originalPath === undefined) {
          delete process.env.PATH;
        } else {
          process.env.PATH = originalPath;
        }
        if (originalPidFile === undefined) {
          delete process.env.MXC_TEST_DESCENDANT_PID_FILE;
        } else {
          process.env.MXC_TEST_DESCENDANT_PID_FILE = originalPidFile;
        }
        fs.rmSync(dir, { recursive: true, force: true });
      }
    },
  );

  it(
    'does not return a successful result before terminating closed-pipe descendants',
    { skip: os.platform() !== 'linux' },
    () => {
      const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mxc-bwrap-closed-descendant-'));
      const originalPath = process.env.PATH;
      const originalPidFile = process.env.MXC_TEST_DESCENDANT_PID_FILE;
      const pidFile = path.join(dir, 'descendant.pid');
      let descendantPid: number | undefined;
      try {
        const wrapper = path.join(dir, 'bwrap');
        fs.writeFileSync(
          wrapper,
          '#!/bin/sh\n' +
            '(sleep 30) >/dev/null 2>&1 &\n' +
            'echo "$!" > "$MXC_TEST_DESCENDANT_PID_FILE"\n' +
            "exec /bin/echo 'bubblewrap 0.5.0'\n",
        );
        fs.chmodSync(wrapper, 0o755);
        process.env.PATH = `${dir}${path.delimiter}${originalPath ?? ''}`;
        process.env.MXC_TEST_DESCENDANT_PID_FILE = pidFile;

        const result = _runBwrapVersionCommand(1000);
        assert.deepStrictEqual(result, {
          kind: 'output',
          stdout: 'bubblewrap 0.5.0\n',
        });
        descendantPid = readPidFileEventually(pidFile);
        assertProcessTerminated(
          descendantPid,
          'probe returned before terminating the background descendant',
        );
      } finally {
        if (descendantPid !== undefined) {
          try {
            process.kill(descendantPid, 'SIGKILL');
          } catch (err) {
            if ((err as NodeJS.ErrnoException).code !== 'ESRCH') throw err;
          }
        }
        if (originalPath === undefined) {
          delete process.env.PATH;
        } else {
          process.env.PATH = originalPath;
        }
        if (originalPidFile === undefined) {
          delete process.env.MXC_TEST_DESCENDANT_PID_FILE;
        } else {
          process.env.MXC_TEST_DESCENDANT_PID_FILE = originalPidFile;
        }
        fs.rmSync(dir, { recursive: true, force: true });
      }
    },
  );

  it('nests the probe and publish deadlines inside the caller budget', () => {
    for (const timeoutMs of [5000, 1000, 100, 2]) {
      const { probeTimeoutMs, publishTimeoutMs } = _bwrapProbeDeadlines(timeoutMs);
      assert.ok(probeTimeoutMs >= 1, `probe deadline must be positive for ${timeoutMs}ms`);
      assert.ok(
        probeTimeoutMs < publishTimeoutMs,
        `probe deadline must precede the publish deadline for ${timeoutMs}ms`,
      );
      assert.ok(
        publishTimeoutMs <= timeoutMs,
        `publish deadline must stay inside the caller budget for ${timeoutMs}ms`,
      );
    }
  });

  it('subtracts worker setup time from the caller-visible wait budget', async () => {
    const delay = new Int32Array(new SharedArrayBuffer(4));
    let worker: Worker | undefined;
    _setBwrapProbeWorkerFactory(() => {
      Atomics.wait(delay, 0, 0, 300);
      worker = new Worker('setInterval(() => {}, 1000);', { eval: true });
      return worker;
    });
    try {
      const started = Date.now();
      const result = _runBwrapVersionCommand(400);
      const elapsed = Date.now() - started;
      assert.deepStrictEqual(result, {
        kind: 'failed',
        status: null,
        detail: 'timed out after 400ms',
      });
      assert.ok(elapsed >= 350, `probe returned before its remaining budget: ${elapsed}ms`);
      assert.ok(elapsed < 550, `probe added a full wait after setup: ${elapsed}ms`);
    } finally {
      _setBwrapProbeWorkerFactory(null);
      if (worker) await worker.terminate();
    }
  });

  it('reports missing or corrupt worker modules without waiting for the probe timeout', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mxc-bwrap-worker-startup-'));
    const corruptWorker = path.join(dir, 'corrupt-worker.mjs');
    fs.writeFileSync(corruptWorker, 'export const = ;\n');
    const cases = [
      path.join(dir, 'missing-worker.mjs'),
      corruptWorker,
    ];
    const workers: Worker[] = [];

    try {
      for (const workerPath of cases) {
        _setBwrapProbeWorkerFactory((bootstrap, options) => {
          const worker = new Worker(bootstrap, {
            ...options,
            workerData: {
              ...(options.workerData as Record<string, unknown>),
              workerPath,
            },
          });
          workers.push(worker);
          return worker;
        });

        const started = Date.now();
        const result = _runBwrapVersionCommand(3000);
        const elapsed = Date.now() - started;

        assert.strictEqual(result.kind, 'failed');
        if (result.kind === 'failed') {
          assert.match(result.detail, /^probe worker failed to start:/);
          assert.doesNotMatch(result.detail, /timed out/i);
        }
        assert.ok(elapsed < 1500, `worker startup failure took ${elapsed}ms`);
      }
    } finally {
      _setBwrapProbeWorkerFactory(null);
      await Promise.all(workers.map((worker) => worker.terminate()));
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it(
    'returns within the caller-visible timeout when the probe hangs',
    { skip: os.platform() !== 'linux' },
    () => {
      const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mxc-bwrap-bound-'));
      const originalPath = process.env.PATH;
      try {
        const wrapper = path.join(dir, 'bwrap');
        fs.writeFileSync(wrapper, '#!/bin/sh\nexec sleep 30\n');
        fs.chmodSync(wrapper, 0o755);
        process.env.PATH = `${dir}${path.delimiter}${originalPath ?? ''}`;

        const started = Date.now();
        const result = _runBwrapVersionCommand(1000);
        const elapsed = Date.now() - started;
        assert.deepStrictEqual(result, {
          kind: 'failed',
          status: null,
          detail: 'timed out after 1000ms',
        });
        // The supervision layers run inside the caller's budget, so the total
        // wait must not stack their margins on top of it.
        assert.ok(elapsed < 1500, `probe took ${elapsed}ms, expected under 1500ms`);
      } finally {
        if (originalPath === undefined) {
          delete process.env.PATH;
        } else {
          process.env.PATH = originalPath;
        }
        fs.rmSync(dir, { recursive: true, force: true });
      }
    },
  );

  it(
    'reports an existing wrapper with a missing interpreter as broken',
    { skip: os.platform() !== 'linux' },
    () => {
      const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mxc-bwrap-missing-interpreter-'));
      const originalPath = process.env.PATH;
      try {
        const wrapper = path.join(dir, 'bwrap');
        fs.writeFileSync(wrapper, '#!/this/interpreter/does/not/exist\n');
        fs.chmodSync(wrapper, 0o755);
        // Keep execvp from falling through to a real system bwrap after the
        // synthetic wrapper's missing shebang interpreter returns ENOENT.
        process.env.PATH = dir;

        const result = _runBwrapVersionCommand(1000);
        assert.strictEqual(result.kind, 'failed');
        if (result.kind === 'failed') {
          assert.strictEqual(result.status, null);
          assert.match(result.detail, /missing interpreter or loader/i);
        }
      } finally {
        if (originalPath === undefined) {
          delete process.env.PATH;
        } else {
          process.env.PATH = originalPath;
        }
        fs.rmSync(dir, { recursive: true, force: true });
      }
    },
  );

  it(
    'reports an actually missing bwrap executable as not found',
    { skip: os.platform() !== 'linux' },
    () => {
      const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mxc-bwrap-missing-'));
      const originalPath = process.env.PATH;
      try {
        process.env.PATH = dir;
        assert.deepStrictEqual(_runBwrapVersionCommand(1000), { kind: 'notFound' });
      } finally {
        if (originalPath === undefined) {
          delete process.env.PATH;
        } else {
          process.env.PATH = originalPath;
        }
        fs.rmSync(dir, { recursive: true, force: true });
      }
    },
  );

  it(
    'terminates the probe when the helper exits without printing a result',
    { skip: os.platform() !== 'linux' },
    () => {
      // The wrapper kills the probe helper but keeps running. A separate
      // sentinel must retain process-group ownership until the worker kills the
      // whole group; using the helper itself as leader orphaned this wrapper.
      const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mxc-bwrap-no-result-'));
      const originalPath = process.env.PATH;
      const originalPidFile = process.env.MXC_TEST_DESCENDANT_PID_FILE;
      const pidFile = path.join(dir, 'probe.pid');
      let probePid: number | undefined;
      try {
        const wrapper = path.join(dir, 'bwrap');
        fs.writeFileSync(
          wrapper,
          '#!/bin/sh\n' +
            'echo "$$" > "$MXC_TEST_DESCENDANT_PID_FILE"\n' +
            'kill $PPID\n' +
            'sleep 30\n',
        );
        fs.chmodSync(wrapper, 0o755);
        process.env.PATH = `${dir}${path.delimiter}${originalPath ?? ''}`;
        process.env.MXC_TEST_DESCENDANT_PID_FILE = pidFile;

        const result = _runBwrapVersionCommand(1000);
        assert.strictEqual(result.kind, 'failed');
        if (result.kind === 'failed') {
          assert.match(result.detail, /exited without a result/i);
        }
        probePid = readPidFileEventually(pidFile);
        const pollBuffer = new Int32Array(new SharedArrayBuffer(4));
        const deadline = Date.now() + 1000;
        let terminated = false;
        while (Date.now() < deadline) {
          try {
            const stat = fs.readFileSync(`/proc/${probePid}/stat`, 'utf8');
            const state = stat.slice(stat.lastIndexOf(') ') + 2, stat.lastIndexOf(') ') + 3);
            if (state === 'Z') {
              terminated = true;
              break;
            }
            Atomics.wait(pollBuffer, 0, 0, 10);
          } catch (err) {
            if (isProcessGoneError(err)) {
              terminated = true;
              break;
            }
            throw err;
          }
        }
        assert.ok(terminated, 'probe must terminate after its helper exits');
      } finally {
        if (probePid !== undefined) {
          try {
            process.kill(probePid, 'SIGKILL');
          } catch (err) {
            if ((err as NodeJS.ErrnoException).code !== 'ESRCH') throw err;
          }
        }
        if (originalPath === undefined) {
          delete process.env.PATH;
        } else {
          process.env.PATH = originalPath;
        }
        if (originalPidFile === undefined) {
          delete process.env.MXC_TEST_DESCENDANT_PID_FILE;
        } else {
          process.env.MXC_TEST_DESCENDANT_PID_FILE = originalPidFile;
        }
        fs.rmSync(dir, { recursive: true, force: true });
      }
    },
  );
});

// The minimum-version comparison itself, driven through the injectable
// runner. Without these the SDK gate could drift from the Rust gate in
// `src/backends/bubblewrap/common/src/bwrap_version.rs` unnoticed.
describe('bwrap minimum-version gate', () => {
  afterEach(() => {
    _setBwrapVersionRunner(null);
    _setLxcAvailabilityProbe(null);
    _setPlatformDiagnosticLogger(null);
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
    assert.strictEqual(
      probe.reason,
      'Bubblewrap (bwrap) 0.4.1 is too old: version 0.5.0 or newer is required ' +
        '(the sandbox uses `--clearenv`, added in bwrap 0.5.0). Upgrade the bubblewrap package.',
    );
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
    assert.strictEqual(
      probe.reason,
      'Could not determine the Bubblewrap (bwrap) version: `bwrap --version` printed ' +
        '"something else entirely". Version 0.5.0 or newer is required.',
    );
  });

  it('fails closed when unrelated output contains a number', () => {
    withVersion('some other tool 999\n');
    const probe = _probeBubblewrap();
    assert.strictEqual(probe.available, false);
    assert.match(probe.reason, /could not determine/i);
  });

  it('reports a missing binary as not installed', () => {
    _setBwrapVersionRunner(() => ({ kind: 'notFound' }));
    const probe = _probeBubblewrap();
    assert.strictEqual(probe.available, false);
    assert.strictEqual(
      probe.reason,
      'Bubblewrap (bwrap) is not installed or not on PATH. ' +
        'Install it via your package manager (e.g., apt install bubblewrap). ' +
        'Version 0.5.0 or newer is required.',
    );
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
    assert.strictEqual(
      probe.reason,
      'The Bubblewrap (bwrap) availability probe `bwrap --version` exited with status 126: ' +
        'bwrap: permission denied. Version 0.5.0 or newer is required; ' +
        'check PATH and the installation before using the Bubblewrap backend.',
    );
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
    assert.doesNotMatch(probe.reason, /is present/);
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

  it(
    'keeps Linux supported and logs the bwrap reason when LXC is available',
    { skip: os.platform() !== 'linux' },
    () => {
      _setLxcAvailabilityProbe(() => true);
      withVersion('bubblewrap 0.4.1\n');
      const logs: string[] = [];
      _setPlatformDiagnosticLogger((message) => logs.push(message));
      _resetPlatformSupportCache();

      const support = getPlatformSupport();
      assert.strictEqual(support.isSupported, true);
      assert.deepStrictEqual(support.availableMethods, ['lxc']);
      assert.strictEqual(support.reason, '');
      assert.deepStrictEqual(support.unavailableReasons, {
        bubblewrap:
          'Bubblewrap (bwrap) 0.4.1 is too old: version 0.5.0 or newer is required ' +
          '(the sandbox uses `--clearenv`, added in bwrap 0.5.0). Upgrade the bubblewrap package.',
      });
      assert.strictEqual(logs.length, 1);
      assert.match(logs[0], /0\.4\.1 is too old/i);
    },
  );

  it(
    'reports the bwrap failure reason when neither Linux backend is available',
    { skip: os.platform() !== 'linux' },
    () => {
      _setLxcAvailabilityProbe(() => false);
      withVersion('bubblewrap 0.4.1\n');
      _resetPlatformSupportCache();

      const support = getPlatformSupport();
      assert.strictEqual(support.isSupported, false);
      assert.deepStrictEqual(support.availableMethods, []);
      assert.deepStrictEqual(support.unavailableReasons, {
        lxc: 'LXC is not installed or not available on this system.',
        bubblewrap:
          'Bubblewrap (bwrap) 0.4.1 is too old: version 0.5.0 or newer is required ' +
          '(the sandbox uses `--clearenv`, added in bwrap 0.5.0). Upgrade the bubblewrap package.',
      });
      assert.strictEqual(
        support.reason,
        'Neither LXC nor Bubblewrap is available on this system ' +
          '(Bubblewrap (bwrap) 0.4.1 is too old: version 0.5.0 or newer is required ' +
          '(the sandbox uses `--clearenv`, added in bwrap 0.5.0). Upgrade the bubblewrap package.)',
      );
    },
  );

  it(
    'reports LXC as unavailable when Bubblewrap keeps Linux supported',
    { skip: os.platform() !== 'linux' },
    () => {
      _setLxcAvailabilityProbe(() => false);
      withVersion('bubblewrap 0.5.0\n');
      _resetPlatformSupportCache();

      const support = getPlatformSupport();
      assert.strictEqual(support.isSupported, true);
      assert.deepStrictEqual(support.availableMethods, ['bubblewrap']);
      assert.deepStrictEqual(support.unavailableReasons, {
        lxc: 'LXC is not installed or not available on this system.',
      });
    },
  );
});
