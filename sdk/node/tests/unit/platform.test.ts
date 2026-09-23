// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert';
import * as fs from 'node:fs';
import * as os from 'os';
import * as path from 'path';
import {
  getAvailableBackends,
  getPlatformSupport,
  _resetPlatformSupportCache,
  _setPlatformSupportSnapshotReader,
  _setPlatformDiagnosticLogger,
  findWxcExecutable,
  _resetWxcExecutableCache,
  _setWxcExecutableVerifier,
} from '../../src/platform.js';
import { _readOwnedJson } from '../../src/bindings/platform-support.js';

const isWindows = os.platform() === 'win32';

describe('getPlatformSupport host-services projection', () => {
  beforeEach(() => {
    _resetPlatformSupportCache();
  });

  afterEach(() => {
    _setPlatformSupportSnapshotReader(null);
    _resetPlatformSupportCache();
  });

  // `bubblewrapNetwork` is a Linux-only fact. Off Linux it must be *absent*
  // rather than `unsupported`, which would claim the host was evaluated and
  // found wanting. Nothing else pins the non-Linux shape.
  it('omits bubblewrapNetwork off Linux', { skip: os.platform() === 'linux' }, () => {
    _setPlatformSupportSnapshotReader(() => ({
      platformSupportJson: '{"isSupported":true,"availableMethods":["seatbelt"]}',
      availableBackendsJson: '[{"backend":"seatbelt"}]',
    }));
    assert.strictEqual(getPlatformSupport().bubblewrapNetwork, undefined);
  });

  it('projects bubblewrap network support from native capabilities', { skip: os.platform() !== 'linux' }, () => {
    _setPlatformSupportSnapshotReader(() => ({
      platformSupportJson:
        '{"isSupported":true,"availableMethods":["bubblewrap"],'
        + '"bubblewrapNetwork":{"proxyEnforcement":"supported","warnings":[]}}',
      availableBackendsJson:
        '[{"backend":"bubblewrap","capabilities":["proxyEnforcement"]}]',
    }));
    assert.deepStrictEqual(getPlatformSupport().bubblewrapNetwork, {
      proxyEnforcement: 'supported',
      warnings: [],
    });
  });

  it('caches the projected platform-support result', () => {
    let calls = 0;
    _setPlatformSupportSnapshotReader(() => {
      calls += 1;
      return {
        platformSupportJson: '{"isSupported":true,"availableMethods":["processcontainer"]}',
        availableBackendsJson: '[{"backend":"processcontainer","tier":"base-container"}]',
      };
    });
    const a = getPlatformSupport();
    const b = getPlatformSupport();
    assert.strictEqual(a, b, 'cached object identity');
    assert.strictEqual(calls, 1);
  });

  it('fails closed when the native host-services read throws', () => {
    _setPlatformSupportSnapshotReader(() => {
      throw new Error('missing mxc_ffi');
    });
    const support = getPlatformSupport();
    assert.strictEqual(support.isSupported, false);
    assert.strictEqual(support.reason, 'missing mxc_ffi');
    assert.deepStrictEqual(support.availableMethods, []);
  });

  it('fails closed when native Windows capability details are malformed', () => {
    _setPlatformSupportSnapshotReader(() => ({
      platformSupportJson: JSON.stringify({
        isSupported: true,
        availableMethods: ['processcontainer'],
        uiCapabilities: {
          canBlockClipboardRead: 'yes',
        },
      }),
      availableBackendsJson: '[{"backend":"processcontainer","tier":"base-container"}]',
    }));
    const support = getPlatformSupport();
    assert.strictEqual(support.isSupported, false);
    assert.strictEqual(support.reason, 'mxc_platform_support_json returned malformed JSON');
    assert.deepStrictEqual(support.availableMethods, []);
  });

  it('still returns the base PlatformSupport shape on non-Windows', { skip: isWindows }, () => {
    _setPlatformSupportSnapshotReader(() => ({
      platformSupportJson: '{"isSupported":true,"availableMethods":["seatbelt"]}',
      availableBackendsJson: '[{"backend":"seatbelt"}]',
    }));
    const support = getPlatformSupport();
    assert.strictEqual(support.isolationTier, undefined);
    assert.strictEqual(support.isolationWarnings, undefined);
    assert.strictEqual(support.uiCapabilities, undefined);
    assert.ok(Array.isArray(support.availableMethods));
  });

  it('projects Windows isolation and UI details from native platform support', { skip: !isWindows }, () => {
    _setPlatformSupportSnapshotReader(() => ({
      platformSupportJson: JSON.stringify({
        isSupported: true,
        availableMethods: ['processcontainer', 'wslc'],
        isolationTier: 'appcontainer-bfs',
        isolationWarnings: ['Base Container is unavailable; using AppContainer + BFS.'],
        uiCapabilities: {
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
        },
      }),
      availableBackendsJson: '['
        + '{"backend":"processcontainer","tier":"appcontainer-bfs"},'
        + '{"backend":"windows_sandbox"},'
        + '{"backend":"hyperlight"}'
        + ']',
    }));
    const support = getPlatformSupport();
    assert.strictEqual(support.isSupported, true);
    assert.strictEqual(support.isolationTier, 'appcontainer-bfs');
    assert.deepStrictEqual(support.availableMethods, [
      'processcontainer',
      'wslc',
    ]);
    assert.deepStrictEqual(support.isolationWarnings, [
      'Base Container is unavailable; using AppContainer + BFS.',
    ]);
    assert.deepStrictEqual(support.uiCapabilities, {
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
    });
  });

  it('does not infer host-only LXC availability from the SDK-launchable result', { skip: os.platform() !== 'linux' }, () => {
    _setPlatformSupportSnapshotReader(() => ({
      platformSupportJson: JSON.stringify({
        isSupported: false,
        reason: 'Bubblewrap (bwrap) 0.4.1 is too old.',
        availableMethods: [],
      }),
      availableBackendsJson: '[{"backend":"lxc"}]',
    }));
    const support = getPlatformSupport();
    assert.strictEqual(support.isSupported, false);
    assert.deepStrictEqual(support.availableMethods, []);
    assert.strictEqual(support.reason, 'Bubblewrap (bwrap) 0.4.1 is too old.');
    assert.deepStrictEqual(support.unavailableReasons, {
      bubblewrap: 'Bubblewrap (bwrap) 0.4.1 is too old.',
    });
  });

  it('reconstructs Linux Bubblewrap unavailability details', { skip: os.platform() !== 'linux' }, () => {
    _setPlatformSupportSnapshotReader(() => ({
      platformSupportJson: JSON.stringify({
        isSupported: false,
        reason: 'Bubblewrap (bwrap) 0.4.1 is too old.',
        availableMethods: [],
      }),
      availableBackendsJson: '[]',
    }));
    const support = getPlatformSupport();
    assert.strictEqual(support.isSupported, false);
    assert.deepStrictEqual(support.availableMethods, []);
    assert.strictEqual(support.reason, 'Bubblewrap (bwrap) 0.4.1 is too old.');
    assert.deepStrictEqual(support.unavailableReasons, {
      bubblewrap: 'Bubblewrap (bwrap) 0.4.1 is too old.',
    });
  });
});

describe('getAvailableBackends host capability projection', () => {
  afterEach(() => {
    _setPlatformSupportSnapshotReader(null);
  });

  it('keeps host-capability backends separate from platform support', () => {
    _setPlatformSupportSnapshotReader(() => ({
      platformSupportJson:
        '{"isSupported":true,"availableMethods":["processcontainer"]}',
      availableBackendsJson: JSON.stringify([
        {
          backend: 'processcontainer',
          tier: 'base-container',
          capabilities: [
            'captureDenials',
            'filesystemDeniedPaths',
            'filesystemEnumeratePaths',
            'ingressHostLoopbackAllow',
          ],
        },
        {
          backend: 'windows_sandbox',
          warnings: ['optional feature probe was inconclusive'],
        },
      ]),
    }));

    assert.deepStrictEqual(getPlatformSupport().availableMethods, ['processcontainer']);
    assert.deepStrictEqual(getAvailableBackends(), [
      {
        backend: 'processcontainer',
        tier: 'base-container',
        capabilities: [
          'captureDenials',
          'filesystemDeniedPaths',
          'filesystemEnumeratePaths',
          'ingressHostLoopbackAllow',
        ],
        warnings: [],
      },
      {
        backend: 'windows_sandbox',
        tier: undefined,
        capabilities: [],
        warnings: ['optional feature probe was inconclusive'],
      },
    ]);
  });

  it('maps newer backend probe values to forward-compatible unknowns', () => {
    _setPlatformSupportSnapshotReader(() => ({
      platformSupportJson: '{"isSupported":false,"availableMethods":[]}',
      availableBackendsJson:
        '[{"backend":"future_backend","tier":"future-tier",'
        + '"capabilities":["futureCapability"]}]',
    }));

    assert.deepStrictEqual(getAvailableBackends(), [{
      backend: 'unknown',
      tier: 'unknown',
      capabilities: ['unknown'],
      warnings: [],
    }]);
  });

  it('throws when the native backend probe payload is malformed', () => {
    _setPlatformSupportSnapshotReader(() => ({
      platformSupportJson: '{"isSupported":false,"availableMethods":[]}',
      availableBackendsJson: '{"backend":"bubblewrap"}',
    }));

    assert.throws(
      () => getAvailableBackends(),
      /mxc_available_backends_json returned malformed JSON/,
    );
  });

  it('reprobes available backends on every call', () => {
    let calls = 0;
    _setPlatformSupportSnapshotReader(() => {
      calls += 1;
      return {
        platformSupportJson: '{"isSupported":false,"availableMethods":[]}',
        availableBackendsJson: '[]',
      };
    });

    getAvailableBackends();
    getAvailableBackends();
    assert.strictEqual(calls, 2);
  });
});

describe('platform-support native ownership', () => {
  it('rejects a null native payload without freeing it', () => {
    let frees = 0;
    assert.throws(
      () => _readOwnedJson(
        (() => null) as never,
        (() => { frees += 1; }) as never,
        'mxc_platform_support_json',
      ),
      /returned a null JSON payload/,
    );
    assert.strictEqual(frees, 0);
  });

  it('frees a non-null native payload when decoding fails', () => {
    const pointer = {};
    let freed: unknown;
    assert.throws(() => _readOwnedJson(
      (() => pointer) as never,
      ((value: unknown) => { freed = value; }) as never,
      'mxc_platform_support_json',
    ));
    assert.strictEqual(freed, pointer);
  });
});

// findWxcExecutable failure-mode: keep returning either a string path or `null`
// even under hostile inputs to its env-var search seam.
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
