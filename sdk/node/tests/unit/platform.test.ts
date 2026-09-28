// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import assert from 'node:assert/strict';
import * as os from 'node:os';
import { afterEach, beforeEach, describe, it } from 'node:test';
import {
  _resetPlatformSupportCache,
  _resetWxcExecutableCache,
  _setAvailableBackendsProbe,
  _setProbeRunner,
  _setWxcExecutableVerifier,
  findWxcExecutable,
  getPlatformSupport,
} from '../../src/platform.js';

describe('getPlatformSupport', () => {
  beforeEach(() => {
    _resetPlatformSupportCache();
  });

  afterEach(() => {
    _setAvailableBackendsProbe();
    _setProbeRunner(null);
    _resetPlatformSupportCache();
  });

  it('omits bubblewrapNetwork off Linux', { skip: os.platform() === 'linux' }, () => {
    assert.strictEqual(getPlatformSupport().bubblewrapNetwork, undefined);
  });

  it(
    'does not advertise bubblewrap when canonical discovery omits it',
    { skip: os.platform() !== 'linux' },
    () => {
      _setAvailableBackendsProbe(() => [
        { backend: 'lxc', capabilities: [], warnings: [] },
      ]);

      const support = getPlatformSupport();
      assert.deepStrictEqual(support.availableMethods, ['lxc']);
      assert.match(support.unavailableReasons?.bubblewrap ?? '', /not launchable/i);
      assert.strictEqual(support.bubblewrapNetwork, undefined);
    },
  );

  it(
    'projects both Linux backends and bubblewrap capability from one snapshot',
    { skip: os.platform() !== 'linux' },
    () => {
      let calls = 0;
      _setAvailableBackendsProbe(() => {
        calls += 1;
        return [
          { backend: 'lxc', capabilities: [], warnings: [] },
          {
            backend: 'bubblewrap',
            capabilities: ['proxyEnforcement'],
            warnings: [],
          },
        ];
      });

      const first = getPlatformSupport();
      const second = getPlatformSupport();
      assert.strictEqual(first, second);
      assert.strictEqual(calls, 1);
      assert.deepStrictEqual(first.availableMethods, ['lxc', 'bubblewrap']);
      assert.deepStrictEqual(first.bubblewrapNetwork, {
        proxyEnforcement: 'supported',
        warnings: [],
      });
    },
  );

  it(
    'preserves canonical bubblewrap warnings when proxy enforcement is absent',
    { skip: os.platform() !== 'linux' },
    () => {
      _setAvailableBackendsProbe(() => [{
        backend: 'bubblewrap',
        capabilities: [],
        warnings: ['slirp4netns not found'],
      }]);

      const support = getPlatformSupport();
      assert.strictEqual(support.isSupported, true);
      assert.deepStrictEqual(support.bubblewrapNetwork, {
        proxyEnforcement: 'unsupported',
        warnings: ['slirp4netns not found'],
      });
      assert.match(support.unavailableReasons?.lxc ?? '', /not installed/i);
    },
  );

  it(
    'reports Linux unsupported when canonical discovery is empty',
    { skip: os.platform() !== 'linux' },
    () => {
      _setAvailableBackendsProbe(() => []);
      const support = getPlatformSupport();
      assert.strictEqual(support.isSupported, false);
      assert.deepStrictEqual(support.availableMethods, []);
      assert.match(support.reason ?? '', /Neither LXC nor Bubblewrap/i);
    },
  );

  it(
    'reports Linux unsupported when canonical discovery fails',
    { skip: os.platform() !== 'linux' },
    () => {
      _setAvailableBackendsProbe(() => {
        throw new Error('native library missing');
      });

      assert.doesNotThrow(() => getPlatformSupport());
      const support = getPlatformSupport();
      assert.strictEqual(support.isSupported, false);
      assert.deepStrictEqual(support.availableMethods, []);
      assert.match(support.reason ?? '', /native library missing/i);
      assert.match(support.unavailableReasons?.lxc ?? '', /discovery failed/i);
      assert.match(support.unavailableReasons?.bubblewrap ?? '', /discovery failed/i);
    },
  );

  it('keeps the retained Windows probe projection', { skip: os.platform() !== 'win32' }, () => {
    _setProbeRunner(() => JSON.stringify({
      tier: 'appcontainer-bfs',
      warnings: ['fallback'],
      probes: {
        isolationSessionAvailable: true,
        hyperlightAvailable: false,
      },
    }));
    const support = getPlatformSupport();
    assert.strictEqual(support.isolationTier, 'appcontainer-bfs');
    assert.deepStrictEqual(support.isolationWarnings, ['fallback']);
    assert.ok(support.availableMethods.includes('isolation_session'));
  });

  it('keeps the retained Hyperlight availability projection', { skip: os.platform() !== 'win32' }, () => {
    _setProbeRunner(() => JSON.stringify({
      probes: {
        isolationSessionAvailable: false,
        hyperlightAvailable: true,
      },
    }));
    const support = getPlatformSupport();
    assert.ok(support.availableMethods.includes('hyperlight'));
    assert.ok(!support.availableMethods.includes('isolation_session'));
  });

  it('ignores malformed retained Windows probe output', { skip: os.platform() !== 'win32' }, () => {
    _setProbeRunner(() => 'not json');
    assert.doesNotThrow(() => getPlatformSupport());
    assert.strictEqual(getPlatformSupport().isolationTier, undefined);
  });
});

describe('findWxcExecutable', () => {
  const originalBinDir = process.env.MXC_BIN_DIR;

  afterEach(() => {
    if (originalBinDir === undefined) delete process.env.MXC_BIN_DIR;
    else process.env.MXC_BIN_DIR = originalBinDir;
    _setWxcExecutableVerifier(null);
    _resetWxcExecutableCache();
  });

  it('prefers and caches a valid explicit binary directory', () => {
    process.env.MXC_BIN_DIR = 'custom';
    let checks = 0;
    _setWxcExecutableVerifier((candidate) => {
      checks += 1;
      return candidate.includes('custom');
    });

    const first = findWxcExecutable();
    const second = findWxcExecutable();
    assert.strictEqual(first, second);
    assert.match(first ?? '', /custom/);
    assert.strictEqual(checks, 2, 'one initial verification and one cache verification');
  });

  it('does not cache a failed executable lookup', () => {
    process.env.MXC_BIN_DIR = 'missing';
    _setWxcExecutableVerifier(() => false);
    assert.strictEqual(findWxcExecutable(), null);

    _setWxcExecutableVerifier((candidate) => candidate.includes('missing'));
    assert.match(findWxcExecutable() ?? '', /missing/);
  });

  it('honors an explicit binary directory configured after a cached lookup', () => {
    delete process.env.MXC_BIN_DIR;
    _setWxcExecutableVerifier(() => true);
    const initial = findWxcExecutable();
    assert.ok(initial);

    process.env.MXC_BIN_DIR = 'override';
    const resolved = findWxcExecutable();
    assert.match(resolved ?? '', /override/);
    assert.notStrictEqual(resolved, initial);
  });
});
