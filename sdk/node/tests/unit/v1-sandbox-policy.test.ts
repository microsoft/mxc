// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import assert from 'node:assert';
import { describe, it } from 'node:test';
import {
  buildSandboxPayload,
  createConfigFromPolicy,
} from '../../src/sandbox.js';
import type { SandboxPolicy } from '../../src/types.js';

describe('v1 high-level policy', () => {
  it('owns exact contract 1.0.0', () => {
    const config = createConfigFromPolicy({});
    assert.strictEqual(config.version, '1.0.0');
    assert.strictEqual(config.network, undefined);
  });

  it('rejects caller-selected exact versions with raw-config guidance', () => {
    assert.throws(
      () => createConfigFromPolicy({ version: '0.9.0-alpha' } as SandboxPolicy),
      /no longer accepts a caller-selected version.*ContainerConfig/,
    );
  });

  for (const field of [
    'allowOutbound',
    'defaultPolicy',
    'enforcementMode',
    'allowLocalNetwork',
    'allowedHosts',
    'blockedHosts',
    'proxy',
  ]) {
    it(`rejects legacy network.${field}`, () => {
      assert.throws(
        () => createConfigFromPolicy({
          network: { [field]: field === 'proxy' ? null : false },
        } as SandboxPolicy),
        new RegExp(`network\\.${field}.*not part of the v1 API`),
      );
    });
  }

  it('maps directional network and runtime proxy separately', () => {
    const config = createConfigFromPolicy({
      network: {
        egress: { default: 'deny' },
        ingress: { default: 'allow', hostLoopback: 'deny' },
      },
      runtimeConfig: { networkProxy: 'http://127.0.0.1:8080' },
    });

    assert.deepStrictEqual(config.network, {
      egress: { default: 'deny' },
      ingress: { default: 'allow', hostLoopback: 'deny' },
    });
    assert.deepStrictEqual(config.runtimeConfig, {
      networkProxy: 'http://127.0.0.1:8080',
    });
  });

  it('maps directional posture to ProcessContainer capabilities', () => {
    const original = Object.getOwnPropertyDescriptor(process, 'platform');
    Object.defineProperty(process, 'platform', { value: 'win32' });
    try {
      const config = createConfigFromPolicy({
        network: {
          egress: { default: 'allow' },
          ingress: { default: 'allow' },
        },
      });
      assert.ok(config.processContainer?.capabilities?.includes('internetClient'));
      assert.ok(
        config.processContainer?.capabilities?.includes(
          'privateNetworkClientServer',
        ),
      );
    } finally {
      if (original) Object.defineProperty(process, 'platform', original);
    }
  });

  it('preserves filesystem, UI, timeout, telemetry, and command intent', () => {
    const config = buildSandboxPayload('echo hello', {
      filesystem: {
        readwritePaths: ['C:\\work'],
        readonlyPaths: ['C:\\input'],
        deniedPaths: ['C:\\secret'],
        clearPolicyOnExit: false,
      },
      ui: {
        allowWindows: true,
        clipboard: 'read',
        allowInputInjection: true,
      },
      timeoutMs: 5000,
      telemetry: { enabled: true },
    }, 'C:\\work');

    assert.strictEqual(config.process?.commandLine, 'echo hello');
    assert.strictEqual(config.process?.cwd, 'C:\\work');
    assert.strictEqual(config.process?.timeout, 5000);
    assert.deepStrictEqual(config.filesystem?.deniedPaths, ['C:\\secret']);
    assert.strictEqual(config.lifecycle?.preservePolicy, true);
    assert.deepStrictEqual(config.ui, {
      disable: false,
      clipboard: 'read',
      injection: true,
    });
    assert.deepStrictEqual(config.telemetry, { enabled: true });
  });

  it('supports v1.0 containments and rejects development-only containments', () => {
    for (const containment of [
      'process',
      'processcontainer',
      'wslc',
      'lxc',
      'seatbelt',
      'isolation_session',
      'bubblewrap',
    ] as const) {
      assert.doesNotThrow(() => createConfigFromPolicy({}, containment));
    }
    for (const containment of [
      'vm',
      'microvm',
      'windows_sandbox',
      'hyperlight',
    ] as const) {
      assert.throws(
        () => createConfigFromPolicy({}, containment as never),
        /not available in the v1\.0 high-level SDK/,
      );
    }
  });

  it('limits enumeratePaths to Windows ProcessContainer', () => {
    const policy: SandboxPolicy = {
      processContainer: {
        filesystem: { enumeratePaths: ['C:\\tools'] },
      },
    };
    const original = Object.getOwnPropertyDescriptor(process, 'platform');
    Object.defineProperty(process, 'platform', { value: 'win32' });
    try {
      const config = createConfigFromPolicy(policy, 'processcontainer');
      assert.deepStrictEqual(
        config.processContainer?.filesystem?.enumeratePaths,
        ['C:\\tools'],
      );
      assert.throws(
        () => createConfigFromPolicy(policy, 'wslc'),
        /supported only by the Windows ProcessContainer backend/,
      );
    } finally {
      if (original) Object.defineProperty(process, 'platform', original);
    }
  });
});
