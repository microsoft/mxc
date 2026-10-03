// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import assert from 'node:assert';
import { describe, it } from 'node:test';
import {
  createConfigFromRequest,
  SDK_CONTRACT_VERSION as factoryContractVersion,
} from '../../src/sandbox.js';
import { prepareOneShotRequest } from '../../src/bindings/one-shot.js';
import { SDK_CONTRACT_VERSION } from '../../src/contract-version.js';
import type { ContainerRequest } from '../../src/types.js';

describe('v1 container request adapter', () => {
  it('owns exact contract 1.0.0', () => {
    const config = createConfigFromRequest({ command: '' });
    assert.strictEqual(factoryContractVersion, SDK_CONTRACT_VERSION);
    assert.strictEqual(config.version, SDK_CONTRACT_VERSION);
    assert.match(config.containerId!, /^[0-9a-f]{32}$/);
    assert.strictEqual(config.network, undefined);
  });

  it('rejects caller-selected exact versions with raw-config guidance', () => {
    assert.throws(
      () => createConfigFromRequest({ command: '', version: '0.9.0-alpha' } as never),
      /does not accept a caller-selected version/,
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
    'removeRulesOnExit',
  ]) {
    it(`rejects legacy network.${field}`, () => {
      assert.throws(
        () => createConfigFromRequest({
          command: '',
          network: { [field]: field === 'proxy' ? null : false },
        } as never),
        new RegExp(`network\\.${field}.*not part of the v1 API`),
      );
    });
  }

  it('maps directional network and runtime proxy separately', () => {
    const config = createConfigFromRequest({
      command: '',
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

  it('does not derive ProcessContainer capabilities from directional posture', () => {
    const original = Object.getOwnPropertyDescriptor(process, 'platform');
    Object.defineProperty(process, 'platform', { value: 'win32' });
    try {
      const config = createConfigFromRequest({
        command: '',
        network: {
          egress: { default: 'allow' },
          ingress: { default: 'allow' },
        },
        containment: { type: 'processcontainer' },
      });
      assert.deepStrictEqual(config.processContainer?.capabilities, [
        'internetClient',
        'privateNetworkClientServer',
      ]);
      assert.deepStrictEqual(
        prepareOneShotRequest({
          ...config,
          process: { commandLine: 'echo hello' },
        }).processContainer?.capabilities,
        [],
      );
    } finally {
      if (original) Object.defineProperty(process, 'platform', original);
    }
  });

  it('preserves filesystem, UI, timeout, telemetry, and command intent', () => {
    const request: ContainerRequest = {
      command: 'echo hello',
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
      workingDirectory: 'C:\\work',
      environment: { A: '1', B: '2' },
      inheritDefaultEnvironment: true,
    };
    const config = createConfigFromRequest(request);
    const exactRequest = prepareOneShotRequest(config, {
      workingDirectory: request.workingDirectory,
      env: request.environment,
      inheritDefaultEnv: request.inheritDefaultEnvironment,
    });

    assert.strictEqual(exactRequest.process?.commandLine, 'echo hello');
    assert.strictEqual(exactRequest.process?.cwd, 'C:\\work');
    assert.deepStrictEqual(exactRequest.process?.env, ['A=1', 'B=2']);
    assert.strictEqual(exactRequest.process?.inheritDefaultEnv, true);
    assert.strictEqual(exactRequest.process?.timeout, 5000);
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
      assert.doesNotThrow(() => createConfigFromRequest({
        command: '',
        containment: { type: containment },
      }));
    }
    for (const containment of [
      'vm',
      'microvm',
      'windows_sandbox',
      'hyperlight',
    ] as const) {
      assert.throws(
        () => createConfigFromRequest({
          command: '',
          containment: { type: containment as never },
        }),
        /not available in the v1\.0 high-level SDK/,
      );
    }
  });

  it('omits unsupported IsolationSession UI policy', () => {
    const config = createConfigFromPolicy({}, 'isolation_session');
    assert.strictEqual(config.ui, undefined);
    assert.throws(
      () => createConfigFromPolicy(
        { ui: { allowWindows: false } },
        'isolation_session',
      ),
      /IsolationSession does not enforce UI policy/,
    );
  });

  it('limits enumeratePaths to Windows ProcessContainer', () => {
    const request: ContainerRequest = {
      command: '',
      containment: {
        type: 'processcontainer',
        config: { filesystem: { enumeratePaths: ['C:\\tools'] } },
      },
    };
    const original = Object.getOwnPropertyDescriptor(process, 'platform');
    Object.defineProperty(process, 'platform', { value: 'win32' });
    try {
      const config = createConfigFromRequest(request);
      assert.deepStrictEqual(
        config.processContainer?.filesystem?.enumeratePaths,
        ['C:\\tools'],
      );
      Object.defineProperty(process, 'platform', { value: 'linux' });
      assert.throws(
        () => createConfigFromRequest(request),
        /supported only by the Windows ProcessContainer backend/,
      );
    } finally {
      if (original) Object.defineProperty(process, 'platform', original);
    }
  });
});
