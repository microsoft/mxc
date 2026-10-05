// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import assert from 'node:assert';
import { describe, it } from 'node:test';
import {
  createConfigFromRequest,
  prepareContainerRequest,
  SDK_CONTRACT_VERSION as factoryContractVersion,
} from '../../src/v1/container.js';
import { prepareOneShotRequest } from '../../src/bindings/one-shot.js';
import { SDK_CONTRACT_VERSION } from '../../src/v1/contract-version.js';
import type { ContainerRequest } from '../../src/v1/types.js';

describe('v1 container request adapter', () => {
  it('preserves absent and explicit telemetry without mutating reusable requests', () => {
    const request = Object.freeze({ command: 'echo hello', containerName: 'reusable' });
    assert.strictEqual(prepareContainerRequest(request).telemetry, undefined);
    for (const enabled of [true, false]) {
      const telemetry = Object.freeze({ enabled });
      assert.deepStrictEqual(prepareContainerRequest(request, telemetry).telemetry, { enabled });
    }
    assert.strictEqual(prepareContainerRequest(request).telemetry, undefined);
    assert.strictEqual(Object.hasOwn(request, 'telemetry'), false);
  });

  it('rejects request telemetry with operation-options guidance', () => {
    assert.throws(
      () => createConfigFromRequest({ command: 'echo hello', telemetry: { enabled: true } } as never),
      /use the operation options instead/,
    );
  });

  it('rejects the removed ProcessContainer least-privilege option', () => {
    for (const leastPrivilege of [true, false, undefined]) {
      assert.throws(
        () => createConfigFromRequest({
          command: 'echo hello',
          containment: { type: 'processcontainer', config: { leastPrivilege } },
        } as never),
        /containment\.config\.leastPrivilege is not part of the V1 authoring API/,
      );
    }
  });

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
        runtimeConfig: { networkProxy: 'http://127.0.0.1:8080' },
      },
    });

    assert.deepStrictEqual(config.network, {
      egress: { default: 'deny' },
      ingress: { default: 'allow', hostLoopback: 'deny' },
    });
    assert.deepStrictEqual(config.runtimeConfig, {
      networkProxy: 'http://127.0.0.1:8080',
    });
  });

  it('rejects runtime proxy configuration outside network', () => {
    assert.throws(
      () => createConfigFromRequest({
        command: '',
        runtimeConfig: { networkProxy: 'http://127.0.0.1:8080' },
      } as never),
      /ContainerRequest\.runtimeConfig.*use network\.runtimeConfig/,
    );
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
        disable: false,
        clipboard: 'read',
        allowInputInjection: true,
      },
      timeoutMs: 5000,
      workingDirectory: 'C:\\work',
      environment: { A: '1', B: '2' },
      inheritDefaultEnvironment: true,
    };
    const config = createConfigFromRequest(request);
    const exactRequest = prepareContainerRequest(request, { enabled: true });

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
    assert.deepStrictEqual(exactRequest.telemetry, { enabled: true });
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
    const config = createConfigFromRequest({
      command: '',
      containment: { type: 'isolation_session' },
    });
    assert.strictEqual(config.ui, undefined);
    assert.throws(
      () => createConfigFromRequest({
        command: '',
        containment: { type: 'isolation_session' },
        ui: { disable: true },
      }),
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
