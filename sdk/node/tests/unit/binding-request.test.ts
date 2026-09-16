// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import assert from 'node:assert';
import { describe, it } from 'node:test';
import {
  bindingRequestUnsupportedReason,
  prepareRequestSpec,
} from '../../src/bindings/request.js';
import type { ContainerConfig } from '../../src/types.js';

describe('native binding request', () => {
  it('projects an existing ContainerConfig at the binding boundary', () => {
    const request = prepareRequestSpec({
      version: '0.9.0-alpha',
      containerId: 'sample',
      process: {
        commandLine: 'echo hello',
        cwd: 'C:\\config-work',
        env: ['FROM_CONFIG=value', 'OVERRIDE=old'],
        timeout: 5000,
      },
      filesystem: { readonlyPaths: ['C:\\input'], clearPolicyOnExit: false },
      network: { egress: { default: 'deny' } },
      runtimeConfig: { networkProxy: 'http://127.0.0.1:8080' },
      ui: { disable: false, clipboard: 'read', injection: true },
      telemetry: { enabled: false },
    }, {
      workingDirectory: 'C:\\work',
      env: { OVERRIDE: 'new', OMIT: undefined },
      experimental: true,
    });

    assert.deepStrictEqual(request, {
      policy: {
        version: '0.9.0-alpha',
        filesystem: { readonlyPaths: ['C:\\input'], clearPolicyOnExit: false },
        network: {
          allowOutbound: undefined,
          allowLocalNetwork: undefined,
          allowedHosts: undefined,
          blockedHosts: undefined,
          proxy: undefined,
          egress: { default: 'deny' },
          ingress: undefined,
          runtimeConfig: { networkProxy: 'http://127.0.0.1:8080' },
        },
        ui: {
          allowWindows: true,
          clipboard: 'read',
          allowInputInjection: true,
        },
        timeoutMs: 5000,
        telemetry: { enabled: false },
      },
      command: 'echo hello',
      containment: { type: 'process' },
      containerName: 'sample',
      workingDirectory: 'C:\\work',
      environment: { FROM_CONFIG: 'value', OVERRIDE: 'new' },
      inheritDefaultEnv: false,
      experimental: true,
    });
  });

  it('preserves environment inheritance and explicit overrides', () => {
    const baseConfig: ContainerConfig = {
      version: '0.9.0-alpha',
      process: { commandLine: 'echo hello' },
    };

    const defaultRequest = prepareRequestSpec(baseConfig);
    assert.strictEqual(defaultRequest.environment, undefined);
    assert.strictEqual(defaultRequest.inheritDefaultEnv, false);

    const inheritedRequest = prepareRequestSpec({
      ...baseConfig,
      process: { commandLine: 'echo hello', inheritDefaultEnv: true },
    });
    assert.deepStrictEqual(inheritedRequest.environment, {});
    assert.strictEqual(inheritedRequest.inheritDefaultEnv, true);

    const inheritanceDisabled = prepareRequestSpec({
      ...baseConfig,
      process: { commandLine: 'echo hello', inheritDefaultEnv: true },
    }, {
      inheritDefaultEnv: false,
    });
    assert.strictEqual(inheritanceDisabled.environment, undefined);
    assert.strictEqual(inheritanceDisabled.inheritDefaultEnv, false);

    const inheritanceEnabled = prepareRequestSpec(baseConfig, {
      env: {},
      inheritDefaultEnv: true,
    });
    assert.deepStrictEqual(inheritanceEnabled.environment, {});
    assert.strictEqual(inheritanceEnabled.inheritDefaultEnv, true);
  });

  it('preserves explicit block policy and empty collections', () => {
    const request = prepareRequestSpec({
      version: '0.9.0-alpha',
      process: { commandLine: 'echo hello' },
      network: { defaultPolicy: 'block', allowedHosts: [] },
    });

    assert.strictEqual(request.policy.network!.allowOutbound, false);
    assert.deepStrictEqual(request.policy.network!.allowedHosts, []);
    assert.strictEqual(request.experimental, false);
  });

  it('preserves lifecycle policy through the request policy projection', () => {
    const request = prepareRequestSpec({
      version: '0.9.0-alpha',
      process: { commandLine: 'echo hello' },
      lifecycle: { preservePolicy: true },
    });

    assert.strictEqual(request.policy.filesystem!.clearPolicyOnExit, false);
  });

  it('does not silently drop ProcessContainer settings from process intent', () => {
    assert.throws(
      () => prepareRequestSpec({
        version: '0.9.0-alpha',
        containment: 'process',
        process: { commandLine: 'echo hello' },
        processContainer: { learningMode: true },
      }),
      /require containment 'processcontainer'/,
    );
  });

  it('normalizes legacy containment aliases privately', () => {
    const request = prepareRequestSpec({
      version: '0.9.0-alpha',
      containment: 'appcontainer' as 'processcontainer',
      process: { commandLine: 'echo hello' },
      appContainer: { learningMode: true },
    });

    assert.deepStrictEqual(request.containment, {
      type: 'processContainer',
      learningMode: true,
    });
  });

  it('defaults a partial UI config to no window access', () => {
    const request = prepareRequestSpec({
      version: '0.9.0-alpha',
      process: { commandLine: 'echo hello' },
      ui: { clipboard: 'read' } as NonNullable<ContainerConfig['ui']>,
    });

    assert.strictEqual(request.policy.ui!.allowWindows, false);
  });

  it('moves ProcessContainer configuration onto tagged containment', () => {
    const request = prepareRequestSpec({
      version: '0.9.0-alpha',
      containment: 'processcontainer',
      process: { commandLine: 'echo hello' },
      processContainer: {
        name: 'legacy-name',
        leastPrivilege: true,
        learningMode: true,
        capabilities: ['internetClient'],
        captureDenials: { mode: 'block', outputPath: 'C:\\denials.json', retainEtl: true },
        ui: {
          isolation: 'atoms',
          desktopSystemControl: false,
          systemSettings: 'none',
          ime: false,
        },
        network: { allowedProxyPeer: 'proxy' },
      },
    });

    assert.deepStrictEqual(request.containment, {
      type: 'processContainer',
      leastPrivilege: true,
      learningMode: true,
      capabilities: ['internetClient'],
      captureDenials: { mode: 'block', outputPath: 'C:\\denials.json', retainEtl: true },
      ui: {
        isolation: 'atoms',
        desktopSystemControl: false,
        systemSettings: 'none',
        ime: false,
      },
      network: { allowedProxyPeer: 'proxy' },
    });
  });

  it('moves WSLC configuration onto tagged containment', () => {
    const request = prepareRequestSpec({
      version: '0.9.0-alpha',
      containment: 'wslc',
      process: { commandLine: 'echo hello' },
      experimental: {
        wslc: {
          image: 'alpine:latest',
          targetOs: 'linux',
          cpuCount: 2,
          portMappings: [{ windowsPort: 8080, containerPort: 80, protocol: 'tcp' }],
        },
      },
    }, { experimental: true });

    assert.deepStrictEqual(request.containment, {
      type: 'wslc',
      image: 'alpine:latest',
      cpuCount: 2,
      portMappings: [{ windowsPort: 8080, containerPort: 80 }],
    });

  });

  it('rejects configurations the native one-shot contract cannot represent', () => {
    assert.match(
      bindingRequestUnsupportedReason({
        version: '0.9.0-alpha',
        containment: 'lxc',
        process: { commandLine: 'echo hello' },
      })!,
      /containment 'lxc' is not supported/,
    );

    const config = {
      version: '0.9.0-alpha',
      process: { commandLine: 'echo hello' },
      network: { proxy: { builtinTestServer: true } },
    } as unknown as ContainerConfig;
    assert.match(
      bindingRequestUnsupportedReason(config)!,
      /not supported by the in-process Node SDK/,
    );
  });
});
