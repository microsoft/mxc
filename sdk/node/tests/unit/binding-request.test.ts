// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import assert from 'node:assert';
import { describe, it } from 'node:test';
import {
  bindingRequestUnsupportedReason,
  prepareRequestSpec,
} from '../../src/bindings/request.js';
import { MxcError } from '../../src/errors.js';
import type { ContainerConfig } from '../../src/types.js';

describe('native binding request', () => {
  it('projects an existing ContainerConfig at the binding boundary', () => {
    const request = prepareRequestSpec({
      version: '1.0.0',
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
        filesystem: { readonlyPaths: ['C:\\input'], clearPolicyOnExit: false },
        network: {
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
      version: '1.0.0',
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

  it('rejects network enforcement mode instead of silently dropping it', () => {
    assert.throws(
      () => prepareRequestSpec({
        version: '1.0.0',
        process: { commandLine: 'echo hello' },
        network: { enforcementMode: 'firewall' },
      } as unknown as ContainerConfig),
      (error: unknown) =>
        error instanceof MxcError
        && error.code === 'malformed_request'
        && error.message.includes('network.enforcementMode'),
    );
  });

  it('preserves lifecycle policy through the request policy projection', () => {
    const request = prepareRequestSpec({
      version: '1.0.0',
      process: { commandLine: 'echo hello' },
      lifecycle: { preservePolicy: true },
    });

    assert.strictEqual(request.policy.filesystem!.clearPolicyOnExit, false);
  });

  it('does not silently drop ProcessContainer settings from process intent', () => {
    assert.throws(
      () => prepareRequestSpec({
        version: '1.0.0',
        containment: 'process',
        process: { commandLine: 'echo hello' },
        processContainer: { learningMode: true },
      }),
      /require containment 'processcontainer'/,
    );

    assert.throws(
      () => prepareRequestSpec({
        version: '1.0.0',
        containment: 'process',
        process: { commandLine: 'echo hello' },
        processContainer: {
          filesystem: { enumeratePaths: ['C:\\tools'] },
        },
      }),
      /require containment 'processcontainer'/,
    );

    assert.throws(
      () => prepareRequestSpec({
        version: '1.0.0',
        containment: 'seatbelt',
        process: { commandLine: 'echo hello' },
        processContainer: {
          network: { allowedProxyPeer: 'Contoso.Proxy_123' },
        },
      }),
      /require containment 'processcontainer'/,
    );
  });

  it('rejects retired aliases for the SDK-owned v1 contract', () => {
    for (const config of [
      {
        version: '1.0.0',
        containment: 'appcontainer',
        process: { commandLine: 'echo hello' },
      },
      {
        version: '1.0.0',
        containment: 'macos_sandbox',
        process: { commandLine: 'echo hello' },
      },
      {
        version: '1.0.0',
        containment: 'processcontainer',
        process: { commandLine: 'echo hello' },
        appContainer: {},
      },
      {
        version: '1.0.0',
        containment: 'seatbelt',
        process: { commandLine: 'echo hello' },
        macos_sandbox: {},
      },
    ]) {
      assert.throws(
        () => prepareRequestSpec(config as ContainerConfig),
        (error: unknown) =>
          error instanceof MxcError
          && error.code === 'malformed_request'
          && /does not support legacy/.test(error.message),
      );
    }
  });

  it('defaults a partial UI config to no window access', () => {
    const request = prepareRequestSpec({
      version: '1.0.0',
      process: { commandLine: 'echo hello' },
      ui: { clipboard: 'read' } as NonNullable<ContainerConfig['ui']>,
    });

    assert.strictEqual(request.policy.ui!.allowWindows, false);
    assert.strictEqual(request.policy.ui!.allowInputInjection, false);
    assert.strictEqual(request.policy.ui!.clipboard, 'read');
  });

  it('projects an omitted Seatbelt section as empty backend settings', () => {
    const request = prepareRequestSpec({
      version: '1.0.0',
      containment: 'seatbelt',
      process: { commandLine: 'echo hello' },
    });

    assert.deepStrictEqual(request.containment, { type: 'seatbelt' });
  });

  it('moves ProcessContainer configuration onto tagged containment', () => {
    const request = prepareRequestSpec({
      version: '1.0.0',
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
    assert.strictEqual(request.containerName, 'legacy-name');
  });

  it('moves WSLC configuration onto tagged containment', () => {
    const request = prepareRequestSpec({
      version: '1.0.0',
      containment: 'wslc',
      process: { commandLine: 'echo hello' },
      wslc: {
        image: 'alpine:latest',
        targetOs: 'linux',
        cpuCount: 2,
        portMappings: [{ windowsPort: 8080, containerPort: 80, protocol: 'tcp' }],
      },
    });

    assert.deepStrictEqual(request.containment, {
      type: 'wslc',
      image: 'alpine:latest',
      cpuCount: 2,
      portMappings: [{ windowsPort: 8080, containerPort: 80 }],
    });

  });

  it('rejects unsupported WSLC protocol and foreign backend settings', () => {
    assert.throws(
      () => prepareRequestSpec({
        version: '1.0.0',
        containment: 'wslc',
        process: { commandLine: 'echo hello' },
        wslc: {
          portMappings: [{
            windowsPort: 8080,
            containerPort: 80,
            protocol: 'udp' as unknown as 'tcp',
          }],
        },
      }),
      /support only protocol 'tcp'/,
    );

    assert.throws(
      () => prepareRequestSpec({
        version: '1.0.0',
        containment: 'process',
        process: { commandLine: 'echo hello' },
        wslc: { image: 'alpine:latest' },
      }),
      /require containment 'wslc'/,
    );
  });

  it('moves Unix backend configuration onto tagged containment', () => {
    const seatbelt = prepareRequestSpec({
      version: '1.0.0',
      containment: 'seatbelt',
      process: { commandLine: 'echo hello' },
      seatbelt: {
        profileOverride: '(version 1)',
        guiAccess: true,
        nestedPty: false,
        keychainAccess: true,
        extraMachLookups: ['com.example.service'],
      },
    });
    assert.deepStrictEqual(seatbelt.containment, {
      type: 'seatbelt',
      profileOverride: '(version 1)',
      guiAccess: true,
      nestedPty: false,
      keychainAccess: true,
      extraMachLookups: ['com.example.service'],
    });

    const lxc = prepareRequestSpec({
      version: '1.0.0',
      containment: 'lxc',
      process: { commandLine: 'echo hello' },
      lxc: {
        containerName: 'node-sdk-test',
        distribution: 'ubuntu',
        release: '24.04',
        destroyOnExit: true,
      },
    });
    assert.deepStrictEqual(lxc.containment, {
      type: 'lxc',
      distribution: 'ubuntu',
      release: '24.04',
    });
    assert.strictEqual(lxc.containerName, 'node-sdk-test');

    const bubblewrap = prepareRequestSpec({
      version: '1.0.0',
      containment: 'bubblewrap',
      process: { commandLine: 'echo hello' },
    });
    assert.deepStrictEqual(bubblewrap.containment, { type: 'bubblewrap' });

    const isolationSession = prepareRequestSpec({
      version: '1.0.0',
      containment: 'isolation_session',
      process: { commandLine: 'echo hello' },
    }, { experimental: true });
    assert.deepStrictEqual(isolationSession.containment, {
      type: 'isolationSession',
    });
  });

  it('rejects Unix backend settings under another containment', () => {
    assert.throws(
      () => prepareRequestSpec({
        version: '1.0.0',
        containment: 'process',
        process: { commandLine: 'echo hello' },
        seatbelt: { nestedPty: false },
      }),
      /require containment 'seatbelt'/,
    );

    assert.throws(
      () => prepareRequestSpec({
        version: '1.0.0',
        containment: 'process',
        process: { commandLine: 'echo hello' },
        lxc: { distribution: 'ubuntu' },
      }),
      /require containment 'lxc'/,
    );

    assert.throws(
      () => prepareRequestSpec({
        version: '1.0.0',
        containment: 'lxc',
        process: { commandLine: 'echo hello' },
        lxc: { destroyOnExit: false },
      }),
      /destroyOnExit=false is not supported/,
    );
  });

  it('rejects configurations the native one-shot contract cannot represent', () => {
    const config = {
      version: '1.0.0',
      process: { commandLine: 'echo hello' },
      network: { proxy: { builtinTestServer: true } },
    } as unknown as ContainerConfig;
    assert.match(
      bindingRequestUnsupportedReason(config)!,
      /not supported by the in-process Node SDK/,
    );
    assert.throws(
      () => prepareRequestSpec(config),
      (error) => error instanceof MxcError && error.code === 'malformed_request',
    );
  });

  it('uses a typed malformed-request error when the command is absent', () => {
    assert.throws(
      () => prepareRequestSpec({ version: '1.0.0' }),
      (error) => error instanceof MxcError && error.code === 'malformed_request',
    );
  });
});
