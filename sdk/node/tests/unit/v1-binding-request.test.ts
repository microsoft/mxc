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
  it('projects the SDK-owned v1 request without a policy version', () => {
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
    assert.ok(!('version' in request.policy));
  });

  it('rejects raw exact versions at the co-versioned binding boundary', () => {
    for (const version of ['0.9.0-alpha', '1.1.0-alpha']) {
      assert.throws(
        () => prepareRequestSpec({
          version,
          process: { commandLine: 'echo hello' },
        }),
        /accepts only the SDK-owned 1\.0\.0 contract.*spawnSandboxFromConfig/,
      );
    }
  });

  it('preserves environment inheritance and explicit overrides', () => {
    const baseConfig: ContainerConfig = {
      version: '1.0.0',
      process: { commandLine: 'echo hello' },
    };
    assert.strictEqual(prepareRequestSpec(baseConfig).environment, undefined);

    const inherited = prepareRequestSpec(baseConfig, {
      env: {},
      inheritDefaultEnv: true,
    });
    assert.deepStrictEqual(inherited.environment, {});
    assert.strictEqual(inherited.inheritDefaultEnv, true);
  });

  it('rejects unsupported containment and persistent lifecycle requests', () => {
    assert.match(
      bindingRequestUnsupportedReason({
        version: '1.0.0',
        containment: 'microvm',
        process: { commandLine: 'echo hello' },
      }) ?? '',
      /not supported by the in-process Node SDK/,
    );
    assert.throws(
      () => prepareRequestSpec({
        version: '1.0.0',
        process: { commandLine: 'echo hello' },
        lifecycle: { destroyOnExit: false },
      }),
      MxcError,
    );
  });

  it('requires a command', () => {
    assert.throws(
      () => prepareRequestSpec({ version: '1.0.0' }),
      /script is required/,
    );
  });
});
