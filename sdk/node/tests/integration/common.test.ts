// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import assert from 'node:assert';
import { describe, it } from 'node:test';
import os from 'os';
import type { SandboxSpawnOptions } from '@microsoft/mxc-sdk';
import {
  sdk,
  supportedVersions,
  debugSpawnOptions,
} from './test-helpers.js';

describe('Platform support', () => {
  it('should report platform support information', () => {
    const support = sdk.getPlatformSupport();
    assert.ok(typeof support.isSupported === 'boolean', 'isSupported should be a boolean');
    assert.ok(Array.isArray(support.availableMethods), 'availableMethods should be an array');
  });
});

const platformSupport = sdk.getPlatformSupport();
const executorDryRun = { dryRun: true } as unknown as SandboxSpawnOptions;

// The exact 0.6 contract predates Seatbelt, which is the native macOS backend.
const platformVersions = os.platform() === 'darwin'
  ? supportedVersions.filter((version) => version.compare('0.7.0-alpha') >= 0)
  : supportedVersions;

for (const schemaVersion of platformVersions) {
  const skipReason = !platformSupport.isSupported
    ? `Platform not supported: ${platformSupport.reason}`
    : undefined;

  describe(`Dry-run smoke tests (schema ${schemaVersion})`, { skip: skipReason }, () => {
    const policy = {
      version: schemaVersion.raw,
      filesystem: {
        readwritePaths: [os.tmpdir()],
        readonlyPaths: [process.cwd()],
      },
      network: {
        allowOutbound: false,
      },
      ui: {
        allowWindows: false,
      },
      timeoutMs: 30000,
    };

    it('should reject executor-only dry-run via spawnSandboxFromConfig', () => {
      const config = sdk.createConfigFromPolicy(policy);
      config.process = config.process ?? { commandLine: '' };
      config.process.commandLine = 'cmd.exe /c echo test';
      config.containerId = `dryrun-npty-${schemaVersion}`;

      assert.throws(
        () => sdk.spawnSandboxFromConfig(config, { ...executorDryRun, ...debugSpawnOptions }),
        /does not support executor-only option 'dryRun'/,
      );
    });

    it('should reject executor-only dry-run via spawnSandboxAsync', async () => {
      await assert.rejects(
        sdk.spawnSandboxAsync(
          'cmd.exe /c echo test', policy, executorDryRun, undefined, `dryrun-async-${schemaVersion}`,
        ),
        /does not support executor-only option 'dryRun'/,
      );
    });

    it('should reject executor-only dry-run via spawnSandbox', () => {
      assert.throws(
        () => sdk.spawnSandbox(
          'cmd.exe /c echo test', policy, { ...executorDryRun, ...debugSpawnOptions }, undefined, `dryrun-streaming-${schemaVersion}`,
        ),
        /does not support executor-only option 'dryRun'/,
      );
    });
  });
}
