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
  isLinuxBubblewrap,
  sandboxSkipReason,
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

const streamingSchemaVersion = platformVersions.at(-1)!;
const streamingSkipReason =
  sandboxSkipReason ??
  (!platformSupport.isSupported ? `Platform not supported: ${platformSupport.reason}` : undefined) ??
  (os.platform() === 'linux' && !isLinuxBubblewrap
    ? 'Native streaming requires Bubblewrap on Linux'
    : undefined);

describe(`Native streaming (schema ${streamingSchemaVersion})`, {
  skip: streamingSkipReason,
}, () => {
  it('should deliver output before the sandbox exits', { timeout: 30000 }, async () => {
    const command = os.platform() === 'win32'
      ? 'powershell.exe -NoProfile -Command "Write-Output STREAM_FIRST; ' +
        'Start-Sleep -Milliseconds 500; Write-Output STREAM_SECOND; ' +
        '[Console]::Error.WriteLine(\'STREAM_ERROR\')"'
      : 'sh -c "printf \'STREAM_FIRST\\n\'; sleep 0.5; ' +
        'printf \'STREAM_SECOND\\n\'; printf \'STREAM_ERROR\\n\' >&2"';
    const policy = {
      version: streamingSchemaVersion.raw,
      ...(os.platform() === 'win32' ? { ui: { allowWindows: true } } : {}),
    };
    const sandbox = sdk.spawnSandbox(command, policy, debugSpawnOptions);
    assert.ok(sandbox.standardOutput, 'streaming stdout should be available');
    assert.ok(sandbox.standardError, 'streaming stderr should be available');

    let stdout = '';
    let stderr = '';
    let resolveFirstChunk: (() => void) | undefined;
    const firstChunk = new Promise<void>((resolve) => {
      resolveFirstChunk = resolve;
    });
    sandbox.standardOutput.on('data', (data: Buffer) => {
      stdout += data.toString();
      if (stdout.includes('STREAM_FIRST')) {
        resolveFirstChunk?.();
      }
    });
    sandbox.standardError.on('data', (data: Buffer) => {
      stderr += data.toString();
    });

    let completed = false;
    const wait = sandbox.waitAsync().then((result) => {
      completed = true;
      return result;
    });

    await firstChunk;
    assert.strictEqual(completed, false, 'first output should arrive before process completion');

    const result = await wait;
    assert.strictEqual(result.exitCode, 0, stderr);
    assert.ok(stdout.includes('STREAM_FIRST'));
    assert.ok(stdout.includes('STREAM_SECOND'));
    assert.ok(stderr.includes('STREAM_ERROR'));
  });
});
