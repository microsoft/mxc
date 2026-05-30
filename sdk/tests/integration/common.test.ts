// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import assert from 'node:assert';
import { describe, it } from 'node:test';
import os from 'os';
import {
  sdk,
  supportedVersions,
  assertDryRunResult,
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

for (const schemaVersion of supportedVersions) {
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

    it('should dry-run via spawnSandboxFromConfig with usePty: false', async () => {
      const config = sdk.createConfigFromPolicy(policy);
      config.process = config.process ?? { commandLine: '' };
      config.process.commandLine = 'cmd.exe /c echo test';
      config.containerId = `dryrun-npty-${schemaVersion}`;

      const result = await new Promise<{ code: number; stdout: string; stderr: string }>((resolve, reject) => {
        const child = sdk.spawnSandboxFromConfig(config, { dryRun: true, usePty: false, ...debugSpawnOptions });
        let stdout = '';
        let stderr = '';
        child.stdout?.on('data', (d: Buffer) => { stdout += d.toString(); });
        child.stderr?.on('data', (d: Buffer) => { stderr += d.toString(); });
        child.on('close', (code: number) => resolve({ code, stdout, stderr }));
        child.on('error', reject);
      });
      assertDryRunResult(result.stdout, result.code, schemaVersion.raw);
    });

    it('should dry-run via spawnSandboxAsync', async () => {
      const result = await sdk.spawnSandboxAsync(
        'cmd.exe /c echo test', policy, { dryRun: true, ...debugSpawnOptions }, undefined, `dryrun-async-${schemaVersion}`,
      );
      assertDryRunResult(result.stdout, result.exitCode, schemaVersion.raw);
    });

    it('should dry-run via spawnSandboxFromConfig', async () => {
      const config = sdk.createConfigFromPolicy(policy);
      config.process = config.process ?? { commandLine: '' };
      config.process.commandLine = 'cmd.exe /c echo test';
      config.containerId = `dryrun-fromcfg-${schemaVersion}`;

      const result = await new Promise<{ exitCode: number; stdout: string }>((resolve) => {
        const ptyProcess = sdk.spawnSandboxFromConfig(config, { dryRun: true, ...debugSpawnOptions });
        let stdout = '';
        ptyProcess.onData((data: string) => { stdout += data; });
        ptyProcess.onExit((event: { exitCode: number }) => {
          resolve({ exitCode: event.exitCode, stdout });
        });
      });
      assertDryRunResult(result.stdout, result.exitCode, schemaVersion.raw);
    });

    it('should dry-run via spawnSandbox (PTY)', async () => {
      const result = await new Promise<{ exitCode: number; stdout: string }>((resolve) => {
        const ptyProcess = sdk.spawnSandbox(
          'cmd.exe /c echo test', policy, { dryRun: true, ...debugSpawnOptions }, undefined, `dryrun-pty-${schemaVersion}`,
        );
        let stdout = '';
        ptyProcess.onData((data: string) => { stdout += data; });
        ptyProcess.onExit((event: { exitCode: number }) => {
          resolve({ exitCode: event.exitCode, stdout });
        });
      });
      assertDryRunResult(result.stdout, result.exitCode, schemaVersion.raw);
    });
  });
}
