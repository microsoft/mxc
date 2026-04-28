// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// SDK end-to-end tests — these tests spawn real containers via wxc-exec.exe.
// They require the appropriate runtime to be installed and configured.
//
// WSLC tests require:
//   - Windows 11 with WSL2 enabled
//   - WSLC SDK runtime installed
//   - wxc-exec.exe built with --features wslc
//   - wslcsdk.dll in the same directory as wxc-exec.exe
//   - alpine:latest and python:3.12-alpine images pre-pulled
//
// Run via: npm test (from integration directory)

import { describe, it } from 'node:test';
import assert from 'node:assert';
import fs from 'node:fs';
import path from 'node:path';
import os from 'os';
import { ChildProcess } from 'child_process';
import { sdk } from './test-helpers';

const skipInCi = process.env.MXC_SKIP_OS_BUILD_DEPENDENT_TESTS === '1';
const isWslcAvailable = os.platform() === 'win32' && !skipInCi;

describe('WSLC SDK E2E — createConfigFromPolicy → customize → spawn', {
  skip: !isWslcAvailable ? 'WSLC tests require Windows with WSL2 and WSLC SDK' : undefined,
}, () => {

  it('should run with all WSLC-specific fields set', async () => {
    // Create temp directories for volume mount and storage.
    // Use short paths under os.tmpdir() — WSLC SDK can fail with very long paths.
    const testDir = fs.mkdtempSync(path.join(os.tmpdir(), 'mxc-e2e-'));
    const storageDir = path.join(testDir, 'storage');
    const mountDir = path.join(testDir, 'mount');
    fs.mkdirSync(storageDir);
    fs.mkdirSync(mountDir);

    try {
      const policy = {
        version: '0.5.0-alpha',
        network: { allowOutbound: true },
        filesystem: { readwritePaths: [mountDir] },
      };
      const config = sdk.createConfigFromPolicy(policy, 'wslc');
      config.process!.commandLine = [
        "python3 -c \"import sys; print(f'Python {sys.version_info.major}.{sys.version_info.minor}')\"",
        "nproc",
        "cat /proc/meminfo | grep MemTotal",
        "echo 'All fields work'",
      ].join(' && ');
      config.experimental!.wslc!.image = 'python:3.12-alpine';
      config.experimental!.wslc!.cpuCount = 2;
      config.experimental!.wslc!.memoryMb = 1024;
      config.experimental!.wslc!.storagePath = storageDir;

      const { stdout, exitCode } = await new Promise<{ stdout: string; stderr: string; exitCode: number }>((resolve, reject) => {
        const child = sdk.spawnSandboxFromConfig(config, { experimental: true, debug: true, usePty: false }) as ChildProcess;
        let stdout = '';
        let stderr = '';
        child.stdout?.on('data', (data: Buffer) => { stdout += data.toString(); });
        child.stderr?.on('data', (data: Buffer) => { stderr += data.toString(); });
        child.on('error', (error: Error) => {
          reject(new Error(`Failed to spawn WSLC sandbox process: ${error.message}${stderr ? `\n${stderr}` : ''}`));
        });
        child.on('close', (code: number | null) => {
          resolve({ stdout, stderr, exitCode: code ?? -1 });
        });
      });

      assert.strictEqual(exitCode, 0);
      assert.ok(stdout.includes('Python 3.12'));
      assert.ok(stdout.includes('All fields work'));
    } finally {
      fs.rmSync(testDir, { recursive: true, force: true });
    }
  });
});
