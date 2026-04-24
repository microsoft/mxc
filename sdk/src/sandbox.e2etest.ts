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
// Run: node --test dist/sandbox.e2etest.js

import { describe, it } from 'node:test';
import assert from 'node:assert';
import os from 'os';
import { createConfigFromPolicy } from './sandbox';
import { SandboxPolicy } from './types';

/**
 * Helper: spawn a container from a pre-built config using child_process.
 * Uses child_process.spawn (non-PTY) for reliable exit codes on Windows.
 * Tests the full flow: createConfigFromPolicy → customize → spawn → capture output.
 */
function spawnConfigAndCollect(
  config: ReturnType<typeof createConfigFromPolicy>,
): Promise<{ stdout: string; stderr: string; exitCode: number }> {
  return new Promise((resolve) => {
    const { spawn } = require('child_process');
    const configJson = JSON.stringify(config);
    const configBase64 = Buffer.from(configJson, 'utf-8').toString('base64');

    // Find wxc-exec.exe using the SDK's platform module
    const { findWxcExecutable } = require('./platform');
    const executablePath = findWxcExecutable();
    if (!executablePath) {
      resolve({ stdout: '', stderr: 'wxc-exec.exe not found', exitCode: -1 });
      return;
    }

    const args = ['--config-base64', configBase64, '--experimental', '--debug'];
    const child = spawn(executablePath, args, {
      stdio: ['pipe', 'pipe', 'pipe'],
    });

    let stdout = '';
    let stderr = '';
    child.stdout?.on('data', (data: Buffer) => { stdout += data.toString(); });
    child.stderr?.on('data', (data: Buffer) => { stderr += data.toString(); });
    child.on('close', (code: number | null) => {
      resolve({ stdout, stderr, exitCode: code ?? -1 });
    });
  });
}

const isWslcAvailable = os.platform() === 'win32';

describe('WSLC SDK E2E — createConfigFromPolicy → customize → spawn', {
  skip: !isWslcAvailable ? 'WSLC tests require Windows with WSL2 and WSLC SDK' : undefined,
}, () => {

  it('should run with all WSLC-specific fields set', async () => {
    const policy: SandboxPolicy = {
      version: '0.5.0-alpha',
      network: { allowOutbound: true },
      filesystem: { readwritePaths: ['C:\\workspace'] },
    };
    const config = createConfigFromPolicy(policy, 'wslc');
    config.process!.commandLine = [
      "python3 -c \"import sys; print(f'Python {sys.version_info.major}.{sys.version_info.minor}')\"",
      "nproc",
      "cat /proc/meminfo | grep MemTotal",
      "ls /mnt/c/workspace",
      "echo 'All fields work'",
    ].join(' && ');
    config.experimental!.wslc!.image = 'python:3.12-alpine';
    config.experimental!.wslc!.cpuCount = 2;
    config.experimental!.wslc!.memoryMb = 1024;
    config.experimental!.wslc!.storagePath = 'C:\\workspace\\wslc-all-fields-test';

    const result = await spawnConfigAndCollect(config);
    assert.strictEqual(result.exitCode, 0);
    assert.ok(result.stdout.includes('Python 3.12'));
    assert.ok(result.stdout.includes('All fields work'));
  });
});
