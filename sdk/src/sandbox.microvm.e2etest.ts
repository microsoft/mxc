// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// MicroVM SDK end-to-end tests — these tests spawn real NanVix VMs via wxc-exec.exe.
//
// Requirements:
//   - Windows with WHP enabled (bcdedit /set hypervisorlaunchtype auto)
//   - wxc-exec.exe built (in src/target/debug/ or src/target/x86_64-pc-windows-msvc/debug/)
//   - NanVix binaries next to wxc-exec.exe: nanvixd.exe, kernel.elf, python.elf, cpython-ramfs.img
//   - nanvixd must support -mount (v0.12.472+ from nanvix dev branch)
//
// Run: npx tsc && node --test dist/sandbox.microvm.e2etest.js
//
// Uses spawnSandboxFromConfig with usePty:false for reliable exit codes
// and separate stdout/stderr streams.

import { describe, it } from 'node:test';
import assert from 'node:assert';
import fs from 'node:fs';
import path from 'node:path';
import os from 'os';
import { spawnSandboxFromConfig } from './sandbox';
import { ContainerConfig } from './types';
import { ChildProcess } from 'child_process';

const isMicrovmAvailable = os.platform() === 'win32';

/**
 * Spawn a microvm sandbox using spawnSandboxFromConfig with usePty:false.
 * Returns stdout, stderr, and exit code.
 */
function runMicrovm(
  config: ContainerConfig,
  options: { timeoutMs?: number } = {},
): Promise<{ stdout: string; stderr: string; exitCode: number }> {
  return new Promise((resolve, reject) => {
    const timeout = options.timeoutMs ?? 120_000;

    try {
      const child: ChildProcess = spawnSandboxFromConfig(config, {
        experimental: true,
        debug: true,
        usePty: false,
      });

      let stdout = '';
      let stderr = '';

      child.stdout?.on('data', (data: Buffer) => { stdout += data.toString(); });
      child.stderr?.on('data', (data: Buffer) => { stderr += data.toString(); });

      const timer = setTimeout(() => {
        child.kill();
        reject(new Error(`MicroVM test timed out after ${timeout}ms.\nstdout: ${stdout}\nstderr: ${stderr}`));
      }, timeout);

      child.on('error', (error: Error) => {
        clearTimeout(timer);
        reject(new Error(`Failed to spawn wxc-exec: ${error.message}`));
      });

      child.on('close', (code: number | null) => {
        clearTimeout(timer);
        resolve({ stdout, stderr, exitCode: code ?? -1 });
      });
    } catch (error) {
      reject(error);
    }
  });
}

describe('MicroVM SDK E2E — spawnSandboxFromConfig with containment: microvm', {
  skip: !isMicrovmAvailable ? 'MicroVM tests require Windows with WHP' : undefined,
}, () => {

  it('should run a simple Python script and capture output', async () => {
    const config: ContainerConfig = {
      version: '0.5.0-alpha',
      containment: 'microvm',
      process: {
        commandLine: "print('Hello from MicroVM SDK E2E!')",
        timeout: 30000,
      },
    };

    const { stdout, stderr, exitCode } = await runMicrovm(config);
    const combined = stdout + stderr;
    assert.strictEqual(exitCode, 0, `Expected exit code 0, got ${exitCode}.\nstdout: ${stdout}\nstderr: ${stderr}`);
    assert.ok(combined.includes('Hello from MicroVM SDK E2E!'), `Expected greeting in output:\n${combined}`);
  });

  it('should propagate non-zero exit codes', async () => {
    const config: ContainerConfig = {
      version: '0.5.0-alpha',
      containment: 'microvm',
      process: {
        commandLine: "import sys; sys.exit(42)",
        timeout: 30000,
      },
    };

    const { exitCode } = await runMicrovm(config);
    assert.strictEqual(exitCode, 42, `Expected exit code 42, got ${exitCode}`);
  });

  it('should run multiline scripts with imports', async () => {
    const config: ContainerConfig = {
      version: '0.5.0-alpha',
      containment: 'microvm',
      process: {
        commandLine: [
          "import sys",
          "import json",
          "result = {'python': f'{sys.version_info.major}.{sys.version_info.minor}', 'platform': sys.platform}",
          "print(json.dumps(result))",
        ].join('\n'),
        timeout: 30000,
      },
    };

    const { stdout, stderr, exitCode } = await runMicrovm(config);
    const combined = stdout + stderr;
    assert.strictEqual(exitCode, 0, `Expected exit code 0.\nstdout: ${stdout}\nstderr: ${stderr}`);
    assert.ok(combined.includes('"platform": "nanvix"'), `Expected nanvix platform in output:\n${combined}`);
  });

  it('should support readwritePaths and expose MXC_PATH_* env vars', async () => {
    const testDir = fs.mkdtempSync(path.join(os.tmpdir(), 'mxc-microvm-e2e-'));
    const rwDir = path.join(testDir, 'work');
    fs.mkdirSync(rwDir);
    fs.writeFileSync(path.join(rwDir, 'input.txt'), 'data from host');

    try {
      const config: ContainerConfig = {
        version: '0.5.0-alpha',
        containment: 'microvm',
        process: {
          commandLine: [
            "import os",
            "path = os.environ['MXC_PATH_WORK']",
            "print(f'Guest path: {path}')",
            "with open(os.path.join(path, 'input.txt')) as f:",
            "    print(f'Read: {f.read().strip()}')",
          ].join('\n'),
          timeout: 30000,
        },
        filesystem: {
          readwritePaths: [rwDir],
        },
      };

      const { stdout, stderr, exitCode } = await runMicrovm(config);
      const combined = stdout + stderr;
      assert.strictEqual(exitCode, 0, `Expected exit code 0.\nstdout: ${stdout}\nstderr: ${stderr}`);
      assert.ok(combined.includes('Guest path: /mnt/rw/work'), `Expected guest path in output:\n${combined}`);
      assert.ok(combined.includes('Read: data from host'), `Expected host data in output:\n${combined}`);
    } finally {
      fs.rmSync(testDir, { recursive: true, force: true });
    }
  });

  it('should reject denied_paths with an error', async () => {
    const config: ContainerConfig = {
      version: '0.5.0-alpha',
      containment: 'microvm',
      process: {
        commandLine: "print('should not run')",
        timeout: 30000,
      },
      filesystem: {
        deniedPaths: ['/secret'],
      },
    };

    const { stdout, stderr, exitCode } = await runMicrovm(config);
    const combined = stdout + stderr;
    assert.notStrictEqual(exitCode, 0, `Expected non-zero exit code for denied_paths`);
    assert.ok(combined.includes('denied_paths'), `Expected denied_paths error in output:\n${combined}`);
  });
});
