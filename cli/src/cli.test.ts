// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { describe, it, afterEach } from 'node:test';
import assert from 'node:assert';
import { execSync } from 'child_process';
import path from 'path';
import fs from 'fs';
import os from 'os';

const cliPath = path.join(__dirname, '..', 'dist', 'cli.js');

function runCli(args: string): string {
  try {
    return execSync(`node ${cliPath} ${args}`, {
      encoding: 'utf-8',
      timeout: 60000,
      cwd: path.join(__dirname, '..'),
    });
  } catch (error: any) {
    const stderr = error.stderr?.toString() ?? '';
    const stdout = error.stdout?.toString() ?? '';
    throw new Error(`CLI failed (exit ${error.status}):\nstdout: ${stdout}\nstderr: ${stderr}`);
  }
}

describe('SDK end-to-end', () => {
  let tempDir = '';

  afterEach(() => {
    if (tempDir && fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
      tempDir = '';
    }
  });

  function createTempDir(): string {
    tempDir = path.join(os.tmpdir(), `mxc-test-${Date.now()}`);
    fs.mkdirSync(tempDir);
    return tempDir;
  }

  function writeTempPolicy(dir: string, policy: object): string {
    const filePath = path.join(dir, 'policy.json');
    fs.writeFileSync(filePath, JSON.stringify(policy));
    return filePath;
  }

  it('cmd.exe: should execute in appcontainer', () => {
    const dir = createTempDir();
    const policyFile = writeTempPolicy(dir, { version: '0.4.0-alpha' });
    const output = runCli(`run-sdk --script "cmd.exe /c echo Container test successful" --cwd "${dir}" --container-name "test-1" --policy-file "${policyFile}"`);
    assert.ok(output.includes('Container test successful'));
    assert.ok(output.includes('Process exited with code 0'));
  });

  it('powershell 5.1: should execute in appcontainer', () => {
    const dir = createTempDir();
    const policyFile = writeTempPolicy(dir, { version: '0.4.0-alpha' });
    const output = runCli(`run-sdk --script "powershell.exe -NoProfile -Command Write-Output 'PowerShell test successful'" --cwd "${dir}" --container-name "test-2" --policy-file "${policyFile}"`);
    assert.ok(output.includes('PowerShell test successful'));
    assert.ok(output.includes('Process exited with code 0'));
  });

  it('python: should execute in appcontainer', () => {
    const dir = createTempDir();
    const policyFile = writeTempPolicy(dir, { version: '0.4.0-alpha' });
    const output = runCli(`run-sdk --script "python -c \\"print('Python test successful')\\"" --cwd "${dir}" --container-name "test-3" --policy-file "${policyFile}"`);
    assert.ok(output.includes('Python test successful'));
    assert.ok(output.includes('Process exited with code 0'));
  });

  it('readwritePaths: should allow writing to brokered path', () => {
    const dir = createTempDir();
    const testFile = path.join(dir, 'output.txt');
    const scriptFile = path.join(dir, 'write_test.py');
    fs.writeFileSync(scriptFile, `f = open(r'${testFile}', 'w')\nf.write('hello')\nf.close()\nprint('WRITE_OK')\n`);
    const policyFile = writeTempPolicy(dir, {
      version: '0.4.0-alpha',
      filesystem: { readwritePaths: [dir] },
    });
    const output = runCli(`run-sdk --script "python ${scriptFile}" --cwd "${dir}" --container-name "test-4" --policy-file "${policyFile}"`);
    assert.ok(output.includes('WRITE_OK'));
    assert.ok(output.includes('Process exited with code 0'));
    assert.ok(fs.existsSync(testFile), 'File should have been written to readwrite path');
  });

  it('readonlyPaths: should allow reading from brokered path', () => {
    const dir = createTempDir();
    fs.writeFileSync(path.join(dir, 'input.txt'), 'readonly test data');
    const inputFile = path.join(dir, 'input.txt');
    const policyFile = writeTempPolicy(dir, {
      version: '0.4.0-alpha',
      filesystem: { readonlyPaths: [dir] },
    });
    const output = runCli(`run-sdk --script "cmd.exe /c type ${inputFile}" --cwd "${dir}" --container-name "test-5" --policy-file "${policyFile}"`);
    assert.ok(output.includes('readonly test data'));
    assert.ok(output.includes('Process exited with code 0'));
  });
});
