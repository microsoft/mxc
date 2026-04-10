// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { describe, it, afterEach } from 'node:test';
import assert from 'node:assert';
import { execSync, ChildProcess } from 'child_process';
import path from 'path';
import fs from 'fs';
import os from 'os';
import { startTestProxy } from './test-helpers';

const cliPath = path.join(__dirname, '..', 'dist', 'cli.js');

function runCli(args: string, timeoutMs: number = 60000): string {
  try {
    return execSync(`node ${cliPath} ${args}`, {
      encoding: 'utf-8',
      timeout: timeoutMs,
      cwd: path.join(__dirname, '..'),
    });
  } catch (error: any) {
    const stderr = error.stderr?.toString() ?? '';
    const stdout = error.stdout?.toString() ?? '';
    throw new Error(`CLI failed (exit ${error.status}):\nstdout: ${stdout}\nstderr: ${stderr}`);
  }
}

function createTempDir(prefix: string = 'mxc-test'): string {
  const dir = path.join(os.tmpdir(), `${prefix}-${Date.now()}`);
  fs.mkdirSync(dir);
  return dir;
}

function writeTempPolicy(dir: string, policy: object): string {
  const filePath = path.join(dir, 'policy.json');
  fs.writeFileSync(filePath, JSON.stringify(policy));
  return filePath;
}

describe('SDK end-to-end', () => {
  let tempDir = '';

  afterEach(() => {
    if (tempDir && fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
      tempDir = '';
    }
  });

  // Skipped: AppContainer can't find executables on GitHub workflow runners, run locally until then
  it.skip('cmd.exe: should execute in appcontainer', () => {
    const dir = createTempDir();
    const policyFile = writeTempPolicy(dir, { version: '0.4.0-alpha' });
    const output = runCli(`run-sdk --script "cmd.exe /c echo Container test successful" --cwd "${dir}" --container-name "test-1" --policy-file "${policyFile}"`);
    assert.ok(output.includes('Container test successful'));
    assert.ok(output.includes('Process exited with code 0'));
  });

  // Skipped: AppContainer can't find executables on GitHub workflow runners, run locally until then
  it.skip('powershell 5.1: should execute in appcontainer', () => {
    const dir = createTempDir();
    const policyFile = writeTempPolicy(dir, { version: '0.4.0-alpha' });
    const output = runCli(`run-sdk --script "powershell.exe -NoProfile -Command Write-Output 'PowerShell test successful'" --cwd "${dir}" --container-name "test-2" --policy-file "${policyFile}"`);
    assert.ok(output.includes('PowerShell test successful'));
    assert.ok(output.includes('Process exited with code 0'));
  });

  // Skipped: bfscfg.exe doesn't exist on workflow machines currently, run locally until then
  it.skip('python: should execute in appcontainer', () => {
    const dir = createTempDir();
    const policyFile = writeTempPolicy(dir, { version: '0.4.0-alpha' });
    const output = runCli(`run-sdk --script "python -c \\"print('Python test successful')\\"" --cwd "${dir}" --container-name "test-3" --policy-file "${policyFile}"`);
    assert.ok(output.includes('Python test successful'));
    assert.ok(output.includes('Process exited with code 0'));
  });

  // Skipped: bfscfg.exe doesn't exist on workflow machines currently, run locally until then
  it.skip('readwritePaths: should allow writing to brokered path', () => {
    tempDir = createTempDir();
    const testFile = path.join(tempDir, 'output.txt');
    const scriptFile = path.join(tempDir, 'write_test.py');
    fs.writeFileSync(scriptFile, `f = open(r'${testFile}', 'w')\nf.write('hello')\nf.close()\nprint('WRITE_OK')\n`);
    const policyFile = writeTempPolicy(tempDir, {
      version: '0.4.0-alpha',
      filesystem: { readwritePaths: [tempDir] },
    });
    const output = runCli(`run-sdk --script "python ${scriptFile}" --cwd "${tempDir}" --container-name "test-4" --policy-file "${policyFile}"`);
    assert.ok(output.includes('WRITE_OK'));
    assert.ok(output.includes('Process exited with code 0'));
    assert.ok(fs.existsSync(testFile), 'File should have been written to readwrite path');
  });

  // Skipped: bfscfg.exe doesn't exist on workflow machines currently, run locally until then
  it.skip('readonlyPaths: should allow reading from brokered path', () => {
    tempDir = createTempDir();
    fs.writeFileSync(path.join(tempDir, 'input.txt'), 'readonly test data');
    const inputFile = path.join(tempDir, 'input.txt');
    const policyFile = writeTempPolicy(tempDir, {
      version: '0.4.0-alpha',
      filesystem: { readonlyPaths: [tempDir] },
    });
    const output = runCli(`run-sdk --script "cmd.exe /c type ${inputFile}" --cwd "${tempDir}" --container-name "test-5" --policy-file "${policyFile}"`);
    assert.ok(output.includes('readonly test data'));
    assert.ok(output.includes('Process exited with code 0'));
  });

  it('should reject policy with missing version', () => {
    tempDir = createTempDir();
    const policyFile = writeTempPolicy(tempDir, {});
    assert.throws(
      () => runCli(`run-sdk --script "cmd.exe /c echo hi" --cwd "${tempDir}" --container-name "test-no-ver" --policy-file "${policyFile}"`),
      { message: /version is required/ },
    );
  });

  it('should reject policy with invalid version', () => {
    tempDir = createTempDir();
    const policyFile = writeTempPolicy(tempDir, { version: '99.0.0' });
    assert.throws(
      () => runCli(`run-sdk --script "cmd.exe /c echo hi" --cwd "${tempDir}" --container-name "test-bad-ver" --policy-file "${policyFile}"`),
      { message: /newer than supported/ },
    );
  });

  // Skipped: AppContainer can't find executables on GitHub workflow runners, run locally until then
  it.skip('should launch basic appcontainer with valid version', () => {
    tempDir = createTempDir();
    const policyFile = writeTempPolicy(tempDir, { version: '0.4.0-alpha' });
    const output = runCli(`run-sdk --script "cmd.exe /c echo version ok" --container-name "test-ver" --policy-file "${policyFile}"`);
    assert.ok(output.includes('version ok'));
    assert.ok(output.includes('Process exited with code 0'));
  });
});

// Skipped: requires admin currently and not runnable in pipelines, run locally until then
describe.skip('SDK proxy end-to-end', () => {
  let tempDir = '';
  let proxyProcess: ChildProcess | null = null;

  afterEach(() => {
    if (proxyProcess) {
      proxyProcess.kill();
      proxyProcess = null;
    }
    if (tempDir && fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
      tempDir = '';
    }
  });

  it('builtinTestServer proxy: should route traffic through built-in proxy', () => {
    tempDir = createTempDir('mxc-proxy-test');
    const scriptFile = path.join(tempDir, 'proxy_cmd.txt');
    fs.writeFileSync(scriptFile, `python -c "import urllib.request; r = urllib.request.urlopen('https://api.github.com/zen', timeout=15); print('PROXY_RESPONSE: ' + r.read().decode())"`);
    const policyFile = writeTempPolicy(tempDir, {
      version: '0.4.0-alpha',
      network: {
        allowOutbound: true,
        proxy: { builtinTestServer: true },
      },
      filesystem: { readonlyPaths: [tempDir] },
    });

    const output = runCli(
      `run-sdk --script-file "${scriptFile}" --policy-file "${policyFile}" --debug`,
      90000,
    );
    assert.ok(output.includes('PROXY_RESPONSE:'), 'Expected a response through the proxy');
    assert.ok(output.includes('Process exited with code 0'));
    assert.ok(output.includes('Proxy policy active'), 'Expected proxy policy to be set up');
  });

  it('localhost proxy: should route traffic through external proxy', () => {
    tempDir = createTempDir('mxc-proxy-test');
    const { port, proxyProcess: proc } = startTestProxy(tempDir);
    proxyProcess = proc;

    const scriptFile = path.join(tempDir, 'proxy_cmd.txt');
    fs.writeFileSync(scriptFile, `python -c "import urllib.request; r = urllib.request.urlopen('https://api.github.com/zen', timeout=15); print('PROXY_RESPONSE: ' + r.read().decode())"`);
    const policyFile = writeTempPolicy(tempDir, {
      version: '0.4.0-alpha',
      network: {
        allowOutbound: true,
        proxy: { localhost: port },
      },
      filesystem: { readonlyPaths: [tempDir] },
    });

    const output = runCli(
      `run-sdk --script-file "${scriptFile}" --policy-file "${policyFile}" --debug`,
      90000,
    );
    assert.ok(output.includes('PROXY_RESPONSE:'), 'Expected a response through the proxy');
    assert.ok(output.includes('Process exited with code 0'));
    assert.ok(output.includes('Proxy policy active'), 'Expected proxy policy to be set up');
  });
});
