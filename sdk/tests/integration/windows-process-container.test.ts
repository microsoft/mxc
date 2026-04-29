// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { describe, it, before, after, afterEach } from 'node:test';
import assert from 'node:assert';
import { ChildProcess } from 'child_process';
import { EventEmitter } from 'events';
import fs from 'fs';
import os from 'os';
import path from 'path';
import {
  sdk,
  supportedVersions,
  sandboxSkipReason,
  createTempDir,
  withToolPaths,
  startTestProxy,
  debugSpawnOptions,
  pythonCommand,
  pythonSkipReason,
} from './test-helpers';

for (const schemaVersion of supportedVersions) {
describe(`Windows Process Container (schema ${schemaVersion})`, {
  skip: os.platform() !== 'win32' ? 'Windows Process Container tests can only be ran on Windows' : undefined,
}, () => {
  let tempDir = '';

  afterEach(() => {
    if (tempDir && fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
      tempDir = '';
    }
  });

  it('should execute cmd.exe in process container', { skip: sandboxSkipReason }, async () => {
    const result = await sdk.spawnSandboxAsync(
      'cmd.exe /c echo Container test successful',
      { version: schemaVersion.raw },
      debugSpawnOptions,
      undefined,
      `test-1-${schemaVersion}`,
    );
    assert.strictEqual(result.exitCode, 0, `[${schemaVersion}] Expected exit 0: ${result.stderr}`);
    assert.ok(result.stdout.includes('Container test successful'));
  });

  it('should execute powershell 5.1 in process container', { skip: sandboxSkipReason }, async () => {
    const result = await sdk.spawnSandboxAsync(
      "powershell.exe -NoProfile -Command Write-Output 'PowerShell test successful'",
      { version: schemaVersion.raw, ui: { allowWindows: true } },
      debugSpawnOptions,
      undefined,
      `test-2-${schemaVersion}`,
    );
    assert.strictEqual(result.exitCode, 0, `[${schemaVersion}] Expected exit 0: ${result.stderr}`);
    assert.ok(result.stdout.includes('PowerShell test successful'));
  });

  it('should execute python in process container', { skip: sandboxSkipReason ?? pythonSkipReason }, async () => {
    const policy = withToolPaths({ version: schemaVersion.raw, ui: { allowWindows: true } });
    const result = await sdk.spawnSandboxAsync(
      `${pythonCommand} -c "print('Python test successful')"`,
      policy,
      debugSpawnOptions,
      undefined,
      `test-3-${schemaVersion}`,
    );
    assert.strictEqual(result.exitCode, 0, `[${schemaVersion}] Expected exit 0: ${result.stderr}`);
    assert.ok(result.stdout.includes('Python test successful'));
  });

  it('should allow writing to brokered readwrite path', { skip: sandboxSkipReason ?? pythonSkipReason }, async () => {
    tempDir = createTempDir();
    const testFile = path.join(tempDir, 'output.txt');
    const scriptFile = path.join(tempDir, 'write_test.py');
    fs.writeFileSync(scriptFile, `f = open(r'${testFile}', 'w')\nf.write('hello')\nf.close()\nprint('WRITE_OK')\n`);
    const policy = withToolPaths({
      version: schemaVersion.raw,
      ui: { allowWindows: true },
      filesystem: { readwritePaths: [tempDir] },
    });
    const result = await sdk.spawnSandboxAsync(
      `${pythonCommand} ${scriptFile}`,
      policy,
      debugSpawnOptions,
      tempDir,
      `test-4-${schemaVersion}`,
    );
    assert.strictEqual(result.exitCode, 0, `[${schemaVersion}] Expected exit 0: ${result.stderr}`);
    assert.ok(result.stdout.includes('WRITE_OK'));
    assert.ok(fs.existsSync(testFile), 'File should have been written to readwrite path');
  });

  it('should allow reading from brokered readonly path', { skip: sandboxSkipReason }, async () => {
    tempDir = createTempDir();
    fs.writeFileSync(path.join(tempDir, 'input.txt'), 'readonly test data');
    const inputFile = path.join(tempDir, 'input.txt');
    const policy = withToolPaths({
      version: schemaVersion.raw,
      filesystem: { readonlyPaths: [tempDir] },
    });
    const result = await sdk.spawnSandboxAsync(
      `cmd.exe /c type ${inputFile}`,
      policy,
      debugSpawnOptions,
      tempDir,
      `test-5-${schemaVersion}`,
    );
    assert.strictEqual(result.exitCode, 0, `[${schemaVersion}] Expected exit 0: ${result.stderr}`);
    assert.ok(result.stdout.includes('readonly test data'));
  });

  it('should launch basic process container with valid version', { skip: sandboxSkipReason }, async () => {
    const result = await sdk.spawnSandboxAsync(
      'cmd.exe /c echo version ok',
      { version: schemaVersion.raw },
      debugSpawnOptions,
      undefined,
      `test-ver-${schemaVersion}`,
    );
    assert.strictEqual(result.exitCode, 0, `[${schemaVersion}] Expected exit 0: ${result.stderr}`);
    assert.ok(result.stdout.includes('version ok'));
  });

  describe('proxy end-to-end', { skip: sandboxSkipReason }, () => {
    let proxyProcess: ChildProcess | null = null;
    let originalMaxListeners: number;

    // Proxy tests can accumulate socket listeners when connections hang (e.g. BaseContainer proxy issues).
    // Raise the cap to avoid spurious MaxListenersExceededWarning noise in test output.
    before(() => {
      originalMaxListeners = EventEmitter.defaultMaxListeners;
      EventEmitter.defaultMaxListeners = 30;
    });
    after(() => {
      EventEmitter.defaultMaxListeners = originalMaxListeners;
    });

    afterEach(() => {
      if (proxyProcess) {
        proxyProcess.kill();
        proxyProcess = null;
      }
    });

    it('should route traffic through built-in proxy', async () => {
      tempDir = createTempDir('mxc-proxy-test');
      const policy = withToolPaths({
        version: schemaVersion.raw,
        network: { allowOutbound: true, proxy: { builtinTestServer: true } },
        ui: { allowWindows: true },
      });
      const script =
        `powershell.exe -NoProfile -Command "` +
        `$h = New-Object -ComObject WinHttp.WinHttpRequest.5.1; ` +
        `$h.Open('GET','https://api.github.com/zen',$false); ` +
        `$h.Send(); ` +
        `Write-Output ('PROXY_RESPONSE: ' + $h.ResponseText)"`;
      const result = await sdk.spawnSandboxAsync(
        script, policy, { debug: true }, undefined, `proxy-builtin-${schemaVersion}`,
      );

      assert.strictEqual(result.exitCode, 0, `[${schemaVersion}] Expected exit 0: ${result.stderr}`);
      assert.ok(result.stdout.includes('PROXY_RESPONSE:'));
      assert.ok(result.stdout.includes('Proxy policy active'));
    });

    it('should route traffic through external proxy', async () => {
      tempDir = createTempDir('mxc-proxy-test');
      const { port, proxyProcess: proc } = startTestProxy(tempDir);
      proxyProcess = proc;

      const policy = withToolPaths({
        version: schemaVersion.raw,
        network: { allowOutbound: true, proxy: { localhost: port } },
        ui: { allowWindows: true },
      });
      const script =
        `powershell.exe -NoProfile -Command "` +
        `$h = New-Object -ComObject WinHttp.WinHttpRequest.5.1; ` +
        `$h.Open('GET','https://api.github.com/zen',$false); ` +
        `$h.Send(); ` +
        `Write-Output ('PROXY_RESPONSE: ' + $h.ResponseText)"`;
      const result = await sdk.spawnSandboxAsync(
        script, policy, { debug: true }, undefined, `proxy-ext-${schemaVersion}`,
      );

      assert.strictEqual(result.exitCode, 0, `[${schemaVersion}] Expected exit 0: ${result.stderr}`);
      assert.ok(result.stdout.includes('PROXY_RESPONSE:'));
      assert.ok(result.stdout.includes('Proxy policy active'));
    });
  });
});
}
