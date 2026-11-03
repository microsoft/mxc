// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { describe, it, before, after, afterEach } from 'node:test';
import assert from 'node:assert';
import { ChildProcess, execFileSync } from 'child_process';
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
  pythonCommand,
  pythonSkipReason,
} from './test-helpers.js';

const proxyOriginUrl = process.env.MXC_TEST_PROXY_ORIGIN_URL;
const proxyExpectedBody = process.env.MXC_TEST_PROXY_EXPECTED_BODY;
const proxySkipReason = sandboxSkipReason ??
  (process.env.MXC_ENABLE_PROCESSCONTAINER_PROXY_TESTS === '1'
    ? (proxyOriginUrl && proxyExpectedBody ? undefined : 'Set MXC_TEST_PROXY_ORIGIN_URL and MXC_TEST_PROXY_EXPECTED_BODY')
    : 'Set MXC_ENABLE_PROCESSCONTAINER_PROXY_TESTS=1 to run ProcessContainer proxy tests');

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

  for (const [name, operation] of [['run', sdk.run]] as const) {
    it(`public ${name} captures output and the workload exit code`, { skip: sandboxSkipReason }, async () => {
      const result = await operation({
        containment: { type: 'processcontainer' },
        command: 'cmd.exe /c "echo PUBLIC_RUN_OK & echo PUBLIC_RUN_ERROR 1>&2 & exit /b 7"',
        timeoutMs: 30000,
      });
      assert.strictEqual(result.exitCode, 7);
      assert.strictEqual(result.timedOut, false);
      assert.ok(result.stdout.includes('PUBLIC_RUN_OK'));
      assert.ok(result.stderr.includes('PUBLIC_RUN_ERROR'));
      assert.ok(Array.isArray(result.warnings));
    });
  }

  for (const [name, operation] of [['spawn', sdk.spawn]] as const) {
    it(`public ${name} returns an SDK process with live standard streams`, { skip: sandboxSkipReason }, async () => {
      const handle = await operation({
        containment: { type: 'processcontainer' },
        command: 'cmd.exe /c "echo PUBLIC_SPAWN_OK & echo PUBLIC_SPAWN_ERROR 1>&2 & exit /b 9"',
        timeoutMs: 30000,
      });
      try {
        const stdout = handle.standardOutput;
        const stderr = handle.standardError;
        assert.ok(stdout);
        assert.ok(stderr);
        const read = async (stream: NodeJS.ReadableStream): Promise<string> => {
          let text = '';
          for await (const chunk of stream) text += chunk.toString();
          return text;
        };
        const output = read(stdout);
        const error = read(stderr);
        const result = await handle.wait();
        assert.strictEqual(result.exitCode, 9);
        assert.strictEqual(result.timedOut, false);
        assert.ok((await output).includes('PUBLIC_SPAWN_OK'));
        assert.ok((await error).includes('PUBLIC_SPAWN_ERROR'));
        assert.ok(Array.isArray(handle.warnings));
      } finally {
        handle.dispose();
      }
    });
  }

  it('public spawnWithPty supports interactive ProcessContainer I/O', { skip: sandboxSkipReason }, async () => {
    const terminal = await sdk.spawnWithPty({
      containment: { type: 'processcontainer' },
      command: 'cmd.exe',
      timeoutMs: 30000,
    });
    try {
      assert.ok(terminal.id > 0);
      const output = (async (): Promise<string> => {
        let text = '';
        for await (const chunk of terminal.output) text += chunk.toString();
        return text;
      })();
      terminal.input.write('echo PUBLIC_PTY_OK\r\nexit /b 13\r\n');

      const result = await terminal.wait();
      assert.strictEqual(result.exitCode, 13);
      assert.strictEqual(result.timedOut, false);
      assert.ok((await output).includes('PUBLIC_PTY_OK'));
    } finally {
      terminal.dispose();
    }
  });

  it('should execute cmd.exe in process container', { skip: sandboxSkipReason }, async () => {
    const result = await sdk.runRequestForTest(
      'cmd.exe /c echo Container test successful',
      {},
      {},
      undefined,
      `test-1-${schemaVersion}`,
    );
    assert.strictEqual(result.exitCode, 0, `[${schemaVersion}] Expected exit 0: ${result.stderr}`);
    assert.ok(result.stdout.includes('Container test successful'));
  });

  it('should execute powershell 5.1 in process container', { skip: sandboxSkipReason }, async () => {
    const result = await sdk.runRequestForTest(
      "powershell.exe -NoProfile -Command Write-Output 'PowerShell test successful'",
      { ui: { disable: false } },
      {},
      undefined,
      `test-2-${schemaVersion}`,
    );
    assert.strictEqual(result.exitCode, 0, `[${schemaVersion}] Expected exit 0: ${result.stderr}`);
    assert.ok(result.stdout.includes('PowerShell test successful'));
  });

  it('should execute python in process container', { skip: sandboxSkipReason ?? pythonSkipReason }, async () => {
    const policy = withToolPaths({ ui: { disable: false } });
    const result = await sdk.runRequestForTest(
      `${pythonCommand} -c "print('Python test successful')"`,
      policy,
      {},
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
      ui: { disable: false },
      filesystem: { readwritePaths: [tempDir] },
    });
    const result = await sdk.runRequestForTest(
      `${pythonCommand} ${scriptFile}`,
      policy,
      {},
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
      filesystem: { readonlyPaths: [tempDir] },
    });
    const result = await sdk.runRequestForTest(
      `cmd.exe /c type ${inputFile}`,
      policy,
      {},
      tempDir,
      `test-5-${schemaVersion}`,
    );
    assert.strictEqual(result.exitCode, 0, `[${schemaVersion}] Expected exit 0: ${result.stderr}`);
    assert.ok(result.stdout.includes('readonly test data'));
  });

  it('public tool discovery allows tool reads but denies sibling private files', { skip: sandboxSkipReason }, async () => {
    tempDir = createTempDir('mxc-tool-discovery', import.meta.dirname);
    const systemDirectory = path.join(process.env.SystemRoot || 'C:\\Windows', 'System32');
    // Keep the new fixture private even when the host temp directory grants AppContainer access.
    execFileSync(path.join(systemDirectory, 'WindowsPowerShell', 'v1.0', 'powershell.exe'), [
      '-NoProfile', '-NonInteractive', '-Command',
      "$ErrorActionPreference = 'Stop'; " +
      '$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value; ' +
      '$acl = [Security.AccessControl.DirectorySecurity]::new(); ' +
      '$acl.SetSecurityDescriptorSddlForm("D:P(A;OICI;FA;;;$sid)", ' +
      '[Security.AccessControl.AccessControlSections]::Access); ' +
      '[IO.Directory]::SetAccessControl($env:MXC_TOOL_DISCOVERY_FIXTURE, $acl)',
    ], {
      env: { ...process.env, MXC_TOOL_DISCOVERY_FIXTURE: tempDir },
      windowsHide: true,
      timeout: 30000,
    });

    const toolDirectory = path.join(tempDir, 'tools');
    const privateDirectory = path.join(tempDir, 'private');
    fs.mkdirSync(toolDirectory);
    fs.mkdirSync(privateDirectory);
    fs.writeFileSync(path.join(toolDirectory, 'pwsh.exe'), '');
    const toolFile = path.join(toolDirectory, 'tool-data.txt');
    const privateFile = path.join(privateDirectory, 'sentinel.txt');
    const toolData = 'MXC_DISCOVERED_TOOL_READ_OK';
    const privateData = 'MXC_PRIVATE_SIBLING_MUST_NOT_BE_READ';
    fs.writeFileSync(toolFile, toolData);
    fs.writeFileSync(privateFile, privateData);
    assert.strictEqual(fs.readFileSync(privateFile, 'utf8'), privateData);

    const readFile = (file: string, filesystem: Parameters<typeof sdk.run>[0]['filesystem'] = {}) => sdk.run({
      containment: { type: 'processcontainer' },
      command: `cmd.exe /d /c type "${file}"`,
      workingDirectory: systemDirectory,
      filesystem,
      timeoutMs: 30000,
    });
    const assertDenied = (result: Awaited<ReturnType<typeof readFile>>) => {
      assert.strictEqual(result.timedOut, false);
      assert.notStrictEqual(result.exitCode, 0, `Unexpected private-file access: ${result.stdout}`);
      assert.ok(!result.stdout.includes(privateData), 'Private sentinel contents escaped containment');
    };
    assertDenied(await readFile(privateFile));

    const discovered = sdk.policy.filesystem.getAvailableToolsPolicy({
      PATH: toolDirectory,
      SystemDrive: path.parse(tempDir).root.replace(/\\$/, ''),
    });
    assert.deepStrictEqual(discovered.readonlyPaths, [path.resolve(toolDirectory)]);
    const allowed = await readFile(toolFile, discovered);
    assert.strictEqual(allowed.timedOut, false);
    assert.strictEqual(allowed.exitCode, 0, allowed.stderr);
    assert.strictEqual(allowed.stdout.trim(), toolData);
    assertDenied(await readFile(privateFile, discovered));
  });

  it('should launch basic process container with valid version', { skip: sandboxSkipReason }, async () => {
    const result = await sdk.runRequestForTest(
      'cmd.exe /c echo version ok',
      {},
      {},
      undefined,
      `test-ver-${schemaVersion}`,
    );
    assert.strictEqual(result.exitCode, 0, `[${schemaVersion}] Expected exit 0: ${result.stderr}`);
    assert.ok(result.stdout.includes('version ok'));
  });

  describe('proxy end-to-end', { skip: proxySkipReason }, () => {
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

    for (const [name, operation] of [['run', sdk.run]] as const) {
      it(`public ${name} routes traffic through an unpackaged proxy`, async () => {
        assert.ok(proxyExpectedBody);
        tempDir = createTempDir('mxc-proxy-test');
        const { port, proxyProcess: proc } = startTestProxy(tempDir);
        proxyProcess = proc;

        const script =
          `powershell.exe -NoProfile -Command "` +
          `$ErrorActionPreference = 'Stop'; ` +
          `$h = New-Object -ComObject WinHttp.WinHttpRequest.5.1; ` +
          `$h.SetTimeouts(5000,5000,5000,5000); ` +
          `$h.Open('GET','${proxyOriginUrl}',$false); ` +
          `$h.Send(); ` +
          `if ($h.Status -ne 200) { throw ('HTTP status ' + $h.Status) }; ` +
          `Write-Output ('PROXY_RESPONSE: ' + $h.ResponseText)"`;
        const result = await operation({
          command: script,
          containment: { type: 'processcontainer' },
          ui: { disable: false },
          timeoutMs: 30000,
          network: {
            egress: { default: 'deny' },
            ingress: { default: 'allow', hostLoopback: 'allow' },
            runtimeConfig: { networkProxy: `http://127.0.0.1:${port}` },
          },
        });

        assert.strictEqual(result.exitCode, 0, `[${schemaVersion}] Expected exit 0: ${result.stderr}`);
        assert.strictEqual(result.timedOut, false);
        assert.ok(result.stdout.includes('PROXY_RESPONSE: '), result.stdout);
        assert.ok(result.stdout.includes(proxyExpectedBody), result.stdout);
      });
    }
  });
});
}
