// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { describe, it, before, after, afterEach } from 'node:test';
import assert from 'node:assert';
import { ChildProcess, execFileSync } from 'child_process';
import { EventEmitter } from 'events';
import fs from 'fs';
import os from 'os';
import path from 'path';
import type { ContainerConfig, SandboxPolicy } from '@microsoft/mxc-sdk';
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
  getSdkBinDir,
  assertDryRunResult,
} from './test-helpers.js';

const baseContainerSkipReason = (() => {
  if (os.platform() !== 'win32') return 'BaseContainer dry-run tests require Windows';
  if (sandboxSkipReason) return sandboxSkipReason;
  try {
    const probe = JSON.parse(
      execFileSync(path.join(getSdkBinDir(), 'wxc-exec.exe'), ['--probe'], {
        encoding: 'utf8',
        timeout: 30_000,
      }),
    ) as { tier?: string; error?: string };
    return probe.tier === 'base-container'
      ? undefined
      : `BaseContainer tier 1 unavailable: ${probe.error ?? probe.tier ?? 'unknown tier'}`;
  } catch (error) {
    return `BaseContainer probe failed: ${error instanceof Error ? error.message : String(error)}`;
  }
})();

async function dryRunProcessContainer(config: ContainerConfig): Promise<void> {
  const result = await new Promise<{ exitCode: number; stdout: string; stderr: string }>(
    (resolve, reject) => {
      const child = sdk.spawnSandboxFromConfig(config, {
        dryRun: true,
        usePty: false,
        ...debugSpawnOptions,
      });
      let stdout = '';
      let stderr = '';
      child.stdout?.on('data', (data: Buffer) => {
        stdout += data.toString();
      });
      child.stderr?.on('data', (data: Buffer) => {
        stderr += data.toString();
      });
      child.on('close', (exitCode: number) => resolve({ exitCode, stdout, stderr }));
      child.on('error', reject);
    },
  );

  assertDryRunResult(
    `${result.stdout}\n${result.stderr}`,
    result.exitCode,
    config.version,
  );
}

describe('Windows BaseContainer schema 0.8 networking dry-run', {
  skip: baseContainerSkipReason,
}, () => {
  const cases: Array<{ name: string; network: NonNullable<ContainerConfig['network']> }> = [
    {
      name: 'deny defaults',
      network: {
        egress: { default: 'deny' },
        ingress: { default: 'deny', hostLoopback: 'deny' },
      },
    },
    {
      name: 'allow egress default',
      network: {
        egress: { default: 'allow' },
        ingress: { default: 'deny', hostLoopback: 'deny' },
      },
    },
    {
      name: 'allow private-network ingress',
      network: {
        egress: { default: 'deny' },
        ingress: { default: 'allow', hostLoopback: 'deny' },
      },
    },
    {
      name: 'CIDR protocol and port rules',
      network: {
        egress: {
          default: 'deny',
          allow: [{
            to: [{ cidr: '10.0.0.0/8', except: ['10.1.0.0/16'] }],
            ports: [{ protocol: 'tcp', port: 443 }],
          }],
          deny: [{
            to: [{ cidr: '10.2.0.0/16' }],
            ports: [{ protocol: 'udp', port: 53 }],
          }],
        },
        ingress: { default: 'deny', hostLoopback: 'deny' },
      },
    },
  ];

  for (const testCase of cases) {
    it(`accepts ${testCase.name}`, async () => {
      await dryRunProcessContainer({
        version: '0.8.0-alpha',
        containerId: `dryrun-network-${testCase.name.replaceAll(' ', '-')}`,
        containment: 'processcontainer',
        process: { commandLine: 'cmd.exe /c echo test' },
        processContainer: {},
        network: testCase.network,
      });
    });
  }
});

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
    const policy = withToolPaths({ version: schemaVersion.raw, ui: { allowWindows: true } }) as SandboxPolicy;
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
    }) as SandboxPolicy;
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
    }) as SandboxPolicy;
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
      }) as SandboxPolicy;
      const script =
        `powershell.exe -NoProfile -Command "` +
        `$h = New-Object -ComObject WinHttp.WinHttpRequest.5.1; ` +
        `$h.Open('GET','https://api.github.com/zen',$false); ` +
        `$h.Send(); ` +
        `Write-Output ('PROXY_RESPONSE: ' + $h.ResponseText)"`;
      const result = await sdk.spawnSandboxAsync(
        script, policy, { debug: true, allowTestingFeatures: true }, undefined, `proxy-builtin-${schemaVersion}`,
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
      }) as SandboxPolicy;
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
