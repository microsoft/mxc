// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { describe, it, afterEach } from 'node:test';
import assert from 'node:assert';
import fs from 'fs';
import os from 'os';
import path from 'path';
import {
  sdk,
  supportedVersions,
  isLinuxRoot,
  createTempDir,
  NETWORK_TEST_URL,
  lxcNetworkSkipReason,
  debugSpawnOptions,
} from './test-helpers.js';

for (const schemaVersion of supportedVersions) {
describe(`Linux Process Container (schema ${schemaVersion})`, {
  skip: !isLinuxRoot ? 'Linux Process Container tests require Linux with root privileges (sudo npm test)' : undefined,
}, () => {
  let tempDir = '';

  afterEach(() => {
    if (tempDir && fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
      tempDir = '';
    }
  });

  it('should execute hello world in LXC container', async () => {
    const result = await sdk.spawnSandboxAsync(
      "echo 'Hello from LXC via CLI'",
      { version: schemaVersion.raw },
      debugSpawnOptions,
      undefined,
      `lxc-hello-${schemaVersion}`,
    );
    assert.strictEqual(result.exitCode, 0, `[${schemaVersion}] Expected exit 0: ${result.stderr}`);
    assert.ok(result.stdout.includes('Hello from LXC via CLI'));
  });

  it('should propagate exit code', async () => {
    const result = await sdk.spawnSandboxAsync(
      "echo 'about to exit' && exit 0",
      { version: schemaVersion.raw },
      debugSpawnOptions,
      undefined,
      `lxc-exit-${schemaVersion}`,
    );
    assert.strictEqual(result.exitCode, 0, `[${schemaVersion}] Expected exit 0: ${result.stderr}`);
    assert.ok(result.stdout.includes('about to exit'));
  });

  it('should report system info', async () => {
    const result = await sdk.spawnSandboxAsync(
      "uname -a && echo 'System info test passed'",
      { version: schemaVersion.raw },
      debugSpawnOptions,
      undefined,
      `lxc-sysinfo-${schemaVersion}`,
    );
    assert.strictEqual(result.exitCode, 0, `[${schemaVersion}] Expected exit 0: ${result.stderr}`);
    assert.ok(result.stdout.includes('System info test passed'));
  });

  it('should allow outbound network access', { skip: lxcNetworkSkipReason }, async () => {
    const policy = { version: schemaVersion.raw, network: { allowOutbound: true } };
    const result = await sdk.spawnSandboxAsync(
      `wget -q -T 10 -O /dev/null '${NETWORK_TEST_URL}' && echo 'Network accessible'`,
      policy,
      debugSpawnOptions,
      undefined,
      `lxc-net-${schemaVersion}`,
    );
    assert.strictEqual(result.exitCode, 0, `[${schemaVersion}] Expected exit 0: ${result.stderr}`);
    assert.ok(result.stdout.includes('Network accessible'));
  });

  it('should mount readwrite filesystem path', async () => {
    tempDir = createTempDir('mxc-lxc-test');
    fs.writeFileSync(path.join(tempDir, 'test.txt'), 'original');
    const policy = { version: schemaVersion.raw, filesystem: { readwritePaths: [tempDir] } };
    const script = `cat ${tempDir}/test.txt && echo 'overwritten' > ${tempDir}/test.txt && cat ${tempDir}/test.txt`;
    const result = await sdk.spawnSandboxAsync(
      script, policy, debugSpawnOptions, undefined, `lxc-rw-${schemaVersion}`,
    );
    assert.strictEqual(result.exitCode, 0, `[${schemaVersion}] Expected exit 0: ${result.stderr}`);
    assert.ok(result.stdout.includes('overwritten'));
  });

  it('should mount readonly filesystem path', async () => {
    tempDir = createTempDir('mxc-lxc-test');
    fs.writeFileSync(path.join(tempDir, 'data.txt'), 'readonly content');
    const policy = { version: schemaVersion.raw, filesystem: { readonlyPaths: [tempDir] } };
    const result = await sdk.spawnSandboxAsync(
      `cat ${tempDir}/data.txt && echo 'Read succeeded'`,
      policy,
      debugSpawnOptions,
      undefined,
      `lxc-ro-${schemaVersion}`,
    );
    assert.strictEqual(result.exitCode, 0, `[${schemaVersion}] Expected exit 0: ${result.stderr}`);
    assert.ok(result.stdout.includes('Read succeeded'));
  });

  it('should download file to writable mount', { skip: lxcNetworkSkipReason }, async () => {
    tempDir = createTempDir('mxc-lxc-test');
    const policy = {
      version: schemaVersion.raw,
      filesystem: { readwritePaths: [tempDir] },
      network: { allowOutbound: true },
    };
    const script =
      `wget -q -T 10 -O ${tempDir}/download.json '${NETWORK_TEST_URL}'` +
      ` && test -s ${tempDir}/download.json && echo 'Combined test passed'`;
    const result = await sdk.spawnSandboxAsync(
      script, policy, debugSpawnOptions, undefined, `lxc-combined-${schemaVersion}`,
    );
    assert.strictEqual(result.exitCode, 0, `[${schemaVersion}] Expected exit 0: ${result.stderr}`);
    assert.ok(result.stdout.includes('Combined test passed'));
  });

  it('should access HTTPS endpoint', { skip: lxcNetworkSkipReason }, async () => {
    const policy = { version: schemaVersion.raw, network: { allowOutbound: true } };
    const result = await sdk.spawnSandboxAsync(
      `wget -q -T 10 -O /dev/null '${NETWORK_TEST_URL}' && echo 'HTTPS endpoint accessible'`,
      policy,
      debugSpawnOptions,
      undefined,
      `lxc-https-${schemaVersion}`,
    );
    assert.strictEqual(result.exitCode, 0, `[${schemaVersion}] Expected exit 0: ${result.stderr}`);
    assert.ok(result.stdout.includes('HTTPS endpoint accessible'));
  });

  it('should run multi-command pipeline', async () => {
    const script = "echo 'step 1' && ls / && echo 'step 2' && whoami && echo 'Multi-command passed'";
    const result = await sdk.spawnSandboxAsync(
      script, { version: schemaVersion.raw }, debugSpawnOptions, undefined, `lxc-pipeline-${schemaVersion}`,
    );
    assert.strictEqual(result.exitCode, 0, `[${schemaVersion}] Expected exit 0: ${result.stderr}`);
    assert.ok(result.stdout.includes('Multi-command passed'));
  });
});
}
