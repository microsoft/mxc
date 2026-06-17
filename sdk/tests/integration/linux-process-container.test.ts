// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { describe, it, afterEach } from 'node:test';
import assert from 'node:assert';
import fs from 'fs';
import os from 'os';
import path from 'path';
import type { SandboxPolicy } from '@microsoft/mxc-sdk';
import {
  sdk,
  supportedVersions,
  isLinuxRoot,
  createTempDir,
  NETWORK_TEST_URL,
  lxcNetworkSkipReason,
  debugSpawnOptions,
  spawnFromConfigAsync,
} from './test-helpers.js';

// MXC_SKIP_LXC_TESTS=1 skips the entire LXC describe block. Used by the GHA
// PR pipeline because classic LXC is unreliable on the ubuntu-latest (24.04)
// runner image; full LXC coverage runs in the ADO pipeline on merge to main
// and nightly.
const skipLxcTests = process.env.MXC_SKIP_LXC_TESTS === '1';
const lxcSkipReason = !isLinuxRoot
  ? 'Linux LXC Container tests require Linux with root privileges (sudo npm test)'
  : skipLxcTests
    ? 'Skipped: LXC tests disabled (MXC_SKIP_LXC_TESTS)'
    : undefined;

// Route through explicit `containment: 'lxc'` so these tests genuinely exercise
// the LXC backend. spawnSandboxAsync internally routes through abstract
// `containment: 'process'`, which on Linux resolves to a different backend
// (Bubblewrap). The LXC backend is covered by an explicit opt-in only.
async function runLxc(
  script: string,
  policy: SandboxPolicy,
  containerId: string,
): Promise<{ stdout: string; stderr: string; exitCode: number }> {
  const config = sdk.createConfigFromPolicy(policy, 'lxc', containerId);
  config.process!.commandLine = script;
  return spawnFromConfigAsync(config, debugSpawnOptions);
}

for (const schemaVersion of supportedVersions) {
describe(`Linux LXC Container (schema ${schemaVersion})`, {
  skip: lxcSkipReason,
}, () => {
  let tempDir = '';

  afterEach(() => {
    if (tempDir && fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
      tempDir = '';
    }
  });

  it('should execute hello world in LXC container', async () => {
    const result = await runLxc(
      "echo 'Hello from LXC via CLI'",
      { version: schemaVersion.raw },
      `lxc-hello-${schemaVersion}`,
    );
    assert.strictEqual(result.exitCode, 0, `[${schemaVersion}] Expected exit 0: ${result.stderr}`);
    assert.ok(result.stdout.includes('Hello from LXC via CLI'));
  });

  it('should propagate exit code', async () => {
    const result = await runLxc(
      "echo 'about to exit' && exit 0",
      { version: schemaVersion.raw },
      `lxc-exit-${schemaVersion}`,
    );
    assert.strictEqual(result.exitCode, 0, `[${schemaVersion}] Expected exit 0: ${result.stderr}`);
    assert.ok(result.stdout.includes('about to exit'));
  });

  it('should report system info', async () => {
    const result = await runLxc(
      "uname -a && echo 'System info test passed'",
      { version: schemaVersion.raw },
      `lxc-sysinfo-${schemaVersion}`,
    );
    assert.strictEqual(result.exitCode, 0, `[${schemaVersion}] Expected exit 0: ${result.stderr}`);
    assert.ok(result.stdout.includes('System info test passed'));
  });

  it('should select LXC backend (not Bubblewrap) on explicit containment="lxc"', async () => {
    // Probe PID 1 to distinguish backends:
    //   bwrap -> PID 1 comm == 'bwrap' (bwrap re-execs itself as init in the new pid namespace)
    //   LXC   -> PID 1 comm is 'init' / 'systemd' (the container's init)
    // We assert NOT bwrap by checking PID 1 is not 'bwrap'.
    const probe =
      "PID1=$(cat /proc/1/comm); " +
      "echo \"pid1=$PID1\"; " +
      "[ \"$PID1\" != bwrap ] || { echo 'FAIL: PID 1 is bwrap, looks like Bubblewrap, not LXC'; exit 1; }; " +
      "echo 'OK: not under Bubblewrap'";
    const result = await runLxc(
      probe,
      { version: schemaVersion.raw },
      `lxc-probe-${schemaVersion}`,
    );
    assert.strictEqual(result.exitCode, 0, `[${schemaVersion}] LXC backend probe failed: ${result.stdout}`);
    assert.ok(result.stdout.includes('OK: not under Bubblewrap'), `[${schemaVersion}] ${result.stdout}`);
  });

  it('should allow outbound network access', { skip: lxcNetworkSkipReason }, async () => {
    const policy = { version: schemaVersion.raw, network: { allowOutbound: true } };
    const result = await runLxc(
      `wget -q -T 10 -O /dev/null '${NETWORK_TEST_URL}' && echo 'Network accessible'`,
      policy,
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
    const result = await runLxc(script, policy, `lxc-rw-${schemaVersion}`);
    assert.strictEqual(result.exitCode, 0, `[${schemaVersion}] Expected exit 0: ${result.stderr}`);
    assert.ok(result.stdout.includes('overwritten'));
  });

  it('should mount readonly filesystem path', async () => {
    tempDir = createTempDir('mxc-lxc-test');
    fs.writeFileSync(path.join(tempDir, 'data.txt'), 'readonly content');
    const policy = { version: schemaVersion.raw, filesystem: { readonlyPaths: [tempDir] } };
    const result = await runLxc(
      `cat ${tempDir}/data.txt && echo 'Read succeeded'`,
      policy,
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
    const result = await runLxc(script, policy, `lxc-combined-${schemaVersion}`);
    assert.strictEqual(result.exitCode, 0, `[${schemaVersion}] Expected exit 0: ${result.stderr}`);
    assert.ok(result.stdout.includes('Combined test passed'));
  });

  it('should access HTTPS endpoint', { skip: lxcNetworkSkipReason }, async () => {
    const policy = { version: schemaVersion.raw, network: { allowOutbound: true } };
    const result = await runLxc(
      `wget -q -T 10 -O /dev/null '${NETWORK_TEST_URL}' && echo 'HTTPS endpoint accessible'`,
      policy,
      `lxc-https-${schemaVersion}`,
    );
    assert.strictEqual(result.exitCode, 0, `[${schemaVersion}] Expected exit 0: ${result.stderr}`);
    assert.ok(result.stdout.includes('HTTPS endpoint accessible'));
  });

  it('should run multi-command pipeline', async () => {
    const script = "echo 'step 1' && ls / && echo 'step 2' && whoami && echo 'Multi-command passed'";
    const result = await runLxc(
      script,
      { version: schemaVersion.raw },
      `lxc-pipeline-${schemaVersion}`,
    );
    assert.strictEqual(result.exitCode, 0, `[${schemaVersion}] Expected exit 0: ${result.stderr}`);
    assert.ok(result.stdout.includes('Multi-command passed'));
  });
});
}
