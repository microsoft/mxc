// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { describe, it, afterEach } from 'node:test';
import assert from 'node:assert';
import { execSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';
import {
  sdk,
  NETWORK_TEST_URL,
  createTempDir,
} from './test-helpers.js';

// Clipboard tests require a running pasteboard service. Probe once at
// module load and skip clipboard tests when the service is unavailable
// (e.g. headless CI runners without a GUI session).
function isClipboardAvailable(): boolean {
  try {
    execSync('echo probe | pbcopy && pbpaste', { timeout: 5000, stdio: 'pipe' });
    return true;
  } catch {
    return false;
  }
}

const clipboardAvailable = os.platform() === 'darwin' && isClipboardAvailable();
const clipboardSkipReason = !clipboardAvailable
  ? 'Clipboard (pasteboard service) not available on this host'
  : undefined;

// Network tests can be skipped independently of sandbox availability.
const skipNetworkTests = process.env.MXC_SKIP_SEATBELT_NETWORK_TESTS === '1';
const networkSkipReason = skipNetworkTests
  ? 'Skipped: network tests disabled (MXC_SKIP_SEATBELT_NETWORK_TESTS)'
  : undefined;

describe('macOS Seatbelt Container', {
  skip: os.platform() !== 'darwin'
    ? 'Seatbelt tests can only run on macOS'
    : undefined,
}, () => {
  let tempDir = '';

  afterEach(() => {
    if (tempDir && fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
      tempDir = '';
    }
  });

  it('should execute hello world in seatbelt sandbox', async () => {
    const result = await sdk.runRequestForTest(
      "echo 'Hello from seatbelt'",
      {},
      {},
      undefined,
      'seatbelt-hello',
    );
    assert.strictEqual(result.exitCode, 0, `Expected exit 0: ${result.stderr}`);
    assert.ok(result.stdout.includes('Hello from seatbelt'));
  });

  it('should propagate exit code', async () => {
    const result = await sdk.runRequestForTest(
      'exit 42',
      {},
      {},
      undefined,
      'seatbelt-exit-code',
    );
    assert.strictEqual(result.exitCode, 42);
  });

  it('should allow a process to signal its child', async () => {
    // The EXIT trap matters on the failing path this test exists to catch: if
    // `kill -TERM` is denied, `exit 1` would otherwise skip `wait` and orphan
    // the child. The runner deliberately won't group-kill it afterwards (a
    // reaped pid/pgid can be recycled), so it would outlive the test.
    const script = [
      'sleep 5 </dev/null >/dev/null 2>&1 & child=$!',
      `trap 'kill -KILL "$child" 2>/dev/null || true; wait "$child" 2>/dev/null || true' 0`,
      'kill -TERM "$child" || exit 1',
      'wait "$child"; status=$?',
      'trap - 0',
      'test "$status" -eq 143',
    ].join('\n');
    const result = await sdk.runRequestForTest(
      script,
      {},
      {},
      undefined,
      'seatbelt-child-signal',
    );
    // The in-process path returns stdout and stderr separately.
    assert.strictEqual(result.exitCode, 0, `Expected exit 0: ${result.stdout}`);
  });

  it('should deny filesystem access by default', async () => {
    // The default seatbelt profile denies access to /Users.
    const result = await sdk.runRequestForTest(
      'ls /Users 2>&1 || true',
      {},
      {},
      undefined,
      'seatbelt-filesystem-deny',
    );
    assert.ok(
      result.stdout.includes('Operation not permitted') ||
      result.stdout.includes('Permission denied') ||
      result.exitCode !== 0,
      `Expected filesystem denial, got: ${result.stdout}`,
    );
  });

  it('should deny network access when egress defaults to deny', async () => {
    const policy = {
      network: { egress: { default: 'deny' as const } },
    };
    const result = await sdk.runRequestForTest(
      "curl --max-time 5 --fail --silent --show-error https://example.com 2>&1; echo CURL_EXIT=$?",
      policy,
      {},
      undefined,
      'seatbelt-network-deny',
    );
    // curl should fail when network is blocked
    assert.ok(
      result.stdout.includes('CURL_EXIT=') && !result.stdout.includes('CURL_EXIT=0'),
      `Expected network denial, got: ${result.stdout}`,
    );
  });

  it('should allow network access when egress defaults to allow', { skip: networkSkipReason }, async () => {
    const policy = {
      network: { egress: { default: 'allow' as const } },
    };
    const result = await sdk.runRequestForTest(
      `RESULT=$(curl --max-time 10 --fail --silent '${NETWORK_TEST_URL}') && echo 'NETWORK_OK'`,
      policy,
      {},
      undefined,
      'seatbelt-network-allow',
    );
    assert.strictEqual(result.exitCode, 0, `Expected exit 0: ${result.stderr}`);
    assert.ok(result.stdout.includes('NETWORK_OK'));
  });

  it('should deny clipboard access when clipboard is none', { skip: clipboardSkipReason }, async () => {
    const policy = {
      ui: { disable: true, clipboard: 'none' as const },
    };
    const result = await sdk.runRequestForTest(
      "echo test_clip | pbcopy 2>&1 && pbpaste 2>&1",
      policy,
      {},
      undefined,
      'seatbelt-clipboard-deny',
    );
    // When clipboard is denied, pbcopy/pbpaste fail and exit code is non-zero
    assert.notStrictEqual(result.exitCode, 0, `Expected clipboard denial, got exit 0`);
  });

  it('should allow clipboard access when clipboard is all', { skip: clipboardSkipReason }, async () => {
    const uniqueToken = `seatbelt_clip_${Date.now()}`;
    const policy = {
      ui: { disable: true, clipboard: 'all' as const },
    };
    const result = await sdk.runRequestForTest(
      `echo '${uniqueToken}' | pbcopy && pbpaste`,
      policy,
      {},
      undefined,
      'seatbelt-clipboard-allow',
    );
    assert.strictEqual(result.exitCode, 0, `Expected exit 0: ${result.stderr}`);
    assert.ok(result.stdout.includes(uniqueToken));
  });

  it('should run multi-command pipeline', async () => {
    const result = await sdk.runRequestForTest(
      "echo 'step 1' && uname -s && echo 'step 2' && whoami && echo 'Pipeline complete'",
      {},
      {},
      undefined,
      'seatbelt-pipeline',
    );
    assert.strictEqual(result.exitCode, 0, `Expected exit 0: ${result.stderr}`);
    assert.ok(result.stdout.includes('Pipeline complete'));
    assert.ok(result.stdout.includes('Darwin'));
  });

  it('should enforce timeout on long-running scripts', async () => {
    const policy = {
      timeoutMs: 2000,
    };
    const result = await sdk.runRequestForTest(
      'sleep 30',
      policy,
      {},
      undefined,
      'seatbelt-timeout',
    );
    assert.strictEqual(result.timedOut, true);
    assert.strictEqual(result.exitCode, -1);
  });

  it('should apply profile override from seatbelt config', { timeout: 30_000 }, async () => {
    const process = sdk.spawn({
      command: "echo 'profile override works'",
      containment: {
        type: 'seatbelt',
        config: { profileOverride: '(version 1)\n(allow default)' },
      },
      containerName: 'seatbelt-profile-override',
    });
    const standardOutput = process.standardOutput;
    assert.ok(standardOutput, 'stdout should be available');
    let stdout = '';
    const outputEnded = new Promise<void>((resolve, reject) => {
      standardOutput.on('data', (data: Buffer) => { stdout += data.toString(); });
      standardOutput.once('end', resolve);
      standardOutput.once('error', reject);
    });
    const outcome = await process.waitAsync();
    await outputEnded;
    assert.strictEqual(outcome.exitCode, 0, `Expected exit 0: ${stdout}`);
    assert.ok(stdout.includes('profile override works'));
  });
});
