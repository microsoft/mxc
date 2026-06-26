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
  debugSpawnOptions,
  NETWORK_TEST_URL,
  createTempDir,
} from './test-helpers.js';

const seatbeltSpawnOptions = { ...debugSpawnOptions, experimental: true };

// Seatbelt requires at least schema 0.5.0; the corpus floor is now 0.6.0-alpha.
const schemaVersion = '0.6.0-alpha';

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
    const result = await sdk.spawnSandboxAsync(
      "echo 'Hello from seatbelt'",
      { version: schemaVersion },
      seatbeltSpawnOptions,
      undefined,
      'seatbelt-hello',
    );
    assert.strictEqual(result.exitCode, 0, `Expected exit 0: ${result.stderr}`);
    assert.ok(result.stdout.includes('Hello from seatbelt'));
  });

  it('should propagate exit code', async () => {
    const result = await sdk.spawnSandboxAsync(
      'exit 42',
      { version: schemaVersion },
      seatbeltSpawnOptions,
      undefined,
      'seatbelt-exit-code',
    );
    assert.strictEqual(result.exitCode, 42);
  });

  it('should deny filesystem access by default', async () => {
    // The default seatbelt profile denies access to /Users.
    const result = await sdk.spawnSandboxAsync(
      'ls /Users 2>&1 || true',
      { version: schemaVersion },
      seatbeltSpawnOptions,
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

  it('should deny network access when allowOutbound is false', async () => {
    const policy = {
      version: schemaVersion,
      network: { allowOutbound: false },
    };
    const result = await sdk.spawnSandboxAsync(
      "curl --max-time 5 --fail --silent --show-error https://example.com 2>&1; echo CURL_EXIT=$?",
      policy,
      seatbeltSpawnOptions,
      undefined,
      'seatbelt-network-deny',
    );
    // curl should fail when network is blocked
    assert.ok(
      result.stdout.includes('CURL_EXIT=') && !result.stdout.includes('CURL_EXIT=0'),
      `Expected network denial, got: ${result.stdout}`,
    );
  });

  it('should allow network access when allowOutbound is true', { skip: networkSkipReason }, async () => {
    const policy = {
      version: schemaVersion,
      network: { allowOutbound: true },
    };
    const result = await sdk.spawnSandboxAsync(
      `RESULT=$(curl --max-time 10 --fail --silent '${NETWORK_TEST_URL}') && echo 'NETWORK_OK'`,
      policy,
      seatbeltSpawnOptions,
      undefined,
      'seatbelt-network-allow',
    );
    assert.strictEqual(result.exitCode, 0, `Expected exit 0: ${result.stderr}`);
    assert.ok(result.stdout.includes('NETWORK_OK'));
  });

  it('should deny clipboard access when clipboard is none', { skip: clipboardSkipReason }, async () => {
    const policy = {
      version: schemaVersion,
      ui: { clipboard: 'none' as const },
    };
    const result = await sdk.spawnSandboxAsync(
      "echo test_clip | pbcopy 2>&1 && pbpaste 2>&1",
      policy,
      seatbeltSpawnOptions,
      undefined,
      'seatbelt-clipboard-deny',
    );
    // When clipboard is denied, pbcopy/pbpaste fail and exit code is non-zero
    assert.notStrictEqual(result.exitCode, 0, `Expected clipboard denial, got exit 0`);
  });

  it('should allow clipboard access when clipboard is all', { skip: clipboardSkipReason }, async () => {
    const uniqueToken = `seatbelt_clip_${Date.now()}`;
    const policy = {
      version: schemaVersion,
      ui: { clipboard: 'all' as const },
    };
    const result = await sdk.spawnSandboxAsync(
      `echo '${uniqueToken}' | pbcopy && pbpaste`,
      policy,
      seatbeltSpawnOptions,
      undefined,
      'seatbelt-clipboard-allow',
    );
    assert.strictEqual(result.exitCode, 0, `Expected exit 0: ${result.stderr}`);
    assert.ok(result.stdout.includes(uniqueToken));
  });

  it('should reject blockedHosts with a clear error', async () => {
    const policy = {
      version: schemaVersion,
      network: {
        allowOutbound: true,
        blockedHosts: ['evil.example.com'],
      },
    };
    const result = await sdk.spawnSandboxAsync(
      'echo should-not-run',
      policy,
      seatbeltSpawnOptions,
      undefined,
      'seatbelt-blocked-hosts',
    );
    // blockedHosts is unsupported on seatbelt; the runner rejects it with exit -1/255
    assert.notStrictEqual(result.exitCode, 0, 'Expected non-zero exit for blockedHosts rejection');
    const combined = result.stdout + result.stderr;
    assert.ok(
      combined.includes('blockedHosts') || combined.includes('cannot be enforced') || result.exitCode === 255,
      `Expected blockedHosts rejection, got exit ${result.exitCode}: ${combined}`,
    );
  });

  it('should run multi-command pipeline', async () => {
    const result = await sdk.spawnSandboxAsync(
      "echo 'step 1' && uname -s && echo 'step 2' && whoami && echo 'Pipeline complete'",
      { version: schemaVersion },
      seatbeltSpawnOptions,
      undefined,
      'seatbelt-pipeline',
    );
    assert.strictEqual(result.exitCode, 0, `Expected exit 0: ${result.stderr}`);
    assert.ok(result.stdout.includes('Pipeline complete'));
    assert.ok(result.stdout.includes('Darwin'));
  });

  it('should enforce timeout on long-running scripts', async () => {
    const policy = {
      version: schemaVersion,
      timeoutMs: 2000,
    };
    const result = await sdk.spawnSandboxAsync(
      'sleep 30',
      policy,
      seatbeltSpawnOptions,
      undefined,
      'seatbelt-timeout',
    );
    // The runner should kill the process before 30s and return non-zero
    assert.notStrictEqual(result.exitCode, 0, 'Expected non-zero exit for timed-out script');
  });

  it('should apply profile override from seatbelt config', { timeout: 30_000 }, async () => {
    // Build a config with a custom seatbelt profile that allows everything
    const config = sdk.createConfigFromPolicy({ version: schemaVersion });
    config.process = { commandLine: "echo 'profile override works'" };
    config.seatbelt = { profileOverride: '(version 1)\n(allow default)' };
    config.containerId = 'seatbelt-profile-override';

    const result = await new Promise<{ exitCode: number; stdout: string }>((resolve, reject) => {
      const ptyProcess = sdk.spawnSandboxFromConfig(config, seatbeltSpawnOptions);
      let stdout = '';
      const timer = setTimeout(() => reject(new Error('Test timed out waiting for onExit')), 25_000);
      ptyProcess.onData((data: string) => { stdout += data; });
      ptyProcess.onExit((event: { exitCode: number }) => {
        clearTimeout(timer);
        resolve({ exitCode: event.exitCode, stdout });
      });
    });
    assert.strictEqual(result.exitCode, 0, `Expected exit 0: ${result.stdout}`);
    assert.ok(result.stdout.includes('profile override works'));
  });
});
