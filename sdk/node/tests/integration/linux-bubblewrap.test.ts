// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { describe, it, after } from 'node:test';
import assert from 'node:assert';
import os from 'node:os';
import path from 'node:path';
import fs from 'node:fs';
import {
  sdk,
  supportedVersions,
  isLinuxRoot,
  isLinuxBubblewrap,
  debugSpawnOptions,
  spawnFromConfigAsync,
  startUnixTestProxy,
  isTestProxyAvailable,
} from './test-helpers.js';
import type { ChildProcess } from 'node:child_process';

// Bwrap fingerprint: when invoked with `--unshare-pid`, bubblewrap creates a
// new PID namespace and stays as PID 1 in that namespace, acting as init
// (reaping orphans, forwarding signals). It does NOT exec the child shell
// directly — the script runs as PID 2. So /proc/1/comm always reads "bwrap"
// from inside the sandbox, regardless of how bwrap is invoked or which user
// runs it. This is documented bubblewrap behavior (see bwrap(1)) and the
// most reliable cross-context signal — mount-count heuristics break under
// WSL2 where bind-mount propagation can produce 40+ entries.
const BWRAP_PROBE =
  "PID1=$(cat /proc/1/comm 2>/dev/null || echo unknown); " +
  "MOUNTS=$(wc -l </proc/self/mountinfo); " +
  "echo \"pid1=$PID1 mountinfo_lines=$MOUNTS\"; " +
  "[ \"$PID1\" = \"bwrap\" ] || { echo \"FAIL: not under bubblewrap (pid1=$PID1)\"; exit 1; }; " +
  "echo 'OK: under bubblewrap (pid1=bwrap)'";

for (const schemaVersion of supportedVersions) {
describe(`Linux Bubblewrap (schema ${schemaVersion})`, {
  skip: !isLinuxRoot ? 'Linux Bubblewrap tests require Linux with root privileges (sudo npm test)' : undefined,
}, () => {
  it('should default to Bubblewrap when containment is omitted (silent default)', async () => {
    // spawnSandboxAsync routes through abstract `containment: 'process'`,
    // which on Linux resolves to Bubblewrap in the binary. No --experimental
    // flag is required for this path.
    const result = await sdk.spawnSandboxAsync(
      BWRAP_PROBE,
      { version: schemaVersion.raw },
      debugSpawnOptions,
      undefined,
      `bwrap-default-${schemaVersion}`,
    );
    assert.strictEqual(result.exitCode, 0, `[${schemaVersion}] silent-default Bubblewrap probe failed: ${result.stdout}`);
    assert.ok(result.stdout.includes('OK: under bubblewrap'), `[${schemaVersion}] ${result.stdout}`);
  });

  it('should select Bubblewrap for abstract containment="process"', async () => {
    const config = sdk.createConfigFromPolicy(
      { version: schemaVersion.raw },
      'process',
      `bwrap-process-${schemaVersion}`,
    );
    config.process!.commandLine = BWRAP_PROBE;
    assert.strictEqual(config.containment, 'process', 'wire-format containment should be "process"');
    const result = await spawnFromConfigAsync(config, debugSpawnOptions);
    assert.strictEqual(result.exitCode, 0, `[${schemaVersion}] containment=process Bubblewrap probe failed: ${result.stdout}`);
    assert.ok(result.stdout.includes('OK: under bubblewrap'), `[${schemaVersion}] ${result.stdout}`);
  });

  it('should select Bubblewrap for explicit containment="bubblewrap" with experimental flag', async () => {
    // Explicit "bubblewrap" still requires `experimental: true` per the SDK
    // gate in helper.ts (`ExperimentalBackends`).
    const config = sdk.createConfigFromPolicy(
      { version: schemaVersion.raw },
      'bubblewrap',
      `bwrap-explicit-${schemaVersion}`,
    );
    config.process!.commandLine = BWRAP_PROBE;
    assert.strictEqual(config.containment, 'bubblewrap', 'wire-format containment should be "bubblewrap"');
    const result = await spawnFromConfigAsync(config, { ...debugSpawnOptions, experimental: true });
    assert.strictEqual(result.exitCode, 0, `[${schemaVersion}] explicit Bubblewrap probe failed: ${result.stdout}`);
    assert.ok(result.stdout.includes('OK: under bubblewrap'), `[${schemaVersion}] ${result.stdout}`);
  });
});
}

// Network proxy tests use the cooperative env-var proxy, which is
// unprivileged by design -- the entire reason the proxy path exists is to
// avoid the root requirement of iptables-based enforcement. Gate on
// "Linux + bwrap available" rather than "Linux + root". Pinned to schema
// 0.6.0-alpha because Bubblewrap proxy support is only available in 0.6+.
const PROXY_SCHEMA = '0.6.0-alpha';
// The dev/test-only `unix-test-proxy` is intentionally excluded from the
// shipped per-platform package; it is sourced out-of-band for these E2E tests.
// See https://github.com/microsoft/mxc/issues/512 for the rationale.
describe('Linux Bubblewrap network proxy (schema 0.6.0-alpha)', {
  skip: !isLinuxBubblewrap
    ? 'Linux Bubblewrap proxy tests require Linux with bwrap installed'
    : !isTestProxyAvailable('unix-test-proxy')
    ? 'unix-test-proxy unavailable (excluded from shipped package per #512; set MXC_TEST_PROXY_DIR or build the Rust binaries locally)'
    : undefined,
}, () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'mxc-sdk-bwrap-proxy-'));
  const proxies: ChildProcess[] = [];

  after(() => {
    for (const p of proxies) {
      try { p.kill('SIGTERM'); } catch { /* ignore */ }
    }
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ignore */ }
  });

  it('should route HTTPS traffic through an externally launched unix-test-proxy', async () => {
    const { port, proxyProcess } = startUnixTestProxy(tmpDir);
    proxies.push(proxyProcess);

    const config = sdk.createConfigFromPolicy(
      { version: PROXY_SCHEMA },
      'bubblewrap',
      'bwrap-external-proxy',
    );
    config.process!.commandLine =
      'curl -fsSL https://api.github.com/zen > /dev/null && echo PROXY_OK';
    config.network = {
      ...(config.network ?? {}),
      defaultPolicy: 'allow',
      proxy: { localhost: port },
    };

    const result = await spawnFromConfigAsync(config, { ...debugSpawnOptions, experimental: true });
    assert.strictEqual(result.exitCode, 0, `external-proxy run failed: ${result.stdout}`);
    assert.ok(result.stdout.includes('PROXY_OK'), `missing PROXY_OK in: ${result.stdout}`);
  });

  it('should launch a builtinTestServer proxy and route traffic through it', async () => {
    const config = sdk.createConfigFromPolicy(
      { version: PROXY_SCHEMA },
      'bubblewrap',
      'bwrap-builtin-proxy',
    );
    config.process!.commandLine =
      'curl -fsSL https://api.github.com/zen > /dev/null && echo BUILTIN_OK';
    config.network = {
      ...(config.network ?? {}),
      defaultPolicy: 'allow',
      proxy: { builtinTestServer: true },
    };

    const result = await spawnFromConfigAsync(config, { ...debugSpawnOptions, experimental: true, allowTestingFeatures: true });
    assert.strictEqual(result.exitCode, 0, `builtin-proxy run failed: ${result.stdout}`);
    assert.ok(result.stdout.includes('BUILTIN_OK'), `missing BUILTIN_OK in: ${result.stdout}`);
  });

  it('should enforce allowedHosts at the proxy layer', async () => {
    const config = sdk.createConfigFromPolicy(
      { version: PROXY_SCHEMA },
      'bubblewrap',
      'bwrap-allowlist-proxy',
    );
    // Sentinel pattern: allowed host succeeds, disallowed host fails with 403
    // from the proxy and curl exits non-zero. The script swallows that and
    // prints BLOCKED_OK so we can assert both signals are present.
    config.process!.commandLine =
      'set -e; ' +
      'curl -fsSL https://api.github.com/zen > /dev/null && echo SENTINEL_OK; ' +
      'if curl -fsS --max-time 5 https://example.com > /dev/null 2>&1; then ' +
      '  echo SENTINEL_BAD_LEAK; exit 1; ' +
      'else ' +
      '  echo BLOCKED_OK; ' +
      'fi';
    config.network = {
      ...(config.network ?? {}),
      defaultPolicy: 'allow',
      proxy: { builtinTestServer: true },
      allowedHosts: ['api.github.com'],
    };

    const result = await spawnFromConfigAsync(config, { ...debugSpawnOptions, experimental: true, allowTestingFeatures: true });
    assert.strictEqual(result.exitCode, 0, `allowlist run failed: ${result.stdout}`);
    assert.ok(result.stdout.includes('SENTINEL_OK'), `missing SENTINEL_OK in: ${result.stdout}`);
    assert.ok(result.stdout.includes('BLOCKED_OK'), `disallowed host was not blocked: ${result.stdout}`);
    assert.ok(!result.stdout.includes('SENTINEL_BAD_LEAK'), `allowlist leaked: ${result.stdout}`);
  });
});
