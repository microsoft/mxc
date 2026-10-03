// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { describe, it, after } from 'node:test';
import assert from 'node:assert';
import os from 'node:os';
import path from 'node:path';
import fs from 'node:fs';
import { execFileSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';
import {
  sdk,
  supportedVersions,
  isLinuxRoot,
  isLinuxBubblewrap,
  runConfigForTest,
  startUnixTestProxy,
  getSdkBinDir,
  getSdkPackageRoot,
  NETWORK_TEST_URL,
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
    // runAsync routes through abstract `containment: 'process'`,
    // which on Linux resolves to Bubblewrap in the binary.
    const result = await sdk.runRequestForTest(
      BWRAP_PROBE,
      {},
      {},
      undefined,
      `bwrap-default-${schemaVersion}`,
    );
    assert.strictEqual(result.exitCode, 0, `[${schemaVersion}] silent-default Bubblewrap probe failed: ${result.stdout}`);
    assert.ok(result.stdout.includes('OK: under bubblewrap'), `[${schemaVersion}] ${result.stdout}`);
  });

  it('should select Bubblewrap for abstract containment="process"', async () => {
    const config = sdk.createConfigForTest(
      {},
      'process',
      `bwrap-process-${schemaVersion}`,
    );
    config.process!.commandLine = BWRAP_PROBE;
    assert.strictEqual(config.containment, 'process', 'wire-format containment should be "process"');
    const result = await runConfigForTest(config);
    assert.strictEqual(result.exitCode, 0, `[${schemaVersion}] containment=process Bubblewrap probe failed: ${result.stdout}`);
    assert.ok(result.stdout.includes('OK: under bubblewrap'), `[${schemaVersion}] ${result.stdout}`);
  });

  it('should select Bubblewrap for explicit containment="bubblewrap"', async () => {
    const config = sdk.createConfigForTest(
      {},
      'bubblewrap',
      `bwrap-explicit-${schemaVersion}`,
    );
    config.process!.commandLine = BWRAP_PROBE;
    assert.strictEqual(config.containment, 'bubblewrap', 'wire-format containment should be "bubblewrap"');
    const result = await runConfigForTest(config);
    assert.strictEqual(result.exitCode, 0, `[${schemaVersion}] explicit Bubblewrap probe failed: ${result.stdout}`);
    assert.ok(result.stdout.includes('OK: under bubblewrap'), `[${schemaVersion}] ${result.stdout}`);
  });
});
}

// The v1 policy replaces legacy `network.proxy`, `defaultPolicy`, and host
// lists with a real endpoint named by `runtimeConfig.networkProxy`. The parser
// accepts only loopback endpoints, and the request resolves to the proxy-only
// posture: egress must be deny-by-default with no rules, and the backend opens
// the proxy endpoint alone.
//
// That posture is enforced from inside a private network namespace routed by
// rootless slirp4netns, which the legacy path does not need -- hence the extra
// prerequisite here.
//
// The SDK's own capability answers it: the native probe runs `slirp4netns
// --version`, checks that private namespaces can actually be unshared, and
// inspects the iptables backend, so it fails closed on any part of the
// dependency set. Testing for the binary alone would let a host with an
// unusable slirp, `unshare`, `nsenter`, `iptables`, or `ip6tables` past the
// gate and report an environmental failure as a test failure.
const hasProxyEnforcement =
  isLinuxBubblewrap &&
  sdk.getPlatformSupport().bubblewrapNetwork?.proxyEnforcement === 'supported';

describe('Linux Bubblewrap network proxy (v1 SDK policy)', {
  skip: !isLinuxBubblewrap
    ? 'Linux Bubblewrap proxy tests require Linux with bwrap installed'
    : !hasProxyEnforcement
      ? 'this host cannot enforce proxy-only egress (see PlatformSupport.bubblewrapNetwork.warnings)'
      : undefined,
}, () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'mxc-sdk-bwrap-proxy-v1-'));
  const proxies: ChildProcess[] = [];

  // The helper announces its port through a fixed-name ready file, so two
  // proxies sharing a directory would have the second read the first one's
  // port. Each gets its own directory instead.
  const startProxy = (): number => {
    const { port, proxyProcess } = startUnixTestProxy(
      fs.mkdtempSync(path.join(tmpDir, 'proxy-')),
    );
    proxies.push(proxyProcess);
    return port;
  };

  after(() => {
    for (const p of proxies) {
      try { p.kill('SIGTERM'); } catch { /* ignore */ }
    }
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ignore */ }
  });

  it('should route traffic through the endpoint named by runtimeConfig.networkProxy', async () => {
    const port = startProxy();

    const config = sdk.createConfigForTest(
      {},
      'bubblewrap',
      'bwrap-runtime-proxy-v1',
    );
    config.process!.commandLine =
      `curl -fsSL '${NETWORK_TEST_URL}' > /dev/null && echo PROXY_V1_OK`;
    config.network = {
      egress: { default: 'deny' },
      ingress: { default: 'deny', hostLoopback: 'deny' },
    };
    config.runtimeConfig = {
      ...(config.runtimeConfig ?? {}),
      networkProxy: `http://127.0.0.1:${port}`,
    };

    // No allowTestingFeatures: the v1 policy names a caller-supplied endpoint,
    // not the testing-only built-in proxy.
    const result = await runConfigForTest(config, { experimental: true });
    assert.strictEqual(result.exitCode, 0, `v1 proxy run failed: ${result.stdout}`);
    assert.ok(result.stdout.includes('PROXY_V1_OK'), `missing PROXY_V1_OK in: ${result.stdout}`);
  });

  it('should confine egress to the proxy endpoint', async () => {
    const port = startProxy();

    const config = sdk.createConfigForTest(
      {},
      'bubblewrap',
      'bwrap-runtime-proxy-v1-egress',
    );
    // `--noproxy '*'` is the load-bearing part: it opts the request out of the
    // proxy env vars, so a success would mean the sandbox reached the internet
    // directly and the proxy-only posture was never enforced.
    config.process!.commandLine =
      'set -e; ' +
      `if curl -fsS --noproxy '*' --max-time 10 '${NETWORK_TEST_URL}' > /dev/null 2>&1; then ` +
      '  echo DIRECT_V1_LEAKED; exit 1; ' +
      'else ' +
      '  echo DIRECT_V1_BLOCKED_OK; ' +
      'fi; ' +
      `curl -fsSL '${NETWORK_TEST_URL}' > /dev/null && echo PROXY_V1_STILL_OK`;
    config.network = {
      egress: { default: 'deny' },
      ingress: { default: 'deny', hostLoopback: 'deny' },
    };
    config.runtimeConfig = {
      ...(config.runtimeConfig ?? {}),
      networkProxy: `http://127.0.0.1:${port}`,
    };

    const result = await runConfigForTest(config, { experimental: true });
    assert.strictEqual(result.exitCode, 0, `v1 egress run failed: ${result.stdout}`);
    assert.ok(
      result.stdout.includes('DIRECT_V1_BLOCKED_OK'),
      `direct egress was not blocked: ${result.stdout}`,
    );
    assert.ok(
      result.stdout.includes('PROXY_V1_STILL_OK'),
      `the proxied request did not complete: ${result.stdout}`,
    );
    assert.ok(
      !result.stdout.includes('DIRECT_V1_LEAKED'),
      `proxy-only egress leaked: ${result.stdout}`,
    );
  });
});

// The Rust serializer and the TypeScript parser are each unit-tested against
// fixtures, but a fixture cannot catch the two drifting apart. This pins the
// transport: the real `lxc-exec --available-backends` payload is fed to the
// real SDK parser, so a rename or reshape on either side fails here.
//
// The gate is only "Linux with a bwrap on PATH" — whether that bwrap is
// actually *usable* is what the tests below assert, not something they assume.
describe('lxc-exec --available-backends contract', {
  skip: !isLinuxBubblewrap
    ? 'the backend-discovery contract test requires Linux with bwrap installed'
    : undefined,
}, () => {
  /** Raw stdout of the real CLI, and the array it parses to. */
  function runAvailableBackends(): { stdout: string; backends: Record<string, unknown>[] } {
    const lxcExec = path.join(getSdkBinDir(), 'lxc-exec');
    assert.ok(fs.existsSync(lxcExec), `lxc-exec not found at ${lxcExec}`);
    const stdout = execFileSync(lxcExec, ['--available-backends'], {
      encoding: 'utf-8',
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    const parsed = JSON.parse(stdout);
    assert.ok(Array.isArray(parsed), `--available-backends must emit a JSON array, got: ${stdout}`);
    return { stdout, backends: parsed };
  }

  it('emits the array shape the SDK parser consumes', () => {
    const { stdout, backends } = runAvailableBackends();

    for (const entry of backends) {
      assert.strictEqual(
        typeof entry.backend, 'string',
        `every entry needs a string 'backend' wire name, got: ${stdout}`);
      // The parser reads these as string arrays and would silently fall back
      // to "unsupported" if either became an object or a bare string.
      for (const field of ['capabilities', 'warnings'] as const) {
        if (entry[field] !== undefined) {
          assert.ok(Array.isArray(entry[field]), `'${field}' must be an array, got: ${stdout}`);
          for (const value of entry[field] as unknown[]) {
            assert.strictEqual(
              typeof value, 'string', `'${field}' must hold strings, got: ${stdout}`);
          }
        }
      }
    }
  });

  // Deliberately an assertion rather than a skip gate. `isLinuxBubblewrap` only
  // proves a `bwrap` file is on PATH; both probes additionally require it to run
  // and be >= MIN_BWRAP_VERSION. Those two version floors live in different
  // languages, so pin that they agree instead of trusting either.
  it('agrees with getPlatformSupport on whether bubblewrap is usable', () => {
    const { stdout, backends } = runAvailableBackends();

    const nativeReportsBubblewrap = backends.some((entry) => entry.backend === 'bubblewrap');
    const sdkReportsBubblewrap = sdk.getPlatformSupport().availableMethods.includes('bubblewrap');

    assert.strictEqual(
      nativeReportsBubblewrap,
      sdkReportsBubblewrap,
      'the native probe and the SDK disagree about whether bubblewrap is usable; ' +
        'MIN_BWRAP_VERSION is mirrored between bwrap_version.rs and platform.ts and ' +
        `may have drifted. --available-backends said: ${stdout}`,
    );
  });

  it('projects the native payload into PlatformSupport.bubblewrapNetwork', async (t) => {
    const { stdout, backends } = runAvailableBackends();
    const bubblewrap = backends.find((entry) => entry.backend === 'bubblewrap');
    if (!bubblewrap) {
      // A `bwrap` on PATH can still be too old or not executable, in which case
      // omitting it is the correct contract and there is nothing to project.
      t.skip('this host has no usable bubblewrap to project');
      return;
    }
    const capabilities = (bubblewrap.capabilities ?? []) as string[];
    const cliSupportsProxyEnforcement = capabilities.includes('proxyEnforcement');

    // Drive the real parser with the bytes this CLI just produced. Injecting
    // them rather than re-probing keeps the comparison exact: a second live
    // walk could legitimately disagree by exhausting its pre-flight budget.
    const platform = await import(
      pathToFileURL(path.join(getSdkPackageRoot(), 'dist', 'platform.js')).href
    ) as {
      getPlatformSupport(): { bubblewrapNetwork?: { proxyEnforcement: string; warnings: string[] } };
      _setLinuxProbeRunner(runner: (() => string) | null): void;
      _resetPlatformSupportCache(): void;
    };

    try {
      platform._setLinuxProbeRunner(() => stdout);
      platform._resetPlatformSupportCache();
      const network = platform.getPlatformSupport().bubblewrapNetwork;

      assert.ok(network, `bubblewrapNetwork must be reported when bubblewrap is available: ${stdout}`);
      assert.strictEqual(
        network.proxyEnforcement,
        cliSupportsProxyEnforcement ? 'supported' : 'unsupported',
        `the SDK disagreed with the CLI capability list: ${stdout}`);

      if (cliSupportsProxyEnforcement) {
        assert.deepStrictEqual(network.warnings, [], 'a supported host reports no warnings');
      } else {
        // Never fail closed anonymously: the reason is the only actionable
        // detail an unsupported host gives a caller.
        assert.ok(
          network.warnings.length > 0,
          `an unsupported host must explain why, got: ${JSON.stringify(network)}`);
        for (const warning of network.warnings) {
          assert.strictEqual(typeof warning, 'string');
        }
      }
    } finally {
      platform._setLinuxProbeRunner(null);
      platform._resetPlatformSupportCache();
    }
  });
});
