// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { describe, it } from 'node:test';
import assert from 'node:assert';
import {
  sdk,
  supportedVersions,
  isLinuxRoot,
  debugSpawnOptions,
  spawnFromConfigAsync,
} from './test-helpers.js';

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
