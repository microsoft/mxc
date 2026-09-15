// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { afterEach, describe, it } from 'node:test';
import assert from 'node:assert';
import fs from 'node:fs';
import path from 'node:path';
import { sdk, supportedVersions, isLinuxRoot, createTempDir } from './test-helpers.js';

const BWRAP_PROBE =
  "PID1=$(cat /proc/1/comm 2>/dev/null || echo unknown); " +
  "echo \"pid1=$PID1\"; " +
  "[ \"$PID1\" = \"bwrap\" ] || { echo \"FAIL: not under bubblewrap (pid1=$PID1)\"; exit 1; }; " +
  "echo 'OK: under bubblewrap (pid1=bwrap)'";

for (const schemaVersion of supportedVersions) {
describe(`Linux Bubblewrap (schema ${schemaVersion})`, {
  skip: !isLinuxRoot ? 'Linux Bubblewrap tests require Linux with root privileges (sudo npm test)' : undefined,
}, () => {
  let tempDir = '';

  afterEach(() => {
    if (tempDir && fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
      tempDir = '';
    }
  });

  it('runs the default process surface under bubblewrap', async () => {
    const result = await sdk.spawnSandboxAsync(
      BWRAP_PROBE,
      { version: schemaVersion.raw },
      {},
      undefined,
      `bwrap-default-${schemaVersion}`,
    );
    assert.strictEqual(result.exitCode, 0, `[${schemaVersion}] bubblewrap probe failed: ${result.stdout}`);
    assert.ok(result.stdout.includes('OK: under bubblewrap'), `[${schemaVersion}] ${result.stdout}`);
  });

  it('honors readwrite filesystem mounts on the default process surface', async () => {
    tempDir = createTempDir('mxc-bwrap-test');
    const testFile = path.join(tempDir, 'test.txt');
    fs.writeFileSync(testFile, 'original', 'utf8');

    const result = await sdk.spawnSandboxAsync(
      `cat '${testFile}' && echo 'overwritten' > '${testFile}' && cat '${testFile}'`,
      {
        version: schemaVersion.raw,
        filesystem: { readwritePaths: [tempDir] },
      },
      {},
      undefined,
      `bwrap-rw-${schemaVersion}`,
    );

    assert.strictEqual(result.exitCode, 0, `[${schemaVersion}] Expected exit 0: ${result.stderr}`);
    assert.ok(result.stdout.includes('original'), `[${schemaVersion}] missing original content: ${result.stdout}`);
    assert.ok(result.stdout.includes('overwritten'), `[${schemaVersion}] missing updated content: ${result.stdout}`);
    assert.strictEqual(fs.readFileSync(testFile, 'utf8').trim(), 'overwritten');
  });
});
}
