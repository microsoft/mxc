// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// SDK end-to-end tests for the IsolationSession state-aware lifecycle.
//
// These tests invoke real wxc-exec.exe and exercise the full lifecycle:
// provision -> start -> exec -> stop -> deprovision. The whole suite skips
// at module evaluation time when this host lacks IsolationSession runtime
// support (or when wxc-exec was built without `--features isolation_session`),
// so the suite runs cleanly on any Windows host but only meaningfully on
// a host with IsolationSession runtime support.
//
// Build prerequisites:
//   - wxc-exec.exe built with `--features isolation_session`

import { describe, it } from 'node:test';
import assert from 'node:assert';
import fs from 'fs';
import os from 'os';
import path from 'path';
import {
  execInSandboxAsync,
  provisionSandbox,
  startSandbox,
  stopSandbox,
} from '@microsoft/mxc-sdk';
import { createTempDir, probeStateAwareRuntime, safeDeprovision } from './test-helpers.js';

const skipReason = os.platform() !== 'win32'
  ? 'IsolationSession is Windows-only'
  : await probeStateAwareRuntime('isolation_session');

describe('IsolationSession state-aware lifecycle E2E', { skip: skipReason }, () => {
  it('runs full lifecycle: provision -> start -> exec -> stop -> deprovision', async () => {
    const provisionResult = await provisionSandbox('isolation_session', {}, { experimental: true });
    const sandboxId = provisionResult.sandboxId;
    assert.ok(
      sandboxId.startsWith('iso:'),
      `Expected sandboxId to start with 'iso:', got '${sandboxId}'`,
    );

    try {
      await startSandbox(sandboxId, {}, { experimental: true });

      const result = await execInSandboxAsync(
        sandboxId,
        { process: { commandLine: 'cmd /c echo hello' } },
        { experimental: true },
      );

      assert.strictEqual(result.exitCode, 0, `exec exit code: stdout=${result.stdout}, stderr=${result.stderr}`);
      assert.ok(
        result.stdout.includes('hello'),
        `stdout did not contain 'hello': ${result.stdout}`,
      );

      await stopSandbox(sandboxId, undefined, { experimental: true });
    } finally {
      await safeDeprovision(sandboxId);
    }
  });

  it('exec surfaces a non-zero script exit as ExecResult.exitCode', async () => {
    const provisionResult = await provisionSandbox('isolation_session', {}, { experimental: true });
    const sandboxId = provisionResult.sandboxId;

    try {
      await startSandbox(sandboxId, {}, { experimental: true });

      const result = await execInSandboxAsync(
        sandboxId,
        { process: { commandLine: 'cmd /c exit 7' } },
        { experimental: true },
      );

      assert.strictEqual(result.exitCode, 7, `expected exit 7, got ${result.exitCode}`);

      await stopSandbox(sandboxId, undefined, { experimental: true });
    } finally {
      await safeDeprovision(sandboxId);
    }
  });

  it('honors readwritePaths at provision: agent writes are visible on the host', async () => {
    const rwDir = createTempDir('mxc-iso-rw');
    const markerName = 'agent-write.txt';
    const markerHostPath = path.join(rwDir, markerName);
    const markerExpected = 'agent-wrote-this';

    const provisionResult = await provisionSandbox(
      'isolation_session',
      { filesystem: { readwritePaths: [rwDir] } },
      { experimental: true },
    );
    const sandboxId = provisionResult.sandboxId;

    try {
      await startSandbox(sandboxId, {}, { experimental: true });

      const result = await execInSandboxAsync(
        sandboxId,
        { process: { commandLine: `cmd /c echo ${markerExpected}> "${rwDir}\\${markerName}"` } },
        { experimental: true },
      );

      assert.strictEqual(result.exitCode, 0, `exec exit code: stdout=${result.stdout}, stderr=${result.stderr}`);
      assert.ok(fs.existsSync(markerHostPath), `expected ${markerHostPath} to exist after agent write`);
      assert.strictEqual(fs.readFileSync(markerHostPath, 'utf-8').trim(), markerExpected);

      await stopSandbox(sandboxId, undefined, { experimental: true });
    } finally {
      await safeDeprovision(sandboxId);
      fs.rmSync(rwDir, { recursive: true, force: true });
    }
  });

  it('honors readonlyPaths at provision: agent reads pre-seeded content', async () => {
    const roDir = createTempDir('mxc-iso-ro');
    const markerName = 'host-seeded.txt';
    const markerHostPath = path.join(roDir, markerName);
    const markerExpected = 'host-seeded-content';
    fs.writeFileSync(markerHostPath, markerExpected, 'utf-8');

    const provisionResult = await provisionSandbox(
      'isolation_session',
      { filesystem: { readonlyPaths: [roDir] } },
      { experimental: true },
    );
    const sandboxId = provisionResult.sandboxId;

    try {
      await startSandbox(sandboxId, {}, { experimental: true });

      const result = await execInSandboxAsync(
        sandboxId,
        { process: { commandLine: `cmd /c type "${roDir}\\${markerName}"` } },
        { experimental: true },
      );

      assert.strictEqual(result.exitCode, 0, `exec exit code: stdout=${result.stdout}, stderr=${result.stderr}`);
      assert.ok(
        result.stdout.includes(markerExpected),
        `stdout did not contain seeded content '${markerExpected}': ${result.stdout}`,
      );

      await stopSandbox(sandboxId, undefined, { experimental: true });
    } finally {
      await safeDeprovision(sandboxId);
      fs.rmSync(roDir, { recursive: true, force: true });
    }
  });

  it('honors readonlyPaths at provision: agent writes to a readonly path fail', async () => {
    const roDir = createTempDir('mxc-iso-ro-write');
    const markerName = 'agent-should-not-write.txt';

    const provisionResult = await provisionSandbox(
      'isolation_session',
      { filesystem: { readonlyPaths: [roDir] } },
      { experimental: true },
    );
    const sandboxId = provisionResult.sandboxId;

    try {
      await startSandbox(sandboxId, {}, { experimental: true });

      const result = await execInSandboxAsync(
        sandboxId,
        { process: { commandLine: `cmd /c echo nope> "${roDir}\\${markerName}"` } },
        { experimental: true },
      );

      assert.notStrictEqual(
        result.exitCode, 0,
        `expected non-zero exit when writing to a readonly path, got ${result.exitCode}; stdout=${result.stdout}, stderr=${result.stderr}`,
      );

      await stopSandbox(sandboxId, undefined, { experimental: true });
    } finally {
      await safeDeprovision(sandboxId);
      fs.rmSync(roDir, { recursive: true, force: true });
    }
  });
});
