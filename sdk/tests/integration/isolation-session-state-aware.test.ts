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
import os from 'os';
import {
  execInSandboxAsync,
  provisionSandbox,
  startSandbox,
  stopSandbox,
} from '@microsoft/mxc-sdk';
import { probeStateAwareRuntime, safeDeprovision, sandboxSkipReason } from './test-helpers.js';

const skipReason = os.platform() !== 'win32'
  ? 'IsolationSession is Windows-only'
  : sandboxSkipReason ?? await probeStateAwareRuntime('isolation_session');

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
});
