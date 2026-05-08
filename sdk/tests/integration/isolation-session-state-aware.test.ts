// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// SDK end-to-end tests for the IsolationSession state-aware lifecycle.
//
// These tests invoke real wxc-exec.exe and exercise the full lifecycle:
// provision -> start -> exec -> stop -> deprovision. Each test calls into
// the SDK and skips itself when wxc-exec returns `backend_unavailable`,
// so the suite runs cleanly on any Windows host but only meaningfully on
// a host with IsolationSession runtime support.
//
// Build prerequisites:
//   - wxc-exec.exe built with `--features isolation_session`

import { describe, it, type TestContext } from 'node:test';
import assert from 'node:assert';
import os from 'os';
import {
  MxcBackendUnavailableError,
  MxcUnsupportedPhaseError,
  deprovisionSandbox,
  execInSandboxAsync,
  provisionSandbox,
  startSandbox,
  stopSandbox,
  type SandboxId,
} from '@microsoft/mxc-sdk';

const isWindows = os.platform() === 'win32';

async function runOrSkipIfBackendUnavailable<T>(
  t: TestContext,
  label: string,
  fn: () => Promise<T>,
): Promise<T | undefined> {
  try {
    return await fn();
  } catch (err) {
    if (err instanceof MxcBackendUnavailableError) {
      t.skip(`${label}: IsolationSession runtime unavailable on this host`);
      return undefined;
    }
    if (err instanceof MxcUnsupportedPhaseError) {
      // wxc-exec was built without `--features isolation_session`, so the
      // state-aware dispatch path is compiled out. Same outcome from the
      // test's perspective as a host without the IS runtime: we cannot
      // exercise the lifecycle, so skip rather than fail.
      t.skip(`${label}: wxc-exec lacks the isolation_session feature; rebuild with --features isolation_session to run this test`);
      return undefined;
    }
    throw err;
  }
}

async function safeDeprovision(sandboxId: SandboxId<'isolation_session'>): Promise<void> {
  try {
    await deprovisionSandbox(sandboxId, undefined, { experimental: true });
  } catch (err) {
    // Don't override the original test failure. Surface for debugging only.
    console.error(`Cleanup deprovision failed for ${sandboxId}: ${err}`);
  }
}

describe('IsolationSession state-aware lifecycle E2E', {
  skip: !isWindows ? 'IsolationSession is Windows-only' : undefined,
}, () => {
  it('full lifecycle: provision -> start -> exec -> stop -> deprovision', async (t) => {
    const provisionResult = await runOrSkipIfBackendUnavailable(t, 'provision', () =>
      provisionSandbox('isolation_session', {}, { experimental: true }),
    );
    if (!provisionResult) return;

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

  it('exec surfaces a non-zero script exit as ExecResult.exitCode', async (t) => {
    const provisionResult = await runOrSkipIfBackendUnavailable(t, 'provision', () =>
      provisionSandbox('isolation_session', {}, { experimental: true }),
    );
    if (!provisionResult) return;

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
