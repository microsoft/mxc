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
import fs from 'node:fs';
import path from 'node:path';
import os from 'os';
import {
  execInSandboxAsync,
  MxcError,
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
    const provisionResult = await provisionSandbox('isolation_session', { network: { defaultPolicy: 'allow', allowLocalNetwork: true } }, { experimental: true });
    const sandboxId = provisionResult.sandboxId;
    assert.ok(
      sandboxId.startsWith('iso:'),
      `Expected sandboxId to start with 'iso:', got '${sandboxId}'`,
    );

    // Provision now returns the agent SID and the shared ephemeral workspace
    // path alongside the agent user name.
    const metadata = provisionResult.metadata;
    assert.ok(metadata, 'provision result carries metadata');
    assert.ok(
      (metadata?.agentUserName?.length ?? 0) > 0,
      `metadata.agentUserName is non-empty: ${JSON.stringify(metadata)}`,
    );
    assert.ok(
      (metadata?.agentUserSid?.length ?? 0) > 0,
      `metadata.agentUserSid is non-empty: ${JSON.stringify(metadata)}`,
    );
    assert.ok(
      (metadata?.ephemeralWorkspacePath?.length ?? 0) > 0,
      `metadata.ephemeralWorkspacePath is non-empty: ${JSON.stringify(metadata)}`,
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

  it('shares files with the session through the ephemeral workspace', async () => {
    const provisionResult = await provisionSandbox('isolation_session', { network: { defaultPolicy: 'allow', allowLocalNetwork: true } }, { experimental: true });
    const sandboxId = provisionResult.sandboxId;
    const workspace = provisionResult.metadata?.ephemeralWorkspacePath;
    assert.ok(
      workspace && workspace.length > 0,
      `provision did not return an ephemeralWorkspacePath: ${JSON.stringify(provisionResult.metadata)}`,
    );
    // node:assert's `ok` does not narrow the type, so pin it explicitly for tsc.
    const ws = workspace as string;

    try {
      await startSandbox(sandboxId, {}, { experimental: true });

      // Caller -> session: the test (the calling user) stages a file into the
      // shared workspace and the session reads it back. Proves the SDK surfaces
      // a *usable* path a consumer can share files through, not just a non-empty
      // string.
      fs.writeFileSync(path.join(ws, 'caller_to_session.txt'), 'from-caller', 'ascii');
      const readResult = await execInSandboxAsync(
        sandboxId,
        { process: { commandLine: `cmd /c type "${ws}\\caller_to_session.txt"` } },
        { experimental: true },
      );
      assert.strictEqual(
        readResult.exitCode,
        0,
        `read exit: stdout=${readResult.stdout}, stderr=${readResult.stderr}`,
      );
      assert.ok(
        readResult.stdout.includes('from-caller'),
        `session did not see the caller's file: ${readResult.stdout}`,
      );

      // Session -> caller: the session writes into its workspace and the caller
      // reads it back on the host.
      const writeResult = await execInSandboxAsync(
        sandboxId,
        { process: { commandLine: `cmd /c echo from-session> "${ws}\\session_to_caller.txt"` } },
        { experimental: true },
      );
      assert.strictEqual(
        writeResult.exitCode,
        0,
        `write exit: stdout=${writeResult.stdout}, stderr=${writeResult.stderr}`,
      );
      const backFile = path.join(ws, 'session_to_caller.txt');
      assert.ok(fs.existsSync(backFile), 'caller does not see the file the session wrote');
      assert.match(
        fs.readFileSync(backFile, 'ascii'),
        /from-session/,
        'caller could not read the session output',
      );

      await stopSandbox(sandboxId, undefined, { experimental: true });
    } finally {
      await safeDeprovision(sandboxId);
    }
  });

  it('exec surfaces a non-zero script exit as ExecResult.exitCode', async () => {
    const provisionResult = await provisionSandbox('isolation_session', { network: { defaultPolicy: 'allow', allowLocalNetwork: true } }, { experimental: true });
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

  // --- Runtime backend guard for the network acknowledgment ----------------
  // The TypeScript type makes `network` required (and pins its value) at
  // provision, but a plain-JS caller can bypass that. These assert the backend
  // itself refuses a missing or non-canonical network acknowledgment — the
  // "respect or refuse" guarantee must not rest on the compile-time type alone.
  // Validation runs before the OS service is touched, so no cleanup is needed.
  type UntypedProvision = (
    containment: 'isolation_session',
    config: unknown,
    options: unknown,
  ) => Promise<unknown>;
  const provisionUntyped = provisionSandbox as unknown as UntypedProvision;

  it('backend refuses a provision that omits the network acknowledgment', async () => {
    await assert.rejects(
      () => provisionUntyped('isolation_session', {}, { experimental: true }),
      (err: unknown) => err instanceof MxcError && err.code === 'policy_validation',
    );
  });

  it('backend refuses a provision with a non-canonical network (defaultPolicy=block)', async () => {
    await assert.rejects(
      () => provisionUntyped(
        'isolation_session',
        { network: { defaultPolicy: 'block' } },
        { experimental: true },
      ),
      (err: unknown) => err instanceof MxcError && err.code === 'policy_validation',
    );
  });

  it('backend refuses a provision whose network omits allowLocalNetwork', async () => {
    await assert.rejects(
      () => provisionUntyped(
        'isolation_session',
        { network: { defaultPolicy: 'allow' } },
        { experimental: true },
      ),
      (err: unknown) => err instanceof MxcError && err.code === 'policy_validation',
    );
  });

  // --- Runtime backend guard for UI policy --------------------------------
  // `ui` is absent from every IsolationSession per-phase Config, so a
  // TypeScript caller cannot pass it. It is a cross-cutting field though, so a
  // plain-JS caller who supplies it still gets it lifted to the top level of
  // the envelope. The backend must refuse: the isolation session is a separate
  // OS session, which isolates the host's UI from the contained code but does
  // not deny it UI capabilities (window creation, GDI and the session's own
  // clipboard all work inside it), so a UI restriction cannot be honored.
  // Validation runs before the OS service is touched, so nothing is
  // provisioned and no cleanup is needed.
  type UntypedStart = (
    sandboxId: string,
    config: unknown,
    options: unknown,
  ) => Promise<unknown>;
  const startUntyped = startSandbox as unknown as UntypedStart;

  it('backend refuses a provision that supplies a ui policy', async () => {
    await assert.rejects(
      () => provisionUntyped(
        'isolation_session',
        {
          network: { defaultPolicy: 'allow', allowLocalNetwork: true },
          ui: { disable: true },
        },
        { experimental: true },
      ),
      (err: unknown) => err instanceof MxcError && err.code === 'policy_validation',
    );
  });

  it('backend refuses a lockdown-equivalent ui policy too (presence, not value)', async () => {
    // `UiPolicy::default()` is full lockdown, so an explicit lockdown `ui` is
    // indistinguishable by value from an absent one — presence drives the
    // refusal, exactly as it does for the network acknowledgment.
    await assert.rejects(
      () => provisionUntyped(
        'isolation_session',
        {
          network: { defaultPolicy: 'allow', allowLocalNetwork: true },
          ui: {},
        },
        { experimental: true },
      ),
      (err: unknown) => err instanceof MxcError && err.code === 'policy_validation',
    );
  });

  it('backend refuses a ui policy on a post-provision phase', async () => {
    // No provision needed: `validate_start` refuses before the sandbox id is
    // ever resolved against the OS service.
    await assert.rejects(
      () => startUntyped(
        'iso:not-a-real-sandbox',
        { ui: { disable: false, clipboard: 'all', injection: true } },
        { experimental: true },
      ),
      (err: unknown) => err instanceof MxcError && err.code === 'policy_validation',
    );
  });
});
