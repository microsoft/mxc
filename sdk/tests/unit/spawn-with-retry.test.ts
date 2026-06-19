// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { describe, it } from 'node:test';
import assert from 'node:assert';
import {
  driveRetryLoop,
  type RetryAttemptResult,
  type SpawnSandboxWithRetryOptions,
} from '../../src/learning-mode/spawn-with-retry.js';
import type { DeniedResource } from '../../src/denial-channel/stream.js';
import type { SandboxPolicy } from '../../src/types.js';

// ---- fixtures -------------------------------------------------------------

function fileDenial(path: string): DeniedResource {
  return {
    kind: 'file',
    path,
    resourceType: 'file',
    accessType: 'read',
    pid: 42,
    filetime: 100,
  };
}

function attempt(
  index: number,
  exitCode: number,
  denials: DeniedResource[] = [],
  captureDenialsActive: boolean = true,
  childProcessesObserved: number = 0,
  descendantPidsCovered: number = 0,
): RetryAttemptResult {
  return {
    index,
    exitCode,
    stdout: '',
    stderr: '',
    denials,
    summary: {
      exitCode,
      totalDenials: denials.length,
      deniedResourcesTruncated: false,
      captureDenialsActive,
      childProcessesObserved,
      descendantPidsCovered,
    },
  };
}

const basePolicy: SandboxPolicy = {
  version: '0.5.0-alpha',
  filesystem: { readonlyPaths: [], readwritePaths: [] },
};

function baseOptions(overrides: Partial<SpawnSandboxWithRetryOptions> = {}): SpawnSandboxWithRetryOptions {
  return {
    script: 'cmd /c echo test',
    policy: basePolicy,
    onDenied: () => ({ approve: [] }),
    ...overrides,
  };
}

// ---- driveRetryLoop -------------------------------------------------------

describe('driveRetryLoop', () => {
  it('returns success on first attempt when exitCode is 0', async () => {
    let calls = 0;
    const result = await driveRetryLoop(baseOptions(), async (_p, i) => {
      calls += 1;
      return attempt(i, 0, []);
    });
    assert.strictEqual(result.stopReason, 'success');
    assert.strictEqual(result.attempts.length, 1);
    assert.strictEqual(calls, 1, 'no retry on success');
  });

  it('returns success even when denials are present (informational)', async () => {
    let onDeniedFired = 0;
    const result = await driveRetryLoop(
      baseOptions({
        onDenied: () => {
          onDeniedFired += 1;
          return { approve: [] };
        },
      }),
      async (_p, i) => attempt(i, 0, [fileDenial('C:\\foo')]),
    );
    assert.strictEqual(result.stopReason, 'success');
    assert.strictEqual(
      onDeniedFired,
      0,
      'onDenied must not fire when exit code is 0 — success means success',
    );
  });

  it('returns no-denials-no-retry when workload fails without producing denials', async () => {
    let calls = 0;
    let onDeniedFired = 0;
    const result = await driveRetryLoop(
      baseOptions({
        onDenied: () => {
          onDeniedFired += 1;
          return { approve: [] };
        },
      }),
      async (_p, i) => {
        calls += 1;
        return attempt(i, 1, []);
      },
    );
    assert.strictEqual(result.stopReason, 'no-denials-no-retry');
    assert.strictEqual(calls, 1, 'no retry without denials');
    assert.strictEqual(onDeniedFired, 0, 'onDenied not consulted with no denials');
  });

  it('returns user-cancelled when the callback signals cancel', async () => {
    const result = await driveRetryLoop(
      baseOptions({
        maxRetries: 1,
        onDenied: () => ({ cancel: true, approve: [] }),
      }),
      async (_p, i) => attempt(i, 1, [fileDenial('C:\\foo')]),
    );
    assert.strictEqual(result.stopReason, 'user-cancelled');
    assert.strictEqual(result.attempts.length, 1, 'no retry after cancel');
  });

  it('returns no-approvals when the callback returns an empty approve list', async () => {
    const result = await driveRetryLoop(
      baseOptions({
        maxRetries: 1,
        onDenied: () => ({ approve: [] }),
      }),
      async (_p, i) => attempt(i, 1, [fileDenial('C:\\foo')]),
    );
    assert.strictEqual(result.stopReason, 'no-approvals');
    assert.strictEqual(result.attempts.length, 1);
  });

  it('retries once with regenerated policy when approvals are returned', async () => {
    const seenPolicies: SandboxPolicy[] = [];
    let onDeniedCalls = 0;
    const result = await driveRetryLoop(
      baseOptions({
        maxRetries: 1,
        onDenied: (denials) => {
          onDeniedCalls += 1;
          return { approve: [...denials] };
        },
      }),
      async (policy, i) => {
        seenPolicies.push(policy);
        // First attempt: 1 denial; second attempt: clean.
        if (i === 0) return attempt(i, 1, [fileDenial('C:\\Users\\Alice\\file.txt')]);
        return attempt(i, 0, []);
      },
    );
    assert.strictEqual(result.stopReason, 'success');
    assert.strictEqual(result.attempts.length, 2);
    assert.strictEqual(onDeniedCalls, 1, 'onDenied fires once between attempts');
    assert.deepStrictEqual(seenPolicies[0].filesystem?.readonlyPaths, []);
    assert.deepStrictEqual(seenPolicies[1].filesystem?.readonlyPaths, [
      'C:\\Users\\Alice\\file.txt',
    ]);
    assert.ok(result.regen, 'regen audit trail is exposed on retried results');
    assert.strictEqual(result.regen!.added.length, 1);
  });

  it('returns still-denied-different when retry trips a fresh path the workload progressed onto', async () => {
    const result = await driveRetryLoop(
      baseOptions({
        maxRetries: 1,
        onDenied: (denials) => ({ approve: [denials[0]] }),
      }),
      async (_p, i) => {
        // First attempt: blocked on A. Caller approves A. Retry:
        // workload gets past A but trips on B — that's *progress*,
        // a re-prompt could continue. Distinct from "approved A,
        // still blocked on A" (same).
        if (i === 0) return attempt(i, 1, [fileDenial('C:\\a.txt')]);
        return attempt(i, 1, [fileDenial('C:\\b.txt')]);
      },
    );
    assert.strictEqual(result.stopReason, 'still-denied-different');
    assert.strictEqual(result.attempts.length, 2);
    assert.deepStrictEqual(
      result.attempts[1].denials.map((d) => d.path),
      ['C:\\b.txt'],
    );
  });

  it('returns still-denied-same when retry trips the exact same denials again', async () => {
    // Useful failure mode to surface: regen no-op'd (e.g. the
    // approval was for a path that's already a system-critical
    // skip) so the policy didn't change, or the workload is
    // re-tripping a path it had already triggered. Either way, no
    // progress -- the wrapper signals "trying again won't help."
    const samePath = 'C:\\persistent.txt';
    const result = await driveRetryLoop(
      baseOptions({
        maxRetries: 1,
        onDenied: (denials) => ({ approve: [...denials] }),
      }),
      async (_p, i) => attempt(i, 1, [fileDenial(samePath)]),
    );
    assert.strictEqual(result.stopReason, 'still-denied-same');
    assert.strictEqual(result.attempts.length, 2);
  });

  it('returns still-denied-same when retry trips a subset of the original denials', async () => {
    // Subset case: original had {A, B, C}, retry has just {B}.
    // The workload made some progress (A, C are no longer denied)
    // but B is the same denial we'd already seen. We label as
    // "same" because the *retry's* denial set is a subset of the
    // prior one -- no new prompt to surface, just B left over.
    const result = await driveRetryLoop(
      baseOptions({
        maxRetries: 1,
        onDenied: (denials) => ({ approve: [denials[0], denials[2]] }),
      }),
      async (_p, i) => {
        if (i === 0) {
          return attempt(i, 1, [
            fileDenial('C:\\a.txt'),
            fileDenial('C:\\b.txt'),
            fileDenial('C:\\c.txt'),
          ]);
        }
        return attempt(i, 1, [fileDenial('C:\\b.txt')]);
      },
    );
    assert.strictEqual(result.stopReason, 'still-denied-same');
  });

  it('defaults maxRetries to 0 (single attempt, no retry)', async () => {
    // Behavioral guard: changing the default back to 1 would
    // silently auto-retry workloads that consumers expected to
    // single-shot. The default is 0 by design (see file header).
    let calls = 0;
    let onDeniedFired = 0;
    const result = await driveRetryLoop(
      baseOptions({
        // No maxRetries -> defaults to 0.
        onDenied: () => {
          onDeniedFired += 1;
          return { approve: [] };
        },
      }),
      async (_p, i) => {
        calls += 1;
        return attempt(i, 1, [fileDenial('C:\\foo')]);
      },
    );
    assert.strictEqual(calls, 1, 'default must not retry');
    assert.strictEqual(onDeniedFired, 0, 'onDenied must not fire when retry budget is 0');
    assert.strictEqual(result.stopReason, 'retry-exhausted');
  });

  it('caps retries at maxRetries=0 (no retry budget)', async () => {
    let calls = 0;
    const result = await driveRetryLoop(
      baseOptions({
        maxRetries: 0,
        onDenied: (denials) => ({ approve: [...denials] }),
      }),
      async (_p, i) => {
        calls += 1;
        return attempt(i, 1, [fileDenial('C:\\foo')]);
      },
    );
    // No retry possible: returns immediately after the first run.
    assert.strictEqual(result.stopReason, 'retry-exhausted');
    assert.strictEqual(calls, 1, 'maxRetries=0 means a single attempt only');
  });

  it('honors a custom maxRetries=2 (three attempts total, still-denied-different when each attempt trips a new path)', async () => {
    let calls = 0;
    const result = await driveRetryLoop(
      baseOptions({
        maxRetries: 2,
        onDenied: (denials) => ({ approve: [...denials] }),
      }),
      async (_p, i) => {
        calls += 1;
        // Workload keeps denying a fresh path every attempt.
        return attempt(i, 1, [fileDenial(`C:\\step${i}.txt`)]);
      },
    );
    assert.strictEqual(calls, 3);
    assert.strictEqual(result.stopReason, 'still-denied-different');
    assert.strictEqual(result.attempts.length, 3);
  });

  it('throws synchronously on negative maxRetries', async () => {
    await assert.rejects(
      () =>
        driveRetryLoop(
          baseOptions({ maxRetries: -1 }),
          async () => attempt(0, 0, []),
        ),
      /maxRetries must be >= 0/,
    );
  });

  it('forces captureDenials: true on the policy fed to the first runner call', async () => {
    const optionsPolicyHasNoFlag: SandboxPolicy = {
      version: '0.5.0-alpha',
      filesystem: { readonlyPaths: [] },
    };
    let firstSeenPolicy: SandboxPolicy | undefined;
    await driveRetryLoop(
      baseOptions({ policy: optionsPolicyHasNoFlag }),
      async (policy, i) => {
        if (i === 0) firstSeenPolicy = policy;
        return attempt(i, 0, []);
      },
    );
    assert.strictEqual(
      firstSeenPolicy?.captureDenials,
      true,
      'wrapper must force captureDenials on so the underlying runner has the events to consume',
    );
  });

  it('passes attemptIndex, summary and exitCode to onDenied', async () => {
    let captured: Parameters<NonNullable<SpawnSandboxWithRetryOptions['onDenied']>>[1] | undefined;
    await driveRetryLoop(
      baseOptions({
        maxRetries: 1,
        onDenied: (_d, ctx) => {
          captured = ctx;
          return { cancel: true, approve: [] };
        },
      }),
      async (_p, i) => attempt(i, 13, [fileDenial('C:\\foo')]),
    );
    assert.ok(captured, 'onDenied should have been called');
    assert.strictEqual(captured!.attemptIndex, 0);
    assert.strictEqual(captured!.exitCode, 13);
    assert.strictEqual(captured!.summary?.exitCode, 13);
    assert.strictEqual(captured!.summary?.totalDenials, 1);
  });

  it('supports async onDenied callbacks', async () => {
    let calls = 0;
    const result = await driveRetryLoop(
      baseOptions({
        maxRetries: 1,
        onDenied: async (denials) => {
          await new Promise((r) => setTimeout(r, 5));
          calls += 1;
          return { approve: [...denials] };
        },
      }),
      async (_p, i) => {
        if (i === 0) return attempt(i, 1, [fileDenial('C:\\async.txt')]);
        return attempt(i, 0, []);
      },
    );
    assert.strictEqual(result.stopReason, 'success');
    assert.strictEqual(calls, 1);
  });

  it('returns capture-inactive when the native side reports the collector did not attach', async () => {
    let onDeniedFired = 0;
    const result = await driveRetryLoop(
      baseOptions({
        onDenied: () => {
          onDeniedFired += 1;
          return { approve: [] };
        },
      }),
      // Workload exits non-zero, the capture never activated, no
      // denials surface. Without the capture-inactive check this
      // would look identical to no-denials-no-retry and the caller
      // would have no idea the feature wasn't working.
      async (_p, i) => attempt(i, 1, [], /* captureDenialsActive */ false),
    );
    assert.strictEqual(result.stopReason, 'capture-inactive');
    assert.strictEqual(result.attempts.length, 1, 'no retry when capture is inactive');
    assert.strictEqual(
      onDeniedFired,
      0,
      'onDenied must not fire when there is no functioning capture to act on',
    );
  });

  it('capture-inactive trumps success when the workload exits 0 but capture never attached', async () => {
    // Subtle: even a "successful" workload run is suspicious if the
    // capture was supposed to be on and silently wasn't. The
    // application asked for captureDenials for a reason; not getting
    // it should be visible regardless of the workload's outcome.
    const result = await driveRetryLoop(
      baseOptions(),
      async (_p, i) => attempt(i, 0, [], /* captureDenialsActive */ false),
    );
    assert.strictEqual(result.stopReason, 'capture-inactive');
  });
});
