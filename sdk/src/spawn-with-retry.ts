// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * `spawnSandboxWithRetry` — high-level wrapper that drives the
 * captureDenials retry loop on top of {@link spawnSandboxFromConfig}
 * and {@link parseDenialStream}.
 *
 * Flow:
 *
 *   1. Build a config from `policy` with `captureDenials: true`.
 *   2. Spawn the workload in non-PTY mode (required to read stderr
 *      separately from stdout — the captureDenials NDJSON protocol
 *      lives on stderr).
 *   3. Stream denials to the caller via `onDenied`.
 *   4. If the workload exited non-zero AND any denials surfaced AND
 *      the caller's `onDenied` callback returned at least one
 *      approval, regenerate the policy and re-run **once**.
 *
 * The retry is intentionally capped at one. Repeated retries
 * usually mean either (a) a runaway denial loop, or (b) the
 * workload is denying *something*, the user is approving *something
 * else*, and we'll loop forever. Both cases want the SDK to bail
 * out and surface the final state to the application instead of
 * spinning.
 */

import type { ChildProcess } from 'child_process';
import type { SandboxPolicy } from './types.js';
import type { DeniedResource, DenialStreamSummary } from './denial-stream.js';
import { parseDenialStream, defaultDenialFilters } from './denial-stream.js';
import {
  createConfigFromPolicy,
  spawnSandboxFromConfig,
  type SandboxSpawnOptions,
} from './sandbox.js';
import { regenerateSandboxPolicy, type RegenResult } from './policy-regen.js';

/**
 * Decision the caller hands back from {@link OnDeniedCallback}.
 *
 * - `cancel: true` ends the loop immediately and returns the
 *   current attempt's result to the caller, regardless of how many
 *   denials were collected.
 * - `approve: DeniedResource[]` lists the denials the user has
 *   approved (typically a subset of `denials`). May be empty; an
 *   empty array means "no approvals, don't retry".
 */
export interface OnDeniedDecision {
  cancel?: boolean;
  approve: DeniedResource[];
}

/**
 * Called with the captured denials at the end of each attempt. The
 * caller drives the user-approval UX here (prompt, persist
 * approvals, etc.) and returns an {@link OnDeniedDecision} telling
 * the retry loop what to do next.
 *
 * `attemptIndex` starts at 0 (first attempt) and increments per
 * retry. Today the loop caps at one retry, so the callback fires
 * at most twice — once after the first run, and (if approvals were
 * returned) once after the retry to surface any *still*-denied
 * paths to the application.
 */
export type OnDeniedCallback = (
  denials: readonly DeniedResource[],
  context: {
    attemptIndex: number;
    summary: DenialStreamSummary | undefined;
    exitCode: number;
  },
) => Promise<OnDeniedDecision> | OnDeniedDecision;

/**
 * Options for {@link spawnSandboxWithRetry}.
 */
export interface SpawnSandboxWithRetryOptions {
  /**
   * The command line the sandboxed workload should run. Same shape
   * as `config.process.commandLine`.
   */
  script: string;

  /**
   * The sandbox policy. The wrapper forces `captureDenials: true`
   * on each attempt regardless of what the policy carries — this is
   * a captureDenials helper, the field would be redundant on the
   * caller's side.
   */
  policy: SandboxPolicy;

  /**
   * The user-approval driver. Receives the captured denials, returns
   * what to do next.
   */
  onDenied: OnDeniedCallback;

  /**
   * Optional. Forwarded into `spawnSandboxFromConfig` for each
   * attempt. `usePty` is always set to `false` regardless of what
   * the caller passes here — PTY mode merges stdout+stderr and
   * would corrupt the captureDenials wire format.
   */
  spawnOptions?: Omit<SandboxSpawnOptions, 'usePty'>;

  /**
   * Optional working directory; forwarded to spawn.
   */
  workingDirectory?: string;

  /**
   * Optional container name; forwarded to spawn.
   */
  containerName?: string;

  /**
   * Maximum number of retries. Defaults to 1 (so up to 2 attempts
   * total). Hard-capped — see file header for the rationale.
   */
  maxRetries?: number;
}

/**
 * Outcome of a single spawn attempt inside the retry loop.
 */
export interface RetryAttemptResult {
  /** 0 for the first attempt, increments per retry. */
  index: number;
  /** Workload exit code from this attempt (or -1 if the child died). */
  exitCode: number;
  /** All bytes the workload wrote to stdout, decoded as UTF-8. */
  stdout: string;
  /**
   * All bytes the *workload* wrote to stderr (not the captureDenials
   * envelopes, which the demuxer pulls out separately). Decoded as
   * UTF-8.
   */
  stderr: string;
  /** Unique denials that survived the SDK noise filters. */
  denials: readonly DeniedResource[];
  /** Terminator summary line, if present. */
  summary: DenialStreamSummary | undefined;
}

/**
 * Outcome of the whole {@link spawnSandboxWithRetry} call.
 */
export interface SpawnSandboxWithRetryResult {
  /** Every attempt in order. Length is 1 (no retry) or 2 (one retry). */
  attempts: RetryAttemptResult[];
  /** Reason the retry loop stopped. */
  stopReason:
    | 'success'             // workload exited 0 (with or without denials)
    | 'no-denials-no-retry' // workload failed but produced no actionable denials
    | 'user-cancelled'      // onDenied returned cancel=true
    | 'no-approvals'        // onDenied returned an empty approve list
    | 'still-denied'        // retried, workload still produced denials
    | 'retry-exhausted';    // hit maxRetries
  /**
   * Net policy used for the final attempt. Equal to the input
   * policy when no retry happened, otherwise the regenerated one.
   */
  finalPolicy: SandboxPolicy;
  /**
   * Audit trail of the regen step (added grants, skipped approvals).
   * Undefined when no retry happened.
   */
  regen?: RegenResult;
}

/**
 * Drive the captureDenials retry loop end-to-end. See file header
 * for the flow and the "why one retry only" rationale.
 *
 * @example
 * ```typescript
 * const result = await spawnSandboxWithRetry({
 *   script: 'cmd /c type C:\\Users\\Alice\\Documents\\report.txt',
 *   policy: { version: '0.5.0-alpha' },
 *   onDenied: async (denials) => ({
 *     approve: await promptUser(denials),
 *   }),
 * });
 *
 * if (result.stopReason === 'success') {
 *   console.log('Workload finished. Output:', result.attempts[0].stdout);
 * } else {
 *   console.log(`Stopped: ${result.stopReason}.`);
 *   console.log('Still-denied resources:', result.attempts.at(-1)!.denials);
 * }
 * ```
 */
export async function spawnSandboxWithRetry(
  options: SpawnSandboxWithRetryOptions,
): Promise<SpawnSandboxWithRetryResult> {
  return driveRetryLoop(options, (policy, index) => runOnce(policy, options, index));
}

/**
 * Pure orchestration core, extracted so the retry-loop decisions
 * can be unit-tested with a stubbed `runner` (no real spawns).
 * `spawnSandboxWithRetry` is a thin wrapper that supplies the real
 * runner.
 *
 * Exported for tests; not part of the public API.
 */
export async function driveRetryLoop(
  options: SpawnSandboxWithRetryOptions,
  runner: (policy: SandboxPolicy, attemptIndex: number) => Promise<RetryAttemptResult>,
): Promise<SpawnSandboxWithRetryResult> {
  const maxRetries = options.maxRetries ?? 1;
  if (maxRetries < 0) {
    throw new TypeError('maxRetries must be >= 0');
  }

  const attempts: RetryAttemptResult[] = [];
  let currentPolicy: SandboxPolicy = { ...options.policy, captureDenials: true };
  let regen: RegenResult | undefined;

  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    const result = await runner(currentPolicy, attempt);
    attempts.push(result);

    // Success: workload finished cleanly. No retry regardless of
    // whether denials surfaced (informational only).
    if (result.exitCode === 0) {
      return { attempts, stopReason: 'success', finalPolicy: currentPolicy, regen };
    }

    // Workload failed but no actionable denials. Nothing the
    // approval UX could do; bail out.
    if (result.denials.length === 0) {
      return {
        attempts,
        stopReason: 'no-denials-no-retry',
        finalPolicy: currentPolicy,
        regen,
      };
    }

    // Out of retry budget. If we made any retry attempts, label the
    // outcome as "still-denied" to make the failure mode obvious;
    // otherwise (maxRetries === 0) call it "retry-exhausted".
    if (attempt === maxRetries) {
      return {
        attempts,
        stopReason: attempt > 0 ? 'still-denied' : 'retry-exhausted',
        finalPolicy: currentPolicy,
        regen,
      };
    }

    // Ask the caller what to do.
    const decision = await options.onDenied(result.denials, {
      attemptIndex: attempt,
      summary: result.summary,
      exitCode: result.exitCode,
    });

    if (decision.cancel) {
      return { attempts, stopReason: 'user-cancelled', finalPolicy: currentPolicy, regen };
    }
    if (!decision.approve || decision.approve.length === 0) {
      return { attempts, stopReason: 'no-approvals', finalPolicy: currentPolicy, regen };
    }

    // Approvals -> regen policy -> loop.
    regen = regenerateSandboxPolicy({
      basePolicy: currentPolicy,
      approvedDenials: decision.approve,
    });
    currentPolicy = regen.policy;
  }

  // Unreachable: the loop always exits via one of the explicit
  // returns above. Kept as a defensive fallback so the type checker
  // accepts the function's return type even if the loop's exit
  // analysis ever drifts.
  /* c8 ignore next 6 */
  return {
    attempts,
    stopReason: 'still-denied',
    finalPolicy: currentPolicy,
    regen,
  };
}

/**
 * Run the workload once, consume its stdout/stderr + the
 * captureDenials NDJSON stream, return a typed result for the
 * retry loop to act on.
 */
async function runOnce(
  policy: SandboxPolicy,
  options: SpawnSandboxWithRetryOptions,
  attemptIndex: number,
): Promise<RetryAttemptResult> {
  // Build a fresh config from the (possibly regenerated) policy.
  // captureDenials is force-set: the wrapper exists *for* this
  // feature, the field would be confusing to expose as a no-op.
  const config = createConfigFromPolicy(policy, 'process', options.containerName);
  config.captureDenials = true;
  config.process = { ...(config.process ?? { commandLine: '' }), commandLine: options.script };

  // PTY mode merges stdout+stderr — we need them split so the
  // captureDenials demuxer can split stderr on 0x1E without seeing
  // the workload's own stdout interleaved into the segments.
  const child = spawnSandboxFromConfig(
    config,
    { ...(options.spawnOptions ?? {}), usePty: false },
    options.workingDirectory,
  ) as ChildProcess;

  const stdoutChunks: Buffer[] = [];
  child.stdout?.on('data', (c: Buffer) => stdoutChunks.push(c));

  // Capture *workload* stderr (i.e. the bytes that fall through the
  // captureDenials demuxer's passthrough) separately so the caller
  // can surface the workload's own error messages alongside the
  // structured denial list.
  const stderrChunks: Buffer[] = [];

  const denials: DeniedResource[] = [];
  let summary: DenialStreamSummary | undefined;

  const streamP = parseDenialStream(child.stderr!, {
    filters: defaultDenialFilters,
    onDenial: (r) => denials.push(r),
    onSummary: (s) => { summary = s; },
    onPassthrough: (c) => stderrChunks.push(c),
  });

  const exitP = new Promise<number>((resolve) => {
    child.on('exit', (code) => resolve(code ?? -1));
  });

  const [, exitCode] = await Promise.all([streamP, exitP]);

  return {
    index: attemptIndex,
    exitCode,
    stdout: Buffer.concat(stdoutChunks).toString('utf8'),
    stderr: Buffer.concat(stderrChunks).toString('utf8'),
    denials,
    summary,
  };
}
