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
import type pty from 'node-pty';
import type { Socket } from 'net';
import type { SandboxPolicy } from '../types.js';
import type { DeniedResource, DenialStreamSummary } from '../denial-channel/stream.js';
import { parseDenialStream, defaultDenialFilters } from '../denial-channel/stream.js';
import {
  createConfigFromPolicy,
  spawnSandboxFromConfig,
  spawnSandboxWithSideChannel,
  type SandboxSpawnOptions,
} from '../sandbox.js';
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
   * Optional real-time denial callback. Fires once for **each** denial
   * the moment it streams off the native binary, before the batched
   * {@link onDenied} for that attempt. Use it for live progress UI or
   * logging; use {@link onDenied} for the approve/retry decision.
   *
   * `attemptIndex` matches the attempt the denial belongs to (0 for the
   * first attempt, incrementing per retry), so a single handler can
   * attribute live denials across retries. A plain
   * `(resource) => void` is assignable here too — the second argument
   * is optional for callers that don't need it.
   *
   * Receives the same filtered + path-normalised `DeniedResource` that
   * lands in the attempt's `denials` array (the default noise filters
   * are applied first). Throwing from this callback is not recommended;
   * it propagates out of the attempt.
   */
  onDenial?: (resource: DeniedResource, attemptIndex: number) => void;

  /**
   * Optional. Forwarded into `spawnSandboxFromConfig` for each
   * attempt. The wrapper picks the right `usePty` value based on
   * its top-level `usePty` option (see below) -- callers that try
   * to override it via `spawnOptions.usePty` are silently
   * disregarded.
   */
  spawnOptions?: Omit<SandboxSpawnOptions, 'usePty'>;

  /**
   * When true, the workload runs in PTY mode (interactive terminal,
   * color, `isatty()` returns true) and the captureDenials stream
   * is routed through a private named-pipe side channel so it
   * doesn't corrupt the workload's terminal. Returns the IPty
   * handle on `RetryAttemptResult.pty` so the caller can wire it
   * up to a host terminal.
   *
   * When false (the default), the workload runs in non-PTY mode
   * (stdout/stderr are separate pipes) and captureDenials uses
   * stderr as the transport.
   *
   * Windows-only when true (named pipes are Windows-only and
   * captureDenials itself is Windows-only).
   */
  usePty?: boolean;

  /**
   * Optional working directory; forwarded to spawn.
   */
  workingDirectory?: string;

  /**
   * Optional container name; forwarded to spawn.
   */
  containerName?: string;

  /**
   * Maximum number of retries beyond the first attempt. Defaults to
   * **0** — i.e. a single attempt, no retry. Set to `1` to enable
   * one retry (two attempts total), or higher for more.
   *
   * The default was changed from `1` to `0` after experience showed
   * that consumers usually want to drive the prompt-and-retry loop
   * themselves (e.g. to persist approvals across runs, dedupe
   * prompts the user has already seen, or step through approvals
   * one at a time). When the wrapper retries automatically, those
   * UX behaviors have to be reimplemented inside `onDenied`, which
   * is awkward. Defaulting to 0 makes the simple
   * "spawn → collect → return to caller" path the path of least
   * resistance; consumers that want auto-retry opt in explicitly.
   *
   * Setting `maxRetries` higher than 1 is allowed but discouraged:
   * "the workload keeps tripping new denials" is usually a sign of
   * a noisy workload that the application should surface to the
   * user rather than approve through.
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
  /**
   * Workload stdout for the attempt, decoded as UTF-8.
   *
   * In non-PTY mode (the default), this is the child's stdout pipe.
   * In PTY mode (`options.usePty: true`), the workload's stdout
   * and stderr are merged onto the PTY -- this field accumulates
   * the merged terminal bytes so callers that don't want to wire
   * up the live `pty` handle can still read what the workload
   * printed.
   */
  stdout: string;
  /**
   * Workload stderr (the bytes that fall through the
   * captureDenials demuxer's passthrough).
   *
   * In non-PTY mode this is the child's stderr pipe with the 0x1E
   * envelopes already peeled off. In PTY mode this is always empty
   * (PTY merges stdout+stderr, so the bytes land in `stdout`
   * instead).
   */
  stderr: string;
  /** Unique denials that survived the SDK noise filters. */
  denials: readonly DeniedResource[];
  /** Terminator summary line, if present. */
  summary: DenialStreamSummary | undefined;
  /**
   * Live IPty handle when the attempt ran in PTY mode, undefined
   * otherwise. Consumers wire this up to a host terminal for
   * interactive workloads (`pty.onData(d => write(d))`,
   * `pty.write(stdin)`, etc.). Already torn down by the time the
   * attempt result is returned -- exposed for symmetry with the
   * non-PTY ChildProcess case and for callers that captured the
   * handle live during the run.
   */
  pty?: pty.IPty;
}

/**
 * Outcome of the whole {@link spawnSandboxWithRetry} call.
 */
export interface SpawnSandboxWithRetryResult {
  /** Every attempt in order. Length is 1 (no retry) or 2 (one retry). */
  attempts: RetryAttemptResult[];
  /** Reason the retry loop stopped. */
  stopReason:
    | 'success'                // workload exited 0 (with or without denials)
    | 'no-denials-no-retry'    // workload failed but produced no actionable denials
    | 'user-cancelled'         // onDenied returned cancel=true
    | 'no-approvals'           // onDenied returned an empty approve list
    | 'still-denied-same'      // retried, same denials tripped again -- approvals
                               // didn't take effect (regen no-op'd, or workload
                               // re-tried the same path before policy reload)
    | 'still-denied-different' // retried, workload made progress past the
                               // approved denials but tripped on new ones --
                               // a re-prompt + another retry could continue
    | 'retry-exhausted'        // hit maxRetries (no retry budget left)
    | 'capture-inactive';      // captureDenials requested but couldn't be
                               // activated (shim missing/unreachable on host)
                               // -- nothing the retry loop could do, app
                               // should surface the host-prep step to the user
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
  // Default to **zero** retries (a single attempt). See
  // SpawnSandboxWithRetryOptions.maxRetries doc for the rationale.
  const maxRetries = options.maxRetries ?? 0;
  if (maxRetries < 0) {
    throw new TypeError('maxRetries must be >= 0');
  }

  const attempts: RetryAttemptResult[] = [];
  let currentPolicy: SandboxPolicy = { ...options.policy, captureDenials: true };
  let regen: RegenResult | undefined;

  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    const result = await runner(currentPolicy, attempt);
    attempts.push(result);

    // captureDenials was requested but the runner couldn't attach
    // the ETW collector. The application has nothing meaningful to
    // prompt about (no denials are coming) and retrying won't help
    // (the shim isn't reachable). Bail out with a distinct reason
    // so the app can surface the host-prep step to the user.
    //
    // Inactive capture is only possible when a summary line was
    // emitted *and* it carries active=false. Older native binaries
    // that don't emit the field are treated as active=true by the
    // wire-format parser, so this check is a no-op against them.
    if (result.summary && result.summary.captureDenialsActive === false) {
      return {
        attempts,
        stopReason: 'capture-inactive',
        finalPolicy: currentPolicy,
        regen,
      };
    }

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

    // Out of retry budget. Differentiate why we're stopping:
    //
    //   - maxRetries === 0 (the default): no retry was budgeted
    //     in the first place -> `retry-exhausted`. The wrapper is
    //     handing the denials to the application; the app drives
    //     the next loop iteration itself.
    //
    //   - attempt > 0 (we ran out *after* retrying): differentiate
    //     "the retry tripped the same denials" (regen didn't
    //     help -- usually a non-actionable denial like a registry
    //     key the user can't grant) from "the retry tripped new
    //     denials" (real progress, the workload could in principle
    //     finish after another approval round).
    if (attempt === maxRetries) {
      if (attempt === 0) {
        return {
          attempts,
          stopReason: 'retry-exhausted',
          finalPolicy: currentPolicy,
          regen,
        };
      }
      const prior = attempts[attempt - 1];
      const stopReason = denialsAreSubsetOfPrior(result.denials, prior.denials)
        ? 'still-denied-same'
        : 'still-denied-different';
      return { attempts, stopReason, finalPolicy: currentPolicy, regen };
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
    stopReason: 'still-denied-same',
    finalPolicy: currentPolicy,
    regen,
  };
}

/**
 * True when every denial in `current` was also in `prior` (compared
 * by `(path, accessType)`). Used by {@link driveRetryLoop} to
 * decide between `still-denied-same` (no progress: retry tripped
 * a subset of what we'd already seen) and `still-denied-different`
 * (made progress: at least one new denial means the workload got
 * past the approved ones and is now reaching for something else).
 *
 * Empty `current` returns true vacuously, but the call sites never
 * hit that branch -- the `denials.length === 0` check upstream
 * returns `no-denials-no-retry` first.
 */
function denialsAreSubsetOfPrior(
  current: readonly DeniedResource[],
  prior: readonly DeniedResource[],
): boolean {
  if (current.length === 0) return true;
  const priorKeys = new Set(prior.map((d) => `${d.path}\u0000${d.accessType}`));
  return current.every((d) => priorKeys.has(`${d.path}\u0000${d.accessType}`));
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

  if (options.usePty) {
    return runOncePty(config, options, attemptIndex);
  }
  return runOnceChild(config, options, attemptIndex);
}

/**
 * Builds the per-denial sink the single-attempt runners hand to
 * {@link parseDenialStream}: it records each denial for the attempt's
 * batch (consumed by `onDenied`) and forwards it to the optional
 * real-time {@link SpawnSandboxWithRetryOptions.onDenial} callback,
 * tagged with the attempt index.
 *
 * Exported for tests; not part of the public API.
 */
export function makeDenialSink(
  denials: DeniedResource[],
  options: SpawnSandboxWithRetryOptions,
  attemptIndex: number,
): (resource: DeniedResource) => void {
  return (resource) => {
    denials.push(resource);
    options.onDenial?.(resource, attemptIndex);
  };
}

/**
 * Non-PTY single-attempt runner. Workload runs with separate
 * stdin/stdout/stderr; captureDenials uses stderr as the transport
 * (the 0x1E demuxer + workload-stderr passthrough split the bytes
 * downstream).
 */
async function runOnceChild(
  config: ReturnType<typeof createConfigFromPolicy>,
  options: SpawnSandboxWithRetryOptions,
  attemptIndex: number,
): Promise<RetryAttemptResult> {
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
    onDenial: makeDenialSink(denials, options, attemptIndex),
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

/**
 * PTY single-attempt runner. Workload runs with a real PTY (color,
 * `isatty()` true, interactive); captureDenials uses a private
 * named-pipe side channel so the user's terminal stays clean.
 *
 * Windows-only -- the side channel uses Windows named pipes, and
 * captureDenials itself is Windows-only.
 */
async function runOncePty(
  config: ReturnType<typeof createConfigFromPolicy>,
  options: SpawnSandboxWithRetryOptions,
  attemptIndex: number,
): Promise<RetryAttemptResult> {
  const sideChannel = spawnSandboxWithSideChannel(
    config,
    { ...(options.spawnOptions ?? {}), usePty: true },
    options.workingDirectory,
  );

  // Cast: usePty: true guarantees IPty.
  const ptyProcess = sideChannel.process as pty.IPty;

  const stdoutChunks: Buffer[] = [];
  // Accumulate the PTY's merged output. Consumers that want live
  // rendering should also wire their own onData listener -- both
  // can coexist because node-pty's onData is multicast.
  ptyProcess.onData((data: string) => {
    stdoutChunks.push(Buffer.from(data, 'utf8'));
  });

  const denials: DeniedResource[] = [];
  let summary: DenialStreamSummary | undefined;

  const streamP = sideChannel.denialStream.then((socket: Socket) =>
    parseDenialStream(socket, {
      filters: defaultDenialFilters,
      onDenial: makeDenialSink(denials, options, attemptIndex),
      onSummary: (s) => { summary = s; },
      // No passthrough channel in PTY mode -- the workload's stderr
      // is merged into stdout (the PTY). Nothing should land here.
    }),
  );

  const exitP = new Promise<number>((resolve) => {
    ptyProcess.onExit(({ exitCode }) => resolve(exitCode));
  });

  const [, exitCode] = await Promise.all([streamP, exitP]);
  sideChannel.close();

  return {
    index: attemptIndex,
    exitCode,
    stdout: Buffer.concat(stdoutChunks).toString('utf8'),
    stderr: '',
    denials,
    summary,
    pty: ptyProcess,
  };
}
