// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * captureDenials "approve → restart → access" end-to-end functional
 * test. It exercises the full learning-mode loop a real application
 * implements when a user approves a denied path:
 *
 *   1. Run the workload under a default-deny policy with
 *      `captureDenials: true`. The workload tries to read a target
 *      file, is denied, and the denial surfaces via
 *      `parseDenialStream`.
 *   2. Mimic the user clicking "Allow" on that denial:
 *      `regenerateSandboxPolicy` folds the approved path into an
 *      expanded policy (additive, never removes existing grants).
 *   3. Re-spawn (restart) the same workload with the regenerated
 *      policy. This time the read succeeds: the file contents land on
 *      stdout and no denial is captured for the target.
 *
 * Phases 1-3 drive that loop by hand to exercise the low-level pieces
 * (spawnSandboxFromConfig + parseDenialStream + regenerateSandboxPolicy)
 * and assert real-time denial delivery via parseDenialStream's onDenial.
 * A final phase repeats the whole thing through the high-level
 * spawnSandboxWithRetry wrapper (maxRetries: 1) to cover its built-in
 * approve -> regen -> retry loop and its real-time onDenial passthrough.
 *
 * This consumes the published @microsoft/mxc-sdk package exactly like
 * a real downstream caller would, against a live wxc-exec on Windows
 * with the MxcLearningModeShim service installed.
 *
 * Usage (after `npm install <sdk-tarball>` next to this file):
 *   node captureDenials-approval-restart-e2e.mjs [--target <abs-path>]
 *
 * If --target is omitted the test creates its own temp file with a
 * known sentinel string, then cleans it up at the end.
 *
 * Env vars:
 *   MXC_DENIAL_VERBOSE=1   forwarded to wxc-exec, adds rawEventCount
 *   MXC_FT_FILTERS=none    bypass the SDK's default noise filters
 *
 * Exits 0 on success, 1 on assertion failure, 2 on setup error.
 */

import {
  spawnSandboxFromConfig,
  spawnSandboxWithRetry,
  createConfigFromPolicy,
  parseDenialStream,
  defaultDenialFilters,
  regenerateSandboxPolicy,
  getPlatformSupport,
} from '@microsoft/mxc-sdk';

import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';

// Case-insensitive path key with trailing separators folded out, so
// `C:\Foo\` and `c:\foo` compare equal. Mirrors the SDK's own
// normalisation in policy-regen.
function normKey(p) {
  return (p ?? '').toLowerCase().replace(/[\\/]+$/, '');
}

// ---- CLI parsing ----------------------------------------------------------

const args = process.argv.slice(2);
function takeArg(name) {
  const i = args.indexOf(name);
  if (i < 0 || i === args.length - 1) return undefined;
  const value = args[i + 1];
  args.splice(i, 2);
  return value;
}

const explicitTarget = takeArg('--target');
const useNoFilters = process.env.MXC_FT_FILTERS === 'none';

// ---- Platform check -------------------------------------------------------

const support = getPlatformSupport();
console.error(`[functional-test] platform supported: ${support.isSupported}`);
console.error(`[functional-test] available backends:  ${support.availableMethods.join(', ')}`);
if (!support.isSupported) {
  console.error(`[functional-test] SKIP: ${support.reason ?? 'platform unsupported'}`);
  process.exit(0);
}

// ---- Set up the target file ----------------------------------------------

const SENTINEL = `mxc-approval-restart-${crypto.randomUUID()}`;
let target = explicitTarget;
let createdTarget = false;

// Default-deny denials surface at *directory* granularity (the
// containing folder the workload was blocked from traversing), not at
// the exact file path -- and anything under C:\Windows is dropped by
// the default noise filters. So the self-created target lives directly
// under C:\Users\Public: its parent (C:\Users\Public) is what gets
// denied, approved, and re-granted.
try {
  if (!target) {
    target = path.join(
      'C:\\Users\\Public',
      `mxc-approval-restart-${crypto.randomBytes(6).toString('hex')}.txt`,
    );
    await fs.writeFile(target, SENTINEL + os.EOL, 'utf8');
    createdTarget = true;
  }
} catch (err) {
  console.error(`[functional-test] SETUP ERROR creating target: ${err?.message ?? err}`);
  process.exit(2);
}

// The directory the approval/grant actually operates on.
const targetDir = path.dirname(target);

console.error(`[functional-test] target path:     ${target}`);
console.error(`[functional-test] target created:  ${createdTarget} (sentinel match ${createdTarget})`);
console.error(`[functional-test] verbose summary: ${process.env.MXC_DENIAL_VERBOSE === '1'}`);
console.error('');

// ---- Helper: run the workload once, collect denials + stdout + exit ------

/**
 * Spawn `cmd /c type "<target>"` under `policy`, stream denials, and
 * return { exit, stdout, denials, summary, parseErrors }.
 */
async function runAttempt(label, policy) {
  const config = createConfigFromPolicy(policy, 'process');
  config.process.commandLine = `cmd /c type "${target}"`;

  console.error(`[${label}] containment:     ${config.containment ?? '(default)'}`);
  console.error(`[${label}] captureDenials:  ${config.captureDenials}`);
  console.error(`[${label}] readonlyPaths:   ${JSON.stringify(policy.filesystem?.readonlyPaths ?? [])}`);

  const startedAt = Date.now();
  const child = spawnSandboxFromConfig(config, { usePty: false });

  const midRunDenials = [];
  const passthroughBuf = [];

  const denialStreamP = parseDenialStream(child.stderr, {
    filters: useNoFilters ? 'none' : defaultDenialFilters,
    onDenial: (r) => {
      midRunDenials.push(r);
      console.error(`[${label}] denied: ${r.path} (${r.accessType})`);
    },
    onPassthrough: (chunk) => passthroughBuf.push(chunk),
  });

  let stdoutBuf = '';
  child.stdout.on('data', (c) => { stdoutBuf += c.toString('utf8'); });

  const exitP = new Promise((resolve) => {
    child.on('exit', (code, signal) => resolve({ code, signal }));
  });

  const [denialResult, exit] = await Promise.all([denialStreamP, exitP]);

  return {
    label,
    durationMs: Date.now() - startedAt,
    exit,
    stdout: stdoutBuf,
    passthrough: Buffer.concat(passthroughBuf).toString('utf8'),
    denials: denialResult.denials,
    midRunDenials,
    summary: denialResult.summary,
    parseErrors: denialResult.parseErrors,
  };
}

// A captured denial is "relevant" to our target when it names the
// target file itself OR the directory subtree the file lives in.
// Denials surface at directory granularity, so in practice this
// matches the parent directory (e.g. C:\Users\Public).
function matchesTargetSubtree(resource) {
  const got = normKey(resource.path);
  const file = normKey(target);
  const dir = normKey(targetDir);
  return got === file || got === dir || got.startsWith(dir + '\\');
}

// ---- Phase 1: default-deny, capture the denial ---------------------------

const basePolicy = {
  version: '0.5.0-alpha',
  filesystem: {
    // Default-deny: nothing granted, so reading the target is denied.
    readwritePaths: [],
    readonlyPaths: [],
  },
  captureDenials: true,
};

console.error('--- PHASE 1: default-deny (expect denial) ---');
const phase1 = await runAttempt('phase1', basePolicy);

// Denials relevant to our target's directory subtree.
const targetDenials = phase1.denials.filter(matchesTargetSubtree);

// ---- User approves: regenerate the policy --------------------------------
//
// Mimic the user clicking "Allow" on the surfaced denials. We approve
// every captured (already noise-filtered) denial -- this is the real
// learning-mode loop: the app shows the user what the workload was
// blocked on, and the user grants it. regenerateSandboxPolicy refuses
// anything system-critical even if approved. We strip trailing
// separators so the grant is the clean directory path.

console.error('\n--- USER APPROVAL: regenerate policy with approved paths ---');
const approvedDenials = phase1.denials.map((d) => ({
  ...d,
  path: d.path.replace(/[\\/]+$/, ''),
}));
const regen = regenerateSandboxPolicy({ basePolicy, approvedDenials });
console.error(`[approval] added:   ${JSON.stringify(regen.added)}`);
console.error(`[approval] skipped: ${JSON.stringify(regen.skipped)}`);

// Did the approval grant the target's directory subtree?
const grantedReadonly = regen.policy.filesystem?.readonlyPaths ?? [];
const grantedTargetDir = grantedReadonly.some((p) => {
  const g = normKey(p);
  return g === normKey(targetDir) || normKey(target).startsWith(g + '\\') || g === normKey(target);
});

// ---- Phase 2: restart with the regenerated policy (expect access) --------

console.error('\n--- PHASE 2: restart with approved policy (expect access) ---');
const phase2 = await runAttempt('phase2', regen.policy);

const phase2TargetDenials = phase2.denials.filter(matchesTargetSubtree);

// ---- Phase 3: same loop via spawnSandboxWithRetry -------------------------
//
// Phases 1+2 drive the loop by hand (spawnSandboxFromConfig +
// parseDenialStream + regenerateSandboxPolicy + manual re-spawn). Phase
// 3 covers the high-level wrapper that does all of that internally,
// AND exercises its real-time `onDenial` passthrough (commit that added
// live denials to spawnSandboxWithRetry). With maxRetries: 1 the wrapper
// should: attempt 0 denied -> onDenied approves -> regen -> attempt 1
// reads the file -> stopReason 'success'.

console.error('\n--- PHASE 3: spawnSandboxWithRetry (auto approve + retry + live onDenial) ---');

const retryLiveDenials = [];           // every onDenial (real-time) fire
let onDeniedCalls = 0;                  // batched approval-callback fires

const retryResult = await spawnSandboxWithRetry({
  script: `cmd /c type "${target}"`,
  policy: basePolicy,
  maxRetries: 1,
  // Real-time: fires per denial as it streams, tagged with the attempt.
  onDenial: (resource, attemptIndex) => {
    retryLiveDenials.push({ resource, attemptIndex });
    console.error(`[phase3 live] attempt ${attemptIndex} denied: ${resource.path}`);
  },
  // Batched: the user-approval decision. Approve every captured denial
  // (trailing separators stripped), mirroring the manual phases.
  onDenied: (denials, ctx) => {
    onDeniedCalls += 1;
    console.error(`[phase3 onDenied] attempt ${ctx.attemptIndex}: ${denials.length} denial(s)`);
    return {
      approve: denials.map((d) => ({ ...d, path: d.path.replace(/[\\/]+$/, '') })),
    };
  },
});

const retryFinal = retryResult.attempts.at(-1);
const retryLiveAttempt0 = retryLiveDenials.filter(
  (e) => e.attemptIndex === 0 && matchesTargetSubtree(e.resource),
);

// ---- Report ---------------------------------------------------------------

const report = {
  target,
  targetDir,
  phase1: {
    exit: phase1.exit,
    stdoutBytes: phase1.stdout.length,
    capturedTargetDenials: targetDenials.map((r) => ({
      path: r.path,
      access: r.accessType,
      type: r.resourceType,
    })),
    totalCaptured: phase1.denials.length,
    // Real-time delivery: the parseDenialStream onDenial callback fires.
    realtimeFired: phase1.midRunDenials.length,
    realtimeTargetDenials: phase1.midRunDenials.filter(matchesTargetSubtree).length,
    captureActive: phase1.summary?.captureDenialsActive,
    parseErrors: phase1.parseErrors,
  },
  approval: {
    added: regen.added,
    skipped: regen.skipped,
    grantedTargetDir,
    regeneratedReadonlyPaths: grantedReadonly,
  },
  phase2: {
    exit: phase2.exit,
    stdoutBytes: phase2.stdout.length,
    stdoutSample:
      phase2.stdout.length > 200 ? phase2.stdout.slice(0, 200) + '…' : phase2.stdout,
    sentinelSeen: createdTarget ? phase2.stdout.includes(SENTINEL) : null,
    targetDeniedAgain: phase2TargetDenials.length,
    parseErrors: phase2.parseErrors,
  },
  phase3: {
    stopReason: retryResult.stopReason,
    attempts: retryResult.attempts.length,
    onDeniedCalls,
    realtimeFired: retryLiveDenials.length,
    realtimeTargetDenialsAttempt0: retryLiveAttempt0.length,
    grantedReadonly: retryResult.regen?.policy.filesystem?.readonlyPaths ?? [],
    finalExit: retryFinal?.exitCode,
    finalStdoutSample:
      (retryFinal?.stdout ?? '').length > 200
        ? retryFinal.stdout.slice(0, 200) + '…'
        : retryFinal?.stdout,
    sentinelSeen: createdTarget ? (retryFinal?.stdout ?? '').includes(SENTINEL) : null,
  },
};

console.log('\n========== FUNCTIONAL TEST REPORT ==========');
console.log(JSON.stringify(report, null, 2));
console.log('============================================\n');

// ---- Assertions -----------------------------------------------------------

const failures = [];

// Phase 1: the target subtree must have been denied, and the read must fail.
if (targetDenials.length === 0) {
  failures.push(
    `phase1: expected a denial under the target dir (${targetDir}); captured none ` +
      `(total captured: ${phase1.denials.length})`,
  );
}
if (phase1.exit.code === 0) {
  failures.push(`phase1: expected non-zero exit (read denied), got ${phase1.exit.code}`);
}
if (createdTarget && phase1.stdout.includes(SENTINEL)) {
  failures.push('phase1: target contents leaked to stdout despite being denied');
}
if (phase1.summary && phase1.summary.captureDenialsActive !== true) {
  failures.push(
    `phase1: captureDenialsActive expected true (is MxcLearningModeShim running?), ` +
      `got ${phase1.summary.captureDenialsActive}`,
  );
}
// Phase 1 real-time delivery: the live onDenial callback must have
// delivered the same denials as the batched stream result (and at
// least one under the target dir), proving real-time streaming works.
if (phase1.midRunDenials.length !== phase1.denials.length) {
  failures.push(
    `phase1: real-time onDenial count (${phase1.midRunDenials.length}) != ` +
      `batched denial count (${phase1.denials.length})`,
  );
}
if (phase1.midRunDenials.filter(matchesTargetSubtree).length === 0) {
  failures.push(
    'phase1: real-time onDenial never delivered a denial under the target dir',
  );
}

// Approval: the regen step must have granted the target's directory.
if (regen.added.length === 0) {
  failures.push('approval: regenerateSandboxPolicy added no grants');
}
if (!grantedTargetDir) {
  failures.push(
    `approval: regenerated policy does not grant the target dir (${targetDir})`,
  );
}

// Phase 2: the restart must succeed and read the file.
if (phase2.exit.code !== 0) {
  failures.push(`phase2: expected exit 0 after approval, got ${phase2.exit.code}`);
}
if (createdTarget && !phase2.stdout.includes(SENTINEL)) {
  failures.push('phase2: expected the approved file contents on stdout; sentinel not found');
}
if (phase2TargetDenials.length !== 0) {
  failures.push(
    `phase2: target subtree was denied again after approval (${phase2TargetDenials.length} denials)`,
  );
}
if (phase2.parseErrors !== 0) {
  failures.push(`phase2: expected 0 parseErrors, got ${phase2.parseErrors}`);
}

// Phase 3: the high-level wrapper must approve, retry, and succeed, and
// its real-time onDenial passthrough must have fired during attempt 0.
if (retryResult.stopReason !== 'success') {
  failures.push(`phase3: expected stopReason 'success', got '${retryResult.stopReason}'`);
}
if (retryResult.attempts.length !== 2) {
  failures.push(
    `phase3: expected 2 attempts (one retry), got ${retryResult.attempts.length}`,
  );
}
if (onDeniedCalls < 1) {
  failures.push(`phase3: expected onDenied to fire at least once, got ${onDeniedCalls}`);
}
if (retryLiveAttempt0.length === 0) {
  failures.push(
    'phase3: real-time onDenial never delivered a target-dir denial on attempt 0',
  );
}
if (retryFinal?.exitCode !== 0) {
  failures.push(`phase3: expected final attempt exit 0, got ${retryFinal?.exitCode}`);
}
if (createdTarget && !(retryFinal?.stdout ?? '').includes(SENTINEL)) {
  failures.push('phase3: expected the approved file contents on stdout; sentinel not found');
}

// ---- Cleanup --------------------------------------------------------------

if (createdTarget) {
  try {
    await fs.unlink(target);
  } catch {
    // best-effort cleanup; don't fail the test on this
  }
}

if (failures.length > 0) {
  console.error('[functional-test] FAIL:');
  for (const f of failures) console.error(`  - ${f}`);
  process.exit(1);
}
console.error('[functional-test] PASS');
process.exit(0);
