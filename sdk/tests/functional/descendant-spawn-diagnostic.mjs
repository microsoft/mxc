// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * Descendant-tracking smoke test (Phase B verification).
 *
 * Runs `cmd /c cmd /c type <target>` inside the sandbox with
 * captureDenials on. The outer cmd is the root workload; the
 * inner cmd is a descendant spawned at runtime. With Phase B's
 * IOCP listener wired up, the runner should print
 * `[learning_mode_windows] descendant spawned: PID N` to stderr
 * for the inner cmd's PID.
 *
 * Run on a VM:
 *   node sdk/tests/functional/descendant-spawn-diagnostic.mjs \
 *     --target C:\Users\AdminUser\Documents\file_x.txt
 *
 * Phase B does NOT yet route the descendant's denials into the
 * stream — that's Phase C (shim RPC to extend the ETW PID
 * filter). The descendant still escapes ETW, so its denials are
 * lost. This test just confirms the IOCP detection path works.
 */

import {
  createConfigFromPolicy,
  spawnSandboxFromConfig,
} from '@microsoft/mxc-sdk';

const args = process.argv.slice(2);
function takeArg(name) {
  const i = args.indexOf(name);
  if (i < 0 || i === args.length - 1) return undefined;
  const value = args[i + 1];
  args.splice(i, 2);
  return value;
}

const target = takeArg('--target') ?? 'C:\\Users\\AdminUser\\Documents\\NotGranted.txt';

console.error(`[descendant-spawn] target: ${target}`);

const policy = {
  version: '0.7.0-dev',
  filesystem: {
    // Allow C:\Windows readonly so cmd/whoami can use it as cwd
    // and load their DLLs. Without this the workload aborts with
    // "The current directory is invalid" before spawning anything,
    // and we never get to test the IOCP path.
    readwritePaths: [],
    readonlyPaths: ['C:\\Windows'],
  },
  captureDenials: true,
};

const config = createConfigFromPolicy(policy, 'process');
config.captureDenials = true;
// Outer cmd is the root workload; `whoami.exe` is an external
// executable cmd MUST spawn via CreateProcess (it's not an
// internal command). That spawn triggers the IOCP
// JOB_OBJECT_MSG_NEW_PROCESS we're trying to verify.
config.process.commandLine = `cmd /c whoami`;

const startedAt = Date.now();
const ptyProc = spawnSandboxFromConfig(
  config,
  { usePty: false },
  'C:\\Windows', // cwd: use a path the sandbox can read
);

console.error('[descendant-spawn] spawned, collecting stderr...');

const stderrChunks = [];
ptyProc.stderr.on('data', (data) => { stderrChunks.push(data); });

const stdoutChunks = [];
ptyProc.stdout.on('data', (data) => { stdoutChunks.push(data); });

const exitCode = await new Promise((resolve) =>
  ptyProc.on('close', (code) => resolve(code ?? -1)),
);

const durationMs = Date.now() - startedAt;
const stderr = Buffer.concat(stderrChunks).toString('utf8');
const stdout = Buffer.concat(stdoutChunks).toString('utf8');

const descendantLines = stderr
  .split('\n')
  .filter((l) => l.includes('descendant spawned'));

const report = {
  durationMs,
  exitCode,
  stderrBytes: stderr.length,
  stdoutBytes: stdout.length,
  descendantSpawnLines: descendantLines,
  stderrSample: stderr.length > 1500 ? stderr.slice(0, 1500) + '…' : stderr,
};
console.log('\n========== DESCENDANT SPAWN DIAGNOSTIC ==========');
console.log(JSON.stringify(report, null, 2));
console.log('=================================================\n');

const failures = [];
if (descendantLines.length === 0) {
  failures.push('IOCP did not fire — expected `[learning_mode_windows] descendant spawned: PID N` in stderr');
}

if (failures.length > 0) {
  console.error('[descendant-spawn] FAIL:');
  for (const f of failures) console.error(`  - ${f}`);
  process.exit(1);
}
console.error(`[descendant-spawn] PASS — observed ${descendantLines.length} descendant spawn notification(s)`);
process.exit(0);
