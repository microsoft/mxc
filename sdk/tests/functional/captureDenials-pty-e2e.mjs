// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * PTY + side-channel functional test.
 *
 * Spawns a sandboxed workload in PTY mode and consumes the
 * captureDenials NDJSON stream through the named-pipe side channel
 * (so PTY mode and captureDenials can coexist). This is the
 * scenario the SDK couldn't support before -- interactive workloads
 * like REPLs or color-aware build tools that need a real terminal
 * AND need denials surfaced to the application.
 *
 * Asserts:
 *   - The pipe server accepts the wxc-exec client connection.
 *   - At least one denial envelope flows through the pipe.
 *   - The summary terminator arrives (captureDenialsActive: true).
 *   - The workload's PTY output reaches the consumer.
 *
 * Run on a VM with MxcLearningModeShim installed:
 *   node sdk/tests/functional/captureDenials-pty-e2e.mjs \
 *     --target C:\Users\AdminUser\Documents\file_x.txt
 */

import {
  createConfigFromPolicy,
  spawnSandboxWithSideChannel,
  parseDenialStream,
  defaultDenialFilters,
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

console.error(`[pty-e2e] target: ${target}`);

const policy = {
  version: '0.5.0-alpha',
  filesystem: { readwritePaths: [], readonlyPaths: [] },
  captureDenials: true,
};

const config = createConfigFromPolicy(policy, 'process');
config.captureDenials = true;
config.process.commandLine = `cmd /c type "${target}"`;

const startedAt = Date.now();
const { process: ptyProc, denialStream, close } = spawnSandboxWithSideChannel(
  config,
  { usePty: true },
);

console.error('[pty-e2e] spawned, waiting for pipe client connect...');

const ptyOutputChunks = [];
ptyProc.onData((data) => {
  ptyOutputChunks.push(data);
});

const denials = [];
let summary;

const exitP = new Promise((resolve) =>
  ptyProc.onExit(({ exitCode }) => resolve(exitCode)),
);

// Race the pipe-connect against the process exit + a safety timeout.
// If wxc-exec dies before it ever connects to the pipe (typically
// because the env var wasn't honored, or the workload failed early
// at spawn time), denialStream stays pending forever. Without this
// race the whole test hangs.
const TIMEOUT_MS = 30_000;
const timeoutP = new Promise((_, reject) =>
  setTimeout(() => reject(new Error(`pipe connect timeout (${TIMEOUT_MS}ms)`)), TIMEOUT_MS),
);

let denialP;
try {
  const socket = await Promise.race([
    denialStream,
    exitP.then(() => Promise.reject(new Error('process exited before pipe client connected'))),
    timeoutP,
  ]);
  console.error('[pty-e2e] pipe client connected');
  denialP = parseDenialStream(socket, {
    filters: defaultDenialFilters,
    onDenial: (r) => {
      denials.push(r);
      console.error(`[pty-e2e][mid-run] denied: ${r.path} (${r.accessType})`);
    },
    onSummary: (s) => { summary = s; },
  });
} catch (err) {
  console.error(`[pty-e2e] denial stream setup failed: ${err.message}`);
  console.error('[pty-e2e] waiting for process exit to capture diagnostic output...');
  denialP = Promise.resolve();
}

const exitCode = await exitP;
if (denialP) await denialP;
close();
const durationMs = Date.now() - startedAt;

const ptyOutput = ptyOutputChunks.join('');

const report = {
  durationMs,
  exitCode,
  ptyOutputBytes: ptyOutput.length,
  ptyOutputSample: ptyOutput.length > 200 ? ptyOutput.slice(0, 200) + '…' : ptyOutput,
  denialStream: {
    deniedCount: denials.length,
    deniedPaths: denials.map((d) => d.path),
    summary,
  },
};
console.log('\n========== PTY + SIDE-CHANNEL REPORT ==========');
console.log(JSON.stringify(report, null, 2));
console.log('===============================================\n');

const failures = [];
if (!summary) failures.push('no summary line observed on the side-channel pipe');
if (summary && !summary.captureDenialsActive) {
  failures.push('captureDenialsActive=false on the summary (shim issue?)');
}
if (denials.length === 0) failures.push('no denials reached the consumer via the pipe');
// The PTY output should at minimum contain "Access is denied" -- that's
// the visible workload error rendered on the terminal.
if (!/Access is denied/i.test(ptyOutput)) {
  failures.push('PTY output missing the expected "Access is denied" workload message');
}

if (failures.length > 0) {
  console.error('[pty-e2e] FAIL:');
  for (const f of failures) console.error(`  - ${f}`);
  process.exit(1);
}
console.error('[pty-e2e] PASS');
process.exit(0);
