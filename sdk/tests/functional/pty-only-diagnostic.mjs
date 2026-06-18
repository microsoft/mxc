// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * PTY-only diagnostic: row D of the PTY+captureDenials bisection
 * matrix.
 *
 * Spawns a sandboxed workload under PTY but WITHOUT captureDenials
 * and WITHOUT the side channel. If this works on a host where the
 * full PTY+captureDenials test (captureDenials-pty-e2e.mjs) fails
 * with Win32 error 203, it tells us the trigger is the
 * `captureDenials × PTY` intersection rather than `PTY × sandbox`
 * in general.
 *
 * Asserts:
 *   - The workload reaches exit (any exit code).
 *   - Some PTY output is captured.
 *   - The PTY output does NOT contain "CreateProcessInSandbox failed".
 *
 * Run on a VM:
 *   node sdk/tests/functional/pty-only-diagnostic.mjs \
 *     --target C:\Users\AdminUser\Documents\file_x.txt
 *
 * Set MXC_LAUNCH_VERBOSE=1 (in the parent env) to enable the
 * runner-side dump of env / command line / cwd / creation_flags
 * before Experimental_CreateProcessInSandbox.
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

console.error(`[pty-only] target: ${target}`);

// Same policy shape as the failing PTY+captureDenials test, MINUS
// captureDenials. Reads a file under the user profile; the read
// itself will fail under the sandbox, but the sandbox process
// should still LAUNCH cleanly.
const policy = {
  version: '0.5.0-alpha',
  filesystem: { readwritePaths: [], readonlyPaths: [] },
};

const config = createConfigFromPolicy(policy, 'process');
config.process.commandLine = `cmd /c type "${target}"`;

const startedAt = Date.now();
const ptyProc = spawnSandboxFromConfig(config, { usePty: true });

console.error('[pty-only] spawned, collecting PTY output...');

const ptyOutputChunks = [];
ptyProc.onData((data) => { ptyOutputChunks.push(data); });

const exitCode = await new Promise((resolve) =>
  ptyProc.onExit(({ exitCode }) => resolve(exitCode)),
);

const durationMs = Date.now() - startedAt;
const ptyOutput = ptyOutputChunks.join('');

const report = {
  durationMs,
  exitCode,
  ptyOutputBytes: ptyOutput.length,
  ptyOutputSample: ptyOutput.length > 400 ? ptyOutput.slice(0, 400) + '…' : ptyOutput,
};
console.log('\n========== PTY-ONLY DIAGNOSTIC REPORT ==========');
console.log(JSON.stringify(report, null, 2));
console.log('================================================\n');

const failures = [];
if (ptyOutput.length === 0) failures.push('no PTY output captured');
if (/CreateProcessInSandbox failed/i.test(ptyOutput)) {
  failures.push('PTY output contains "CreateProcessInSandbox failed" — sandbox refused to start the process even WITHOUT captureDenials');
}

if (failures.length > 0) {
  console.error('[pty-only] FAIL — PTY without captureDenials also fails. Bug is PTY × sandbox, NOT captureDenials × PTY.');
  for (const f of failures) console.error(`  - ${f}`);
  process.exit(1);
}
console.error('[pty-only] PASS — PTY without captureDenials works. Bug is in the captureDenials × PTY intersection.');
process.exit(0);
