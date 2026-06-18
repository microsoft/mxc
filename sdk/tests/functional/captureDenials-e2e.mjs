// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * captureDenials end-to-end functional test, consuming the published
 * @microsoft/mxc-sdk package exactly like a real downstream caller
 * would. Drives spawnSandboxFromConfig + parseDenialStream against a
 * live wxc-exec on Windows with the MxcLearningModeShim service installed.
 *
 * Usage (after `npm install <sdk-tarball>` next to this file):
 *   node captureDenials-e2e.mjs --target <absolute-path-the-workload-should-try-to-read>
 *
 * Env vars:
 *   MXC_DENIAL_VERBOSE=1   forwarded to wxc-exec, adds rawEventCount
 *   MXC_FT_FILTERS=none    bypass the SDK's default noise filters
 *
 * Exits 0 on success, 1 on assertion failure, 2 on setup error.
 */

import {
  spawnSandboxFromConfig,
  createConfigFromPolicy,
  parseDenialStream,
  defaultDenialFilters,
  getPlatformSupport,
} from '@microsoft/mxc-sdk';

// ---- CLI parsing ----------------------------------------------------------

const args = process.argv.slice(2);
function takeArg(name) {
  const i = args.indexOf(name);
  if (i < 0 || i === args.length - 1) return undefined;
  const value = args[i + 1];
  args.splice(i, 2);
  return value;
}

const target = takeArg('--target') ?? 'C:\\Users\\AdminUser\\Documents\\NotGranted.txt';

// ---- Platform check -------------------------------------------------------

const support = getPlatformSupport();
console.error(`[functional-test] platform supported: ${support.isSupported}`);
console.error(`[functional-test] available backends:  ${support.availableMethods.join(', ')}`);
if (!support.isSupported) {
  console.error(`[functional-test] SKIP: ${support.reason ?? 'platform unsupported'}`);
  process.exit(0);
}

// ---- Build the policy + config exactly like a consumer would -------------

const policy = {
  version: '0.5.0-alpha',
  filesystem: {
    // Default-deny: nothing is granted, so the workload's attempts
    // to read /target/ will be denied and surface in the stream.
    readwritePaths: [],
    readonlyPaths: [],
  },
  captureDenials: true,
};

const config = createConfigFromPolicy(policy, 'process');
config.process.commandLine = `cmd /c type "${target}"`;

console.error(`[functional-test] target path:     ${target}`);
console.error(`[functional-test] captureDenials:  ${config.captureDenials}`);
console.error(`[functional-test] containment:     ${config.containment ?? '(default)'}`);
console.error(`[functional-test] verbose summary: ${process.env.MXC_DENIAL_VERBOSE === '1'}`);
console.error('');

const useNoFilters = process.env.MXC_FT_FILTERS === 'none';

// ---- Spawn + consume the captureDenials stream ----------------------------

const startedAt = Date.now();
const child = spawnSandboxFromConfig(config, { usePty: false });

const passthroughBuf = [];
const midRunDenials = [];

const denialStreamP = parseDenialStream(child.stderr, {
  filters: useNoFilters ? 'none' : defaultDenialFilters,
  onDenial: (r) => {
    midRunDenials.push(r);
    console.error(`[mid-run] denied: ${r.path} (${r.accessType})`);
  },
  onPassthrough: (chunk) => passthroughBuf.push(chunk),
});

let stdoutBuf = '';
child.stdout.on('data', (c) => { stdoutBuf += c.toString('utf8'); });

const exitP = new Promise((resolve) => {
  child.on('exit', (code, signal) => resolve({ code, signal }));
});

const [denialResult, exitInfo] = await Promise.all([denialStreamP, exitP]);
const durationMs = Date.now() - startedAt;

// ---- Report ---------------------------------------------------------------

const passthrough = Buffer.concat(passthroughBuf).toString('utf8');

const report = {
  durationMs,
  workload: {
    commandLine: config.process.commandLine,
    exit: exitInfo,
    stdoutBytes: stdoutBuf.length,
    stderrBytes: passthrough.length,
  },
  denialStream: {
    midRunCallbackFired: midRunDenials.length,
    streamedUniqueCount: denialResult.summary?.totalDenials,
    rawEventCount: denialResult.summary?.rawEventCount,
    truncated: denialResult.summary?.deniedResourcesTruncated,
    summaryExitCode: denialResult.summary?.exitCode,
    parseErrors: denialResult.parseErrors,
    filterMode: useNoFilters ? 'none' : 'default',
    afterFilterCount: denialResult.denials.length,
    afterFilterPaths: denialResult.denials.map((r) => ({
      path: r.path,
      access: r.accessType,
      type: r.resourceType,
    })),
  },
  passthroughSample:
    passthrough.length > 200 ? passthrough.slice(0, 200) + '…' : passthrough,
};

console.log('\n========== FUNCTIONAL TEST REPORT ==========');
console.log(JSON.stringify(report, null, 2));
console.log('============================================\n');

// ---- Assertions -----------------------------------------------------------

const failures = [];
if (denialResult.summary === undefined) {
  failures.push('expected a summary line, got none');
}
if (denialResult.parseErrors !== 0) {
  failures.push(`expected 0 parseErrors, got ${denialResult.parseErrors}`);
}
if (denialResult.denials.length === 0 && !useNoFilters) {
  failures.push('expected >=1 denial to survive default filters; got 0');
}
if (denialResult.summary && denialResult.summary.exitCode !== exitInfo.code) {
  failures.push(
    `summary.exitCode (${denialResult.summary.exitCode}) != child exit (${exitInfo.code})`,
  );
}
if (denialResult.summary && denialResult.summary.captureDenialsActive !== true) {
  // The host has the MxcLearningModeShim installed (precondition for this
  // functional test to be meaningful), so the run-side capture
  // *should* report active=true. active=false means the shim wasn't
  // reachable -- treat as a hard failure here so we don't ship a
  // silent regression of the wiring.
  failures.push(
    `summary.captureDenialsActive expected true, got ${denialResult.summary.captureDenialsActive}`,
  );
}
if (midRunDenials.length !== denialResult.denials.length) {
  failures.push(
    `midRunDenials (${midRunDenials.length}) != afterFilterCount (${denialResult.denials.length})`,
  );
}

if (failures.length > 0) {
  console.error('[functional-test] FAIL:');
  for (const f of failures) console.error(`  - ${f}`);
  process.exit(1);
}
console.error('[functional-test] PASS');
process.exit(0);
