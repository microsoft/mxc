// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { spawn, ChildProcess, execSync } from 'child_process';
import assert from 'node:assert';
import type { TestContext } from 'node:test';
import path from 'path';
import fs from 'fs';
import os from 'os';
import semver from 'semver';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import * as sdkNamespace from '@microsoft/mxc-sdk';
import {
  MxcError,
  deprovisionSandbox,
  provisionSandbox,
  type SandboxId,
  type StateAwareContainmentBackend,
} from '@microsoft/mxc-sdk';
import { evaluateProxyAvailability } from './proxy-availability.js';

const require = createRequire(import.meta.url);
export const sdk = sdkNamespace;

// Schema versions

export const supportedVersions = [
  new semver.SemVer('0.6.0-alpha'),
  new semver.SemVer('0.7.0-alpha'),
  new semver.SemVer('0.8.0-alpha'),
];

// SDK package location

// Upper bound on how many parent directories to walk when locating the SDK root
// / monorepo layout from this file's (compiled) location. Generous enough to
// cover dist-tests nesting; small enough to terminate quickly at the FS root.
const MAX_PARENT_WALK_UPS = 8;

/** SDK arch label (`x64` | `arm64`) used in platform-package names. */
function sdkArch(): string {
  return os.arch() === 'arm64' ? 'arm64' : 'x64';
}

/** Name of the host's per-platform binary package. */
export function getPlatformPackageName(): string {
  return `@microsoft/mxc-sdk-${process.platform}-${sdkArch()}`;
}

/**
 * Resolve the per-platform binary package directory (where the native executor
 * and its sandbox helpers live after #512 — at the package root, not a
 * `bin/<arch>` subdir). Resolution order:
 *   1. the installed optional package (`@microsoft/mxc-sdk-<os>-<arch>`); else
 *   2. the monorepo dev layout `sdk/node/platform-packages/<os>-<arch>`.
 *
 * The dev-layout fallback matters because the integration suite installs the
 * SDK via `file:../../`, which does NOT pull the os/cpu-filtered optional
 * platform packages — so in a source checkout the installed lookup always
 * misses. Without the fallback this threw at import-time and crashed the entire
 * integration suite. Throws only when neither source is present.
 */
export function getPlatformPackageDir(): string {
  const name = getPlatformPackageName();
  // 1. Installed optional package (published registry or a CI artifact).
  try {
    return path.dirname(require.resolve(`${name}/package.json`));
  } catch {
    // not installed; try the dev layout
  }
  // 2. Monorepo dev layout: walk up to the SDK root and use its
  //    platform-packages/<tuple> dir (robust to this file's compiled location).
  const tuple = `${process.platform}-${sdkArch()}`;
  let dir = path.dirname(fileURLToPath(import.meta.url));
  for (let i = 0; i < MAX_PARENT_WALK_UPS; i++) {
    const candidate = path.join(dir, 'platform-packages', tuple);
    if (fs.existsSync(path.join(candidate, 'package.json'))) {
      return candidate;
    }
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  throw new Error(
    `Platform package ${name} is not installed and no dev layout was found ` +
      `(sdk/node/platform-packages/${tuple}). The integration suite needs the native ` +
      `binary — install the platform package alongside @microsoft/mxc-sdk or ` +
      `build/stage it locally.`,
  );
}

/**
 * Directory the SDK ships its executor + sandbox helpers in. Post-#512 this is
 * the per-platform package root.
 */
export function getSdkBinDir(): string {
  return getPlatformPackageDir();
}

/**
 * Resolve a directory containing the dev/test-only proxy binaries
 * (`wxc-test-proxy.exe` / `unix-test-proxy`). These are intentionally NOT
 * shipped in the per-platform packages (#512), so they are sourced from:
 *   1. `MXC_TEST_PROXY_DIR` (explicit override, e.g. a CI test artifact), or
 *   2. the monorepo Cargo build output (local dev), if present.
 * Returns `null` when no source is available — callers skip proxy tests.
 */
export function getTestBinDir(): string | null {
  const override = process.env.MXC_TEST_PROXY_DIR;
  if (override && fs.existsSync(override)) {
    return override;
  }
  // Walk up from this file to the monorepo root (the dir that has src/target).
  let dir = path.dirname(fileURLToPath(import.meta.url));
  for (let i = 0; i < MAX_PARENT_WALK_UPS; i++) {
    const targetDir = path.join(dir, 'src', 'target');
    if (fs.existsSync(targetDir)) {
      const triple = rustTriple();
      const candidates = [
        path.join(targetDir, triple, 'release'),
        path.join(targetDir, triple, 'debug'),
        path.join(targetDir, 'release'),
        path.join(targetDir, 'debug'),
      ];
      for (const c of candidates) {
        if (fs.existsSync(c)) return c;
      }
    }
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return null;
}

/** Rust target triple for the current host. */
function rustTriple(): string {
  const arch = os.arch() === 'arm64' ? 'aarch64' : 'x86_64';
  if (process.platform === 'linux') return `${arch}-unknown-linux-gnu`;
  if (process.platform === 'darwin') return `${arch}-apple-darwin`;
  return `${arch}-pc-windows-msvc`;
}

/**
 * True when the given test-proxy binary can be sourced, else proxy tests skip.
 *
 * In a CI environment that is expected to run the proxy tests (signalled by
 * `MXC_REQUIRE_PROXY_TESTS`), a missing proxy is a hard failure rather than a
 * silent skip — otherwise a real proxy regression and a missing fixture are
 * indistinguishable (both green-with-skips). Local/dev runs without the env var
 * keep the skip.
 */
export function isTestProxyAvailable(binary: string): boolean {
  return evaluateProxyAvailability({ binary, dir: getTestBinDir() });
}

// Expected per-platform package binaries. After #512 each platform package
// ships only its own host's executor + sandbox helpers — NOT the dev/test-only
// proxies (wxc-test-proxy.exe / unix-test-proxy) or the diagnostic console,
// which are intentionally excluded to keep the install lean.

export const EXPECTED_WINDOWS_BINARIES = [
  'wxc-exec.exe',
  'wxc-host-prep.exe',
  'winhttp-proxy-shim.exe',
  'wxc-windows-sandbox-daemon.exe',
  'wxc-windows-sandbox-guest.exe',
];

export const EXPECTED_LINUX_BINARIES = [
  'lxc-exec',
];

export const EXPECTED_MACOS_BINARIES = [
  'mxc-exec-mac',
];

// Binaries that are optional (feature-gated or only present in certain builds)
// but still legitimate if found in the package.
const OPTIONAL_BINARIES = [
  'wslcsdk.dll',      // Only built with --with-wslc
  'plm.exe',          // Permissive Learning Mode helper (Windows-only); staged
                      // only when the plm crate is included in the build.
  'nanvixd.exe',      // Only built with --with-microvm
  'nanvix_rootfs.img',
  'python3.initrd',
];

// Combined list of all known binaries across platforms. Each platform package
// only ships its own host's binaries, but the "no unexpected binaries" check
// stays permissive across OSes for robustness.
export const ALL_KNOWN_BINARIES = [
  ...EXPECTED_WINDOWS_BINARIES,
  ...EXPECTED_LINUX_BINARIES,
  ...EXPECTED_MACOS_BINARIES,
  ...OPTIONAL_BINARIES,
];

// Dev/test-only proxy binaries — excluded from shipped packages (#512); sourced
// for proxy E2E tests via getTestBinDir(), which skips the tests when absent.
export const TEST_ONLY_BINARIES = [
  'wxc-test-proxy.exe',
  'unix-test-proxy',
];

// Platform / version helpers

/** Return a human-friendly OS name for test descriptions. */
export function platformName(): string {
  return os.platform() === 'win32' ? 'Windows' : 'Linux';
}

/**
 * Assert that a dry-run completed successfully (exit 0 + validation-passed banner).
 *
 * Dry-run failure paths aren't asserted here — the dispatcher's tier-fallback
 * chain (BaseContainer → AppContainer+BFS → AppContainer+DACL) finds a viable
 * runner on every supported host, so a failing dry-run from the test harness
 * is a real regression, not an expected outcome.
 */
export function assertDryRunResult(
  stdout: string,
  exitCode: number,
  version: string,
): void {
  assert.strictEqual(exitCode, 0, `[${version}] Expected exit 0 but got ${exitCode}`);
  assert.ok(stdout.includes('Dry run completed. Result: validation passed'), `[${version}] ${stdout}`);
}

// Environment / skip helpers

const skipOsDependentTests= process.env.MXC_SKIP_OS_BUILD_DEPENDENT_TESTS === '1';
export const sandboxSkipReason = skipOsDependentTests
  ? 'Skipped in CI (MXC_SKIP_OS_BUILD_DEPENDENT_TESTS)'
  : undefined;

export const isLinuxRoot = os.platform() === 'linux' && process.getuid?.() === 0;

/**
 * Linux + bubblewrap available on PATH. The cooperative-proxy backend does
 * not require root, so proxy-focused tests use this gate instead of the
 * stricter `isLinuxRoot` used by other Bubblewrap fingerprint tests.
 */
export const isLinuxBubblewrap = (() => {
  if (os.platform() !== 'linux') return false;
  const pathDirs = (process.env.PATH ?? '').split(path.delimiter);
  for (const dir of pathDirs) {
    if (!dir) continue;
    try {
      if (fs.existsSync(path.join(dir, 'bwrap'))) return true;
    } catch {
      // ignore inaccessible PATH entries
    }
  }
  return false;
})();

// When MXC_DEBUG=true, integration tests pass { debug: true } to spawn options
// so wxc-exec / lxc-exec emit verbose output. Enable via pipeline parameter or locally.
const debugMode = process.env.MXC_DEBUG === 'true';
const experimentalMode = os.platform() === 'darwin';
export const debugSpawnOptions = {
  ...(debugMode ? { debug: true } : {}),
  ...(experimentalMode ? { experimental: true } : {}),
};

// Network test endpoint reachable from both CI (Azure DevOps agents block
// external traffic but allow Azure Artifacts feeds) and local builds.
export const NETWORK_TEST_URL =
  'https://pkgs.dev.azure.com/shine-oss/mxc/_packaging/MxcDependencies/npm/registry/@types/json-schema';

// Set MXC_SKIP_LXC_NETWORK_TESTS=1 to skip network-dependent LXC tests
// (e.g. environments without an `lxcbr0` bridge / IP forwarding /
// outbound network access). Both CI lanes currently set this env var:
// GHA sets it in `.github/workflows/SDK.Integration.Test.Job.yml`
// because the alpine download template doesn't acquire a DHCP-issued
// IPv4 lease within the test window on the runner images, so
// container-side DNS lookups fail; ADO sets it in
// `.azure-pipelines/templates/SDK.Integration.Test.Job.yml` because
// the 1ES Hosted Pool's egress firewall blocks lxcbr0-NAT'd traffic.
// Both CIs still run the non-network LXC paths
// (create/start/attach/mount/exit-code/multi-command) end-to-end.
const skipLxcNetworkTests = process.env.MXC_SKIP_LXC_NETWORK_TESTS === '1';
export const lxcNetworkSkipReason = skipLxcNetworkTests
  ? 'Skipped: LXC network not available in this environment (MXC_SKIP_LXC_NETWORK_TESTS)'
  : undefined;

// State-aware lifecycle helpers

/**
 * Wraps a state-aware SDK call, skipping the test (rather than failing) when
 * the executor reports `backend_unavailable` or `unsupported_phase` — either
 * indicates this environment cannot exercise the lifecycle. Other errors
 * propagate.
 */
export async function runOrSkipIfBackendUnavailable<T>(
  t: TestContext,
  label: string,
  fn: () => Promise<T>,
): Promise<T | undefined> {
  try {
    return await fn();
  } catch (err) {
    if (err instanceof MxcError && err.code === 'backend_unavailable') {
      t.skip(`${label}: state-aware backend runtime unavailable on this host`);
      return undefined;
    }
    if (err instanceof MxcError && err.code === 'unsupported_phase') {
      // wxc-exec was built without the backend's feature flag, so the
      // state-aware dispatch path is compiled out. Same outcome from the
      // test's perspective as a host without the runtime: cannot exercise
      // the lifecycle, skip rather than fail.
      t.skip(`${label}: wxc-exec lacks the backend feature; rebuild with the feature flag to run this test`);
      return undefined;
    }
    throw err;
  }
}

/** Deprovision a sandbox best-effort, swallowing errors so cleanup never masks the original failure. */
export async function safeDeprovision<C extends StateAwareContainmentBackend>(
  sandboxId: SandboxId<C>,
): Promise<void> {
  try {
    await deprovisionSandbox(sandboxId, undefined, { experimental: true });
  } catch (err) {
    console.error(`Cleanup deprovision failed for ${sandboxId}: ${err}`);
  }
}

/**
 * Probes a state-aware backend's runtime by attempting a provision /
 * deprovision cycle. Returns a skip-reason string when the runtime is
 * unavailable (`backend_unavailable` or `unsupported_phase`), `undefined`
 * when the backend can be exercised. Other errors propagate so genuine
 * failures aren't masked as "skipped." Intended for one-shot probing at
 * module load — pair the result with `describe`'s `{ skip }` option.
 */
export async function probeStateAwareRuntime<C extends StateAwareContainmentBackend>(
  containment: C,
): Promise<string | undefined> {
  try {
    const provisionResult = await provisionSandbox(
      containment,
      undefined,
      { experimental: true },
    );
    await safeDeprovision(provisionResult.sandboxId);
    return undefined;
  } catch (err) {
    if (err instanceof MxcError && err.code === 'backend_unavailable') {
      return `${containment} runtime unavailable on this host`;
    }
    if (err instanceof MxcError && err.code === 'unsupported_phase') {
      return `wxc-exec lacks the ${containment} feature; rebuild with --features ${containment} to run this test`;
    }
    throw err;
  }
}

// Temp directory helpers

export function createTempDir(prefix: string = 'mxc-test'): string {
  const tmpBase = fs.realpathSync.native(os.tmpdir());
  const dir = path.join(tmpBase, `${prefix}-${Date.now()}`);
  fs.mkdirSync(dir);
  return dir;
}

// Async spawn from a pre-built ContainerConfig. Mirrors the SDK's own
// spawnSandboxAsync (sandbox.ts) -- it exists because the SDK doesn't expose
// an async wrapper around spawnSandboxFromConfig, and tests that need a
// specific backend build the config directly.
//
// Notes (kept in lockstep with spawnSandboxAsync):
//  - stdout/stderr are merged: wxc-exec runs under node-pty (a single PTY),
//    so the OS combines both streams. stderr: '' is structural padding.
//  - No per-call timeout: node:test enforces test-level timeouts and the
//    config's process.timeout is enforced by the native runner.
//  - IPty has no onError event. Synchronous spawn failures are caught below;
//    post-spawn failures surface as a non-zero exitCode via onExit.
export function spawnFromConfigAsync(
  config: sdkNamespace.ContainerConfig,
  options: sdkNamespace.SandboxSpawnOptions = {},
  workingDirectory?: string,
): Promise<{ stdout: string; stderr: string; exitCode: number }> {
  return new Promise((resolve, reject) => {
    try {
      const ptyProcess = sdkNamespace.spawnSandboxFromConfig(config, options, workingDirectory);
      let output = '';
      ptyProcess.onData((data: string) => {
        output += data;
      });
      ptyProcess.onExit((event: { exitCode: number; signal?: number }) => {
        resolve({ stdout: output, stderr: '', exitCode: event.exitCode });
      });
    } catch (err) {
      reject(err);
    }
  });
}

// Python helpers

/** Detect a usable Python command. Returns undefined if not installed. */
function detectPython(): { command: string | undefined; prefix: string | undefined } {
  const candidates = os.platform() === 'win32' ? ['python', 'python3'] : ['python3', 'python'];
  for (const cmd of candidates) {
    try {
      const prefix = execSync(`${cmd} -c "import sys; print(sys.prefix)"`, {
        encoding: 'utf-8',
        timeout: 10000,
        stdio: ['pipe', 'pipe', 'pipe'],
      }).trim();
      if (!prefix || prefix.toLowerCase().includes('was not found')) continue;
      return { command: cmd, prefix };
    } catch {
      continue;
    }
  }
  return { command: undefined, prefix: undefined };
}

const _python = detectPython();

export const pythonCommand: string | undefined = _python.command;
export const pythonSkipReason: string | undefined = _python.command ? undefined : 'No Python installation found';

/**
 * Merge host tool paths into a policy so the container can find installed tools.
 * Adds the Python prefix as a readwrite path when needed for DLL loading.
 */
export function withToolPaths(policy: Record<string, any>): Record<string, any> {
  const toolsPolicy = sdk.getAvailableToolsPolicy(process.env);
  const merged = { ...policy, filesystem: { ...policy.filesystem } };

  const extraReadwrite: string[] = [];
  if (_python.prefix) {
    extraReadwrite.push(_python.prefix);
  }

  if (toolsPolicy.readonlyPaths.length > 0) {
    merged.filesystem.readonlyPaths = [
      ...(merged.filesystem.readonlyPaths ?? []),
      ...toolsPolicy.readonlyPaths,
    ];
  }
  if (toolsPolicy.readwritePaths.length > 0 || extraReadwrite.length > 0) {
    merged.filesystem.readwritePaths = [
      ...(merged.filesystem.readwritePaths ?? []),
      ...toolsPolicy.readwritePaths,
      ...extraReadwrite,
    ];
  }
  return merged;
}

// Windows-only: proxy helpers

/** Locate wxc-test-proxy.exe in the test-proxy source dir (not shipped in the package). */
function findTestProxyBinary(): string {
  const binDir = getTestBinDir();
  const proxyPath = binDir ? path.join(binDir, 'wxc-test-proxy.exe') : null;
  if (proxyPath && fs.existsSync(proxyPath)) {
    return proxyPath;
  }
  throw new Error(
    'wxc-test-proxy.exe not found. It is excluded from the shipped platform ' +
      'package (#512); set MXC_TEST_PROXY_DIR or build the Rust binaries locally.',
  );
}

/**
 * Start wxc-test-proxy.exe in a child process.
 * It binds to an OS-assigned port and writes it to a ready file.
 * Uses --parent-pid so the proxy exits when tests finish.
 */
export function startTestProxy(dir: string): { port: number; proxyProcess: ChildProcess } {
  const proxyPath = findTestProxyBinary();
  const readyFile = path.join(dir, 'proxy-ready.txt');
  const eventName = `Local\\mxc-cli-test-${process.pid}-${Date.now()}`;

  const proxyProcess = spawn(proxyPath, [
    '--ready-file', readyFile,
    '--cleanup-event', eventName,
    '--parent-pid', process.pid.toString(),
  ], { stdio: 'ignore' });

  // Poll for the ready file (up to 15 seconds)
  const deadline = Date.now() + 15000;
  while (!fs.existsSync(readyFile) && Date.now() < deadline) {
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 100);
  }

  if (!fs.existsSync(readyFile)) {
    proxyProcess.kill();
    throw new Error('wxc-test-proxy did not write ready file within 15 seconds');
  }

  const portStr = fs.readFileSync(readyFile, 'utf-8').trim();
  const port = parseInt(portStr, 10);
  if (isNaN(port) || port <= 0) {
    proxyProcess.kill();
    throw new Error(`Invalid port in ready file: ${portStr}`);
  }

  return { port, proxyProcess };
}

// unix-test-proxy helpers (currently only exercised by the Linux Bubblewrap test)

/** Locate unix-test-proxy in the test-proxy source dir (not shipped in the package). */
function findUnixTestProxyBinary(): string {
  const binDir = getTestBinDir();
  const proxyPath = binDir ? path.join(binDir, 'unix-test-proxy') : null;
  if (proxyPath && fs.existsSync(proxyPath)) {
    return proxyPath;
  }
  throw new Error(
    'unix-test-proxy not found. It is excluded from the shipped platform ' +
      'package (#512); set MXC_TEST_PROXY_DIR or build the Rust binaries locally.',
  );
}

/**
 * Start unix-test-proxy in a child process.
 *
 * Binds to an OS-assigned port on `127.0.0.1` and writes it atomically to a
 * ready file. The proxy watches its stdin for EOF as a cross-platform
 * parent-death signal, so it must be spawned with a piped stdin that this
 * process keeps open: when the test process exits the pipe closes, the proxy
 * reads EOF and shuts down. An ignored/inherited `/dev/null` stdin would
 * signal EOF immediately and make the proxy exit right after binding.
 */
export function startUnixTestProxy(
  dir: string,
  opts: { allowHosts?: string[]; blockHosts?: string[] } = {},
): { port: number; proxyProcess: ChildProcess } {
  const proxyPath = findUnixTestProxyBinary();
  const readyFile = path.join(dir, 'unix-proxy-ready.txt');

  const args: string[] = ['--ready-file', readyFile, '--bind-address', '127.0.0.1'];
  for (const host of opts.allowHosts ?? []) {
    args.push('--allow-host', host);
  }
  for (const host of opts.blockHosts ?? []) {
    args.push('--block-host', host);
  }

  // stdin must stay open (piped, held by this process) so the proxy's
  // stdin-EOF parent-death watcher only fires when the test process exits;
  // `stdio: 'ignore'` would give it a `/dev/null` stdin that EOFs instantly.
  const proxyProcess = spawn(proxyPath, args, { stdio: ['pipe', 'ignore', 'ignore'] });

  const deadline = Date.now() + 15000;
  while (!fs.existsSync(readyFile) && Date.now() < deadline) {
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 100);
  }

  if (!fs.existsSync(readyFile)) {
    proxyProcess.kill('SIGTERM');
    throw new Error('unix-test-proxy did not write ready file within 15 seconds');
  }

  const portStr = fs.readFileSync(readyFile, 'utf-8').trim();
  const port = parseInt(portStr, 10);
  if (isNaN(port) || port <= 0) {
    proxyProcess.kill('SIGTERM');
    throw new Error(`Invalid port in ready file: ${portStr}`);
  }

  return { port, proxyProcess };
}
