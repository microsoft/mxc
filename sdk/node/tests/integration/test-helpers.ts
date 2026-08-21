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
import * as sdkNamespace from '@microsoft/mxc-sdk';
import {
  MxcError,
  deprovisionSandbox,
  provisionSandbox,
  type SandboxId,
  type StateAwareContainmentBackend,
} from '@microsoft/mxc-sdk';

const require = createRequire(import.meta.url);
export const sdk = sdkNamespace;

// Schema versions

export const supportedVersions = [
  new semver.SemVer('0.6.0-alpha'),
  new semver.SemVer('0.7.0-alpha'),
  new semver.SemVer('0.8.0-alpha'),
];

// SDK package location

/** Resolve the root directoryof the installed @microsoft/mxc-sdk package. */
function getSdkPackageRoot(): string {
  const sdkPkg = require.resolve('@microsoft/mxc-sdk/package.json');
  return path.dirname(sdkPkg);
}

/** Return the SDK bin directory for the current architecture. */
export function getSdkBinDir(): string {
  const arch = os.arch() === 'arm64' ? 'arm64' : 'x64';
  return path.join(getSdkPackageRoot(), 'bin', arch);
}

// Expected package binaries

export const EXPECTED_WINDOWS_BINARIES = [
  'wxc-exec.exe',
  'plm.exe',
  'wxc-host-prep.exe',
  'winhttp-proxy-shim.exe',
  'wxc-test-proxy.exe',
  'wxc-windows-sandbox-daemon.exe',
  'wxc-windows-sandbox-guest.exe',
  'mxc-diagnostic-console.exe',
];

export const EXPECTED_LINUX_BINARIES = [
  'lxc-exec',
  'unix-test-proxy',
];

export const EXPECTED_MACOS_BINARIES = [
  'mxc-exec-mac',
  'unix-test-proxy',
];

// Binaries that are optional (feature-gated or only present in certain builds)
// but still legitimate if found in the package.
const OPTIONAL_BINARIES = [
  'wslcsdk.dll',          // Only built with --with-wslc
  'wxc-wslc-daemon.exe',  // Only built with --with-wslc
  'plm.exe',       // Permissive Learning Mode helper (Windows-only); staged
                   // only when the plm crate is included in the build.
  // Test-only binaries. The GitHub build artifact carries them so the
  // validation matrix can run the Windows suites from a downloaded artifact,
  // and the npm packager copies that whole artifact into bin/ — so they show
  // up here. They are not required: no SDK consumer needs them, and the ADO
  // package producer filters its artifact through signPattern, which
  // deliberately ships only product binaries.
  'wxc-ui-probe.exe',     // WinProcessContainer-Tests.ps1
  'wxc-test-driver.exe',  // run_test_configs.ps1
];

// Combined list of all known binaries across platforms. The npm package
// bundles both Windows and Linux binaries in the same arch directory, so
// the "no unexpected binaries" check must allow binaries from either OS.
export const ALL_KNOWN_BINARIES = [
  ...EXPECTED_WINDOWS_BINARIES,
  ...EXPECTED_LINUX_BINARIES,
  ...EXPECTED_MACOS_BINARIES,
  ...OPTIONAL_BINARIES,
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
    // Provision needs a backend-valid minimal config. IsolationSession requires
    // the unrestricted-network acknowledgment at provision (the container's
    // network cannot be filtered or denied); other backends take no required
    // provision config. Without this the probe would hit `policy_validation` on
    // an iso-capable host and rethrow it, breaking the suite at module load.
    //
    // The provision call is made per backend rather than once with a cast
    // config. `provisionSandbox`'s trailing parameters are a conditional tuple
    // keyed on the backend, and that conditional cannot be evaluated while `C`
    // is still an unresolved type parameter — so a single generic call cannot
    // be checked against it. Casting the config would silence that rather than
    // resolve it, and would also hide the day a new backend arrives with a
    // required provision config of its own. Switching on the backend resolves
    // `C` to a literal at each call, so each one is checked properly, and the
    // exhaustiveness guard below turns "a new backend was added" into a
    // compile error here instead of a wrong config at runtime.
    const sandboxId = await (async () => {
      // Widen once into a local of the concrete union, then switch on that.
      // Switching on `containment as StateAwareContainmentBackend` would not
      // narrow inside the arms — an assertion expression is not a narrowable
      // reference — which would in turn force the default arm to cast, and
      // `x as never` compiles unconditionally, leaving the guard unable to
      // ever fire. Binding the local first makes the narrowing real, so the
      // default arm genuinely reduces to `never` and adding a backend to the
      // union becomes a compile error here.
      const backend: StateAwareContainmentBackend = containment;
      switch (backend) {
        case 'isolation_session': {
          const result = await provisionSandbox(
            'isolation_session',
            { network: { defaultPolicy: 'allow', allowLocalNetwork: true } },
            { experimental: true },
          );
          return result.sandboxId;
        }
        case 'windows_sandbox': {
          const result = await provisionSandbox('windows_sandbox', undefined, {
            experimental: true,
          });
          return result.sandboxId;
        }
        case 'wslc': {
          const result = await provisionSandbox('wslc', undefined, {
            experimental: true,
          });
          return result.sandboxId;
        }
        // lxc is not experimental, and its provision config has required
        // members, so unlike the other arms it must pass one.
        case 'lxc': {
          const result = await provisionSandbox('lxc', {
            distribution: 'alpine',
            release: '3.23',
          });
          return result.sandboxId;
        }
        default: {
          const unhandled: never = backend;
          throw new Error(`probeStateAwareRuntime: unhandled backend ${String(unhandled)}`);
        }
      }
    })();
    await safeDeprovision(sandboxId);
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

/**
 * Probes whether `wxc-exec` was built WITH the IsolationSession feature,
 * independently of whether this host can activate a real session. Returns a
 * skip-reason string when the feature is absent, `undefined` when it is
 * present. Other errors propagate so genuine failures aren't masked as
 * "skipped."
 *
 * Deliberately narrower than `probeStateAwareRuntime`; the two are not
 * interchangeable. Policy refusals are raised by the dispatcher's `validate_*`
 * hooks, which run before any IsolationSession API call, so they ARE
 * exercisable on a host with no IsolationSession runtime support — gating them
 * on the runtime probe would silently drop that coverage on every such host,
 * which is most of them. They are NOT exercisable against a binary built
 * without the feature: dispatch fails with `unsupported_phase` before reaching
 * those hooks, so the assertions would fail rather than skip.
 *
 * The probe provisions nothing. It sends the empty config the backend must
 * refuse (IsolationSession requires the unrestricted-network acknowledgment at
 * provision), so a feature-present binary answers `policy_validation` having
 * created no session. That refusal is IsolationSession-specific, so this probe
 * is too — there is no generic form to write here.
 */
export async function probeIsolationSessionFeature(): Promise<string | undefined> {
  // The typed signature makes `network` required at provision, which is exactly
  // the refusal being provoked, so the config must be passed untyped.
  type UntypedProvision = (
    containment: 'isolation_session',
    config: unknown,
    options: unknown,
  ) => Promise<{ sandboxId: SandboxId<'isolation_session'> }>;
  const provisionUntyped = provisionSandbox as unknown as UntypedProvision;

  let provisioned: SandboxId<'isolation_session'>;
  try {
    const result = await provisionUntyped('isolation_session', {}, { experimental: true });
    provisioned = result.sandboxId;
  } catch (err) {
    if (err instanceof MxcError && err.code === 'unsupported_phase') {
      return 'wxc-exec lacks the isolation_session feature; rebuild with `--features isolation_session` (or `build.bat --with-isolation-session`) to run this test';
    }
    if (err instanceof MxcError && err.code === 'policy_validation') {
      return undefined;
    }
    throw err;
  }

  // Reaching here means the empty config was ACCEPTED — the "respect or refuse"
  // guarantee itself breaking, which is precisely what the gated tests assert.
  // Clean up the unexpected session and let them run so they report it.
  await safeDeprovision(provisioned);
  return undefined;
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

/** Locate wxc-test-proxy.exein the SDK package bin directory (package only, no local fallback). */
function findTestProxyBinary(): string {
  const binDir = getSdkBinDir();
  const proxyPath = path.join(binDir, 'wxc-test-proxy.exe');
  if (fs.existsSync(proxyPath)) {
    return proxyPath;
  }
  throw new Error(`wxc-test-proxy.exe not found at expected SDK package location: ${proxyPath}`);
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

/** Locate unix-test-proxy in the SDK package bin directory. */
function findUnixTestProxyBinary(): string {
  const binDir = getSdkBinDir();
  const proxyPath = path.join(binDir, 'unix-test-proxy');
  if (fs.existsSync(proxyPath)) {
    return proxyPath;
  }
  throw new Error(`unix-test-proxy not found at expected SDK package location: ${proxyPath}`);
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
