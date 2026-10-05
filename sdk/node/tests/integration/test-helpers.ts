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
import { pathToFileURL } from 'node:url';
import * as sdkV1Namespace from '@microsoft/mxc-sdk/v1';
import type { OneShotRequest } from './node_modules/@microsoft/mxc-sdk/dist/generated/v1_0_0/wire.js';
import type { ContainerConfig } from './node_modules/@microsoft/mxc-sdk/dist/v1/types.js';
import {
  MxcError,
} from '@microsoft/mxc-sdk/v1';
import {
  deprovisionContainer,
  provisionContainer,
  runAsync,
  type ContainerId,
  type Containment,
  type ContainerRequest,
  type LifecycleContainmentKind,
} from '@microsoft/mxc-sdk/v1';

export type ContainerRequestTestSettings =
  Omit<ContainerRequest, 'command'> & { command?: string };

export const isolationSessionNetwork = {
  egress: { default: 'allow' },
  ingress: { default: 'allow', hostLoopback: 'allow' },
} as const;

const require = createRequire(import.meta.url);

const { runOneShotJsonAsync } = await import(pathToFileURL(
  path.join(getSdkPackageRoot(), 'dist', 'bindings', 'run.js'),
).href) as typeof import('./node_modules/@microsoft/mxc-sdk/dist/bindings/run.js');
const { prepareOneShotRequest } = await import(pathToFileURL(
  path.join(getSdkPackageRoot(), 'dist', 'bindings', 'one-shot.js'),
).href) as typeof import('./node_modules/@microsoft/mxc-sdk/dist/bindings/one-shot.js');
const { createConfigFromRequest } = await import(pathToFileURL(
  path.join(getSdkPackageRoot(), 'dist', 'v1', 'container.js'),
).href) as typeof import('./node_modules/@microsoft/mxc-sdk/dist/v1/container.js');

/** Test-only exact-config path for backend contract tests; always calls mxc_ffi. */
export function runConfigForTest(
  config: ContainerConfig,
  options: { experimental?: boolean } = {},
) {
  const request: OneShotRequest = prepareOneShotRequest(config);
  return runOneShotJsonAsync(request, options.experimental === true);
}

export function createConfigForTest(
  request: ContainerRequestTestSettings,
  containment?: Containment['type'],
  containerName?: string,
): ContainerConfig {
  return createConfigFromRequest({
    ...request,
    command: request.command ?? '',
    ...(containment === undefined ? {} : { containment: { type: containment } }),
    ...(containerName === undefined ? {} : { containerName }),
  });
}

/** Exercise the public V1 buffered API for stable-request integration tests. */
export function runRequestForTest(
  command: string,
  request: ContainerRequestTestSettings,
  _options: Record<string, never> = {},
  workingDirectory?: string,
  containerName?: string,
) {
  return runAsync({
    ...request,
    command,
    ...(workingDirectory === undefined ? {} : { workingDirectory }),
    ...(containerName === undefined ? {} : { containerName }),
  });
}

export const sdk = {
  ...sdkV1Namespace,
  createConfigForTest,
  runRequestForTest,
};

// Schema versions

export const supportedVersions = [
  new semver.SemVer('1.0.0'),
];

// SDK package location

/** Resolve the root directory of the installed @microsoft/mxc-sdk package. */
export function getSdkPackageRoot(): string {
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
  'mxc_ffi.dll',
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
  'libmxc_ffi.so',
  'lxc-exec',
  'unix-test-proxy',
];

export const EXPECTED_MACOS_BINARIES = [
  'libmxc_ffi.dylib',
  'mxc-exec-mac',
  'unix-test-proxy',
];

// Binaries that are optional (feature-gated or only present in certain builds)
// but still legitimate if found in the package.
const OPTIONAL_BINARIES = [
  'wslcsdk.dll',          // Only built with --with-wslc
  'wxc-wslc-daemon.exe',  // Only built with --with-wslc
  'nanvixd.exe',           // Only built with --with-microvm
  'nanvix_rootfs.img',     // Only built with --with-microvm
  'python3.initrd',        // Only built with --with-microvm
  'plm.exe',       // Permissive Learning Mode helper (Windows-only); staged
                   // only when the plm crate is included in the build.
  // Test-only binaries. The GitHub build artifact carries them so the
  // validation matrix can run the Windows suites from a downloaded artifact,
  // and the npm packager copies that whole artifact into bin/ — so they show
  // up here. They are not required: no SDK consumer needs them, and the ADO
  // package producer filters its artifact through signPattern, which
  // deliberately ships only product binaries.
  'wxc-ui-probe.exe',     // run_processcontainer_ui_mitigations_test.ps1
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

export function stateAwareRuntimeUnavailable(error: unknown): boolean {
  return error instanceof MxcError &&
    (nativeFeatureAbsent(error) || addUserFeatureUnavailable(error));
}

function nativeFeatureAbsent(error: MxcError): boolean {
  return error.operation === undefined &&
    (error.code === 'backend_unavailable' || error.code === 'unsupported_phase');
}

function addUserFeatureUnavailable(error: MxcError): boolean {
  return error.code === 'backend_error' &&
    error.operation === 'IsoSessionOps.AddUserAsync2' &&
    String(error.remediation ?? '').includes('Feature_AgentSessionsBaseSupport');
}

/** Classify only failures that prevent feature-probe policy validation. */
export function isolationSessionFeatureSkipReason(error: unknown): string | undefined {
  if (!(error instanceof MxcError)) return undefined;
  if (addUserFeatureUnavailable(error)) {
    return 'isolation_session runtime unavailable on this host';
  }
  if (nativeFeatureAbsent(error)) {
    return 'mxc_ffi lacks the isolation_session feature; rebuild with `--features isolation_session` (or `build.bat --with-isolation-session`) to run this test';
  }
  return undefined;
}

/**
 * Wraps a state-aware SDK call, skipping the test (rather than failing) when
 * the native runtime reports a pre-API `backend_unavailable` or
 * `unsupported_phase`, or the known AddUser feature-gate failure. API-backed
 * failures with other causes propagate.
 */
export async function runOrSkipIfBackendUnavailable<T>(
  t: TestContext,
  label: string,
  fn: () => Promise<T>,
): Promise<T | undefined> {
  try {
    return await fn();
  } catch (err) {
    if (stateAwareRuntimeUnavailable(err)) {
      t.skip(`${label}: state-aware backend runtime unavailable on this host`);
      return undefined;
    }
    throw err;
  }
}

/** Deprovision a sandbox best-effort, swallowing errors so cleanup never masks the original failure. */
export async function safeDeprovision<C extends LifecycleContainmentKind>(
  sandboxId: ContainerId<C>,
): Promise<void> {
  try {
    await deprovisionContainer(sandboxId);
  } catch (err) {
    console.error(`Cleanup deprovision failed for ${sandboxId}: ${err}`);
  }
}

/**
 * Probes a state-aware backend's runtime by attempting a provision /
 * deprovision cycle. Returns a skip-reason string when the runtime is
 * unavailable before an API call (or the known AddUser feature-gate failure),
 * `undefined` when the backend can be exercised. Other errors propagate so
 * genuine failures aren't masked as "skipped." Intended for one-shot probing at
 * module load — pair the result with `describe`'s `{ skip }` option.
 */
export async function probeStateAwareRuntime<C extends LifecycleContainmentKind>(
  containment: C,
): Promise<string | undefined> {
  try {
    // Provision needs a backend-valid minimal config. IsolationSession requires
    // the directional all-allow network posture at provision (the container's
    // network cannot be filtered or denied); other backends take no required
    // provision config. Without this the probe would fail validation on an
    // iso-capable host and rethrow it, breaking the suite at module load.
    //
    // The provision call is made per backend rather than once with a cast
    // config. `provisionContainer`'s trailing parameters are a conditional tuple
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
      // Switching on `containment as LifecycleContainmentKind` would not
      // narrow inside the arms — an assertion expression is not a narrowable
      // reference — which would in turn force the default arm to cast, and
      // `x as never` compiles unconditionally, leaving the guard unable to
      // ever fire. Binding the local first makes the narrowing real, so the
      // default arm genuinely reduces to `never` and adding a backend to the
      // union becomes a compile error here.
      const backend: LifecycleContainmentKind = containment;
      switch (backend) {
        case 'isolation_session': {
          const result = await provisionContainer(
            { containment: 'isolation_session', network: isolationSessionNetwork },
          );
          return result.containerId;
        }
        case 'wslc': {
          const result = await provisionContainer({ containment: 'wslc' });
          return result.containerId;
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
    if (stateAwareRuntimeUnavailable(err)) {
      return `${containment} runtime unavailable on this host`;
    }
    throw err;
  }
}

/**
 * Probes whether `mxc_ffi` was built WITH the IsolationSession feature,
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
 * without the feature: dispatch fails with `unsupported_phase` or a pre-API
 * `backend_unavailable` before reaching those hooks, so the assertions would
 * fail rather than skip. An API-backed `backend_unavailable` carries
 * `operation` and must propagate rather than masquerade as a missing feature.
 *
 * The probe provisions nothing. It sends a structurally valid request with an
 * oversized appId that the backend must refuse before touching the OS, so a
 * feature-present binary answers `policy_validation` having created no
 * session. That refusal is IsolationSession-specific, so this probe is too —
 * there is no generic form to write here.
 */
export async function probeIsolationSessionFeature(): Promise<string | undefined> {
  let provisioned: ContainerId<'isolation_session'>;
  try {
    const result = await provisionContainer(
      { containment: 'isolation_session', network: isolationSessionNetwork, appId: 'x'.repeat(257) },
    );
    provisioned = result.containerId;
  } catch (err) {
    const skipReason = isolationSessionFeatureSkipReason(err);
    if (skipReason !== undefined) return skipReason;

    if (err instanceof MxcError && err.code === 'policy_validation') {
      return undefined;
    }
    throw err;
  }

  // Reaching here means the invalid appId was ACCEPTED — the "respect or
  // refuse" guarantee itself breaking, which is precisely what the gated tests
  // assert.
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
export function withToolPaths(
  request: ContainerRequestTestSettings,
): ContainerRequestTestSettings {
  const toolsPolicy = sdk.policy.filesystem.getAvailableToolsPolicy(process.env);
  const filesystem = { ...request.filesystem };
  const merged: ContainerRequestTestSettings = { ...request, filesystem };

  const extraReadwrite: string[] = [];
  if (_python.prefix) {
    extraReadwrite.push(_python.prefix);
  }

  if (toolsPolicy.readonlyPaths.length > 0) {
    filesystem.readonlyPaths = [
      ...(filesystem.readonlyPaths ?? []),
      ...toolsPolicy.readonlyPaths,
    ];
  }
  if (toolsPolicy.readwritePaths.length > 0 || extraReadwrite.length > 0) {
    filesystem.readwritePaths = [
      ...(filesystem.readwritePaths ?? []),
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
