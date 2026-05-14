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
  new semver.SemVer('0.4.0-alpha'),
  new semver.SemVer('0.5.0-alpha'),
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
  'winhttp-proxy-shim.exe',
  'wxc-test-proxy.exe',
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
  'wslcsdk.dll',   // Only built with --with-wslc
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
 * Check whether the BaseContainer API(processmodel.dll) is likely available.
 * Mirrors the Rust-side probe in `BaseContainerRunner::load_api()`.
 */
function isBaseContainerApiPresent(): boolean {
  const dllPath = path.join(
    process.env.SystemRoot ?? 'C:\\Windows',
    'System32',
    'processmodel.dll',
  );
  return fs.existsSync(dllPath);
}

export enum DryRunExpectation {
  ValidationPass = 'validation_pass',
  ValidationFail = 'validation_fail',
}

const BASE_CONTAINER_MIN_VERSION = new semver.SemVer('0.5.0');

/** Returns true if the given schema version selects the BaseContainer backend. */
function isBaseContainerVersion(schemaVersion: semver.SemVer): boolean {
  return schemaVersion.major > BASE_CONTAINER_MIN_VERSION.major ||
    (schemaVersion.major === BASE_CONTAINER_MIN_VERSION.major &&
     schemaVersion.minor >= BASE_CONTAINER_MIN_VERSION.minor);
}

/** Returns the expected dry-run outcome for the given schema version on this platform. */
export function expectDryRunValidationPass(schemaVersion: semver.SemVer): DryRunExpectation {
  if (os.platform() !== 'win32') {
    return DryRunExpectation.ValidationPass;
  }
  if (isBaseContainerVersion(schemaVersion) && !isBaseContainerApiPresent()) {
    return DryRunExpectation.ValidationFail;
  }
  return DryRunExpectation.ValidationPass;
}

/** Assert that a dry-run result matches the expected outcome. */
export function assertDryRunResult(
  stdout: string,
  exitCode: number,
  expectation: DryRunExpectation,
  version: string,
): void {
  if (expectation === DryRunExpectation.ValidationPass) {
    assert.strictEqual(exitCode, 0, `[${version}] Expected exit 0 but got ${exitCode}`);
    assert.ok(stdout.includes('Dry run completed. Result: validation passed'), `[${version}] ${stdout}`);
  } else {
    assert.notStrictEqual(exitCode, 0, `[${version}] Expected non-zero exit for validation failure`);
    assert.ok(stdout.includes('Dry run completed. Result: validation failed'), `[${version}] ${stdout}`);
  }
}

// Environment / skip helpers

const skipOsDependentTests= process.env.MXC_SKIP_OS_BUILD_DEPENDENT_TESTS === '1';
export const sandboxSkipReason = skipOsDependentTests
  ? 'Skipped in CI (MXC_SKIP_OS_BUILD_DEPENDENT_TESTS)'
  : undefined;

export const isLinuxRoot = os.platform() === 'linux' && process.getuid?.() === 0;

// When MXC_DEBUG=true, integration tests pass { debug: true } to spawn options
// so wxc-exec / lxc-exec emit verbose output. Enable via pipeline parameter or locally.
const debugMode = process.env.MXC_DEBUG === 'true';
export const debugSpawnOptions = debugMode ? { debug: true } : {};

// Network test endpoint reachable from both CI (Azure DevOps agents block
// external traffic but allow Azure Artifacts feeds) and local builds.
export const NETWORK_TEST_URL =
  'https://pkgs.dev.azure.com/shine-oss/mxc/_packaging/MxcDependencies/npm/registry/@types/json-schema';

// TODO: Investigate LXC container networking on CI agents. Containers lack
// network bridge/NAT config on hosted Ubuntu runners, causing outbound
// requests to fail. Needs lxcbr0 bridge + IP forwarding + DNS setup.
// Set MXC_SKIP_LXC_NETWORK_TESTS=1 to skip network-dependent LXC tests.
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

