import * as os from 'os';
import * as fs from 'fs';
import * as path from 'path';
import { performance } from 'node:perf_hooks';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';
import { Worker, type WorkerOptions } from 'node:worker_threads';
import {
  readPlatformSupportSnapshotJson,
  type PlatformSupportSnapshotJson,
} from './bindings/platform-support.js';
import {
  ContainmentBackend,
  IsolationTier,
  PlatformSupport,
  UiCapabilitySupport,
} from './types.js';
import { diagLog } from './diagnostic.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
// This module is emitted as ESM, so there is no ambient CommonJS `require`;
// synthesize one bound to this file's URL for `require.resolve`.
const require = createRequire(import.meta.url);

/**
 * Resolves the SDK package root directory.
 * Uses require.resolve to find the package.json (works when the SDK is installed
 * in node_modules, even if the consuming code is bundled by esbuild/webpack).
 * Falls back to __dirname for local development (monorepo layout).
 */
function getSdkPackageRoot(): string {
  try {
    return path.dirname(require.resolve('@microsoft/mxc-sdk/package.json'));
  } catch {
    // Fallback: __dirname is dist/, so parent is package root
    return path.join(__dirname, '..');
  }
}

const bwrapProbeScriptDirectory = fs.existsSync(
  path.join(__dirname, 'bwrap-probe-worker.js'),
)
  ? __dirname
  : path.join(getSdkPackageRoot(), 'dist');
let wxcExecutableCache: { binDir: string | undefined; executable: string } | undefined;
let wxcExecutableVerifier = verifyWxcExecutable;

const KNOWN_BACKENDS: readonly ContainmentBackend[] = [
  'processcontainer',
  'windows_sandbox',
  'wslc',
  'lxc',
  'microvm',
  'hyperlight',
  'seatbelt',
  'isolation_session',
  'bubblewrap',
];
const KNOWN_TIERS: readonly IsolationTier[] = ['base-container', 'appcontainer-bfs', 'appcontainer-dacl'];

/**
 * Get platform support information.
 *
 * This projects the native host-services exports onto the SDK's existing
 * `PlatformSupport` shape. `availableMethods`, Linux `unavailableReasons`
 * and `bubblewrapNetwork`, and the Windows `isolationTier` are preserved.
 * The narrower FFI surface does not currently expose `isolationWarnings` or
 * `uiCapabilities`, so those fields remain omitted.
 *
 * The result is cached for the lifetime of the SDK module — the underlying
 * machine state is not expected to change at runtime.
 *
 * @returns Platform support details including available sandboxing methods
 */
export function getPlatformSupport(): PlatformSupport {
  if (cachedSupport !== null) {
    return cachedSupport;
  }
  const support = computeSupport();
  cachedSupport = support;
  return support;
}

let cachedSupport: PlatformSupport | null = null;

/** @internal Test-only: clear the cached PlatformSupport. */
export function _resetPlatformSupportCache(): void {
  cachedSupport = null;
}

type PlatformSupportSnapshotReader = () => PlatformSupportSnapshotJson;

let platformSupportSnapshotReader: PlatformSupportSnapshotReader = readPlatformSupportSnapshotJson;

/** @internal Test-only: override native host-services reads. */
export function _setPlatformSupportSnapshotReader(reader: PlatformSupportSnapshotReader | null): void {
  platformSupportSnapshotReader = reader ?? readPlatformSupportSnapshotJson;
}

interface NativePlatformSupportPayload {
  isSupported: boolean;
  reason?: string;
  availableMethods: string[];
}

interface NativeAvailableBackendPayload {
  backend: string;
  tier?: string;
  capabilities: string[];
  warnings: string[];
}

function isContainmentBackend(value: unknown): value is ContainmentBackend {
  return typeof value === 'string' && (KNOWN_BACKENDS as readonly string[]).includes(value);
}

function isIsolationTier(value: unknown): value is IsolationTier {
  return typeof value === 'string' && (KNOWN_TIERS as readonly string[]).includes(value);
}

function parsePlatformSupportPayload(json: string): NativePlatformSupportPayload {
  const parsed: unknown = JSON.parse(json);
  if (parsed === null || typeof parsed !== 'object') {
    throw new Error('mxc_platform_support_json returned malformed JSON');
  }
  const value = parsed as Record<string, unknown>;
  if (
    typeof value.isSupported !== 'boolean'
    || !Array.isArray(value.availableMethods)
    || value.availableMethods.some((method) => typeof method !== 'string')
  ) {
    throw new Error('mxc_platform_support_json returned malformed JSON');
  }
  return {
    isSupported: value.isSupported,
    reason: typeof value.reason === 'string' ? value.reason : undefined,
    availableMethods: value.availableMethods,
  };
}

function parseAvailableBackendsPayload(json: string): NativeAvailableBackendPayload[] {
  const parsed: unknown = JSON.parse(json);
  if (!Array.isArray(parsed)) {
    throw new Error('mxc_available_backends_json returned malformed JSON');
  }
  return parsed.map((entry) => {
    if (entry === null || typeof entry !== 'object') {
      throw new Error('mxc_available_backends_json returned malformed JSON');
    }
    const value = entry as Record<string, unknown>;
    if (typeof value.backend !== 'string') {
      throw new Error('mxc_available_backends_json returned malformed JSON');
    }
    if (value.tier !== undefined && !isIsolationTier(value.tier)) {
      throw new Error('mxc_available_backends_json returned malformed JSON');
    }
    const capabilities = Array.isArray(value.capabilities)
      ? value.capabilities.filter((item): item is string => typeof item === 'string')
      : [];
    const warnings = Array.isArray(value.warnings)
      ? value.warnings.filter((item): item is string => typeof item === 'string')
      : [];
    return {
      backend: value.backend,
      tier: value.tier,
      capabilities,
      warnings,
    };
  });
}

function mergeAvailableMethods(
  platformSupportMethods: readonly string[],
  availableBackends: readonly NativeAvailableBackendPayload[],
): ContainmentBackend[] {
  const methods: ContainmentBackend[] = [];
  for (const method of [
    ...availableBackends.map((entry) => entry.backend),
    ...platformSupportMethods,
  ]) {
    if (isContainmentBackend(method) && !methods.includes(method)) {
      methods.push(method);
    }
  }
  return methods;
}

function linuxUnavailableReasons(
  availableMethods: readonly ContainmentBackend[],
  bubblewrapReason?: string,
): Partial<Record<ContainmentBackend, string>> | undefined {
  const reasons: Partial<Record<ContainmentBackend, string>> = {};
  if (!availableMethods.includes('lxc')) {
    reasons.lxc = 'LXC is not installed or not available on this system.';
  }
  if (!availableMethods.includes('bubblewrap')) {
    reasons.bubblewrap = bubblewrapReason
      ?? 'Bubblewrap (bwrap) is not installed or not available on this system.';
  }
  return Object.keys(reasons).length === 0 ? undefined : reasons;
}

function adaptPlatformSupport(snapshot: PlatformSupportSnapshotJson): PlatformSupport {
  const nativeSupport = parsePlatformSupportPayload(snapshot.platformSupportJson);
  const availableBackends = parseAvailableBackendsPayload(snapshot.availableBackendsJson);
  const availableMethods = mergeAvailableMethods(nativeSupport.availableMethods, availableBackends);
  const support: PlatformSupport = {
    isSupported: nativeSupport.isSupported || availableMethods.length > 0,
    availableMethods,
  };

  if (os.platform() === 'linux') {
    const unavailableReasons = linuxUnavailableReasons(availableMethods, nativeSupport.reason);
    if (unavailableReasons) {
      support.unavailableReasons = unavailableReasons;
    }
    const bubblewrap = availableBackends.find((entry) => entry.backend === 'bubblewrap');
    if (bubblewrap) {
      support.bubblewrapNetwork = bubblewrap.capabilities.includes('proxyEnforcement')
        ? { proxyEnforcement: 'supported', warnings: [] }
        : {
            proxyEnforcement: 'unsupported',
            warnings: bubblewrap.warnings.length > 0
              ? bubblewrap.warnings
              : ['proxy-only egress is not supported on this host'],
          };
    }
    if (!support.isSupported) {
      support.reason = nativeSupport.reason
        ? `Neither LXC nor Bubblewrap is available on this system (${nativeSupport.reason})`
        : 'Neither LXC nor Bubblewrap is available on this system.';
    }
  } else if (!support.isSupported) {
    support.reason = nativeSupport.reason ?? 'MXC is not supported on this platform';
  }

  const processContainer = availableBackends.find((entry) => entry.backend === 'processcontainer');
  if (isIsolationTier(processContainer?.tier)) {
    support.isolationTier = processContainer.tier;
  }
  return support;
}

function computeSupport(): PlatformSupport {
  try {
    return adaptPlatformSupport(platformSupportSnapshotReader());
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    platformDiagnosticLogger(`getPlatformSupport: native host-services probe failed — ${detail}`);
    return {
      isSupported: false,
      reason: detail,
      availableMethods: [],
    };
  }
}

let platformDiagnosticLogger: (message: string) => void = diagLog;

/** @internal Test-only: override platform-support diagnostic logging. */
export function _setPlatformDiagnosticLogger(fn: ((message: string) => void) | null): void {
  platformDiagnosticLogger = fn ?? diagLog;
}

/**
 * Minimum `bwrap` version the Bubblewrap backend supports, as
 * `[major, minor, patch]`.
 *
 * This is the oldest release that has **every** flag the Rust argument builder
 * emits. `--ro-bind-try` (deny-by-default baseline mounts) landed in bwrap
 * 0.3.1 and `--clearenv` (minimal sandbox environment) in 0.5.0, so
 * `--clearenv` sets the floor.
 *
 * Mirrors `MIN_BWRAP_VERSION` in
 * `src/backends/bubblewrap/common/src/bwrap_version.rs` — keep both in sync.
 */
const MIN_BWRAP_VERSION: readonly [number, number, number] = [0, 5, 0];
const MIN_BWRAP_VERSION_REASON = 'the sandbox uses `--clearenv`, added in bwrap 0.5.0';

/** Outcome of the Bubblewrap probe: available, or unavailable with a reason. */
type BubblewrapProbe = { available: true } | { available: false; reason: string };

/**
 * Raw result of running `bwrap --version`, normalized across the ways the call
 * can fail. Mirrors the cases the Rust `probe_bwrap` distinguishes.
 */
type BwrapVersionResult =
  | { kind: 'output'; stdout: string }
  | { kind: 'notFound' }
  | { kind: 'failed'; status: number | null; detail: string };

/**
 * How long to wait for `bwrap --version` before giving up.
 *
 * `getPlatformSupport()` is synchronous, so without a bound a `bwrap` that
 * hangs — a wrapper script on PATH, a binary on a stalled network mount —
 * would block the caller indefinitely. Printing a version string is
 * near-instant, so this is generous. This is the total wall-clock bound the
 * caller observes: the supervision layers run *inside* it.
 */
const BWRAP_VERSION_TIMEOUT_MS = 5000;
const BWRAP_VERSION_MAX_BUFFER_BYTES = 64 * 1024;
const BWRAP_HELPER_RESULT_BYTES = 1024 * 1024;
/**
 * Time reserved out of the caller's budget for the supervision layers to stop
 * the probe, publish a result, and hand it back.
 */
const BWRAP_PROBE_SUPERVISION_MARGIN_MS = 1500;

/**
 * Inline bootstrap for the packaged probe worker.
 *
 * The caller blocks in `Atomics.wait`, so an `error` event on the main-thread
 * Worker object cannot report a missing, corrupt, or throwing worker module in
 * time. This trusted bootstrap runs without a packaged asset, imports the real
 * worker, and publishes import/startup failures through the same shared result
 * buffer the worker uses for normal outcomes.
 */
const BWRAP_PROBE_WORKER_BOOTSTRAP = String.raw`
const { pathToFileURL } = require('node:url');
const { workerData } = require('node:worker_threads');

function publishStartupError(error) {
  const header = new Int32Array(workerData.shared, 0, 3);
  if (Atomics.load(header, 0) !== 0) return;
  const payload = new Uint8Array(workerData.shared, 12);
  const detail = error instanceof Error ? error.message : String(error);
  let encoded = Buffer.from(JSON.stringify({
    kind: 'spawnError',
    detail: 'probe worker failed to start: ' + detail,
  }));
  if (encoded.length > payload.length) {
    encoded = Buffer.from(JSON.stringify({
      kind: 'spawnError',
      detail: 'probe worker startup error exceeded its bound',
    }));
  }
  payload.set(encoded);
  Atomics.store(header, 1, encoded.length);
  if (Atomics.compareExchange(header, 0, 0, 1) === 0) {
    Atomics.notify(header, 0);
  }
}

function publishFatalStartupError(error) {
  publishStartupError(error);
}

process.once('uncaughtException', publishFatalStartupError);
process.once('unhandledRejection', publishFatalStartupError);
import(pathToFileURL(workerData.workerPath).href)
  .then(() => {
    process.removeListener('uncaughtException', publishFatalStartupError);
    process.removeListener('unhandledRejection', publishFatalStartupError);
  })
  .catch(publishStartupError);
`;

/**
 * Split the caller's budget into the probe deadline (how long `bwrap` itself
 * may run) and the worker's publish deadline, so the caller-visible wait never
 * exceeds `timeoutMs`. Budgets smaller than twice the margin split in half
 * rather than starving the probe.
 *
 * @internal Exported for unit tests.
 */
export function _bwrapProbeDeadlines(timeoutMs: number): {
  probeTimeoutMs: number;
  publishTimeoutMs: number;
} {
  const probeTimeoutMs = Math.max(
    1,
    Math.max(Math.ceil(timeoutMs / 2), timeoutMs - BWRAP_PROBE_SUPERVISION_MARGIN_MS),
  );
  const publishTimeoutMs = Math.max(
    probeTimeoutMs + 1,
    timeoutMs - Math.ceil((timeoutMs - probeTimeoutMs) / 2),
  );
  return { probeTimeoutMs, publishTimeoutMs };
}

function resolveBwrapProbeScript(fileName: string): string {
  return path.join(bwrapProbeScriptDirectory, fileName);
}

type BwrapProbeWorkerFactory = (fileName: string, options: WorkerOptions) => Worker;

const defaultBwrapProbeWorkerFactory: BwrapProbeWorkerFactory = (fileName, options) =>
  new Worker(fileName, options);

let bwrapProbeWorkerFactory = defaultBwrapProbeWorkerFactory;

/** @internal Test-only: replace worker construction to exercise setup deadlines. */
export function _setBwrapProbeWorkerFactory(factory: BwrapProbeWorkerFactory | null): void {
  bwrapProbeWorkerFactory = factory ?? defaultBwrapProbeWorkerFactory;
}

type BwrapHelperResult =
  | { kind: 'completed'; status: number | null; signal: string | null; stdout: string; stderr: string }
  | { kind: 'notFound' }
  | { kind: 'timeout' }
  | { kind: 'overflow' }
  | { kind: 'spawnError'; detail: string };

function parseBwrapHelperResult(output: Buffer | string | undefined): BwrapHelperResult | null {
  if (output === undefined || output.length === 0) return null;
  try {
    return JSON.parse(output.toString()) as BwrapHelperResult;
  } catch {
    return null;
  }
}

/** @internal Pure helper-result normalization for unit tests. */
export function _mapBwrapHelperResult(
  result: BwrapHelperResult,
  timeoutMs = BWRAP_VERSION_TIMEOUT_MS,
): BwrapVersionResult {
  switch (result.kind) {
    case 'notFound':
      return { kind: 'notFound' };
    case 'timeout':
      return { kind: 'failed', status: null, detail: `timed out after ${timeoutMs}ms` };
    case 'overflow':
      return {
        kind: 'failed',
        status: null,
        detail: `probe output exceeded the ${BWRAP_VERSION_MAX_BUFFER_BYTES}-byte cap`,
      };
    case 'spawnError':
      return { kind: 'failed', status: null, detail: result.detail };
    case 'completed':
      if (result.status !== 0) {
        return {
          kind: 'failed',
          status: result.status,
          detail: result.stderr.trim() || (result.signal ? `signal ${result.signal}` : ''),
        };
      }
      return { kind: 'output', stdout: result.stdout };
  }
}

/**
 * Run `bwrap --version` beneath a detached Node sentinel that anchors the
 * process group. A child helper performs asynchronous, bounded I/O; the
 * supervising worker holds the helper's bounded result until the anchor closes
 * after tearing down the sentinel-owned group.
 *
 * The probe and the worker run against deadlines derived from `timeoutMs`, so
 * this call returns within `timeoutMs` even when every inner layer stalls.
 *
 * @internal Exported for a real-subprocess regression test.
 */
export function _runBwrapVersionCommand(
  timeoutMs = BWRAP_VERSION_TIMEOUT_MS,
): BwrapVersionResult {
  const started = performance.now();
  const deadline = started + Math.max(0, timeoutMs);
  const shared = new SharedArrayBuffer(12 + BWRAP_HELPER_RESULT_BYTES);
  const header = new Int32Array(shared, 0, 3);
  const setupRemainingMs = Math.floor(deadline - performance.now());
  if (setupRemainingMs < 2) {
    return { kind: 'failed', status: null, detail: `timed out after ${timeoutMs}ms` };
  }
  const { probeTimeoutMs, publishTimeoutMs } = _bwrapProbeDeadlines(setupRemainingMs);
  let worker: Worker;
  try {
    worker = bwrapProbeWorkerFactory(BWRAP_PROBE_WORKER_BOOTSTRAP, {
      eval: true,
      workerData: {
        shared,
        workerPath: resolveBwrapProbeScript('bwrap-probe-worker.js'),
        anchorPath: resolveBwrapProbeScript('bwrap-probe-anchor.js'),
        helperPath: resolveBwrapProbeScript('bwrap-probe-helper.js'),
        probeTimeoutMs,
        publishTimeoutMs,
        outputLimit: BWRAP_VERSION_MAX_BUFFER_BYTES,
      },
    });
  } catch (err) {
    if (performance.now() >= deadline) {
      return { kind: 'failed', status: null, detail: `timed out after ${timeoutMs}ms` };
    }
    return {
      kind: 'failed',
      status: null,
      detail: err instanceof Error ? err.message : String(err),
    };
  }
  worker.on('error', (error) => {
    // The inline bootstrap and the worker's own protocol report recoverable
    // startup/runtime failures synchronously. This catches only catastrophic
    // worker failures that escaped both and avoids an unhandled event.
    platformDiagnosticLogger(`Bubblewrap probe worker failed: ${error.message}`);
  });
  const waitRemainingMs = Math.max(0, deadline - performance.now());
  const waitResult = Atomics.wait(header, 0, 0, waitRemainingMs);
  if (waitResult === 'timed-out') {
    if (Atomics.compareExchange(header, 0, 0, -1) === 0) {
      // The worker owns process cleanup. It may not have published the anchor
      // PID yet, so leave it alive to observe -1 and terminate the group
      // without exposing a stale PID to this process.
      worker.unref();
      return { kind: 'failed', status: null, detail: `timed out after ${timeoutMs}ms` };
    }
    // The worker published just as Atomics.wait timed out. Consume that result
    // instead of overwriting it with a timeout or signalling its former PID.
  }
  const length = Atomics.load(header, 1);
  const result = parseBwrapHelperResult(Buffer.from(shared, 12, length));
  // The worker owns the anchor's ChildProcess handle and must remain alive
  // long enough for libuv to reap it after process-group cleanup.
  worker.unref();
  return result
    ? _mapBwrapHelperResult(result, timeoutMs)
    : { kind: 'failed', status: null, detail: 'probe helper returned no result' };
}

/** Default runner, replaceable in unit tests via {@link _setBwrapVersionRunner}. */
function defaultBwrapVersionRunner(): BwrapVersionResult {
  return _runBwrapVersionCommand();
}

let bwrapVersionRunner: () => BwrapVersionResult = defaultBwrapVersionRunner;

/** @internal Test-only: override the `bwrap --version` runner. */
export function _setBwrapVersionRunner(fn: (() => BwrapVersionResult) | null): void {
  bwrapVersionRunner = fn ?? defaultBwrapVersionRunner;
}

/**
 * Parse the version out of a `bwrap --version` line such as
 * `"bubblewrap 0.11.2"`.
 *
 * Anchored on the `bubblewrap` package name, which is what makes unrecognized
 * output fail closed: without it any numeric token in arbitrary output (say
 * `"some other tool 999"`) would be read as a version and clear the
 * minimum-version gate.
 *
 * Lenient about what *surrounds* each number so distro-patched version strings
 * (`0.4.1-1`, a bare `0.6`) still resolve: the version token is split on `.`
 * and each of the (up to three) components contributes its leading digits.
 * Debian's `+really` marker is honored rather than ignored — see below.
 *
 * Strict about components that are *present but not numeric*: only a component
 * that is genuinely absent defaults to `0`, so `"0.6.invalid"` is rejected
 * rather than silently read as `0.6.0`.
 *
 * @internal Exported for unit tests.
 * @returns `[major, minor, patch]`, or `null` when the version cannot be determined.
 */
export function _parseBwrapVersion(output: string): [number, number, number] | null {
  // bwrap prints its PACKAGE_STRING, "bubblewrap <version>"; that leading name
  // has been stable since 0.1.0.
  const tokens = output.trim().split(/\s+/);
  if (tokens[0]?.toLowerCase() !== 'bubblewrap' || !tokens[1]) return null;
  // Debian's `+really` marker means the package ships the version that FOLLOWS
  // it, so `0.5.0+really0.4.1` is really 0.4.1 — which predates `--clearenv`
  // and must not clear the gate.
  const marker = tokens[1].lastIndexOf('+really');
  const token = marker === -1 ? tokens[1] : tokens[1].slice(marker + '+really'.length);
  const components: number[] = [];
  // Every component must be numeric, including ones past the patch: they are
  // not significant, but `0.5.0.invalid` is an unrecognized banner rather than
  // 0.5.0. Validating (rather than rejecting on count) keeps a distro
  // four-part build such as `0.6.0.1` working.
  for (const part of token.split('.')) {
    const digits = /^\d+/.exec(part);
    // Present but non-numeric: fail closed rather than guessing 0.
    if (!digits) return null;
    const value = parseInt(digits[0], 10);
    // Mirror the Rust parser's `u32`: a larger value is not something bwrap
    // could print, and accepting it would let this gate admit a banner the
    // backend's gate rejects.
    if (value > 0xffffffff) return null;
    components.push(value);
  }
  // Only a genuinely absent component defaults to 0, so "0.6" is 0.6.0.
  return [components[0], components[1] ?? 0, components[2] ?? 0];
}

/** Compare two `[major, minor, patch]` tuples lexicographically. */
function compareVersions(
  a: readonly [number, number, number],
  b: readonly [number, number, number],
): number {
  for (let i = 0; i < 3; i++) {
    if (a[i] !== b[i]) return a[i] - b[i];
  }
  return 0;
}

/**
 * Check whether Bubblewrap (bwrap) is installed *and* new enough.
 *
 * Presence on PATH is not sufficient: a `bwrap` older than
 * {@link MIN_BWRAP_VERSION} would reject flags the backend always emits and
 * fail at spawn time with an opaque "unknown option" error. Unparsable output
 * fails closed — without a version we cannot assert the required flags exist.
 *
 * Mirrors `probe_bwrap` in
 * `src/backends/bubblewrap/common/src/bwrap_version.rs`. A missing command is
 * distinct from observed process failures.
 *
 * @internal Exported for unit tests.
 */
export function _probeBubblewrap(): BubblewrapProbe {
  const minVersion = MIN_BWRAP_VERSION.join('.');
  const result = bwrapVersionRunner();

  if (result.kind === 'notFound') {
    return {
      available: false,
      reason:
        `Bubblewrap (bwrap) is not installed or not on PATH. ` +
        `Install it via your package manager (e.g., apt install bubblewrap). ` +
        `Version ${minVersion} or newer is required.`,
    };
  }
  if (result.kind === 'failed') {
    // This includes failures before PATH lookup completes, so do not claim
    // that a Bubblewrap executable was observed.
    const where =
      result.status === null ? 'failed without an exit status' : `exited with status ${result.status}`;
    const detail = result.detail ? `: ${result.detail}` : '';
    return {
      available: false,
      reason:
        `The Bubblewrap (bwrap) availability probe \`bwrap --version\` ${where}${detail}. ` +
        `Version ${minVersion} or newer is required; check PATH and the installation before using the Bubblewrap backend.`,
    };
  }

  const version = _parseBwrapVersion(result.stdout);
  if (!version) {
    return {
      available: false,
      reason:
        `Could not determine the Bubblewrap (bwrap) version: \`bwrap --version\` printed ` +
        `${JSON.stringify(result.stdout.trim())}. Version ${minVersion} or newer is required.`,
    };
  }
  if (compareVersions(version, MIN_BWRAP_VERSION) < 0) {
    return {
      available: false,
      reason:
        `Bubblewrap (bwrap) ${version.join('.')} is too old: version ${minVersion} or newer is required ` +
        `(${MIN_BWRAP_VERSION_REASON}). Upgrade the bubblewrap package.`,
    };
  }
  return { available: true };
}

/**
 * Check if the macOS sandbox is available. `/usr/bin/sandbox-exec` is part
 * of the macOS base install and present on every shipping version of macOS,
 * so this is effectively a sanity check for a corrupted install.
 */
function isSeatbeltAvailable(): boolean {
  try {
    return fs.existsSync('/usr/bin/sandbox-exec');
  } catch {
    return false;
  }
}

/**
 * Get the simplified architecture name used for SDK bin directory layout.
 * @returns 'arm64' or 'x64'
 */
function getSdkArch(): string {
  return os.arch() === 'arm64' ? 'arm64' : 'x64';
}

/**
 * Get the Rust target triple for the current machine architecture.
 * @returns The Rust target triple string
 */
function getRustTargetTriple(): string {
  const arch = os.arch();
  const platform = os.platform();
  if (platform === 'linux') {
    return arch === 'arm64' ? 'aarch64-unknown-linux-gnu' : 'x86_64-unknown-linux-gnu';
  }
  // Windows
  return arch === 'arm64' ? 'aarch64-pc-windows-msvc' : 'x86_64-pc-windows-msvc';
}

/**
 * Get the Rust target triple for the current Linux machine architecture.
 */
function getLinuxRustTargetTriple(): string {
  const arch = os.arch();
  switch (arch) {
    case 'arm64':
      return 'aarch64-unknown-linux-gnu';
    case 'x64':
    default:
      return 'x86_64-unknown-linux-gnu';
  }
}

/**
 * Get the Rust target triple for the current macOS machine architecture.
 */
function getDarwinRustTargetTriple(): string {
  const arch = os.arch();
  return arch === 'arm64' ? 'aarch64-apple-darwin' : 'x86_64-apple-darwin';
}

/**
 * Find the wxc-exec executable
 * Searches in common locations relative to the SDK package,
 * selecting the build matching the current machine architecture.
 * @returns Path to wxc-exec.exe if found, null otherwise
 */
export function findWxcExecutable(): string | null {
  const binDir = process.env.MXC_BIN_DIR;
  const overridePath = binDir
    ? path.join(binDir, getSdkArch(), 'wxc-exec.exe')
    : undefined;
  const cached = wxcExecutableCache;
  if (
    cached !== undefined
    && cached.binDir === binDir
    && (overridePath === undefined || cached.executable === overridePath)
    && wxcExecutableVerifier(cached.executable)
  ) {
    return cached.executable;
  }
  wxcExecutableCache = undefined;

  // Allow override for bundled deployments (debugging/testing)
  if (overridePath !== undefined) {
    if (wxcExecutableVerifier(overridePath)) {
      wxcExecutableCache = { binDir, executable: overridePath };
      return overridePath;
    }
  }

  const pkgRoot = getSdkPackageRoot();
  const targetTriple = getRustTargetTriple();
  const targetDir = path.join(pkgRoot, '..', '..', 'src', 'target');

  const possiblePaths = [
    // Bundled in the SDK package (e.g. when installed via npm)
    path.join(pkgRoot, 'bin', getSdkArch(), 'wxc-exec.exe'),
    // Architecture-specific release build output (monorepo dev)
    path.join(targetDir, targetTriple, 'release', 'wxc-exec.exe'),
    // Architecture-specific debug build output (monorepo dev)
    path.join(targetDir, targetTriple, 'debug', 'wxc-exec.exe'),
    // Fallback: default Cargo release build output (no explicit --target)
    path.join(targetDir, 'release', 'wxc-exec.exe'),
    // Fallback: default Cargo debug build output (no explicit --target)
    path.join(targetDir, 'debug', 'wxc-exec.exe'),
  ];

  for (const wxcPath of possiblePaths) {
    if (wxcExecutableVerifier(wxcPath)) {
      wxcExecutableCache = { binDir, executable: wxcPath };
      return wxcPath;
    }
  }

  return null;
}

/** @internal Test-only: clear the resolved executable path. */
export function _resetWxcExecutableCache(): void {
  wxcExecutableCache = undefined;
}

/** @internal Test-only: override executable verification. */
export function _setWxcExecutableVerifier(
  verifier: ((execPath: string) => boolean) | null,
): void {
  wxcExecutableVerifier = verifier ?? verifyWxcExecutable;
}

/**
 * Verify that an executable exists at the given path
 * @param execPath - Path to verify
 * @returns true if the executable exists and is a file, false otherwise
 */
function verifyExecutable(execPath: string): boolean {
  try {
    // Paths inside Electron's app.asar exist to fs but can't be executed
    if (execPath.includes('.asar')) {
      return false;
    }
    if (!fs.existsSync(execPath) || !fs.statSync(execPath).isFile()) {
      return false;
    }
    // On non-Windows platforms, also verify execute permission
    if (process.platform !== 'win32') {
      fs.accessSync(execPath, fs.constants.X_OK);
    }
    return true;
  } catch {
    return false;
  }
}

/**
 * Verify that a wxc-exec executable exists at the given path
 * @param wxcPath - Path to verify
 * @returns true if the executable exists and is a file, false otherwise
 */
function verifyWxcExecutable(wxcPath: string): boolean {
  return verifyExecutable(wxcPath);
}

/**
 * Find the lxc-exec executable on Linux
 * Searches in common locations relative to the SDK package.
 * @returns Path to lxc-exec if found, null otherwise
 */
export function findLxcExecutable(): string | null {
  // Allow override for bundled deployments (debugging/testing)
  if (process.env.MXC_BIN_DIR) {
    const overridePath = path.join(process.env.MXC_BIN_DIR, getSdkArch(), 'lxc-exec');
    if (verifyExecutable(overridePath)) {
      return overridePath;
    }
  }

  const pkgRoot = getSdkPackageRoot();
  const targetTriple = getLinuxRustTargetTriple();
  const targetDir = path.join(pkgRoot, '..', '..', 'src', 'target');

  const possiblePaths = [
    // Bundled in the SDK package
    path.join(pkgRoot, 'bin', getSdkArch(), 'lxc-exec'),
    // Architecture-specific release build
    path.join(targetDir, targetTriple, 'release', 'lxc-exec'),
    // Architecture-specific debug build
    path.join(targetDir, targetTriple, 'debug', 'lxc-exec'),
    // Default Cargo release build
    path.join(targetDir, 'release', 'lxc-exec'),
    // Default Cargo debug build
    path.join(targetDir, 'debug', 'lxc-exec'),
  ];

  for (const lxcPath of possiblePaths) {
    if (verifyExecutable(lxcPath)) {
      return lxcPath;
    }
  }

  return null;
}

/**
 * Find the mxc-exec-mac executable on macOS.
 * Searches in the SDK bin directory (npm install path) and Cargo build
 * output directories (monorepo dev path).
 * @returns Path to mxc-exec-mac if found, null otherwise
 */
export function findSeatbeltExecutable(): string | null {
  // Allow override for bundled deployments (debugging/testing)
  if (process.env.MXC_BIN_DIR) {
    const overridePath = path.join(process.env.MXC_BIN_DIR, getSdkArch(), 'mxc-exec-mac');
    if (verifyExecutable(overridePath)) {
      return overridePath;
    }
  }

  const targetTriple = getDarwinRustTargetTriple();
  const targetDir = path.join(__dirname, '..', '..', '..', 'src', 'target');

  const possiblePaths = [
    // Bundled in the SDK package
    path.join(__dirname, '..', 'bin', getSdkArch(), 'mxc-exec-mac'),
    // Architecture-specific release build
    path.join(targetDir, targetTriple, 'release', 'mxc-exec-mac'),
    // Architecture-specific debug build
    path.join(targetDir, targetTriple, 'debug', 'mxc-exec-mac'),
    // Default Cargo release build
    path.join(targetDir, 'release', 'mxc-exec-mac'),
    // Default Cargo debug build
    path.join(targetDir, 'debug', 'mxc-exec-mac'),
  ];

  for (const darwinPath of possiblePaths) {
    if (verifyExecutable(darwinPath)) {
      return darwinPath;
    }
  }

  return null;
}
