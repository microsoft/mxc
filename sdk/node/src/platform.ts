import * as os from 'os';
import * as fs from 'fs';
import * as path from 'path';
import { execSync, execFileSync } from 'child_process';
import { performance } from 'node:perf_hooks';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';
import { Worker, type WorkerOptions } from 'node:worker_threads';
import {
  BubblewrapNetworkSupport,
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
let windowsSandboxAvailableCache: boolean | undefined;

/**
 * Check if Windows Sandbox feature is enabled via DISM.
 * @returns true if the Containers-DisposableClientVM feature is enabled
 */
function isWindowsSandboxAvailable(): boolean {
  if (windowsSandboxAvailableCache !== undefined) {
    return windowsSandboxAvailableCache;
  }

  try {
    const output = execSync(
      'dism /online /get-featureinfo /featurename:Containers-DisposableClientVM',
      { encoding: 'utf-8', stdio: 'pipe', timeout: 10000 },
    );
    windowsSandboxAvailableCache = /State\s*:\s*Enabled/i.test(output);
  } catch {
    // `dism /online` typically requires elevation, so a non-elevated session
    // throws here and we can't distinguish "disabled" from "no permission".
    // Fall back to checking for the sandbox executable — Windows installs it
    // under System32 only when the Containers-DisposableClientVM feature is
    // enabled, and the path is readable without admin.
    const sandboxExe = path.join(
      process.env.SystemRoot || 'C:\\Windows',
      'System32',
      'WindowsSandbox.exe',
    );
    windowsSandboxAvailableCache = fs.existsSync(sandboxExe);
  }

  return windowsSandboxAvailableCache;
}

/**
 * Get platform support information.
 *
 * On Windows, this also invokes `wxc-exec --probe` to populate
 * `isolationTier`, the `isolationWarnings` array (if any), and portable UI
 * capability facts. On Linux, `unavailableReasons` contains per-backend
 * diagnostics for unavailable LXC or Bubblewrap backends, and — when
 * bubblewrap is available — `lxc-exec --available-backends` is invoked to
 * populate `bubblewrapNetwork`. macOS currently does not expose native probe
 * data. `uiCapabilities` is omitted outside Windows. The result is cached for
 * the lifetime of the SDK module — the underlying machine state is not
 * expected to change at runtime.
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

/**
 * Probe runner injection seam. Spawns `wxc-exec --probe` and returns
 * its stdout. Replaceable in unit tests via {@link _setProbeRunner}.
 */
type ProbeRunner = () => string;

let probeRunner: ProbeRunner = defaultProbeRunner;

/** @internal Test-only: override the probe runner. */
export function _setProbeRunner(runner: ProbeRunner | null): void {
  probeRunner = runner ?? defaultProbeRunner;
}

function defaultProbeRunner(): string {
  const wxcPath = findWxcExecutable();
  if (!wxcPath) {
    throw new Error('wxc-exec not found');
  }
  return execFileSync(wxcPath, ['--probe'], {
    timeout: 5000,
    encoding: 'utf-8',
    stdio: ['ignore', 'pipe', 'pipe'],
  });
}

function isValidTier(s: unknown): s is IsolationTier {
  return s === 'base-container' || s === 'appcontainer-bfs' || s === 'appcontainer-dacl';
}

const UI_CAPABILITY_FIELDS: readonly (keyof UiCapabilitySupport)[] = [
  'canBlockClipboardRead',
  'canBlockClipboardWrite',
  'canBlockInputInjection',
  'canBlockInputMethodChanges',
  'canBlockExternalUiObjects',
  'canBlockGlobalUiNamespace',
  'canBlockDesktopSwitching',
  'canBlockLogoffOrShutdown',
  'canBlockSystemParameterChanges',
  'canBlockDisplaySettingsChanges',
];

function isUiCapabilitySupport(value: unknown): value is UiCapabilitySupport {
  if (!value || typeof value !== 'object') {
    return false;
  }
  const capabilities = value as Record<keyof UiCapabilitySupport, unknown>;
  return UI_CAPABILITY_FIELDS.every((field) => typeof capabilities[field] === 'boolean');
}

/**
 * Run the probe binary and merge its results into `support`: the isolation
 * tier, any warnings, portable UI capabilities, and the `isolation_session`
 * and `hyperlight` methods when the probe reports them available. On any
 * failure (binary missing, timeout, malformed JSON), the function
 * silently leaves those fields unset, so callers see the same contract as
 * pre-probe SDKs.
 */
function populateIsolationFromProbe(support: PlatformSupport): void {
  try {
    const stdout = probeRunner();
    const probe = JSON.parse(stdout);
    if (probe && typeof probe === 'object') {
      if (isValidTier(probe.tier)) {
        support.isolationTier = probe.tier;
      }
      if (Array.isArray(probe.warnings) && probe.warnings.length > 0) {
        const warnings = probe.warnings.filter((w: unknown): w is string => typeof w === 'string');
        if (warnings.length > 0) {
          support.isolationWarnings = warnings;
        }
      }
      const facts = probe.probes;
      if (facts && typeof facts === 'object') {
        if (isUiCapabilitySupport(facts.uiCapabilities)) {
          support.uiCapabilities = facts.uiCapabilities;
        }
        if (facts.isolationSessionAvailable === true) {
          support.availableMethods.push('isolation_session');
        }
        if (facts.hyperlightAvailable === true) {
          support.availableMethods.push('hyperlight');
        }
      }
    }
  } catch {
    // Graceful degradation: leave isolation fields unset.
  }
}

/**
 * Linux probe runner injection seam. Spawns `lxc-exec --available-backends` and
 * returns its stdout. Replaceable in unit tests via {@link _setLinuxProbeRunner}.
 */
type LinuxProbeRunner = () => string;

let linuxProbeRunner: LinuxProbeRunner = defaultLinuxProbeRunner;

const LINUX_PROBE_TIMEOUT_MS = 10_000;

/** @internal Test-only: override the Linux probe runner. */
export function _setLinuxProbeRunner(runner: LinuxProbeRunner | null): void {
  linuxProbeRunner = runner ?? defaultLinuxProbeRunner;
}

function defaultLinuxProbeRunner(): string {
  const lxcPath = findLxcExecutable();
  if (!lxcPath) {
    throw new Error('lxc-exec not found');
  }
  return execFileSync(lxcPath, ['--available-backends'], {
    // A backstop, not the real deadline: the native probe bounds its own
    // dependency walk. Killing it here is indistinguishable from an
    // unsupported host, so leave headroom rather than race it.
    timeout: LINUX_PROBE_TIMEOUT_MS,
    encoding: 'utf-8',
    stdio: ['ignore', 'pipe', 'pipe'],
  });
}

/**
 * Ask `lxc-exec --available-backends` whether this host can enforce Bubblewrap
 * proxy-only egress.
 *
 * Unlike the Windows isolation probe, this reports **fail closed**: a missing
 * binary, timeout, or malformed payload yields `'unsupported'` with the reason
 * as a warning, never an absent field. Reporting "unknown" as "supported"
 * would let a caller launch a 0.8 proxy policy the host cannot satisfy, and
 * that policy has no fallback.
 */
export function _probeBubblewrapNetwork(): BubblewrapNetworkSupport {
  let stdout: string;
  try {
    stdout = linuxProbeRunner();
  } catch (err) {
    const reason = err instanceof Error ? err.message : String(err);
    diagLog(`getPlatformSupport: bubblewrap network probe failed — ${reason}`);
    return { proxyEnforcement: 'unsupported', warnings: [`probe failed: ${reason}`] };
  }

  let backends: unknown;
  try {
    backends = JSON.parse(stdout);
  } catch (err) {
    const reason = err instanceof Error ? err.message : String(err);
    diagLog(`getPlatformSupport: bubblewrap network probe returned invalid JSON — ${reason}`);
    return { proxyEnforcement: 'unsupported', warnings: [`probe returned invalid JSON: ${reason}`] };
  }

  if (!Array.isArray(backends)) {
    return { proxyEnforcement: 'unsupported', warnings: ['probe returned an unexpected payload'] };
  }
  const entry = backends.find(
    (b: unknown): b is Record<string, unknown> =>
      !!b && typeof b === 'object' && (b as Record<string, unknown>).backend === 'bubblewrap',
  );
  if (!entry) {
    return { proxyEnforcement: 'unsupported', warnings: ['probe did not report bubblewrap'] };
  }

  const capabilities = Array.isArray(entry.capabilities) ? entry.capabilities : [];
  const warnings = Array.isArray(entry.warnings)
    ? entry.warnings.filter((w: unknown): w is string => typeof w === 'string')
    : [];
  if (capabilities.includes('proxyEnforcement')) {
    return { proxyEnforcement: 'supported', warnings: [] };
  }
  return {
    proxyEnforcement: 'unsupported',
    warnings: warnings.length > 0 ? warnings : ['proxy-only egress is not supported on this host'],
  };
}

function computeSupport(): PlatformSupport {
  const platform = os.platform();
  const support: PlatformSupport = { isSupported: false, reason: '', availableMethods: [] };

  // Non-Windows platforms do not currently have native probes, so fields that
  // depend on probe data (including uiCapabilities) stay omitted.
  if (platform === 'darwin') {
    // seatbelt is the only containment backend on macOS.
    // /usr/bin/sandbox-exec ships with every release of macOS so the check
    // is effectively just confirming we're on a supported OS.
    if (isSeatbeltAvailable()) {
      support.isSupported = true;
      support.availableMethods = ['seatbelt'];
    } else {
      support.reason = '/usr/bin/sandbox-exec not found; macOS install is incomplete';
    }
    return support;
  }

  if (platform === 'linux') {
    // LXC and Bubblewrap are both supported on Linux. Report whichever
    // are installed; callers pick via the containment field.
    const methods: ContainmentBackend[] = [];
    if (lxcAvailabilityProbe()) {
      methods.push('lxc');
    } else {
      support.unavailableReasons = {
        lxc: 'LXC is not installed or not available on this system.',
      };
    }
    const bubblewrap = _probeBubblewrap();
    if (bubblewrap.available) {
      methods.push('bubblewrap');
      support.bubblewrapNetwork = _probeBubblewrapNetwork();
    } else {
      support.unavailableReasons = {
        ...support.unavailableReasons,
        bubblewrap: bubblewrap.reason,
      };
      // Always surface why bwrap is unavailable. When LXC is present the
      // platform is still supported, so `reason` — documented as why the
      // platform is *not* supported — must stay unset, and the detail would
      // otherwise be dropped without the per-backend reason above.
      platformDiagnosticLogger(`getPlatformSupport: bubblewrap unavailable — ${bubblewrap.reason}`);
      if (methods.length === 0) {
        support.reason = `Neither LXC nor Bubblewrap is available on this system (${bubblewrap.reason})`;
      }
    }
    if (methods.length > 0) {
      support.isSupported = true;
      support.availableMethods = methods;
    }
    return support;
  }

  if (platform !== 'win32') {
    support.reason = 'MXC is not supported on this platform';
    return support;
  }

  support.isSupported = true;
  support.availableMethods = ['processcontainer'];
  if (isWindowsSandboxAvailable()) {
    support.availableMethods.push('windows_sandbox');
  }
  populateIsolationFromProbe(support);
  return support;
}

/**
 * Check if LXC is available on the system
 */
function defaultLxcAvailabilityProbe(): boolean {
  try {
    execSync('lxc-ls --version', { encoding: 'utf-8', stdio: 'pipe' });
    return true;
  } catch {
    return false;
  }
}

let lxcAvailabilityProbe = defaultLxcAvailabilityProbe;

/** @internal Test-only: override the LXC availability probe. */
export function _setLxcAvailabilityProbe(fn: (() => boolean) | null): void {
  lxcAvailabilityProbe = fn ?? defaultLxcAvailabilityProbe;
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
  // Allow override for bundled deployments (debugging/testing)
  if (process.env.MXC_BIN_DIR) {
    const overridePath = path.join(process.env.MXC_BIN_DIR, getSdkArch(), 'wxc-exec.exe');
    if (verifyWxcExecutable(overridePath)) {
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
    if (verifyWxcExecutable(wxcPath)) {
      return wxcPath;
    }
  }

  return null;
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
