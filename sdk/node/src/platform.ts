import * as os from 'os';
import * as fs from 'fs';
import * as path from 'path';
import { execSync, execFileSync } from 'child_process';
import { fileURLToPath } from 'node:url';
import { ContainmentBackend, IsolationTier, PlatformSupport, UiCapabilitySupport } from './types.js';
import { diagLog } from './diagnostic.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

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

/**
 * Query Windows Registry for a value
 * @param key - Registry key path (e.g., "HKLM\\Software\\...")
 * @param valueName - Name of the value to query
 * @returns The registry value as a string, or null if not found
 */
function queryWindowsRegistry(key: string, valueName: string): string | null {
  try {
    const command = `reg query "${key}" /v "${valueName}"`;
    const output = execSync(command, { encoding: 'utf-8', stdio: 'pipe' });

    // Parse output - format is:
    // HKEY_LOCAL_MACHINE\...
    //     ValueName    REG_SZ    Value
    const lines = output.split('\n');
    for (const line of lines) {
      if (line.includes(valueName)) {
        // Extract value after REG_SZ or REG_DWORD
        const match = line.match(/REG_\w+\s+(.+)/);
        if (match) {
          return match[1].trim();
        }
      }
    }
    return null;
  } catch {
    return null;
  }
}

/**
 * Result of querying the host's Windows build number, or `null` when the
 * registry values are missing or unparseable.
 */
type WindowsBuild = { major: number; minor: number } | null;

/**
 * Default implementation that reads `CurrentBuild` / `UBR` from the
 * registry. Replaceable via {@link _setWindowsBuildQuery} in tests so we
 * can exercise the IsolationSession version gate deterministically.
 */
function defaultWindowsBuildQuery(): WindowsBuild {
  const registryPath = 'HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion';
  const currentBuild = queryWindowsRegistry(registryPath, 'CurrentBuild');
  if (!currentBuild) {
    return null;
  }
  const major = parseInt(currentBuild, 10);
  if (isNaN(major)) {
    return null;
  }
  // `UBR` is only needed for the IsolationSession minor-build gate, so an
  // unreadable revision degrades to 0 rather than discarding `CurrentBuild` —
  // otherwise a missing value would silently bypass the processcontainer
  // build floor.
  const minor = Number(queryWindowsRegistry(registryPath, 'UBR'));
  return { major, minor: isNaN(minor) ? 0 : minor };
}

let windowsBuildQuery: () => WindowsBuild = defaultWindowsBuildQuery;

/** @internal Test-only: override the Windows build lookup. */
export function _setWindowsBuildQuery(fn: (() => WindowsBuild) | null): void {
  windowsBuildQuery = fn ?? defaultWindowsBuildQuery;
}

/**
 * Minimum Windows build the `processcontainer` backend supports — 26100
 * (Windows 11 24H2). This is the product floor documented in the README and in
 * `docs/process-container/os-version-support.md`.
 *
 * Mirrors `MIN_WINDOWS_BUILD` in `src/core/mxc_engine/src/platform.rs` — keep
 * both in sync.
 */
const MIN_PROCESSCONTAINER_BUILD = 26100;

/**
 * Check whether the host supports the IsolationSession backend.
 * Requires Windows Insider Preview build 26300.8553 or later.
 *
 * No internal cache — `getPlatformSupport` memoizes the full result, and
 * registry reads are cheap relative to the rest of the probe.
 */
function isIsoSessionSupported(): boolean {
  const build = windowsBuildQuery();
  if (!build) {
    return false;
  }

  // Pin to the Windows Insider Preview build that introduced IsolationSession
  // (26300.8553+). Other major builds are not yet supported.
  return build.major === 26300 && build.minor >= 8553;
}

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
 * capability facts. Linux and macOS currently do not expose native probe data,
 * so `uiCapabilities` is omitted on those platforms. The result is cached for
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
 * Run the probe binary and merge its results into `support`. On any
 * failure (binary missing, timeout, malformed JSON, unknown tier), the
 * function silently leaves `support.isolationTier` and
 * `support.isolationWarnings` unset — callers see the same contract as
 * pre-Phase-5 SDKs.
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
      }
    }
  } catch {
    // Graceful degradation: leave isolation fields unset.
  }
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
    if (isLxcAvailable()) methods.push('lxc');
    const bubblewrap = _probeBubblewrap();
    if (bubblewrap.available) {
      methods.push('bubblewrap');
    } else {
      // Always surface why bwrap is unavailable. When LXC is present the
      // platform is still supported, so `reason` — documented as why the
      // platform is *not* supported — must stay unset, and the detail would
      // otherwise be dropped with no way to diagnose the missing backend.
      diagLog(`getPlatformSupport: bubblewrap unavailable — ${bubblewrap.reason}`);
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

  // The host build is the real gate on Windows: below the product floor
  // `processcontainer` fails at spawn rather than at detection. An unreadable
  // registry leaves the build unknown, which is treated as modern so a
  // detection failure never declares a supported host unsupported.
  const build = windowsBuildQuery();
  const methods: ContainmentBackend[] = [];
  if (!build || build.major >= MIN_PROCESSCONTAINER_BUILD) {
    methods.push('processcontainer');
  }
  // Windows Sandbox has its own, lower floor, so a host below the
  // processcontainer floor may still have it. Both it and IsolationSession are
  // reported when present, but they are experimental-only backends reached by
  // explicit opt-in, so they cannot carry `isSupported` — that flag is what
  // guards the default `processcontainer` spawn.
  if (isWindowsSandboxAvailable()) {
    methods.push('windows_sandbox');
  }
  if (isIsoSessionSupported()) {
    methods.push('isolation_session');
  }
  support.availableMethods = methods;

  if (!methods.includes('processcontainer')) {
    const alternatives =
      methods.length > 0 ? ` (experimental backends available: ${methods.join(', ')})` : '';
    support.reason =
      `Windows build ${build?.major} is below ${MIN_PROCESSCONTAINER_BUILD}, ` +
      `the minimum supported build (Windows 11 24H2)${alternatives}`;
    return support;
  }

  support.isSupported = true;
  populateIsolationFromProbe(support);
  return support;
}

/**
 * Check if LXC is available on the system
 */
function isLxcAvailable(): boolean {
  try {
    execSync('lxc-ls --version', { encoding: 'utf-8', stdio: 'pipe' });
    return true;
  } catch {
    return false;
  }
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
 * Whether a `bwrap` candidate exists anywhere on `PATH`.
 *
 * Linux reports `ENOENT` both for a genuinely absent binary and for one that
 * exists but cannot be executed (a missing ELF interpreter or script shebang
 * target), so the spawn error alone cannot tell `notFound` from `failed`. A
 * candidate on `PATH` means the package is installed and the failure is a
 * broken install.
 */
function bwrapExistsOnPath(): boolean {
  const pathVar = process.env.PATH;
  if (!pathVar) return false;
  return pathVar
    .split(path.delimiter)
    .some((dir) => dir !== '' && fs.existsSync(path.join(dir, 'bwrap')));
}

/**
 * How long to wait for `bwrap --version` before giving up.
 *
 * `getPlatformSupport()` is synchronous, so without a bound a `bwrap` that
 * hangs — a wrapper script on PATH, a binary on a stalled network mount —
 * would block the caller indefinitely. Printing a version string is
 * near-instant, so this is generous.
 */
const BWRAP_VERSION_TIMEOUT_MS = 5000;

/**
 * Default runner for `bwrap --version`. Uses `execFileSync` rather than a
 * shell so a missing binary surfaces as `ENOENT` instead of the shell's
 * indistinguishable exit code 127 — that separation is what lets us report
 * "not installed" and "installed but broken" differently.
 *
 * Replaceable in unit tests via {@link _setBwrapVersionRunner}.
 */
function defaultBwrapVersionRunner(): BwrapVersionResult {
  try {
    return {
      kind: 'output',
      stdout: execFileSync('bwrap', ['--version'], {
        encoding: 'utf-8',
        stdio: 'pipe',
        timeout: BWRAP_VERSION_TIMEOUT_MS,
      }),
    };
  } catch (err) {
    const e = err as NodeJS.ErrnoException & {
      status?: number | null;
      stderr?: Buffer | string;
      killed?: boolean;
    };
    // `ENOENT` covers both an absent binary and a present-but-unusable one
    // (missing ELF interpreter / shebang target), so confirm the binary is
    // really absent before blaming the package manager.
    if (e.code === 'ENOENT' && !bwrapExistsOnPath()) {
      return { kind: 'notFound' };
    }
    // Timed out: the child was killed, so there is no meaningful exit status.
    if (e.code === 'ETIMEDOUT' || e.killed) {
      return {
        kind: 'failed',
        status: null,
        detail: `timed out after ${BWRAP_VERSION_TIMEOUT_MS}ms`,
      };
    }
    return {
      kind: 'failed',
      status: e.status ?? null,
      detail: e.stderr?.toString().trim() || e.message,
    };
  }
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
 * `src/backends/bubblewrap/common/src/bwrap_version.rs`, including the
 * distinction between a missing binary and a present-but-broken one.
 *
 * @internal Exported for unit tests.
 */
export function _probeBubblewrap(): BubblewrapProbe {
  const minVersion = MIN_BWRAP_VERSION.join('.');
  const result = bwrapVersionRunner();

  if (result.kind === 'notFound') {
    return {
      available: false,
      reason: `Bubblewrap (bwrap) is not installed or not on PATH; version ${minVersion} or newer is required`,
    };
  }
  if (result.kind === 'failed') {
    // Present but broken: do not send the user to their package manager for a
    // package they already have.
    // Covers both a spawn failure and termination by a signal, neither of
    // which yields an exit code.
    const where =
      result.status === null ? 'failed without an exit status' : `exited with status ${result.status}`;
    const detail = result.detail ? `: ${result.detail}` : '';
    return {
      available: false,
      reason: `Bubblewrap (bwrap) is present but \`bwrap --version\` ${where}${detail}; version ${minVersion} or newer is required`,
    };
  }

  const version = _parseBwrapVersion(result.stdout);
  if (!version) {
    return {
      available: false,
      reason: `could not determine the Bubblewrap (bwrap) version from ${JSON.stringify(result.stdout.trim())}; version ${minVersion} or newer is required`,
    };
  }
  if (compareVersions(version, MIN_BWRAP_VERSION) < 0) {
    return {
      available: false,
      reason: `Bubblewrap (bwrap) ${version.join('.')} is too old; version ${minVersion} or newer is required`,
    };
  }
  // A new enough `bwrap` still cannot sandbox if the host forbids it, and
  // `--version` never creates a namespace, so ask it to build a real one.
  const sandbox = bwrapSandboxRunner();
  if (!sandbox.ok) {
    return {
      available: false,
      reason: `Bubblewrap (bwrap) ${version.join('.')} is installed but cannot create a sandbox on this host: ${sandbox.detail}`,
    };
  }
  return { available: true };
}

/**
 * Arguments for a minimal end-to-end containment probe.
 *
 * `bwrap --version` only prints a banner — it never creates a namespace — so
 * it passes on hosts where unprivileged user namespaces are disabled
 * (`kernel.unprivileged_userns_clone=0`) or where AppArmor denies `bwrap`
 * (Ubuntu 23.10+), both of which then fail at every spawn.
 *
 * The shape mirrors a real run: the same namespaces the Bubblewrap backend
 * unshares, plus `--proc` / `--dev`, and `--clearenv` so the payload is
 * resolved through `execvp`'s built-in `/bin:/usr/bin` default rather than the
 * caller's `PATH`. Binds use `--ro-bind-try` on the few directories a shell
 * needs — binding `/` instead would make the probe fail on any host with an
 * awkward submount, since `bwrap` treats a failed submount remount as fatal.
 *
 * Kept in step with the engine's `BWRAP_PROBE_ARGS`
 * (`src/core/mxc_engine/src/platform.rs`), which is pinned against the
 * production argument builder by a unit test.
 */
const BWRAP_PROBE_ARGS = [
  '--unshare-user',
  '--unshare-pid',
  '--unshare-ipc',
  '--unshare-uts',
  '--unshare-net',
  '--ro-bind-try',
  '/bin',
  '/bin',
  '--ro-bind-try',
  '/usr/bin',
  '/usr/bin',
  '--ro-bind-try',
  '/lib',
  '/lib',
  '--ro-bind-try',
  '/lib64',
  '/lib64',
  '--ro-bind-try',
  '/usr/lib',
  '/usr/lib',
  '--ro-bind-try',
  '/usr/lib64',
  '/usr/lib64',
  '--proc',
  '/proc',
  '--dev',
  '/dev',
  '--clearenv',
  '--',
  'sh',
  '-c',
  'exit 0',
];

/** Outcome of the sandbox probe; `detail` is empty when `ok`. */
export type BubblewrapSandboxProbe = { ok: boolean; detail: string };

/**
 * Run {@link BWRAP_PROBE_ARGS}, reporting bwrap's own diagnostic on failure.
 *
 * Replaceable in unit tests via {@link _setBwrapSandboxRunner}, so the
 * version-gate tests can drive `_probeBubblewrap` on a host without `bwrap`.
 */
function defaultBwrapSandboxRunner(): BubblewrapSandboxProbe {
  try {
    execFileSync('bwrap', BWRAP_PROBE_ARGS, {
      stdio: ['ignore', 'ignore', 'pipe'],
      timeout: BWRAP_VERSION_TIMEOUT_MS,
    });
    return { ok: true, detail: '' };
  } catch (error) {
    return { ok: false, detail: bwrapFailureDetail(error) };
  }
}

let bwrapSandboxRunner: () => BubblewrapSandboxProbe = defaultBwrapSandboxRunner;

/** @internal Test-only: override the Bubblewrap sandbox probe. */
export function _setBwrapSandboxRunner(fn: (() => BubblewrapSandboxProbe) | null): void {
  bwrapSandboxRunner = fn ?? defaultBwrapSandboxRunner;
}

/** Reduce a failed bwrap run to a single length-capped line for a `reason`. */
function bwrapFailureDetail(error: unknown): string {
  const MAX_LEN = 200;
  const { stderr } = (error ?? {}) as { stderr?: Buffer | string };
  const line = (stderr?.toString() ?? '')
    .split('\n')
    .map((l) => l.trim())
    .find((l) => l.length > 0);
  if (!line) {
    return 'it failed with no diagnostic output';
  }
  // Spread so the cap counts code points and never splits a surrogate pair.
  const chars = [...line];
  return chars.length > MAX_LEN ? `${chars.slice(0, MAX_LEN).join('')}…` : line;
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
