import * as os from 'os';
import * as fs from 'fs';
import * as path from 'path';
import { execSync, execFileSync } from 'child_process';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';
import { ContainmentBackend, IsolationTier, PlatformSupport, UiCapabilitySupport } from './types.js';
import { diagLog } from './diagnostic.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ESM-safe `require` for resolving the optional per-platform binary packages.
// Created lazily by getSdkRequire() so a bundler that rewrites `import.meta.url`
// cannot crash module load.

/**
 * Resolves the SDK package root directory.
 * Uses require.resolve to find the package.json (works when the SDK is installed
 * in node_modules, even if the consuming code is bundled by esbuild/webpack).
 * Falls back to __dirname for local development (monorepo layout).
 */
// ESM-safe `require`, created lazily inside a guard. A bundler (Webpack/Vite)
// that rewrites `import.meta.url` into a value `createRequire` rejects must not
// crash module load — we cache the failure and fall back to the legacy/dev
// paths. `undefined` = not yet attempted, `null` = attempted and unavailable.
let cachedSdkRequire: NodeRequire | null | undefined;
// Test seam: `undefined` = use the real lazy require; `null` = force "no require"
// (simulate a bundled/CJS consumer); a function = use it.
let sdkRequireOverride: NodeRequire | null | undefined;

function getSdkRequire(): NodeRequire | null {
  if (sdkRequireOverride !== undefined) {
    return sdkRequireOverride;
  }
  if (cachedSdkRequire === undefined) {
  try {
      cachedSdkRequire = createRequire(import.meta.url);
  } catch {
      cachedSdkRequire = null;
    }
  }
  return cachedSdkRequire;
}

/**
 * @internal Test-only: override the ESM require (or force it absent with `null`).
 * Pass `undefined` to restore the real lazy require; also resets the cache so
 * resolver tests aren't order-dependent.
 */
export function _setSdkRequire(req: NodeRequire | null | undefined): void {
  sdkRequireOverride = req;
  cachedSdkRequire = undefined;
}

let sdkPackageRootOverride: string | undefined;

/** @internal Test-only: override the resolved SDK package root. */
export function _setSdkPackageRoot(dir: string | null | undefined): void {
  sdkPackageRootOverride = dir ?? undefined;
}

/**
 * Resolves the SDK package root directory.
 * Uses the ESM-safe `getSdkRequire()` to find the package.json (works when the SDK is
 * installed in node_modules, even if the consuming code is bundled by
 * esbuild/webpack). Falls back to __dirname for local development (monorepo
 * layout).
 */
function getSdkPackageRoot(): string {
  if (sdkPackageRootOverride !== undefined) {
    return sdkPackageRootOverride;
  }
  const req = getSdkRequire();
  if (req) {
    try {
      return path.dirname(req.resolve('@microsoft/mxc-sdk/package.json'));
    } catch {
      // fall through to the __dirname fallback below
    }
  }
    // Fallback: __dirname is dist/, so parent is package root
    return path.join(__dirname, '..');
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
  const ubrValue = queryWindowsRegistry(registryPath, 'UBR');
  if (!currentBuild || !ubrValue) {
    return null;
  }
  const major = parseInt(currentBuild, 10);
  const minor = Number(ubrValue);
  if (isNaN(major) || isNaN(minor)) {
    return null;
  }
  return { major, minor };
}

let windowsBuildQuery: () => WindowsBuild = defaultWindowsBuildQuery;

/** @internal Test-only: override the Windows build lookup. */
export function _setWindowsBuildQuery(fn: (() => WindowsBuild) | null): void {
  windowsBuildQuery = fn ?? defaultWindowsBuildQuery;
}

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
  const platform = hostId().platform;
  const support: PlatformSupport = { isSupported: false, reason: '', availableMethods: [] };

  // Reject (platform, arch) tuples MXC ships no binary for — most importantly
  // Intel macOS (darwin-x64) and 32-bit/other archs. Without this gate the SDK
  // would report "supported" and then synthesize a platform-package name that
  // 404s on the registry.
  if (!isSupportedPlatformTuple()) {
    support.reason =
      `${platform}-${getSdkArch()} is not a supported MXC target. Supported ` +
      `targets are win32/linux (x64, arm64) and macOS arm64; Intel macOS is not ` +
      `supported. Build from source, or pass an explicit executablePath, or set ` +
      `both skipPlatformCheck and MXC_BIN_DIR.`;
    return support;
  }

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

  support.isSupported = true;
  support.availableMethods = ['processcontainer'];
  if (isWindowsSandboxAvailable()) {
    support.availableMethods.push('windows_sandbox');
  }
  if (isIsoSessionSupported()) {
    support.availableMethods.push('isolation_session');
  }
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
 * Host (platform, arch) identity. Overridable in tests via {@link _setHostId} so
 * non-host tuples (e.g. Intel macOS from a Windows CI box) can be exercised
 * deterministically.
 */
interface HostId {
  platform: NodeJS.Platform;
  arch: string;
}
let hostIdOverride: HostId | undefined;
function hostId(): HostId {
  return hostIdOverride ?? { platform: process.platform, arch: os.arch() };
}
/** @internal Test-only: override the detected host (platform, arch). */
export function _setHostId(host: HostId | null): void {
  hostIdOverride = host ?? undefined;
}

/**
 * The (platform, arch) tuples MXC actually ships a native binary for. Exported
 * as the single source of truth so the packaging tests can assert the on-disk
 * `platform-packages/*` set equals this set in both directions (a tuple added
 * here without a directory — or a directory deleted — must fail a test rather
 * than crash at runtime loading a missing package).
 */
export const SUPPORTED_TUPLES: ReadonlySet<string> = new Set([
  'win32-x64',
  'win32-arm64',
  'linux-x64',
  'linux-arm64',
  'darwin-arm64',
]);

/**
 * Simplified architecture label used in platform-package names and the
 * `MXC_BIN_DIR` layout. `x64`/`arm64` pass through; any other arch is returned
 * as-is so it forms a package name that intentionally does not exist (and is
 * rejected by {@link isSupportedPlatformTuple}).
 */
function getSdkArch(): string {
  const arch = hostId().arch;
  return arch === 'arm64' ? 'arm64' : arch === 'x64' ? 'x64' : arch;
}

/**
 * True when the host (platform, arch) tuple is one MXC ships a binary for. The
 * shipped set is win32/linux × x64/arm64 plus darwin-arm64. `darwin-x64` (Intel
 * macOS) and any 32-bit/other arch are **not** supported — npm publishes no
 * package for them, so callers must give an accurate "unsupported" message
 * rather than synthesize a package name that 404s.
 */
export function isSupportedPlatformTuple(
  platform: NodeJS.Platform = hostId().platform,
  arch: string = getSdkArch(),
): boolean {
  return SUPPORTED_TUPLES.has(`${platform}-${arch}`);
}

/**
 * Executor binary filename for the given OS (defaults to the host). Single
 * source of truth for the per-platform binary names, shared by discovery and
 * the missing-binary error message.
 */
export function getExecutableBinaryName(platform: NodeJS.Platform = hostId().platform): string {
  if (platform === 'linux') return 'lxc-exec';
  if (platform === 'darwin') return 'mxc-exec-mac';
  return 'wxc-exec.exe';
}

/**
 * Name of the optional per-platform binary package for the current host, e.g.
 * `@microsoft/mxc-sdk-win32-x64`. Only meaningful for a supported tuple — guard
 * with {@link isSupportedPlatformTuple} before presenting it to a user.
 */
export function getPlatformPackageName(
  platform: NodeJS.Platform = hostId().platform,
  arch: string = getSdkArch(),
): string {
  return `@microsoft/mxc-sdk-${platform}-${arch}`;
}

/** Explicitly installed companion package containing the NanVix runtime. */
export const NANVIX_PACKAGE_NAME = '@microsoft/mxc-sdk-nanvix-win32-x64';

/** Version of the meta `@microsoft/mxc-sdk` package, or `null` if unreadable. */
function getSdkVersion(): string | null {
  try {
    const metaPkg = JSON.parse(
      fs.readFileSync(path.join(getSdkPackageRoot(), 'package.json'), 'utf8'),
    );
    return typeof metaPkg.version === 'string' ? metaPkg.version : null;
  } catch {
    return null;
  }
}

/**
 * Test seam override for the installed platform-package directory. `undefined`
 * (the default) uses real resolution; a string forces that directory; `null`
 * simulates the platform package being absent.
 */
let platformPackageDirOverride: string | null | undefined = undefined;

/** @internal Test-only: override platform-package directory resolution. */
export function _setPlatformPackageDir(dir: string | null | undefined): void {
  platformPackageDirOverride = dir;
}

let nanvixPackageDirOverride: string | null | undefined = undefined;

/** @internal Test-only: override NanVix companion-package resolution. */
export function _setNanvixPackageDir(dir: string | null | undefined): void {
  nanvixPackageDirOverride = dir;
}

let devModeOverride: boolean | undefined;

/** @internal Test-only: force dev (true) / production (false) resolution mode. */
export function _setDevMode(value: boolean | null): void {
  devModeOverride = value ?? undefined;
}

/**
 * True when running from a monorepo checkout, where freshly-built binaries under
 * `src/target` should win over an installed registry package. Detected by the
 * sibling Rust workspace manifest; always false in an installed `node_modules`
 * layout (where production fail-closed resolution applies).
 */
function isDevMode(): boolean {
  if (devModeOverride !== undefined) {
    return devModeOverride;
  }
  const root = getSdkPackageRoot();
  // An installed package lives under a `node_modules/` segment — always treat it
  // as production, regardless of any sibling marker. A planted/typosquatted
  // `../src/Cargo.toml` in the install tree must NOT be able to flip dev mode and
  // re-open the unvalidated dev fallbacks (the executor is the sandbox boundary).
  // Case-insensitive: Windows/macOS filesystems are case-insensitive, so a
  // `Node_Modules` segment must classify as production too.
  if (root.split(/[\\/]+/).some((seg) => seg.toLowerCase() === 'node_modules')) {
    return false;
  }
  return fs.existsSync(path.join(root, '..', '..', 'src', 'Cargo.toml'));
}

/**
 * Validate that the package.json resolved for the platform package is genuinely
 * our package at the expected version, guarding against an unrelated same-named
 * package resolved from an ancestor `node_modules` being executed as the sandbox
 * binary. Returns the package directory when valid, otherwise `null`. Exported
 * (test-only) so the identity/version guard can be exercised directly.
 */
function validateSdkPackageDir(pkgJsonPath: string, expectedName: string): string | null {
  try {
    const pkg = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf8'));
    if (pkg.name !== expectedName) {
      return null;
    }
    const expected = getSdkVersion();
    // Fail closed when the meta version is unreadable (e.g. a bundled consumer
    // with no co-located meta package.json): a name-only match is NOT enough to
    // trust a binary as the sandbox-enforcement boundary — a planted sibling
    // with the right name but arbitrary content would otherwise be accepted.
    // Such consumers must point the SDK at a trusted payload via MXC_BIN_DIR.
    // Optional deps are exact-pinned to the meta version, so require an exact match.
    if (expected === null || pkg.version !== expected) {
      return null;
    }
    return path.dirname(pkgJsonPath);
  } catch {
    return null;
  }
}

export function _validatePlatformPackageDir(pkgJsonPath: string): string | null {
  return validateSdkPackageDir(pkgJsonPath, getPlatformPackageName());
}

/** @internal Validate the installed NanVix companion package. */
export function _validateNanvixPackageDir(pkgJsonPath: string): string | null {
  return validateSdkPackageDir(pkgJsonPath, NANVIX_PACKAGE_NAME);
}

/**
 * The installed, identity/version-validated per-platform package directory, or
 * `null`. Honors the {@link _setPlatformPackageDir} test override. This is the
 * ONLY binary source trusted in a production (installed) layout.
 *
 * The platform package is an *optional* dependency of `@microsoft/mxc-sdk`, so
 * its absence (npm `os`/`cpu` skip, a silently-failed optional install, or a
 * monorepo dev checkout) must be tolerated without throwing.
 */
function installedPlatformPackageDir(): string | null {
  if (platformPackageDirOverride !== undefined) {
    return platformPackageDirOverride;
  }
  const name = getPlatformPackageName();
  const req = getSdkRequire();
  if (req) {
    try {
      return _validatePlatformPackageDir(req.resolve(`${name}/package.json`));
    } catch {
      // Not resolvable via node_modules require — fall through.
    }
  }
  // Fallback for bundled / transpiled-to-CJS consumers where `createRequire` is
  // unavailable (getSdkRequire() === null): resolve the sibling package relative
  // to the SDK root (node_modules/@scope/<root>/../../@scope/<pkg>) and run it
  // through the SAME identity/version validation so the fallback stays trusted.
  // This assumes a hoisted layout; a nested/conflicted install or a true bundler
  // `dist/` root (where the sibling isn't at `../../`, or the meta version is
  // unreadable so validation fails closed) resolves to null — such consumers
  // must point the SDK at a trusted payload via the explicit MXC_BIN_DIR override.
  try {
    const sibling = path.join(getSdkPackageRoot(), '..', '..', name, 'package.json');
    if (fs.existsSync(sibling)) {
      return _validatePlatformPackageDir(sibling);
    }
  } catch {
    // ignore — treat as absent
  }
  return null;
}

/** Identity/version-validated NanVix companion package, or `null`. */
function installedNanvixPackageDir(): string | null {
  if (nanvixPackageDirOverride !== undefined) {
    return nanvixPackageDirOverride;
  }
  const req = getSdkRequire();
  if (req) {
    try {
      return _validateNanvixPackageDir(
        req.resolve(`${NANVIX_PACKAGE_NAME}/package.json`),
      );
    } catch {
      // Not installed; fall through to the bundled-consumer sibling lookup.
    }
  }
  try {
    const sibling = path.join(
      getSdkPackageRoot(),
      '..',
      '..',
      NANVIX_PACKAGE_NAME,
      'package.json',
    );
    if (fs.existsSync(sibling)) {
      return _validateNanvixPackageDir(sibling);
    }
  } catch {
    // Treat an inaccessible or malformed package as absent.
  }
  return null;
}

/**
 * Rust target triple for a given (platform, arch), defaulting to the host.
 * Single source of truth for the triple mapping, shared by the binary
 * resolvers and the integration test harness. Exported so tests don't
 * re-derive (and drift from) this mapping.
 */
export function getRustTargetTriple(
  platform: NodeJS.Platform = hostId().platform,
  arch: string = hostId().arch,
): string {
  const a = arch === 'arm64' ? 'aarch64' : 'x86_64';
  if (platform === 'linux') return `${a}-unknown-linux-gnu`;
  if (platform === 'darwin') return `${a}-apple-darwin`;
  return `${a}-pc-windows-msvc`;
}

/**
 * Verify that an executable exists at the given path.
 * @param execPath - Path to verify
 * @returns true if the executable exists and is a file, false otherwise
 */
export function verifyExecutable(execPath: string): boolean {
  try {
    // Paths inside Electron's app.asar exist to fs but can't be executed
    if (execPath.includes('.asar')) {
      return false;
    }
    if (!fs.existsSync(execPath) || !fs.statSync(execPath).isFile()) {
      return false;
    }
    // On non-Windows hosts, also verify execute permission — but skip Windows
    // `.exe` binaries, which never carry POSIX exec bits. This matters when a
    // non-Windows host validates a Windows binary (cross-arch packaging/tests).
    if (process.platform !== 'win32' && !execPath.toLowerCase().endsWith('.exe')) {
      fs.accessSync(execPath, fs.constants.X_OK);
    }
    return true;
  } catch {
    return false;
  }
}

/**
 * Resolve an executor binary by name. Two modes:
 *
 * - **Production (installed) layout — fail closed.** The executor is the sandbox
 *   enforcement boundary, so only the `MXC_BIN_DIR` override and the
 *   identity/version-validated platform package are trusted. Unvalidated
 *   binaries in predictable paths near `node_modules` are never executed.
 * - **Dev (monorepo) layout.** Prefer freshly-built local binaries
 *   (`sdk/node/platform-packages/<os>-<arch>`, then `src/target`) over an installed
 *   registry package, so a local Rust build wins (and build failures aren't
 *   masked by a downloaded tarball).
 *
 * Returns the first path that verifies, or `null`.
 */
function resolveExecutable(binary: string, targetTriple: string): string | null {
  // 1. MXC_BIN_DIR override — honored in every mode; short-circuit immediately.
  const override = process.env.MXC_BIN_DIR;
  if (override) {
    const c = path.join(override, getSdkArch(), binary);
    if (verifyExecutable(c)) return c;
  }

  const installed = installedPlatformPackageDir();

  if (!isDevMode()) {
    // Production: trust ONLY the validated platform package.
    if (installed) {
      const c = path.join(installed, binary);
      if (verifyExecutable(c)) return c;
    }
    return null;
  }

  // Dev: prefer local builds, then fall back to the installed package.
  const sdkRoot = getSdkPackageRoot();
  const targetDir = path.join(sdkRoot, '..', '..', 'src', 'target');
  const candidates = [
    path.join(sdkRoot, 'platform-packages', `${hostId().platform}-${getSdkArch()}`, binary),
    path.join(targetDir, targetTriple, 'release', binary),
    path.join(targetDir, targetTriple, 'debug', binary),
    path.join(targetDir, 'release', binary),
    path.join(targetDir, 'debug', binary),
    ...(installed ? [path.join(installed, binary)] : []),
  ];
  for (const candidate of candidates) {
    if (verifyExecutable(candidate)) {
      return candidate;
    }
  }
  return null;
}

/**
 * Find the wxc-exec executable (Windows), preferring the per-platform package.
 * @returns Path to wxc-exec.exe if found, null otherwise
 */
export function findWxcExecutable(): string | null {
  return resolveExecutable('wxc-exec.exe', getRustTargetTriple());
}

/**
 * Find the executor co-located with the explicitly installed NanVix runtime.
 * Production never falls back to the core win32 platform package because that
 * package deliberately excludes the large MicroVM payload.
 */
export function findNanvixExecutable(): string | null {
  const binary = 'wxc-exec.exe';
  const override = process.env.MXC_BIN_DIR;
  if (override) {
    const candidate = path.join(override, getSdkArch(), binary);
    if (verifyExecutable(candidate)) return candidate;
  }

  const installed = installedNanvixPackageDir();
  if (!isDevMode()) {
    if (installed) {
      const candidate = path.join(installed, binary);
      if (verifyExecutable(candidate)) return candidate;
    }
    return null;
  }

  const sdkRoot = getSdkPackageRoot();
  const targetDir = path.join(sdkRoot, '..', '..', 'src', 'target');
  const candidates = [
    path.join(sdkRoot, 'companion-packages', 'nanvix-win32-x64', binary),
    path.join(targetDir, getRustTargetTriple(), 'release', binary),
    path.join(targetDir, getRustTargetTriple(), 'debug', binary),
    path.join(targetDir, 'release', binary),
    path.join(targetDir, 'debug', binary),
    ...(installed ? [path.join(installed, binary)] : []),
  ];
  return candidates.find(verifyExecutable) ?? null;
}

/**
 * Find the lxc-exec executable (Linux), preferring the per-platform package.
 * @returns Path to lxc-exec if found, null otherwise
 */
export function findLxcExecutable(): string | null {
  return resolveExecutable('lxc-exec', getRustTargetTriple('linux'));
}

/**
 * Find the mxc-exec-mac executable (macOS), preferring the per-platform package.
 * @returns Path to mxc-exec-mac if found, null otherwise
 */
export function findSeatbeltExecutable(): string | null {
  return resolveExecutable('mxc-exec-mac', getRustTargetTriple('darwin'));
}
