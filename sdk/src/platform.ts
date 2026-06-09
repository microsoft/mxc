import * as os from 'os';
import * as fs from 'fs';
import * as path from 'path';
import { execSync, execFileSync } from 'child_process';
import { fileURLToPath } from 'node:url';
import { ContainmentBackend, IsolationTier, PlatformSupport, UiCapabilitySupport } from './types.js';

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
    if (isBubblewrapAvailable()) methods.push('bubblewrap');
    if (methods.length > 0) {
      support.isSupported = true;
      support.availableMethods = methods;
    } else {
      support.reason = 'Neither LXC nor Bubblewrap is available on this system';
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
 * Check if Bubblewrap (bwrap) is available on the system
 */
function isBubblewrapAvailable(): boolean {
  try {
    execSync('bwrap --version', { encoding: 'utf-8', stdio: 'pipe' });
    return true;
  } catch {
    return false;
  }
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
  const targetDir = path.join(pkgRoot, '..', 'src', 'target');

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
  const targetDir = path.join(pkgRoot, '..', 'src', 'target');

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
  const targetDir = path.join(__dirname, '..', '..', 'src', 'target');

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
