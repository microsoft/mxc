import * as os from 'os';
import * as fs from 'fs';
import * as path from 'path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';
import {
  readAvailableBackendsJson,
  readPlatformSupportJson,
  type PlatformSupportSnapshotJson,
} from './bindings/platform-support.js';
import {
  AvailableBackend,
  BackendCapability,
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

let wxcExecutableCache: { binDir: string | undefined; executable: string } | undefined;
let wxcExecutableVerifier = verifyWxcExecutable;

const KNOWN_BACKENDS = {
  processcontainer: true,
  windows_sandbox: true,
  wslc: true,
  lxc: true,
  microvm: true,
  hyperlight: true,
  seatbelt: true,
  isolation_session: true,
  bubblewrap: true,
} satisfies Record<ContainmentBackend, true>;

const KNOWN_TIERS = {
  'base-container': true,
  'appcontainer-bfs': true,
  'appcontainer-dacl': true,
} satisfies Record<IsolationTier, true>;

type KnownBackendCapability = Exclude<BackendCapability, 'unknown'>;

const KNOWN_CAPABILITIES = {
  captureDenials: true,
  filesystemDeniedPaths: true,
  filesystemEnumeratePaths: true,
  ingressHostLoopbackAllow: true,
  proxyEnforcement: true,
} satisfies Record<KnownBackendCapability, true>;

/**
 * Get platform support information.
 *
 * This projects the native host-services exports onto the SDK's existing
 * `PlatformSupport` shape. `availableMethods`, Linux `unavailableReasons`
 * and `bubblewrapNetwork`, and the Windows isolation and UI capability
 * details are preserved.
 *
 * The result is cached for the lifetime of the SDK module. On Linux,
 * `bubblewrapNetwork` is advisory and can become stale; backend launch
 * rechecks the required networking dependencies before enforcing policy.
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

let platformSupportSnapshotReader: PlatformSupportSnapshotReader | null = null;

/** @internal Test-only: override native host-services reads. */
export function _setPlatformSupportSnapshotReader(reader: PlatformSupportSnapshotReader | null): void {
  platformSupportSnapshotReader = reader;
}

interface NativePlatformSupportPayload {
  isSupported: boolean;
  reason?: string;
  availableMethods: string[];
  isolationTier?: IsolationTier;
  isolationWarnings?: string[];
  uiCapabilities?: UiCapabilitySupport;
  bubblewrapNetwork?: BubblewrapNetworkSupport;
}

function isContainmentBackend(value: unknown): value is ContainmentBackend {
  return typeof value === 'string'
    && Object.prototype.hasOwnProperty.call(KNOWN_BACKENDS, value);
}

function isIsolationTier(value: unknown): value is IsolationTier {
  return typeof value === 'string'
    && Object.prototype.hasOwnProperty.call(KNOWN_TIERS, value);
}

function isBackendCapability(value: unknown): value is KnownBackendCapability {
  return typeof value === 'string'
    && Object.prototype.hasOwnProperty.call(KNOWN_CAPABILITIES, value);
}

function isBubblewrapNetworkSupport(value: unknown): value is BubblewrapNetworkSupport {
  if (value === null || typeof value !== 'object') {
    return false;
  }
  const network = value as Record<string, unknown>;
  return (
    (network.proxyEnforcement === 'supported' || network.proxyEnforcement === 'unsupported')
    && Array.isArray(network.warnings)
    && network.warnings.every((warning) => typeof warning === 'string')
  );
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
  if (value === null || typeof value !== 'object') {
    return false;
  }
  const capabilities = value as Record<keyof UiCapabilitySupport, unknown>;
  return UI_CAPABILITY_FIELDS.every((field) => typeof capabilities[field] === 'boolean');
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
  if (value.isolationTier !== undefined && !isIsolationTier(value.isolationTier)) {
    throw new Error('mxc_platform_support_json returned malformed JSON');
  }
  if (
    value.isolationWarnings !== undefined
    && (
      !Array.isArray(value.isolationWarnings)
      || value.isolationWarnings.some((warning) => typeof warning !== 'string')
    )
  ) {
    throw new Error('mxc_platform_support_json returned malformed JSON');
  }
  if (value.uiCapabilities !== undefined && !isUiCapabilitySupport(value.uiCapabilities)) {
    throw new Error('mxc_platform_support_json returned malformed JSON');
  }
  if (
    value.bubblewrapNetwork !== undefined
    && !isBubblewrapNetworkSupport(value.bubblewrapNetwork)
  ) {
    throw new Error('mxc_platform_support_json returned malformed JSON');
  }
  return {
    isSupported: value.isSupported,
    reason: typeof value.reason === 'string' ? value.reason : undefined,
    availableMethods: value.availableMethods,
    isolationTier: value.isolationTier,
    isolationWarnings: value.isolationWarnings,
    uiCapabilities: value.uiCapabilities,
    bubblewrapNetwork: value.bubblewrapNetwork,
  };
}

function parseAvailableBackendsPayload(json: string): AvailableBackend[] {
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
    if (value.tier !== undefined && typeof value.tier !== 'string') {
      throw new Error('mxc_available_backends_json returned malformed JSON');
    }
    if (
      value.capabilities !== undefined
      && (
        !Array.isArray(value.capabilities)
        || value.capabilities.some((item) => typeof item !== 'string')
      )
    ) {
      throw new Error('mxc_available_backends_json returned malformed JSON');
    }
    if (
      value.warnings !== undefined
      && (
        !Array.isArray(value.warnings)
        || value.warnings.some((item) => typeof item !== 'string')
      )
    ) {
      throw new Error('mxc_available_backends_json returned malformed JSON');
    }
    return {
      backend: isContainmentBackend(value.backend) ? value.backend : 'unknown',
      tier: value.tier === undefined
        ? undefined
        : isIsolationTier(value.tier) ? value.tier : 'unknown',
      capabilities: (value.capabilities ?? []).map((capability) =>
        isBackendCapability(capability) ? capability : 'unknown'),
      warnings: value.warnings ?? [],
    };
  });
}

function linuxUnavailableReasons(
  availableMethods: readonly ContainmentBackend[],
  bubblewrapReason?: string,
): Partial<Record<ContainmentBackend, string>> | undefined {
  const reasons: Partial<Record<ContainmentBackend, string>> = {};
  if (!availableMethods.includes('bubblewrap')) {
    reasons.bubblewrap = bubblewrapReason
      ?? 'Bubblewrap (bwrap) is not installed or not available on this system.';
  }
  return Object.keys(reasons).length === 0 ? undefined : reasons;
}

function adaptPlatformSupport(json: string): PlatformSupport {
  const nativeSupport = parsePlatformSupportPayload(json);
  const availableMethods = nativeSupport.availableMethods.filter(isContainmentBackend);
  const support: PlatformSupport = {
    isSupported: nativeSupport.isSupported,
    availableMethods,
  };

  if (os.platform() === 'linux') {
    const unavailableReasons = linuxUnavailableReasons(availableMethods, nativeSupport.reason);
    if (unavailableReasons) {
      support.unavailableReasons = unavailableReasons;
    }
    if (nativeSupport.bubblewrapNetwork) {
      support.bubblewrapNetwork = nativeSupport.bubblewrapNetwork;
    }
    if (!support.isSupported) {
      support.reason = nativeSupport.reason
        ?? 'Bubblewrap is not available to the in-process SDK on this system.';
    }
  } else if (!support.isSupported) {
    support.reason = nativeSupport.reason ?? 'MXC is not supported on this platform';
  }

  if (nativeSupport.isolationTier) {
    support.isolationTier = nativeSupport.isolationTier;
  }
  if (nativeSupport.isolationWarnings && nativeSupport.isolationWarnings.length > 0) {
    support.isolationWarnings = nativeSupport.isolationWarnings;
  }
  if (nativeSupport.uiCapabilities) {
    support.uiCapabilities = nativeSupport.uiCapabilities;
  }
  return support;
}

function computeSupport(): PlatformSupport {
  try {
    const json = platformSupportSnapshotReader?.().platformSupportJson
      ?? readPlatformSupportJson();
    return adaptPlatformSupport(json);
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

/**
 * Probe every containment backend the current host can run.
 *
 * This includes host-capability backends that the Node SDK cannot necessarily
 * launch. Use {@link getPlatformSupport} for the SDK-launchable subset. The
 * result is intentionally not cached, so callers receive a current host probe;
 * avoid calling it in a hot loop.
 *
 * @throws When the native library cannot be loaded or returns a malformed
 * payload.
 */
export function getAvailableBackends(): AvailableBackend[] {
  const json = platformSupportSnapshotReader?.().availableBackendsJson
    ?? readAvailableBackendsJson();
  return parseAvailableBackendsPayload(json);
}

let platformDiagnosticLogger: (message: string) => void = diagLog;

/** @internal Test-only: override platform-support diagnostic logging. */
export function _setPlatformDiagnosticLogger(fn: ((message: string) => void) | null): void {
  platformDiagnosticLogger = fn ?? diagLog;
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
