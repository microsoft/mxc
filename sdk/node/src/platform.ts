// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { execFileSync, execSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { getAvailableBackends } from './available-backends.js';
import type {
  AvailableBackend,
  IsolationTier,
  PlatformSupport,
  UiCapabilitySupport,
} from './types.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const require = createRequire(import.meta.url);

function getSdkPackageRoot(): string {
  try {
    return path.dirname(require.resolve('@microsoft/mxc-sdk/package.json'));
  } catch {
    return path.join(__dirname, '..');
  }
}

let windowsSandboxAvailableCache: boolean | undefined;
let wxcExecutableCache: { binDir: string | undefined; executable: string } | undefined;
let wxcExecutableVerifier = verifyWxcExecutable;
let cachedSupport: PlatformSupport | null = null;

type AvailableBackendsProbe = () => AvailableBackend[];
let availableBackendsProbe: AvailableBackendsProbe = getAvailableBackends;

/** @internal Test-only: inject one canonical native discovery snapshot. */
export function _setAvailableBackendsProbe(probe?: AvailableBackendsProbe): void {
  availableBackendsProbe = probe ?? getAvailableBackends;
}

/** @internal Test-only: clear the module-lifetime platform snapshot. */
export function _resetPlatformSupportCache(): void {
  cachedSupport = null;
}

type ProbeRunner = () => string;
let probeRunner: ProbeRunner = defaultProbeRunner;

/** @internal Test-only: override the retained Windows request probe runner. */
export function _setProbeRunner(runner: ProbeRunner | null): void {
  probeRunner = runner ?? defaultProbeRunner;
}

function defaultProbeRunner(): string {
  const wxcPath = findWxcExecutable();
  if (!wxcPath) throw new Error('wxc-exec not found');
  return execFileSync(wxcPath, ['--probe'], {
    timeout: 5000,
    encoding: 'utf-8',
    stdio: ['ignore', 'pipe', 'pipe'],
  });
}

function isWindowsSandboxAvailable(): boolean {
  if (windowsSandboxAvailableCache !== undefined) return windowsSandboxAvailableCache;
  try {
    const output = execSync(
      'dism /online /get-featureinfo /featurename:Containers-DisposableClientVM',
      { encoding: 'utf-8', stdio: 'pipe', timeout: 10000 },
    );
    windowsSandboxAvailableCache = /State\s*:\s*Enabled/i.test(output);
  } catch {
    const sandboxExe = path.join(
      process.env.SystemRoot || 'C:\\Windows',
      'System32',
      'WindowsSandbox.exe',
    );
    windowsSandboxAvailableCache = fs.existsSync(sandboxExe);
  }
  return windowsSandboxAvailableCache;
}

function isValidTier(value: unknown): value is IsolationTier {
  return value === 'base-container'
    || value === 'appcontainer-bfs'
    || value === 'appcontainer-dacl';
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
  if (!value || typeof value !== 'object') return false;
  const capabilities = value as Record<keyof UiCapabilitySupport, unknown>;
  return UI_CAPABILITY_FIELDS.every((field) => typeof capabilities[field] === 'boolean');
}

function populateIsolationFromProbe(support: PlatformSupport): void {
  try {
    const probe: unknown = JSON.parse(probeRunner());
    if (!probe || typeof probe !== 'object') return;
    const record = probe as Record<string, unknown>;
    if (isValidTier(record.tier)) support.isolationTier = record.tier;
    if (Array.isArray(record.warnings)) {
      const warnings = record.warnings.filter(
        (warning: unknown): warning is string => typeof warning === 'string',
      );
      if (warnings.length > 0) support.isolationWarnings = warnings;
    }
    if (!record.probes || typeof record.probes !== 'object') return;
    const facts = record.probes as Record<string, unknown>;
    if (isUiCapabilitySupport(facts.uiCapabilities)) {
      support.uiCapabilities = facts.uiCapabilities;
    }
    if (facts.isolationSessionAvailable === true) {
      support.availableMethods.push('isolation_session');
    }
    if (facts.hyperlightAvailable === true) {
      support.availableMethods.push('hyperlight');
    }
  } catch {
    // The Windows probe remains advisory for backward compatibility.
  }
}

function computeLinuxSupport(): PlatformSupport {
  const support: PlatformSupport = {
    isSupported: false,
    reason: '',
    availableMethods: [],
  };
  const discovered = availableBackendsProbe();
  const lxc = discovered.find((backend) => backend.backend === 'lxc');
  const bubblewrap = discovered.find((backend) => backend.backend === 'bubblewrap');

  if (lxc) {
    support.availableMethods.push('lxc');
  } else {
    support.unavailableReasons = {
      ...support.unavailableReasons,
      lxc: 'LXC is not installed or not available on this system.',
    };
  }

  if (bubblewrap) {
    support.availableMethods.push('bubblewrap');
    const proxySupported = bubblewrap.capabilities.includes('proxyEnforcement');
    support.bubblewrapNetwork = {
      proxyEnforcement: proxySupported ? 'supported' : 'unsupported',
      warnings: bubblewrap.warnings.length > 0
        ? bubblewrap.warnings
        : proxySupported
          ? []
          : ['proxy-only egress is not supported on this host'],
    };
  } else {
    support.unavailableReasons = {
      ...support.unavailableReasons,
      bubblewrap: 'Bubblewrap is not launchable on this host.',
    };
  }

  support.isSupported = support.availableMethods.length > 0;
  if (!support.isSupported) {
    support.reason = 'Neither LXC nor Bubblewrap is launchable on this system.';
  }
  return support;
}

/**
 * Get platform support information.
 *
 * Linux derives LXC, Bubblewrap, and Bubblewrap network support from one
 * canonical native discovery snapshot. The first uncontended Linux call is
 * synchronous and has a conservative 16-second native deadline, excluding
 * ordinary scheduler jitter. The result is cached for this module isolate.
 */
export function getPlatformSupport(): PlatformSupport {
  if (cachedSupport !== null) return cachedSupport;

  const platform = os.platform();
  if (platform === 'linux') {
    cachedSupport = computeLinuxSupport();
    return cachedSupport;
  }
  if (platform === 'darwin') {
    cachedSupport = fs.existsSync('/usr/bin/sandbox-exec')
      ? { isSupported: true, availableMethods: ['seatbelt'] }
      : {
        isSupported: false,
        reason: '/usr/bin/sandbox-exec not found; macOS install is incomplete',
        availableMethods: [],
      };
    return cachedSupport;
  }
  if (platform !== 'win32') {
    cachedSupport = {
      isSupported: false,
      reason: 'MXC is not supported on this platform',
      availableMethods: [],
    };
    return cachedSupport;
  }

  cachedSupport = {
    isSupported: true,
    availableMethods: ['processcontainer'],
  };
  if (isWindowsSandboxAvailable()) {
    cachedSupport.availableMethods.push('windows_sandbox');
  }
  populateIsolationFromProbe(cachedSupport);
  return cachedSupport;
}

function getSdkArch(): string {
  return os.arch() === 'arm64' ? 'arm64' : 'x64';
}

function getRustTargetTriple(): string {
  const prefix = os.arch() === 'arm64' ? 'aarch64' : 'x86_64';
  return os.platform() === 'linux'
    ? `${prefix}-unknown-linux-gnu`
    : `${prefix}-pc-windows-msvc`;
}

function getLinuxRustTargetTriple(): string {
  return os.arch() === 'arm64'
    ? 'aarch64-unknown-linux-gnu'
    : 'x86_64-unknown-linux-gnu';
}

function getDarwinRustTargetTriple(): string {
  return os.arch() === 'arm64' ? 'aarch64-apple-darwin' : 'x86_64-apple-darwin';
}

export function findWxcExecutable(): string | null {
  const binDir = process.env.MXC_BIN_DIR;
  const overridePath = binDir ? path.join(binDir, getSdkArch(), 'wxc-exec.exe') : undefined;
  const cached = wxcExecutableCache;
  if (
    cached
    && cached.binDir === binDir
    && (overridePath === undefined || cached.executable === overridePath)
    && wxcExecutableVerifier(cached.executable)
  ) {
    return cached.executable;
  }
  wxcExecutableCache = undefined;

  if (overridePath && wxcExecutableVerifier(overridePath)) {
    wxcExecutableCache = { binDir, executable: overridePath };
    return overridePath;
  }

  const packageRoot = getSdkPackageRoot();
  const targetDir = path.join(packageRoot, '..', '..', 'src', 'target');
  const candidates = [
    path.join(packageRoot, 'bin', getSdkArch(), 'wxc-exec.exe'),
    path.join(targetDir, getRustTargetTriple(), 'release', 'wxc-exec.exe'),
    path.join(targetDir, getRustTargetTriple(), 'debug', 'wxc-exec.exe'),
    path.join(targetDir, 'release', 'wxc-exec.exe'),
    path.join(targetDir, 'debug', 'wxc-exec.exe'),
  ];
  const executable = candidates.find(wxcExecutableVerifier) ?? null;
  if (executable) wxcExecutableCache = { binDir, executable };
  return executable;
}

/** @internal Test-only: clear the resolved Windows executable path. */
export function _resetWxcExecutableCache(): void {
  wxcExecutableCache = undefined;
}

/** @internal Test-only: override executable verification. */
export function _setWxcExecutableVerifier(
  verifier: ((execPath: string) => boolean) | null,
): void {
  wxcExecutableVerifier = verifier ?? verifyWxcExecutable;
}

function verifyExecutable(executable: string): boolean {
  try {
    if (executable.includes('.asar')) return false;
    if (!fs.statSync(executable).isFile()) return false;
    if (process.platform !== 'win32') fs.accessSync(executable, fs.constants.X_OK);
    return true;
  } catch {
    return false;
  }
}

function verifyWxcExecutable(executable: string): boolean {
  return verifyExecutable(executable);
}

export function findLxcExecutable(): string | null {
  const packageRoot = getSdkPackageRoot();
  const targetDir = path.join(packageRoot, '..', '..', 'src', 'target');
  const override = process.env.MXC_BIN_DIR
    ? path.join(process.env.MXC_BIN_DIR, getSdkArch(), 'lxc-exec')
    : undefined;
  const candidates = [
    override,
    path.join(packageRoot, 'bin', getSdkArch(), 'lxc-exec'),
    path.join(targetDir, getLinuxRustTargetTriple(), 'release', 'lxc-exec'),
    path.join(targetDir, getLinuxRustTargetTriple(), 'debug', 'lxc-exec'),
    path.join(targetDir, 'release', 'lxc-exec'),
    path.join(targetDir, 'debug', 'lxc-exec'),
  ];
  return candidates.find((candidate): candidate is string =>
    candidate !== undefined && verifyExecutable(candidate)) ?? null;
}

export function findSeatbeltExecutable(): string | null {
  const targetDir = path.join(__dirname, '..', '..', '..', 'src', 'target');
  const override = process.env.MXC_BIN_DIR
    ? path.join(process.env.MXC_BIN_DIR, getSdkArch(), 'mxc-exec-mac')
    : undefined;
  const candidates = [
    override,
    path.join(__dirname, '..', 'bin', getSdkArch(), 'mxc-exec-mac'),
    path.join(targetDir, getDarwinRustTargetTriple(), 'release', 'mxc-exec-mac'),
    path.join(targetDir, getDarwinRustTargetTriple(), 'debug', 'mxc-exec-mac'),
    path.join(targetDir, 'release', 'mxc-exec-mac'),
    path.join(targetDir, 'debug', 'mxc-exec-mac'),
  ];
  return candidates.find((candidate): candidate is string =>
    candidate !== undefined && verifyExecutable(candidate)) ?? null;
}
