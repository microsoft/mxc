import * as os from 'os';
import * as fs from 'fs';
import * as path from 'path';
import { execSync } from 'child_process';
import { PlatformSupport } from './types';

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
 * Check Windows build version requirements for WXC
 * 
 * Requirements:
 * - CurrentBuild (major version) must be >= 26100
 * - UBR (minor version) must be >= 7965 (Windows Insider 3A or later)
 * - UBR should not be checked for build versions >= 26500 as they may have different versioning
 * 
 * @returns true if Windows build meets requirements, false otherwise
 */
function checkWindowsBuildVersion(): boolean {
  const registryPath = 'HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion';

  const currentBuild = queryWindowsRegistry(registryPath, 'CurrentBuild');
  if (!currentBuild) {
    return false;
  }

  const majorVersion = parseInt(currentBuild, 10);
  if (isNaN(majorVersion) || majorVersion < 26100) {
    return false;
  }

  const ubrValue = queryWindowsRegistry(registryPath, 'UBR');
  if (!ubrValue) {
    return false;
  }

  // UBR is stored as REG_DWORD (hex format), use Number() to parse
  const minorVersion = Number(ubrValue);
  if (isNaN(minorVersion)) {
    return false;
  }

  if (majorVersion >= 26100 && majorVersion <= 26500 && minorVersion < 7965) {
    return false;
  }

  return true;
}

/**
 * Get platform support information
 * @returns Platform support details including available sandboxing methods
 */
export function getPlatformSupport(): PlatformSupport {
  const platform = os.platform();
  var support : PlatformSupport = { isSupported: false, reason: '', availableMethods: [] };

  // Non-Windows platforms
  if (platform === 'darwin') {
    support.reason = 'MXC is not supported on macOS';
    return support;
  }

  if (platform === 'linux') {
    // Check if LXC is available
    if (isLxcAvailable()) {
      support.isSupported = true;
      support.availableMethods = ['lxc'];
      return support;
    }
    support.reason = 'LXC is not installed or not available on this system';
    return support;
  }

  if (platform !== 'win32') {
        support.reason = 'MXC is not supported on this platform';
    return support;
  }

  const buildSupported = checkWindowsBuildVersion();
  if (buildSupported) {
    support.isSupported = true;
    support.availableMethods = ['appcontainer'];
    return support;
  }

  support.reason = 'Unsupported Windows branch or build version';
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
 * Find the wxc-exec executable
 * Searches in common locations relative to the SDK package,
 * selecting the build matching the current machine architecture.
 * @returns Path to wxc-exec.exe if found, null otherwise
 */
export function findWxcExecutable(): string | null {
  const targetTriple = getRustTargetTriple();
  const targetDir = path.join(__dirname, '..', '..', 'src', 'target');

  const possiblePaths = [
    // Bundled in the SDK package (e.g. when installed via npm)
    path.join(__dirname, '..', 'bin', getSdkArch(), 'wxc-exec.exe'),
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
    return fs.existsSync(execPath) && fs.statSync(execPath).isFile();
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
  const targetTriple = getLinuxRustTargetTriple();
  const targetDir = path.join(__dirname, '..', '..', 'src', 'target');

  const possiblePaths = [
    // Bundled in the SDK package
    path.join(__dirname, '..', 'bin', getSdkArch(), 'lxc-exec'),
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
