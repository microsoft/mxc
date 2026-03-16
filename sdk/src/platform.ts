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
 * - Registry key HKLM\Software\Microsoft\Windows NT\CurrentVersion\BuildLab must exist
 * - BuildLab format: buildNumber.branch.buildDate
 * - Branch must be "ge_current_directwinai*"
 * - Build number must be >= 26559
 * 
 * @returns true if Windows build meets requirements, false otherwise
 */
function checkWindowsBuildVersion(): boolean {
  // Query Windows Registry for BuildLab
  const buildLab = queryWindowsRegistry(
    'HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion',
    'BuildLab'
  );

  if (!buildLab) {
    return false;
  }

  // Split BuildLab into parts: buildNumber.branch.buildDate
  const parts = buildLab.split('.');
  if (parts.length < 3) {
    return false;
  }

  const buildNumber = parseInt(parts[0], 10);
  const branch = parts[1];

  // Check branch
  if (!branch.startsWith('ge_current_directwinai')) {
    return false;
  }

  // Check build number
  if (isNaN(buildNumber) || buildNumber < 26559) {
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
    support.reason = 'WXC is not supported on macOS';
    return support;
  }

  if (platform === 'linux') {
    support.reason = 'WXC is not supported on Linux';
    return support;
  }

  if (platform !== 'win32') {
        support.reason = 'WXC is not supported on this platform';
    return support;
  }

  const buildSupported = checkWindowsBuildVersion();
  if (buildSupported) {
    support.isSupported = true;
    return support;
  }

  support.reason = 'Unsupported Windows branch or build version';
  return support;
}

/**
 * Find the wxc-exec executable
 * Searches in common locations relative to the SDK package
 * @returns Path to wxc-exec.exe if found, null otherwise
 */
export function findWxcExecutable(): string | null {
  const possiblePaths = [
    // Rust release build output
    path.join(__dirname, '..', '..', 'src', 'target', 'release', 'wxc-exec.exe'),
    // Rust debug build output
    path.join(__dirname, '..', '..', 'src', 'target', 'debug', 'wxc-exec.exe'),
  ];

  for (const wxcPath of possiblePaths) {
    if (verifyWxcExecutable(wxcPath)) {
      return wxcPath;
    }
  }

  return null;
}

/**
 * Verify that a wxc-exec executable exists at the given path
 * @param wxcPath - Path to verify
 * @returns true if the executable exists and is a file, false otherwise
 */
function verifyWxcExecutable(wxcPath: string): boolean {
  try {
    return fs.existsSync(wxcPath) && fs.statSync(wxcPath).isFile();
  } catch {
    return false;
  }
}
