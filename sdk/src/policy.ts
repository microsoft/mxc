/**
 * Policy discovery APIs for building sandbox filesystem policy.
 *
 * These functions enumerate the host environment to discover tool paths,
 * user profile locations, and temporary storage — returning policy fragments
 * that callers can merge into a {@link SandboxPolicy}.
 */

import * as fs from 'fs';
import os from 'os';
import * as path from 'path';
import { execSync } from 'child_process';
import { randomBytes } from 'crypto';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/**
 * A composable fragment of filesystem policy.
 * Callers merge one or more fragments into {@link SandboxPolicy.filesystem}.
 */
export interface FilesystemPolicyResult {
    /** Paths that should be granted read-only access inside the container */
    readonlyPaths: string[];
    /** Paths that should be granted read-write access inside the container */
    readwritePaths: string[];
}

/**
 * Options for {@link getAvailableToolsPolicy}.
 */
export interface ToolsPolicyOptions {
    /**
     * When set to `'appcontainer'`, directories whose ACLs already grant
     * access to ALL_APPLICATION_PACKAGES are excluded from the result
     * because AppContainer processes can already see them implicitly.
     */
    containerType?: 'appcontainer';
}

// ---------------------------------------------------------------------------
// Known environment variable registry
// ---------------------------------------------------------------------------

type PathExtractor = (value: string) => string[];

interface KnownEnvVar {
    /** Environment variable name */
    name: string;
    /** Extracts zero or more directory paths from the variable's value */
    extractPaths: PathExtractor;
}

/** Split a path list using the platform-appropriate separator. */
function splitPathList(value: string): string[] {
    const separator = os.platform() === 'win32' ? ';' : ':';
    return value.split(separator).filter(p => p.length > 0);
}

/** Treat the entire value as a single directory path. */
function singlePath(value: string): string[] {
    return value.trim() ? [value.trim()] : [];
}

/**
 * Registry of well-known environment variables that point to tool
 * installations, SDK roots, or language-specific resource directories.
 * Each entry defines how to extract filesystem paths from the variable.
 */
const KNOWN_ENV_VARS: KnownEnvVar[] = [
    // Python
    { name: 'PYTHONPATH', extractPaths: splitPathList },
    { name: 'PYTHONHOME', extractPaths: singlePath },

    // Visual Studio / MSVC
    { name: 'VCINSTALLDIR', extractPaths: singlePath },
    { name: 'VSINSTALLDIR', extractPaths: singlePath },

    // PowerShell modules
    { name: 'PSModulePath', extractPaths: splitPathList },

    // vcpkg
    { name: 'VCPKG_ROOT', extractPaths: singlePath },

    // Go
    { name: 'GOPATH', extractPaths: singlePath },
    { name: 'GOROOT', extractPaths: singlePath },

    // Rust
    { name: 'CARGO_HOME', extractPaths: singlePath },
    { name: 'RUSTUP_HOME', extractPaths: singlePath },

    // Java
    { name: 'JAVA_HOME', extractPaths: singlePath },

    // Node.js
    { name: 'NVM_HOME', extractPaths: singlePath },
    { name: 'NVM_SYMLINK', extractPaths: singlePath },
    { name: 'NODE_PATH', extractPaths: splitPathList },

    // .NET
    { name: 'DOTNET_ROOT', extractPaths: singlePath },

    // Conda / Anaconda
    { name: 'CONDA_PREFIX', extractPaths: singlePath },

    // Linux-specific
    { name: 'LD_LIBRARY_PATH', extractPaths: splitPathList },
    { name: 'VIRTUAL_ENV', extractPaths: singlePath },
    { name: 'PYENV_ROOT', extractPaths: singlePath },
];

// ---------------------------------------------------------------------------
// Filtering helpers
// ---------------------------------------------------------------------------

function getWindowsDirectory(): string {
    return process.env['WINDIR'] || process.env['windir'] || 'C:\\Windows';
}

/**
 * Returns `true` if the path resides under system-critical locations.
 * On Windows: under %WINDIR%. On Linux: /bin, /sbin, /boot, /proc, /sys, /dev, etc.
 */
function isSystemCriticalPath(dirPath: string): boolean {
    if (os.platform() === 'win32') {
        const winDir = getWindowsDirectory().toLowerCase();
        const normalized = path.resolve(dirPath).toLowerCase();
        return normalized === winDir || normalized.startsWith(winDir + '\\');
    }
    // Linux: protect critical system paths
    const normalized = path.resolve(dirPath);
    const criticalPaths = ['/bin', '/sbin', '/usr/bin', '/usr/sbin', '/boot', '/proc', '/sys', '/dev'];
    return criticalPaths.some(cp => normalized === cp || normalized.startsWith(cp + '/'));
}

/**
 * Checks whether the directory ACL already grants access to the
 * ALL_APPLICATION_PACKAGES well-known SID (S-1-15-2-1).
 * Only applicable on Windows.
 */
function hasAllApplicationPackagesAccess(dirPath: string): boolean {
    if (os.platform() !== 'win32') {
        return false; // Only applicable on Windows
    }
    try {
        const output = execSync(`icacls "${dirPath}"`, {
            encoding: 'utf-8',
            stdio: 'pipe',
            timeout: 5000,
        });
        return output.includes('ALL APPLICATION PACKAGES') || output.includes('S-1-15-2-1');
    } catch {
        // If the check fails (access denied, timeout, etc.) assume the
        // directory is NOT already accessible — safer to include it.
        return false;
    }
}

function directoryExists(dirPath: string): boolean {
    try {
        return fs.statSync(dirPath).isDirectory();
    } catch {
        return false;
    }
}

/**
 * Deduplicates an array of paths. Uses case-insensitive comparison on Windows,
 * case-sensitive on other platforms. Paths are resolved to absolute form.
 */
function deduplicatePaths(paths: string[]): string[] {
    const isWindows = os.platform() === 'win32';
    const seen = new Set<string>();
    const result: string[] = [];
    for (const p of paths) {
        const resolved = path.resolve(p);
        const key = isWindows ? resolved.toLowerCase() : resolved;
        if (!seen.has(key)) {
            seen.add(key);
            result.push(resolved);
        }
    }
    return result;
}

// ---------------------------------------------------------------------------
// PowerShell discovery
// ---------------------------------------------------------------------------

/**
 * Check whether PowerShell (pwsh.exe) is available on the machine by scanning
 * the supplied PATH directories for a `pwsh.exe` binary.
 *
 * When PowerShell is found, return a policy fragment with:
 * - `C:\` in `readonlyPaths` — pwsh.exe enumerates the drive root on startup.
 * - The PSReadLine history directory in `readwritePaths` so the PSReadLine
 *   module can persist command history.
 *
 * On non-Windows platforms or when pwsh.exe is not found on PATH, returns an
 * empty policy.
 *
 * @param pathDirs - The list of PATH directories already collected by the caller.
 * @param env - Environment variable map (used to resolve `%USERPROFILE%`).
 */
function getPowerShellPolicy(
    pathDirs: string[],
    env: { [key: string]: string | undefined },
): FilesystemPolicyResult {
    if (os.platform() !== 'win32') {
        return { readonlyPaths: [], readwritePaths: [] };
    }

    const pwshFound = pathDirs.some(dir => {
        try {
            return fs.existsSync(path.join(dir, 'pwsh.exe'));
        } catch {
            return false;
        }
    });

    if (!pwshFound) {
        return { readonlyPaths: [], readwritePaths: [] };
    }

    const systemDrive = process.env["SystemDrive"] || 'C:';
    const systemRoot = systemDrive + "\\";
    const readonlyPaths: string[] = [systemRoot];
    const readwritePaths: string[] = [];

    const userProfile = env['USERPROFILE'];
    if (userProfile) {
        const psReadLineDir = path.join(
            userProfile, 'AppData', 'Roaming', 'Microsoft', 'Windows', 'PowerShell', 'PSReadLine',
        );
        readwritePaths.push(psReadLineDir);
    }

    return { readonlyPaths, readwritePaths };
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Discover tool and SDK directories from the environment and return them as
 * policy paths.
 *
 * Reads the `PATH` variable and a set of well-known tool / SDK environment
 * variables, enumerates the directories they reference, then applies filters:
 *
 * 1. Directories that do not exist on disk are removed.
 * 2. System-critical directories (under `%WINDIR%`) are removed.
 * 3. When `options.containerType` is `'appcontainer'`, directories whose ACLs
 *    already grant access to `ALL_APPLICATION_PACKAGES` are removed because
 *    AppContainer processes can see them without explicit brokering.
 *
 * Additionally, if PowerShell (`pwsh.exe`) is found on PATH, the drive root
 * (`C:\`) is added to `readonlyPaths` and the PSReadLine history directory
 * is added to `readwritePaths` so that interactive PowerShell sessions work
 * correctly inside the container.
 *
 * @param env - Environment variable map. Defaults to `process.env`.
 * @param options - Filtering options.
 * @returns A policy fragment with discovered paths.
 */
export function getAvailableToolsPolicy(
    env?: { [key: string]: string | undefined },
    options?: ToolsPolicyOptions,
): FilesystemPolicyResult {
    const environment = env ?? process.env;
    const collected: string[] = [];

    // PATH directories
    const pathValue = environment['PATH'] || environment['Path'] || '';
    const pathDirs = splitPathList(pathValue);
    collected.push(...pathDirs);

    // Known environment variables
    for (const knownVar of KNOWN_ENV_VARS) {
        const value = environment[knownVar.name];
        if (value) {
            collected.push(...knownVar.extractPaths(value));
        }
    }

    const unique = deduplicatePaths(collected);

    // Filter out non-existent paths, system-critical paths, and (optionally)
    // paths already accessible to containers.
    const filtered = unique.filter(dirPath => {
        if (!directoryExists(dirPath)) {
            return false;
        }
        if (isSystemCriticalPath(dirPath)) {
            return false;
        }
        if (options?.containerType === 'appcontainer' && hasAllApplicationPackagesAccess(dirPath)) {
            return false;
        }
        return true;
    });

    // Merge PowerShell-specific paths when pwsh.exe is available
    const pwshPolicy = getPowerShellPolicy(pathDirs, environment);

    return {
        readonlyPaths: deduplicatePaths([...filtered, ...pwshPolicy.readonlyPaths]),
        readwritePaths: deduplicatePaths([...pwshPolicy.readwritePaths]),
    };
}

/**
 * Build read-only policy for standard user profile application data locations.
 *
 * Enumerates immediate subdirectories of `%LOCALAPPDATA%\Programs`
 * (per-user installed developer tools) as additional read-only paths.
 *
 * @returns A policy fragment with user profile paths in `readonlyPaths`.
 */
export function getUserProfilePolicy(): FilesystemPolicyResult {
    const readonlyPaths: string[] = [];

    if (os.platform() === 'win32') {
        /*  TODO: Need to think through the implications of granting access
            to folders within APPDATA versus LOCALAPPDATA.
        const appData = process.env['APPDATA'];
        if (appData && directoryExists(appData)) {
            readonlyPaths.push(path.resolve(appData));
        }*/

        const localAppData = process.env['LOCALAPPDATA'];
        if (localAppData && directoryExists(localAppData)) {
            // Enumerate per-user program installations
            const programsDir = path.join(localAppData, 'Programs');
            if (directoryExists(programsDir)) {
                try {
                    const entries = fs.readdirSync(programsDir, { withFileTypes: true });
                    for (const entry of entries) {
                        if (entry.isDirectory()) {
                            readonlyPaths.push(path.join(programsDir, entry.name));
                        }
                    }
                } catch {
                    // Ignore enumeration errors (e.g. permission denied)
                }
            }
        }
    } else {
        // Linux: enumerate ~/.local/bin and ~/.local/lib
        const home = process.env['HOME'];
        if (home) {
            const localBin = path.join(home, '.local', 'bin');
            if (directoryExists(localBin)) {
                readonlyPaths.push(localBin);
            }
            const localLib = path.join(home, '.local', 'lib');
            if (directoryExists(localLib)) {
                readonlyPaths.push(localLib);
            }
        }
    }

    return {
        readonlyPaths,
        readwritePaths: [],
    };
}

/**
 * Generate a dedicated temporary directory for a container and return it as
 * read-write policy.
 *
 * If the provided environment contains a `TEMP` (or `TMP`) variable, a
 * uniquely-named subdirectory is created beneath that path and returned in
 * `tempDirectory` and `readwritePaths`. If neither variable is set the
 * container is assumed to manage its own temp directory, so the returned
 * policy is empty.
 *
 * @param env - Environment variable map. Defaults to `process.env`.
 * @returns Policy fragment with the temp directory in both `tempDirectory`
 *          and `readwritePaths`, or empty values when no TEMP path is found.
 */
export function getTemporaryFilesPolicy(
    env?: { [key: string]: string | undefined },
): FilesystemPolicyResult {
    const environment = env ?? process.env;

    // On Linux, prefer TMPDIR; on Windows, prefer TEMP/TMP
    const tempRoot = os.platform() === 'win32'
        ? (environment['TEMP'] || environment['TMP'])
        : (environment['TMPDIR'] || '/tmp');

    if (!tempRoot || !directoryExists(tempRoot)) {
        return {
            readonlyPaths: [],
            readwritePaths: [],
        };
    }

    return {
        readonlyPaths: [],
        readwritePaths: [tempRoot],
    };
}
