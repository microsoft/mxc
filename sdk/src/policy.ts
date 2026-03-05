/**
 * Policy discovery APIs for building sandbox filesystem policy.
 *
 * These functions enumerate the host environment to discover tool paths,
 * user profile locations, and temporary storage — returning policy fragments
 * that callers can merge into a {@link SandboxPolicy}.
 */

import * as fs from 'fs';
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

/** Split a semicolon-delimited path list (PATH, PYTHONPATH, …). */
function splitPathList(value: string): string[] {
    return value.split(';').filter(p => p.length > 0);
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
];

// ---------------------------------------------------------------------------
// Filtering helpers
// ---------------------------------------------------------------------------

function getWindowsDirectory(): string {
    return process.env['WINDIR'] || process.env['windir'] || 'C:\\Windows';
}

/**
 * Returns `true` if the path resides under the Windows directory
 * (e.g. C:\Windows, C:\Windows\System32) or other system-critical locations.
 */
function isSystemCriticalPath(dirPath: string): boolean {
    const winDir = getWindowsDirectory().toLowerCase();
    const normalized = path.resolve(dirPath).toLowerCase();

    return normalized === winDir || normalized.startsWith(winDir + '\\');
}

/**
 * Checks whether the directory ACL already grants access to the
 * ALL_APPLICATION_PACKAGES well-known SID (S-1-15-2-1).
 */
function hasAllApplicationPackagesAccess(dirPath: string): boolean {
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
 * Deduplicates an array of paths using case-insensitive comparison
 * (Windows filesystem semantics). Paths are resolved to absolute form.
 */
function deduplicatePaths(paths: string[]): string[] {
    const seen = new Set<string>();
    const result: string[] = [];
    for (const p of paths) {
        const resolved = path.resolve(p);
        const key = resolved.toLowerCase();
        if (!seen.has(key)) {
            seen.add(key);
            result.push(resolved);
        }
    }
    return result;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Discover tool and SDK directories from the environment and return them as
 * read-only policy paths.
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
 * @param env - Environment variable map. Defaults to `process.env`.
 * @param options - Filtering options.
 * @returns A policy fragment with discovered paths in `readonlyPaths`.
 */
export function getAvailableToolsPolicy(
    env?: { [key: string]: string | undefined },
    options?: ToolsPolicyOptions,
): FilesystemPolicyResult {
    const environment = env ?? process.env;
    const collected: string[] = [];

    // PATH directories
    const pathValue = environment['PATH'] || environment['Path'] || '';
    collected.push(...splitPathList(pathValue));

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

    return {
        readonlyPaths: filtered,
        readwritePaths: [],
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
    const tempRoot = environment['TEMP'] || environment['TMP'];

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
