// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * Policy regeneration utilities for the denied resource approval workflow.
 *
 * After denied resources are detected and the user approves specific paths,
 * this module generates an updated SandboxPolicy with the approved paths
 * properly merged into the filesystem policy.
 */

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { SandboxPolicy } from './types.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/**
 * A path that the user has approved for access within the sandbox.
 */
export interface ApprovedPath {
    /** The filesystem path to grant access to */
    path: string;
    /** The level of access to grant */
    accessLevel: 'readonly' | 'readwrite';
}

/**
 * Options for policy generation.
 */
export interface PolicyGenerationOptions {
    /**
     * Whether to reject paths under system-critical locations.
     * Default: true
     */
    rejectSystemCriticalPaths?: boolean;
    /**
     * Whether to use parent directory instead of specific file paths.
     * When true, if a file path is approved, its parent directory is added instead.
     * Default: false
     */
    useParentDirectories?: boolean;
}

/**
 * Result of policy generation including any warnings.
 */
export interface PolicyGenerationResult {
    /** The updated policy with approved paths merged */
    policy: SandboxPolicy;
    /** Paths that were rejected (e.g., system-critical) with reasons */
    rejected: Array<{ path: string; reason: string }>;
    /** Number of new paths actually added */
    addedCount: number;
}

// ---------------------------------------------------------------------------
// System-critical path detection
// ---------------------------------------------------------------------------

function getWindowsDirectory(): string {
    return process.env['WINDIR'] || process.env['windir'] || 'C:\\Windows';
}

/**
 * Returns true if the path resides under system-critical locations
 * that should not be granted to a sandbox.
 */
function isSystemCriticalPath(dirPath: string): boolean {
    const normalized = path.resolve(dirPath);

    if (os.platform() === 'win32') {
        const lower = normalized.toLowerCase();

        // Reject UNC paths entirely
        if (lower.startsWith('\\\\')) {
            return true;
        }

        const winDir = getWindowsDirectory().toLowerCase();
        if (lower === winDir || lower.startsWith(winDir + '\\')) {
            return true;
        }

        const programFiles = (process.env['ProgramFiles'] || 'C:\\Program Files').toLowerCase();
        const programFilesX86 = (process.env['ProgramFiles(x86)'] || 'C:\\Program Files (x86)').toLowerCase();
        if (lower === programFiles || lower.startsWith(programFiles + '\\') ||
            lower === programFilesX86 || lower.startsWith(programFilesX86 + '\\')) {
            return true;
        }

        // Block ProgramData
        const programData = (process.env['ProgramData'] || 'C:\\ProgramData').toLowerCase();
        if (lower === programData || lower.startsWith(programData + '\\')) {
            return true;
        }

        // Block other users' profiles
        const usersDir = (process.env['SystemDrive'] || 'C:') + '\\Users';
        const usersDirLower = usersDir.toLowerCase();
        const currentUser = os.userInfo().username.toLowerCase();
        if (lower.startsWith(usersDirLower + '\\')) {
            const relPath = normalized.slice(usersDir.length + 1);
            const profileName = relPath.split('\\')[0].toLowerCase();
            if (profileName !== currentUser && profileName !== 'public') {
                return true;
            }
        }

        // Block System Volume Information
        if (lower.includes('\\system volume information')) {
            return true;
        }

        return false;
    }

    // Linux: protect critical system paths
    const criticalPaths = ['/bin', '/sbin', '/usr/bin', '/usr/sbin', '/boot', '/proc', '/sys', '/dev', '/etc'];
    return criticalPaths.some(cp => normalized === cp || normalized.startsWith(cp + '/'));
}

// ---------------------------------------------------------------------------
// Deduplication
// ---------------------------------------------------------------------------

/**
 * Deduplicate paths using platform-appropriate comparison.
 * On Windows: case-insensitive. On Linux: case-sensitive.
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

/**
 * Check if a path is already covered by existing paths in the list.
 * A path is "covered" if it equals or is a child of an existing path.
 */
function isPathCovered(targetPath: string, existingPaths: string[]): boolean {
    const isWindows = os.platform() === 'win32';
    const normalizedTarget = isWindows ? path.resolve(targetPath).toLowerCase() : path.resolve(targetPath);
    const sep = path.sep;

    return existingPaths.some(existing => {
        const normalizedExisting = isWindows ? path.resolve(existing).toLowerCase() : path.resolve(existing);
        return normalizedTarget === normalizedExisting ||
               normalizedTarget.startsWith(normalizedExisting + sep);
    });
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Generate an updated SandboxPolicy with user-approved paths merged into
 * the filesystem configuration.
 *
 * This function:
 * 1. Validates approved paths (rejects system-critical locations)
 * 2. Deduplicates against existing policy paths
 * 3. Merges approved paths into the appropriate arrays (readonlyPaths / readwritePaths)
 * 4. Returns the updated policy + any rejected paths with reasons
 *
 * @param originalPolicy - The original policy that resulted in denials
 * @param approvedPaths - Paths the user has approved with their access level
 * @param options - Optional configuration for policy generation
 * @returns Result containing the updated policy, rejected paths, and count of additions
 *
 * @example
 * ```typescript
 * const result = generateUpdatedPolicy(originalPolicy, [
 *   { path: 'C:\\Users\\me\\project', accessLevel: 'readwrite' },
 *   { path: 'C:\\Python311', accessLevel: 'readonly' },
 * ]);
 * // result.policy has updated filesystem paths
 * // result.rejected lists any paths that were blocked
 * ```
 */
export function generateUpdatedPolicy(
    originalPolicy: SandboxPolicy,
    approvedPaths: ApprovedPath[],
    options: PolicyGenerationOptions = {},
): PolicyGenerationResult {
    const {
        rejectSystemCriticalPaths = true,
        useParentDirectories = false,
    } = options;

    const rejected: Array<{ path: string; reason: string }> = [];
    let addedCount = 0;

    // Start with a deep copy of the original policy
    const newPolicy: SandboxPolicy = structuredClone(originalPolicy);

    // Ensure filesystem section exists
    if (!newPolicy.filesystem) {
        newPolicy.filesystem = {};
    }
    if (!newPolicy.filesystem.readonlyPaths) {
        newPolicy.filesystem.readonlyPaths = [];
    }
    if (!newPolicy.filesystem.readwritePaths) {
        newPolicy.filesystem.readwritePaths = [];
    }

    for (const approval of approvedPaths) {
        let targetPath = path.resolve(approval.path);

        // Detect and reject symlinks/junctions to prevent TOCTOU attacks.
        // realpathSync (below) follows symlinks, so it must only run for
        // non-symlink paths — otherwise rejecting symlinks here and then
        // canonicalizing them anyway would be contradictory.
        let pathExists = true;
        try {
            const stats = fs.lstatSync(targetPath);
            if (stats.isSymbolicLink()) {
                rejected.push({
                    path: approval.path,
                    reason: 'Symbolic links are not allowed in policy paths (TOCTOU risk). Use the real path instead.',
                });
                continue;
            }
        } catch {
            // Path doesn't exist yet — allowed (will be validated at sandbox launch)
            pathExists = false;
        }

        // Resolve to absolute canonical path (only for existing, non-symlink paths)
        if (pathExists) {
            try {
                targetPath = fs.realpathSync(targetPath);
            } catch {
                // Path may not exist yet; use normalized absolute path
                targetPath = path.resolve(targetPath);
            }
        }

        // Optionally use parent directory for file paths
        if (useParentDirectories) {
            const ext = path.extname(targetPath);
            if (ext || !targetPath.endsWith(path.sep)) {
                try {
                    const stats = fs.statSync(targetPath);
                    if (!stats.isDirectory()) {
                        targetPath = path.dirname(targetPath);
                    }
                } catch {
                    // If stat fails, assume it's a file and use parent
                    if (ext) {
                        targetPath = path.dirname(targetPath);
                    }
                }
            }
        }

        // Validate: reject system-critical paths
        if (rejectSystemCriticalPaths && isSystemCriticalPath(targetPath)) {
            rejected.push({
                path: targetPath,
                reason: 'Path is under a system-critical location and cannot be granted to a sandbox',
            });
            continue;
        }

        // Check if already covered by existing policy
        const allExistingPaths = [
            ...newPolicy.filesystem.readwritePaths!,
            ...(approval.accessLevel === 'readonly' ? newPolicy.filesystem.readonlyPaths! : []),
        ];

        if (isPathCovered(targetPath, allExistingPaths)) {
            // Already covered — skip silently
            continue;
        }

        // Add to the appropriate list
        if (approval.accessLevel === 'readwrite') {
            newPolicy.filesystem.readwritePaths!.push(targetPath);
            // Also remove from readonlyPaths if present (readwrite supersedes)
            newPolicy.filesystem.readonlyPaths = newPolicy.filesystem.readonlyPaths!.filter(
                p => {
                    const isWindows = os.platform() === 'win32';
                    const a = isWindows ? path.resolve(p).toLowerCase() : path.resolve(p);
                    const b = isWindows ? targetPath.toLowerCase() : targetPath;
                    return a !== b;
                }
            );
        } else {
            newPolicy.filesystem.readonlyPaths!.push(targetPath);
        }
        addedCount++;
    }

    // Final deduplication
    newPolicy.filesystem.readwritePaths = deduplicatePaths(newPolicy.filesystem.readwritePaths!);
    newPolicy.filesystem.readonlyPaths = deduplicatePaths(newPolicy.filesystem.readonlyPaths!);

    return { policy: newPolicy, rejected, addedCount };
}
