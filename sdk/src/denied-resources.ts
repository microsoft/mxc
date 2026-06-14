// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * Denied resource detection and policy regeneration utilities.
 *
 * Provides functions to:
 * 1. Parse process output for access-denied errors and extract affected paths
 * 2. Generate updated policies with user-approved paths added
 */

import * as os from 'os';
import * as path from 'path';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/**
 * Information about a resource that appears to have been denied access,
 * extracted from process output.
 */
export interface DeniedResourceInfo {
    /** The resource path/name that was denied access */
    path: string;
    /** Type of resource that was denied */
    resourceType: 'file' | 'network';
    /** How this denial was detected */
    source: 'output_parsing' | 'etw_service';
    /** Detection confidence: 'high' for ETW (kernel-verified), 'low' for output parsing (can be faked) */
    confidence: 'high' | 'low';
    /** Type of access that was denied, if determinable */
    accessType?: 'read' | 'write' | 'execute' | 'unknown';
    /** The raw line from the output that contained the denial */
    matchedLine?: string;
    /** The pattern/runtime that matched (for diagnostics) */
    matchedPattern?: string;
}

// ---------------------------------------------------------------------------
// Pattern library
// ---------------------------------------------------------------------------

interface DenialPattern {
    /** Name for diagnostics */
    name: string;
    /** Regex to match. Must have a capturing group for the path. */
    regex: RegExp;
    /** Which capture group contains the path (default: 1) */
    pathGroup?: number;
    /** Inferred access type when this pattern matches */
    accessType: 'read' | 'write' | 'execute' | 'unknown';
    /** Type of resource this pattern detects */
    resourceType: 'file' | 'network';
}

/**
 * Library of patterns that detect access-denied errors across common
 * runtimes and languages on Windows.
 */
const DENIAL_PATTERNS: DenialPattern[] = [
    // -----------------------------------------------------------------------
    // Filesystem patterns
    // -----------------------------------------------------------------------

    // Python PermissionError with path
    {
        name: 'python_permission_error',
        regex: /PermissionError: \[(?:WinError \d+|Errno \d+)\][^']{0,500}'([^']+)'/g,
        accessType: 'write',
        resourceType: 'file',
    },
    // Python OSError / FileNotFoundError that mentions "Access is denied"
    {
        name: 'python_os_error_access_denied',
        regex: /(?:OSError|PermissionError):[^']{0,500}Access is denied[^']{0,500}'([^']+)'/gi,
        accessType: 'unknown',
        resourceType: 'file',
    },
    // Node.js EACCES
    {
        name: 'nodejs_eacces',
        regex: /EACCES:.*?'([^']+)'/g,
        accessType: 'unknown',
        resourceType: 'file',
    },
    // Node.js EPERM
    {
        name: 'nodejs_eperm',
        regex: /EPERM:.*?'([^']+)'/g,
        accessType: 'write',
        resourceType: 'file',
    },
    // PowerShell access denied with path
    {
        name: 'powershell_access_denied',
        regex: /Access to the path '([^']+)' is denied/g,
        accessType: 'write',
        resourceType: 'file',
    },
    // PowerShell UnauthorizedAccessException
    {
        name: 'powershell_unauthorized',
        regex: /UnauthorizedAccessException[^']{0,500}'([^']+)'/g,
        accessType: 'unknown',
        resourceType: 'file',
    },
    // .NET / C# IOException access denied
    {
        name: 'dotnet_io_exception',
        regex: /IOException:[^']{0,500}Access[^']{0,500}denied[^']{0,500}'([^']+)'/gi,
        accessType: 'unknown',
        resourceType: 'file',
    },
    // Windows native "Access is denied" with a preceding or following path
    // Pattern: path then "Access is denied"
    {
        name: 'windows_native_path_then_denied',
        regex: /([A-Za-z]:\\[^\s'"*?<>|]+)\s*[-:]?\s*Access is denied/gi,
        accessType: 'unknown',
        resourceType: 'file',
    },
    // Windows native "Access is denied" with path after
    {
        name: 'windows_native_denied_then_path',
        regex: /Access is denied[.:]?\s*['"]?([A-Za-z]:\\[^\s'"*?<>|]+)/gi,
        accessType: 'unknown',
        resourceType: 'file',
    },
    // Linux permission denied with path
    {
        name: 'linux_permission_denied',
        regex: /permission denied[:\s]+['"]?(\/[^\s'"]+)/gi,
        accessType: 'unknown',
        resourceType: 'file',
    },
    // Generic "cannot open" / "cannot access" with path
    {
        name: 'generic_cannot_access',
        regex: /cannot (?:open|access|read|write|create|delete)\s+['"]?([A-Za-z]:\\[^\s'"*?<>|]+|\/[^\s'"]+)/gi,
        accessType: 'unknown',
        resourceType: 'file',
    },
    // Rust std::io::Error style (code 5 = ACCESS_DENIED)
    {
        name: 'rust_io_error',
        regex: /Os \{ code: 5,.*?['"]([^'"]+)['"]/g,
        accessType: 'unknown',
        resourceType: 'file',
    },

    // -----------------------------------------------------------------------
    // Network patterns
    // -----------------------------------------------------------------------

    {
        name: 'node_econnrefused',
        regex: /Error: connect ECONNREFUSED (\S+)/g,
        pathGroup: 1,
        accessType: 'unknown',
        resourceType: 'network',
    },
    {
        name: 'python_connection_refused',
        regex: /ConnectionRefusedError:[^'"]{0,500}(?:connect to|connecting to)\s+['"]?(\S+?)['"]?(?:\s|$|,)/g,
        pathGroup: 1,
        accessType: 'unknown',
        resourceType: 'network',
    },
    {
        name: 'generic_connection_refused',
        regex: /Connection refused[:\s]+(\S+)/gi,
        pathGroup: 1,
        accessType: 'unknown',
        resourceType: 'network',
    },
    {
        name: 'dns_resolution_failed',
        regex: /(?:getaddrinfo|DNS lookup) (?:ENOTFOUND|failed)[:\s]+(\S+)/gi,
        pathGroup: 1,
        accessType: 'unknown',
        resourceType: 'network',
    },
    {
        name: 'winhttp_error',
        regex: /WinHttpSendRequest[^\r\n]{0,500}(?:error|failed)[^\r\n]{0,500}?(\S+:\d+)/gi,
        pathGroup: 1,
        accessType: 'unknown',
        resourceType: 'network',
    },

];

// ---------------------------------------------------------------------------
// Parser implementation
// ---------------------------------------------------------------------------

/**
 * Upper bound on the total output scanned for denial patterns. Output beyond
 * this is truncated before matching to bound CPU/memory on pathological input.
 */
const MAX_OUTPUT_LENGTH = 1024 * 1024; // 1 MiB

/** Upper bound on a single line; longer lines are truncated before matching. */
const MAX_LINE_LENGTH = 8 * 1024; // 8 KiB

/**
 * Single case-insensitive matcher for the denial keyword pre-filter. Replaces a
 * per-keyword `String.includes` scan over a lowercased copy of the (potentially
 * multi-MB) buffer — testing this regex avoids duplicating the whole buffer.
 * The alternation must cover a distinctive marker from every pattern below.
 */
const DENIAL_KEYWORD_REGEX =
    /denied|permission|eacces|eperm|access|cannot|code: 5|econnrefused|refused|getaddrinfo|dns lookup|enotfound|winhttp|not permitted/i;

/**
 * Parse process output (stdout/stderr, possibly interleaved) for access-denied
 * errors and extract the filesystem paths that were denied.
 *
 * Uses a library of regex patterns covering Python, Node.js, PowerShell,
 * .NET, native Windows, and Linux runtimes.
 *
 * @param output - The raw process output to scan
 * @returns Array of denied resource info, deduplicated by path
 */
export function parseDeniedResources(output: string): DeniedResourceInfo[] {
    if (!output) {
        return [];
    }

    // Bound total work: truncate the buffer, then cap any over-long individual
    // line. This defends against adversarial/runaway output without breaking
    // matching on normal multi-line process output.
    let scanned = output.length > MAX_OUTPUT_LENGTH
        ? output.slice(0, MAX_OUTPUT_LENGTH)
        : output;
    if (scanned.includes('\n')) {
        scanned = scanned
            .split('\n')
            .map(line => (line.length > MAX_LINE_LENGTH ? line.slice(0, MAX_LINE_LENGTH) : line))
            .join('\n');
    } else if (scanned.length > MAX_LINE_LENGTH) {
        scanned = scanned.slice(0, MAX_LINE_LENGTH);
    }

    // Pre-filter: skip the full pattern library if the output contains no
    // denial-related keywords. A single case-insensitive RegExp.test avoids
    // allocating a lowercased copy of the entire buffer.
    if (!DENIAL_KEYWORD_REGEX.test(scanned)) {
        return [];
    }

    const results: Map<string, DeniedResourceInfo> = new Map();

    for (const pattern of DENIAL_PATTERNS) {
        // Reset regex state for global patterns
        pattern.regex.lastIndex = 0;

        let match: RegExpExecArray | null;
        while ((match = pattern.regex.exec(scanned)) !== null) {
            const pathGroup = pattern.pathGroup ?? 1;
            const rawPath = match[pathGroup];
            if (!rawPath) continue;

            // For filesystem resources, normalize and validate the path
            // For non-filesystem resources, use the raw value as-is
            let key: string;
            let resolvedPath: string;
            if (pattern.resourceType === 'file') {
                resolvedPath = normalizePath(rawPath);
                if (!isPlausiblePath(resolvedPath)) continue;
                key = resolvedPath.toLowerCase();
            } else {
                resolvedPath = rawPath.trim();
                key = `${pattern.resourceType}:${resolvedPath.toLowerCase()}`;
            }

            // Deduplicate by key (keep first match)
            if (!results.has(key)) {
                results.set(key, {
                    path: resolvedPath,
                    resourceType: pattern.resourceType,
                    source: 'output_parsing',
                    confidence: 'low',
                    accessType: pattern.accessType,
                    matchedLine: getMatchLine(scanned, match.index),
                    matchedPattern: pattern.name,
                });
            }
        }
    }

    return Array.from(results.values());
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Normalize a path (resolve relative, clean separators) */
function normalizePath(rawPath: string): string {
    // Trim trailing punctuation that may have been captured
    let cleaned = rawPath.replace(/[.,;:!?)}\]]+$/, '');
    // On Windows, normalize forward slashes
    if (os.platform() === 'win32') {
        cleaned = cleaned.replace(/\//g, '\\');
    }
    return path.resolve(cleaned);
}

/** Check if a string looks like a plausible filesystem path */
function isPlausiblePath(p: string): boolean {
    if (os.platform() === 'win32') {
        // Must start with drive letter
        return /^[A-Za-z]:\\/.test(p) && p.length > 3;
    }
    // Unix: must start with /
    return p.startsWith('/') && p.length > 1;
}

/** Extract the line containing the match from the full output */
function getMatchLine(output: string, matchIndex: number): string {
    const lineStart = output.lastIndexOf('\n', matchIndex) + 1;
    const lineEnd = output.indexOf('\n', matchIndex);
    return output.slice(lineStart, lineEnd === -1 ? undefined : lineEnd).trim();
}

