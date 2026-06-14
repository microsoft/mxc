// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * Tiered denied-resource detection — combines ETW service and output parsing
 * into a single unified API.
 */

import * as os from 'os';
import * as path from 'path';

import {
    DeniedResourceInfo,
    parseDeniedResources,
} from './denied-resources.js';
import {
    isDenialServiceRunning,
    readDeniedResources,
} from './denial-service.js';
import {
    generateUpdatedPolicy,
    ApprovedPath,
    PolicyGenerationOptions,
    PolicyGenerationResult,
} from './policy-regen.js';
import { SandboxPolicy } from './types.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/**
 * Options for the unified denied-resource detection API.
 */
export interface DetectionOptions {
    /** Container name for ETW service queries (secondary, best-effort filter) */
    containerName?: string;
    /**
     * Sandboxed process ID for ETW service filtering. This is the **primary**
     * match key — supply it when known. See the denial-service module docs for
     * how to obtain the sandboxed PID.
     */
    pid?: number;
    /** stdout/stderr output to parse for denial patterns */
    output?: string;
    /** Timeout in ms for service pipe connection (default: 2000) */
    serviceTimeout?: number;
}

/**
 * Result of tiered denied-resource detection.
 */
export interface DetectionResult {
    /** All detected denied resources (deduplicated, merged from all sources) */
    deniedResources: DeniedResourceInfo[];
    /** Which detection sources were used */
    sourcesUsed: Array<'etw_service' | 'output_parsing'>;
    /** Whether the ETW diagnostic service is running */
    serviceAvailable: boolean;
    /** If the service is not running, a message telling the user how to install it */
    serviceInstallHint?: string;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Extract hostname from a host:port string, handling IPv6 bracket notation.
 * Examples:
 *   "example.com:443" -> "example.com"
 *   "[::1]:443"       -> "::1"
 *   "example.com"     -> "example.com"
 */
function extractHostname(hostPort: string): string {
    // Handle IPv6 bracket notation: [::1]:443 or [::1]
    const ipv6Match = hostPort.match(/^\[([^\]]+)\](?::\d+)?$/);
    if (ipv6Match) return ipv6Match[1];

    // Handle IPv4/hostname: host:port or just host
    const colonIdx = hostPort.lastIndexOf(':');
    if (colonIdx > 0 && /^\d+$/.test(hostPort.slice(colonIdx + 1))) {
        return hostPort.slice(0, colonIdx);
    }
    return hostPort;
}

// ---------------------------------------------------------------------------
// Deduplication
// ---------------------------------------------------------------------------

/** Source priority: lower index = higher priority */
const SOURCE_PRIORITY: Array<DeniedResourceInfo['source']> = [
    'etw_service',
    'output_parsing',
];

/**
 * Compute a deduplication key for a denial entry.
 * Uses normalized path (lowercase on Windows) + resourceType.
 */
function deduplicationKey(denial: DeniedResourceInfo): string {
    const normalizedPath =
        os.platform() === 'win32'
            ? path.normalize(denial.path).toLowerCase()
            : path.normalize(denial.path);
    return `${normalizedPath}|${denial.resourceType}`;
}

/**
 * Remove duplicate denials by normalized path + resourceType.
 * When duplicates exist, prefers entries from higher-priority sources
 * (etw_service > output_parsing).
 */
export function deduplicateDenials(denials: DeniedResourceInfo[]): DeniedResourceInfo[] {
    const map = new Map<string, DeniedResourceInfo>();

    for (const denial of denials) {
        const key = deduplicationKey(denial);
        const existing = map.get(key);
        if (!existing) {
            map.set(key, denial);
        } else {
            // Keep the one with higher-priority source
            const existingPriority = SOURCE_PRIORITY.indexOf(existing.source);
            const newPriority = SOURCE_PRIORITY.indexOf(denial.source);
            if (newPriority < existingPriority) {
                map.set(key, denial);
            }
        }
    }

    return Array.from(map.values());
}

// ---------------------------------------------------------------------------
// Main detection function
// ---------------------------------------------------------------------------

/**
 * Unified denied-resource detection that combines multiple sources:
 * 1. ETW service pipe (real-time kernel-level denials)
 * 2. Output parsing (regex-based detection from process stdout/stderr)
 *
 * Sources are queried in priority order and results are merged with
 * deduplication (ETW > output parsing).
 *
 * @param options - Detection configuration
 * @returns Merged detection results from all available sources
 */
export async function getDeniedResources(options: DetectionOptions): Promise<DetectionResult> {
    const allDenials: DeniedResourceInfo[] = [];
    const sourcesUsed: Array<'etw_service' | 'output_parsing'> = [];
    const serviceAvailable = isDenialServiceRunning();

    // 1. ETW service (highest priority).
    // PID is the canonical match key; containerName is a best-effort secondary
    // filter. Query the service whenever either is available.
    if ((options.pid !== undefined || options.containerName) && serviceAvailable) {
        try {
            const etwResults = await readDeniedResources({
                ...(options.pid !== undefined && { pid: options.pid }),
                ...(options.containerName !== undefined && { containerName: options.containerName }),
            });
            if (etwResults.length > 0) {
                allDenials.push(...etwResults);
                sourcesUsed.push('etw_service');
            }
        } catch {
            // Graceful fallback: service may have become unavailable
        }
    }

    // 2. Output parsing
    if (options.output) {
        const parsed = parseDeniedResources(options.output);
        if (parsed.length > 0) {
            allDenials.push(...parsed);
            sourcesUsed.push('output_parsing');
        }
    }

    return {
        deniedResources: deduplicateDenials(allDenials),
        sourcesUsed,
        serviceAvailable,
        serviceInstallHint: !serviceAvailable
            ? 'The MXC diagnostic service is not running or not reachable. '
              + 'It detects access denials at the kernel level (ETW) for far '
              + 'more accurate results than output parsing.\n'
              + 'Install and start it with the bundled PowerShell script '
              + '(run from an elevated prompt):\n'
              + '  scripts\\Install-MxcDiagnosticService.ps1\n'
              + 'The denial pipe is per-user: the service must run in your '
              + 'interactive logon session to be reachable. Without it, detection '
              + 'falls back to output parsing (less accurate).'
            : undefined,
    };
}

// ---------------------------------------------------------------------------
// Policy generation from detection results
// ---------------------------------------------------------------------------

/**
 * Generate an updated policy from detection results, wrapping
 * `generateUpdatedPolicy` with additional handling for network denials
 * and policy mode validation.
 *
 * @param originalPolicy - The original sandbox policy
 * @param detectionResult - Result from getDeniedResources()
 * @param approvedPaths - Paths the user has approved
 * @param options - Policy generation options
 * @returns Updated policy with approved paths merged
 * @throws Error if originalPolicy has policyMode === 'managed' (immutable)
 */
export function generateUpdatedPolicyFromDetection(
    originalPolicy: SandboxPolicy,
    detectionResult: DetectionResult,
    approvedPaths: ApprovedPath[],
    options?: PolicyGenerationOptions,
): PolicyGenerationResult {
    // Check for managed (immutable) policy
    const policyWithMode = originalPolicy as SandboxPolicy & { policyMode?: string };
    if (policyWithMode.policyMode === 'managed') {
        throw new Error(
            'Cannot modify a managed policy. Policies with policyMode=\'managed\' are immutable.',
        );
    }

    // Generate base policy update from filesystem approvals
    const result = generateUpdatedPolicy(originalPolicy, approvedPaths, options);

    // Handle network denials: add each approved network host to allowedHosts[]
    const networkDenials = detectionResult.deniedResources.filter(
        d => d.resourceType === 'network',
    );

    // Get all network denials that were explicitly approved by the user
    const approvedNetworkHosts = networkDenials
        .filter(nd => approvedPaths.some(ap => ap.path === nd.path))
        .map(nd => extractHostname(nd.path));

    if (approvedNetworkHosts.length > 0) {
        if (!result.policy.network) {
            result.policy.network = {};
        }
        // allowOutbound is required for allowedHosts to work
        result.policy.network.allowOutbound = true;
        // Add individual hosts to the allowlist (deduplicated)
        const existing = result.policy.network.allowedHosts ?? [];
        const merged = [...new Set([...existing, ...approvedNetworkHosts])];
        result.policy.network.allowedHosts = merged;
    }

    return result;
}
