// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * Denial service client — connects to the MXC denial-tracking service
 * over a named pipe to retrieve real-time ETW-based access denial events.
 *
 * The denial service (mxc-denial-service) runs per-user and exposes a
 * named pipe at \\.\pipe\mxc-denials-{SID}. Clients connect, send a
 * JSON query, and receive denial events as newline-delimited JSON.
 *
 * Graceful fallback: if the pipe is not available (service not running),
 * all functions return empty results so callers can fall back to
 * output-parsing-based denial detection.
 *
 * ## Obtaining the sandboxed PID
 *
 * The service keys denial events by the **sandboxed process PID** (the actual
 * offending process). At the SDK layer this PID is **not directly observable**:
 * `spawnSandbox` returns a node-pty `IPty` whose `.pid` is the `wxc-exec`
 * launcher process, and the sandboxed process runs as a descendant of it.
 * The SDK therefore cannot reliably discover the inner PID on its own.
 *
 * Callers that *do* know the sandboxed PID (e.g. parsed from process output,
 * or surfaced by a future `wxc-exec` announcement on stdout) should pass it via
 * {@link DenialFilter.pid} / `DetectionOptions.pid`; it is the preferred filter.
 * When no PID is available the `containerName` secondary filter is used as a
 * best-effort fallback.
 *
 * ## Server identity
 *
 * Ideally a client would verify the pipe server is SYSTEM or the installed
 * service account via `GetNamedPipeServerProcessId` before trusting events.
 * That Win32 call is not reachable from pure Node without a native addon, which
 * the SDK deliberately avoids. As mitigation the SDK (a) fails closed on the
 * pipe name (never connecting to an un-SID-qualified pipe, see
 * {@link getDenialServicePipeName}) and (b) structurally validates every event
 * received from the pipe before use (see `validateDenialEvent`).
 */

import { execFileSync } from 'child_process';
import * as fs from 'fs';
import * as net from 'net';
import * as os from 'os';
import * as path from 'path';
import { fileURLToPath } from 'node:url';

import { DeniedResourceInfo } from './denied-resources.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/**
 * A denial event as reported by the ETW-based denial service.
 */
export interface DenialEvent {
    /** The resource path that was denied */
    path: string;
    /** Type of resource */
    resourceType: 'file' | 'network' | 'other';
    /** Type of access that was denied */
    accessType: 'read' | 'write' | 'execute' | 'unknown';
    /**
     * Best-effort AppContainer/profile name the denial occurred in.
     * May be empty: the service keys events by `pid`, not by container name.
     */
    containerName: string;
    /** PID of the sandboxed process that triggered the denial */
    pid: number;
    /** Timestamp of the denial event (fixed-width ISO 8601, e.g. 2026-01-15T10:30:00Z) */
    timestamp: string;
    /**
     * Unique event identifier from the service wire format. The service
     * serializes this as a JSON number (optional for older service versions).
     */
    eventId?: number;
}

/**
 * Filter describing which denial events a caller is interested in.
 *
 * **`pid` is the primary match key** — the denial service keys events by the
 * sandboxed process PID and may emit an empty `containerName`. Prefer supplying
 * `pid`. `containerName` is an optional secondary filter.
 */
export interface DenialFilter {
    /**
     * The sandboxed process PID to filter denials for. This is the canonical
     * match key. See the module docs for how to obtain it.
     */
    pid?: number;
    /** Optional AppContainer/profile name (secondary, best-effort) filter. */
    containerName?: string;
    /**
     * Only return events with a timestamp greater than or equal to this
     * fixed-width ISO 8601 timestamp.
     */
    since?: string;
}

/**
 * Unified request sent to the denial service over the named pipe.
 *
 * `mode` is canonical: `'snapshot'` returns the current buffered denials then
 * closes; `'stream'` keeps the connection open and streams new events. The
 * legacy `subscribe: true` flag is also sent alongside `mode: 'stream'` for
 * backward compatibility with older service builds.
 */
export interface DenialRequest {
    /** Query mode: 'snapshot' returns current denials, 'stream' keeps connection open */
    mode: 'snapshot' | 'stream';
    /** Optional AppContainer/profile name filter (secondary). */
    containerName?: string;
    /** Optional PID filter (primary match key). */
    pid?: number;
    /** Optional ISO 8601 lower bound on event timestamps. */
    since?: string;
    /** Legacy flag for older service builds; set when mode === 'stream'. */
    subscribe?: boolean;
}

/**
 * Maximum accepted length for a denial event path. Events whose path exceeds
 * this bound are rejected as implausible (defends against a malicious or
 * malformed pipe peer flooding memory). 32 KiB comfortably covers the Windows
 * extended-length path maximum.
 */
const MAX_EVENT_PATH_LENGTH = 32 * 1024;

// ---------------------------------------------------------------------------
// Service binary discovery
// ---------------------------------------------------------------------------

/**
 * Returns the path to the mxc-diagnostic-console binary shipped with the SDK,
 * or null if not found. Consumers can use this to install the service:
 *
 * @example
 * ```ts
 * import { getServiceBinaryPath } from '@microsoft/mxc-sdk';
 * const binPath = getServiceBinaryPath();
 * if (binPath) {
 *   execSync(`"${binPath}" --install`, { stdio: 'inherit' });
 * }
 * ```
 */
export function getServiceBinaryPath(): string | null {
    const binaryName = 'mxc-diagnostic-console.exe';
    const arch = os.arch();
    const targetTriple = arch === 'arm64'
        ? 'aarch64-pc-windows-msvc'
        : 'x86_64-pc-windows-msvc';

    const possiblePaths = [
        // Bundled in the SDK package (npm-packaged)
        path.join(__dirname, '..', 'bin', targetTriple, binaryName),
        // Architecture-specific release build output (monorepo dev)
        path.join(__dirname, '..', '..', 'src', 'target', targetTriple, 'release', binaryName),
        // Architecture-specific debug build output (monorepo dev)
        path.join(__dirname, '..', '..', 'src', 'target', targetTriple, 'debug', binaryName),
        // Default Cargo release build output (no explicit --target)
        path.join(__dirname, '..', '..', 'src', 'target', 'release', binaryName),
        // Default Cargo debug build output (no explicit --target)
        path.join(__dirname, '..', '..', 'src', 'target', 'debug', binaryName),
    ];

    for (const candidate of possiblePaths) {
        try {
            if (fs.existsSync(candidate) && fs.statSync(candidate).isFile()) {
                return candidate;
            }
        } catch {
            // Skip inaccessible paths
        }
    }

    return null;
}

// ---------------------------------------------------------------------------
// Pipe name resolution
// ---------------------------------------------------------------------------

/**
 * Compute the per-user denial service pipe name (includes current user's SID).
 *
 * Fails closed: returns `null` on non-Windows platforms and whenever the
 * current user's SID cannot be resolved. We never return the bare
 * `\\.\pipe\mxc-denials` name without a SID, since connecting to an
 * un-SID-qualified pipe could expose the client to a spoofed server. Callers
 * must treat `null` as "service unavailable" and skip the ETW tier.
 */
function getDenialServicePipeName(): string | null {
    if (os.platform() !== 'win32') {
        return null;
    }

    const baseName = '\\\\.\\pipe\\mxc-denials';
    try {
        const systemRoot = process.env['SystemRoot'] || process.env['SYSTEMROOT'] || 'C:\\Windows';
        const whoamiPath = path.join(systemRoot, 'System32', 'whoami.exe');
        const output = execFileSync(whoamiPath, ['/user', '/fo', 'csv', '/nh'], {
            encoding: 'utf8',
            timeout: 3000,
            windowsHide: true,
        }).trim();
        // Output is like: "DOMAIN\\user","S-1-5-21-..."
        const match = output.match(/"(S-[\d-]+)"/);
        if (match) {
            return `${baseName}-${match[1]}`;
        }
    } catch {
        // Fall through to fail-closed below.
    }
    // Fail closed: no SID resolved means we cannot safely target the pipe.
    return null;
}

// Cache the pipe name (SID doesn't change during a process lifetime)
let cachedPipeName: string | null | undefined;

function getPipeName(): string | null {
    if (cachedPipeName === undefined) {
        cachedPipeName = getDenialServicePipeName();
    }
    return cachedPipeName;
}

// ---------------------------------------------------------------------------
// Service availability check
// ---------------------------------------------------------------------------

/**
 * Classify a thrown `fs.accessSync` probe error into a service-running verdict.
 *
 * Exported for unit testing the error-code branches in isolation -- exercising
 * the real branches against a live named pipe is not safe in the test suite
 * because the pipe name is global per-user and node:test runs files
 * concurrently, so a real listening pipe would leak into other test files.
 *
 * @param err the error thrown by fs.accessSync (expected NodeJS.ErrnoException)
 * @returns true if the error indicates the pipe object still exists
 */
export function pipeProbeErrorIndicatesRunning(err: unknown): boolean {
    const code = (err as NodeJS.ErrnoException).code;
    // ENOENT means the pipe object is genuinely absent -> service is down.
    if (code === 'ENOENT') {
        return false;
    }
    // Any other errno (EBUSY/EACCES/EPIPE/etc.) means the pipe object EXISTS
    // in the namespace -- the server is up but the handle is momentarily
    // unavailable -- so treat the service as running.
    if (code) {
        return true;
    }
    // Unknown/undefined error code: fail closed, consistent with the
    // fail-closed posture used for SID resolution above.
    return false;
}

/**
 * Check whether the denial service is running by testing if the named pipe exists.
 *
 * @returns true if the denial service pipe is available, false otherwise
 */
export function isDenialServiceRunning(): boolean {
    const pipeName = getPipeName();
    if (!pipeName) {
        return false;
    }

    try {
        // Probe for pipe existence. We deliberately use fs.accessSync rather
        // than fs.statSync: on Windows, calling fs.statSync on a *listening*
        // named-pipe instance throws EBUSY (the server side holds the handle),
        // so the previous `statSync(...) -> true / catch -> false` logic
        // reported the service as DOWN even while the pipe was live and
        // connectable. That single mis-detection gated off the entire ETW
        // (Tier-1) detection path. fs.accessSync merely checks namespace
        // presence and does not require an exclusive handle.
        fs.accessSync(pipeName);
        return true;
    } catch (err) {
        return pipeProbeErrorIndicatesRunning(err);
    }
}

// ---------------------------------------------------------------------------
// Snapshot query (one-shot read)
// ---------------------------------------------------------------------------

/**
 * Connect to the denial service and read all denial events matching the given
 * filter. Returns an empty array if the service is not available.
 *
 * **Prefer filtering by `pid`** (the sandboxed process PID) — it is the
 * canonical match key. `containerName` is a best-effort secondary filter.
 *
 * @param filter - Filter selecting which denials to read (pid preferred)
 * @returns Array of denied resource info from the ETW service
 */
export async function readDeniedResources(
    filter: DenialFilter,
): Promise<DeniedResourceInfo[]> {
    const pipeName = getPipeName();
    if (!pipeName) {
        return [];
    }

    const request: DenialRequest = {
        mode: 'snapshot',
        ...(filter.pid !== undefined && { pid: filter.pid }),
        ...(filter.containerName !== undefined && { containerName: filter.containerName }),
        ...(filter.since !== undefined && { since: filter.since }),
    };

    let events: DenialEvent[];
    try {
        events = await sendQuery(pipeName, request);
    } catch {
        // Graceful fallback: service not available
        return [];
    }

    return events
        .filter(validateDenialEvent)
        .map(mapEventToResourceInfo)
        .filter((e): e is DeniedResourceInfo => e !== null);
}

// ---------------------------------------------------------------------------
// Streaming subscription
// ---------------------------------------------------------------------------

/**
 * Subscribe to real-time denial events matching the given filter. The callback
 * is invoked for each validated denial event as it arrives. Returns a dispose
 * function to close the subscription.
 *
 * **Prefer filtering by `pid`** (the sandboxed process PID); `containerName`
 * is a best-effort secondary filter.
 *
 * If the denial service is not available, returns a no-op dispose function
 * and the callback is never invoked.
 *
 * @param filter - Filter selecting which denials to stream (pid preferred)
 * @param callback - Function called for each validated denial event
 * @returns A function to close the subscription
 */
export function subscribeToDenials(
    filter: DenialFilter,
    callback: (event: DenialEvent) => void,
): () => void {
    const pipeName = getPipeName();
    if (!pipeName) {
        return () => {};
    }

    const request: DenialRequest = {
        mode: 'stream',
        subscribe: true,
        ...(filter.pid !== undefined && { pid: filter.pid }),
        ...(filter.containerName !== undefined && { containerName: filter.containerName }),
        ...(filter.since !== undefined && { since: filter.since }),
    };

    let socket: net.Socket | null = null;
    let destroyed = false;

    try {
        socket = net.createConnection(pipeName, () => {
            socket!.write(JSON.stringify(request) + '\n');
        });

        let buffer = '';
        const MAX_BUFFER_SIZE = 1024 * 1024; // 1MB safety limit

        socket.on('data', (chunk: Buffer) => {
            const chunkStr = chunk.toString('utf8');
            // Safety: discard buffer if appending would exceed the limit (malformed stream)
            if (buffer.length + chunkStr.length > MAX_BUFFER_SIZE) {
                buffer = '';
                socket!.destroy();
                return;
            }
            buffer += chunkStr;
            // Process newline-delimited JSON messages
            const lines = buffer.split('\n');
            buffer = lines.pop() ?? '';

            for (const line of lines) {
                const trimmed = line.trim();
                if (!trimmed) continue;
                try {
                    const parsed: unknown = JSON.parse(trimmed);
                    if (validateDenialEvent(parsed)) {
                        callback(parsed);
                    }
                } catch {
                    // Skip malformed lines
                }
            }
        });

        socket.on('error', () => {
            // Silent failure — consistent with graceful fallback
            destroyed = true;
            socket = null;
        });

        socket.on('close', () => {
            destroyed = true;
            socket = null;
        });

        // Don't let the subscription keep the process alive
        socket.unref();
    } catch {
        // Service not available — graceful fallback
        return () => {};
    }

    return () => {
        if (!destroyed && socket) {
            socket.destroy();
            destroyed = true;
            socket = null;
        }
    };
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * Send a request to the denial service pipe and collect the full response.
 * Used for snapshot mode (service sends response then closes).
 */
function sendQuery(pipeName: string, request: DenialRequest): Promise<DenialEvent[]> {
    return new Promise((resolve, reject) => {
        const socket = net.createConnection(pipeName, () => {
            socket.write(JSON.stringify(request) + '\n');
        });

        const MAX_RESPONSE_SIZE = 10 * 1024 * 1024; // 10MB safety limit
        let buffer = '';
        const events: DenialEvent[] = [];

        const tryParse = (line: string): void => {
            try {
                const parsed: unknown = JSON.parse(line);
                if (validateDenialEvent(parsed)) {
                    events.push(parsed);
                }
            } catch {
                // Skip malformed lines
            }
        };

        socket.on('data', (chunk: Buffer) => {
            const chunkStr = chunk.toString('utf8');
            if (buffer.length + chunkStr.length > MAX_RESPONSE_SIZE) {
                buffer = '';
                socket.destroy();
                reject(new Error('Denial service response exceeded size limit'));
                return;
            }
            buffer += chunkStr;
            // Process complete lines as they arrive
            const lines = buffer.split('\n');
            buffer = lines.pop() ?? '';

            for (const line of lines) {
                const trimmed = line.trim();
                if (!trimmed) continue;
                tryParse(trimmed);
            }
        });

        socket.on('end', () => {
            // Process any remaining buffered data
            if (buffer.trim()) {
                tryParse(buffer.trim());
            }
            resolve(events);
        });

        socket.on('error', (err: Error) => {
            reject(err);
        });

        // Timeout to avoid hanging if service doesn't respond
        socket.setTimeout(5000, () => {
            socket.destroy();
            reject(new Error('Denial service query timed out'));
        });

        // Don't let this keep the process alive
        socket.unref();
    });
}

const VALID_RESOURCE_TYPES = new Set(['file', 'network', 'other']);
const VALID_ACCESS_TYPES = new Set(['read', 'write', 'execute', 'unknown']);

/**
 * Structurally validate and normalize a value parsed from the pipe before it is
 * trusted as a {@link DenialEvent}.
 *
 * The pipe peer is not cryptographically authenticated (see the module docs on
 * server identity), so every field is checked defensively:
 * - `path` must be a non-empty string within {@link MAX_EVENT_PATH_LENGTH}
 * - `resourceType` / `accessType` must be members of their respective enums
 * - `pid` must be a finite non-negative integer
 * - `containerName` / `timestamp` must be strings
 *
 * Implausible or malformed events are rejected so they never reach
 * {@link mapEventToResourceInfo}. Acts as a TypeScript type guard.
 */
export function validateDenialEvent(value: unknown): value is DenialEvent {
    if (typeof value !== 'object' || value === null) {
        return false;
    }
    const e = value as Record<string, unknown>;

    if (typeof e['path'] !== 'string') return false;
    const eventPath = e['path'].trim();
    if (eventPath.length === 0 || eventPath.length > MAX_EVENT_PATH_LENGTH) return false;

    if (typeof e['resourceType'] !== 'string' || !VALID_RESOURCE_TYPES.has(e['resourceType'])) {
        return false;
    }
    if (typeof e['accessType'] !== 'string' || !VALID_ACCESS_TYPES.has(e['accessType'])) {
        return false;
    }
    if (typeof e['containerName'] !== 'string') return false;

    const pid = e['pid'];
    if (typeof pid !== 'number' || !Number.isInteger(pid) || pid < 0) return false;

    if (typeof e['timestamp'] !== 'string') return false;

    // eventId is optional; when present it must be a finite number.
    if (e['eventId'] !== undefined) {
        if (typeof e['eventId'] !== 'number' || !Number.isFinite(e['eventId'])) return false;
    }

    return true;
}

/**
 * Map a DenialEvent from the service wire format to a DeniedResourceInfo.
 * Returns `null` for resource types that are not actionable (e.g., 'other').
 *
 * Exported for direct unit testing.
 */
export function mapEventToResourceInfo(event: DenialEvent): DeniedResourceInfo | null {
    if (event.resourceType !== 'file' && event.resourceType !== 'network') {
        // 'other' (registry, unclassified) is not actionable via policy.
        return null;
    }
    return {
        path: event.path,
        resourceType: event.resourceType,
        source: 'etw_service',
        confidence: 'high',
        accessType: event.accessType,
    };
}
