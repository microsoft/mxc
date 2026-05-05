// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * Diagnostic logging for the MXC SDK.
 *
 * When the MXC diagnostic console (`mxc-diagnostic-console.exe`) is running,
 * this module sends log messages to it over the shared named pipe.
 * Messages are best-effort: if the console is not running or the pipe
 * write fails, the error is silently ignored.
 *
 * Enabled by environment variable `MXC_DIAG_CONSOLE=1` or Windows registry
 * key `HKLM\SOFTWARE\Microsoft\MXC\Diagnostics\ConsoleEnabled` = 1.
 */

import { execSync } from 'child_process';
import * as net from 'net';
import * as os from 'os';

/**
 * Compute the per-user pipe name (includes current user's SID).
 * Falls back to the base name if the SID cannot be determined.
 */
function getDiagnosticPipeName(): string {
    const baseName = '\\\\.\\pipe\\mxc-diagnostics';
    try {
        const output = execSync('whoami /user /fo csv /nh', {
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
        // Best-effort: fall back to base name without SID.
    }
    return baseName;
}

const PIPE_NAME = getDiagnosticPipeName();
const REGISTRY_KEY = 'HKLM\\SOFTWARE\\Microsoft\\MXC\\Diagnostics';
const REGISTRY_VALUE = 'ConsoleEnabled';

/** Cached pipe connection (lazy, best-effort). */
let pipeSocket: net.Socket | null = null;
let pipeConnected = false;
let pipeAttempted = false;
let diagnosticEnabled: boolean | null = null;

/**
 * Check whether diagnostic console logging is enabled via env var or registry.
 */
function isDiagnosticEnabled(): boolean {
    if (diagnosticEnabled !== null) {
        return diagnosticEnabled;
    }

    // Environment variable takes precedence.
    const envVal = process.env['MXC_DIAG_CONSOLE'];
    if (envVal === '1' || envVal?.toLowerCase() === 'true') {
        diagnosticEnabled = true;
        return true;
    }
    if (envVal === '0' || envVal?.toLowerCase() === 'false') {
        diagnosticEnabled = false;
        return false;
    }

    // On Windows, check registry (best-effort, shell-based).
    // Note: @vscode/windows-registry would be cleaner but requires native compilation.
    if (os.platform() === 'win32') {
        try {
            const result = execSync(
                `reg query "${REGISTRY_KEY}" /v ${REGISTRY_VALUE} 2>nul`,
                { encoding: 'utf-8', timeout: 1000 },
            );
            const match = result.match(/REG_DWORD\s+(0x[0-9a-fA-F]+)/);
            if (match && parseInt(match[1], 16) === 1) {
                diagnosticEnabled = true;
                return true;
            }
        } catch (e) {
            // Registry key doesn't exist or access denied -- not actionable.
            console.debug('MXC diagnostics: registry check failed:', e);
        }
    }

    diagnosticEnabled = false;
    return false;
}

/**
 * Ensure the pipe is connected (lazy, best-effort).
 */
function ensurePipe(): net.Socket | null {
    if (pipeConnected && pipeSocket) {
        return pipeSocket;
    }
    if (pipeAttempted) {
        return null;
    }

    // Only supported on Windows.
    if (os.platform() !== 'win32') {
        pipeAttempted = true;
        return null;
    }

    pipeAttempted = true;

    try {
        const socket = net.createConnection(PIPE_NAME);
        // Track connection state.
        socket.on('connect', () => {
            pipeConnected = true;
        });
        socket.on('error', () => {
            pipeConnected = false;
            pipeSocket = null;
        });
        socket.on('close', () => {
            pipeConnected = false;
            pipeSocket = null;
        });
        // Don't let the pipe keep the process alive.
        socket.unref();

        pipeSocket = socket;
        // Connection is in-flight; the 'connect' handler sets pipeConnected.
        // First message may be dropped, which is acceptable for best-effort diagnostics.
        return null;
    } catch {
        return null;
    }
}

/**
 * Send a diagnostic log message to the MXC diagnostic console.
 *
 * Messages are best-effort and non-blocking. If the console is not
 * running, the message is silently dropped.
 *
 * Each message is sent as a newline-delimited JSON envelope so the
 * console can split coalesced stream writes back into individual messages.
 *
 * @param message - The log message to send
 */
export function diagLog(message: string): void {
    if (!isDiagnosticEnabled()) {
        return;
    }

    const socket = ensurePipe();
    if (!socket) {
        return;
    }

    try {
        const envelope = JSON.stringify({ msg: `[SDK] ${message}` }) + '\n';
        socket.write(envelope);
    } catch {
        // Best-effort: ignore write errors.
    }
}

/**
 * Close the diagnostic pipe connection. Called during cleanup.
 */
export function diagClose(): void {
    if (pipeSocket) {
        try {
            pipeSocket.destroy();
        } catch {
            // Ignore.
        }
        pipeSocket = null;
        pipeConnected = false;
    }
}
