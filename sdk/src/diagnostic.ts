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
 * Enabled by environment variable `MXC_DIAG_CONSOLE=1`.
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

/** Cached pipe connection (lazy, best-effort). */
let pipeSocket: net.Socket | null = null;
let pipeConnected = false;
let pipeAttempted = false;
let diagnosticEnabled: boolean | null = null;

/**
 * Check whether diagnostic console logging is enabled via env var.
 */
function isDiagnosticEnabled(): boolean {
    if (diagnosticEnabled !== null) {
        return diagnosticEnabled;
    }

    const envVal = process.env['MXC_DIAG_CONSOLE'];
    diagnosticEnabled =
        envVal === '1' || envVal?.toLowerCase() === 'true';
    return diagnosticEnabled;
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
