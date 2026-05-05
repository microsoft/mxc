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

import * as net from 'net';
import * as os from 'os';

const PIPE_NAME = '\\\\.\\pipe\\mxc-diagnostics';

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

    // On Windows, check registry (best-effort).
    if (os.platform() === 'win32') {
        try {
            const { execSync } = require('child_process');
            const result = execSync(
                'reg query "HKLM\\SOFTWARE\\Microsoft\\MXC\\Diagnostics" /v ConsoleEnabled 2>nul',
                { encoding: 'utf-8', timeout: 1000 },
            );
            if (result.includes('0x1')) {
                diagnosticEnabled = true;
                return true;
            }
        } catch {
            // Registry key doesn't exist or access denied.
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
        pipeConnected = true;
        return socket;
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
