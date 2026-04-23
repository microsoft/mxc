// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * Redeems execution cookies with the AEGIS daemon over a named pipe.
 *
 * Instead of verifying signed tickets locally, the SDK sends the cookie
 * and tool context to the AEGIS daemon, which validates and returns the
 * sandbox envelope.
 */

import * as net from 'net';

const PIPE_NAME = `aegis-${process.env.USERNAME || process.env.USER || 'unknown'}`;

export interface RedeemResult {
  valid: boolean;
  decision?: string;
  reason?: string;
  envelope?: {
    mode?: string;
    sandboxProfile?: string;
    timeoutSeconds?: number;
    networkEnabled?: boolean;
    allowLocalNetwork?: boolean;
    deniedPaths?: string[];
    readonlyPaths?: string[];
    readwritePaths?: string[];
  };
  error?: string;
}

/**
 * Get the named pipe path for the AEGIS daemon.
 */
export function getPipePath(): string {
  return `\\\\.\\pipe\\${PIPE_NAME}`;
}

/**
 * Redeem a cookie with the AEGIS daemon.
 * Sends the cookie + tool context (including raw args), daemon verifies and returns the envelope.
 */
export async function redeemCookie(
  cookie: string,
  toolName: string,
  args: string,
  cwd?: string,
): Promise<RedeemResult> {
  const pipePath = getPipePath();
  const request = JSON.stringify({
    redeem: cookie,
    toolName,
    args,
    ...(cwd !== undefined && { cwd }),
  });

  return new Promise<RedeemResult>((resolve) => {
    let resolved = false;
    const done = (result: RedeemResult) => {
      if (resolved) return;
      resolved = true;
      socket.destroy();
      resolve(result);
    };

    const socket = net.connect(pipePath, () => {
      socket.write(request + '\n');
    });

    socket.setTimeout(10_000);
    socket.on('timeout', () => {
      done({ valid: false, error: 'AEGIS daemon connection timed out (10s)' });
    });

    let data = '';
    socket.on('data', (chunk) => {
      data += chunk.toString();
      const newlineIdx = data.indexOf('\n');
      if (newlineIdx !== -1) {
        const line = data.slice(0, newlineIdx);
        try {
          done(JSON.parse(line) as RedeemResult);
        } catch {
          done({ valid: false, error: `Invalid JSON response from daemon: ${line}` });
        }
      }
    });

    socket.on('error', (err) => {
      done({ valid: false, error: `AEGIS daemon connection failed: ${err.message}` });
    });

    socket.on('end', () => {
      if (data.length > 0) {
        try {
          done(JSON.parse(data.trim()) as RedeemResult);
        } catch {
          done({ valid: false, error: `Invalid JSON response from daemon: ${data}` });
        }
      } else {
        done({ valid: false, error: 'AEGIS daemon closed connection without response' });
      }
    });
  });
}
