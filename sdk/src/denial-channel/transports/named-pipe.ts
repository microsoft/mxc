// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * Side-channel transport for the captureDenials NDJSON stream.
 *
 * The default transport is stderr (see `denial-stream.ts`), which
 * works fine for non-PTY workloads. PTY mode is different: the
 * point of PTY is interactive workloads (REPLs, vim, npm install
 * with its spinning ASCII, cargo build with colors) that need a
 * clean terminal. Splattering `\x1E{"type":"denial",...}` bytes
 * onto a terminal the user is watching is awful UX, and the
 * 0x1E demuxer is more likely to collide with workload-generated
 * bytes when stdout+stderr are merged into one stream.
 *
 * The side channel solves both problems by routing the
 * captureDenials stream through a private Windows named pipe:
 *
 *   1. SDK creates a named-pipe server with a unique random name.
 *   2. SDK sets `MXC_DENIALS_PIPE=<name>` in the wxc-exec process
 *      env (without the `\\.\pipe\` prefix).
 *   3. wxc-exec on startup opens the pipe for writing and uses it
 *      in place of stderr for both denial lines and the summary.
 *   4. SDK reads from the pipe's accepted-connection socket and
 *      feeds bytes into `parseDenialStream` exactly as it would
 *      for the stderr transport.
 *
 * The workload itself never sees the pipe -- only wxc-exec does.
 * The user's terminal stays clean.
 *
 * Named pipes are a Windows concept. The module type-checks and
 * exports on all platforms but `createDenialPipeServer()` throws
 * with a clear error on non-Windows hosts.
 */

import { createServer, type Server, type Socket } from 'net';
import { randomBytes } from 'crypto';
import * as os from 'os';

/**
 * Outcome of {@link createDenialPipeServer}.
 *
 * `pipeName` is the *base name* (no `\\.\pipe\` prefix) you set in
 * the wxc-exec env as `MXC_DENIALS_PIPE`. The Rust side prepends
 * the prefix.
 *
 * `denialStream` resolves when wxc-exec connects to the server.
 * The returned socket implements the Readable interface expected
 * by `parseDenialStream`. The stream emits `end` when wxc-exec
 * closes its side (typically when the workload exits and the
 * runner's writer thread sees its mpsc channel close). If `close()`
 * is called before any client connects, `denialStream` rejects so
 * the shutdown is observable rather than hanging.
 *
 * `close()` tears down the server and the accepted socket. Safe
 * to call multiple times. Idempotent.
 */
export interface DenialPipeServer {
  pipeName: string;
  denialStream: Promise<Socket>;
  close(): void;
}

/**
 * Create a Windows named-pipe server for the captureDenials side
 * channel.
 *
 * The pipe name is randomised per call so concurrent invocations
 * never collide. Format: `mxc-denials-<8 hex bytes>`. The full
 * path the wxc-exec side opens is `\\.\pipe\<name>`.
 *
 * The server is set to listen for exactly one connection (the
 * wxc-exec process spawned for this run). It auto-closes after the
 * client disconnects.
 *
 * Throws on non-Windows hosts, since named pipes are a Windows
 * concept.
 */
export function createDenialPipeServer(): DenialPipeServer {
  if (os.platform() !== 'win32') {
    throw new Error(
      'createDenialPipeServer: Windows named pipes only.',
    );
  }

  const pipeName = `mxc-denials-${randomBytes(8).toString('hex')}`;
  const fullPath = `\\\\.\\pipe\\${pipeName}`;

  let acceptedSocket: Socket | null = null;
  let server: Server | null = null;
  let closed = false;
  let settled = false;
  let rejectStream: (err: Error) => void = () => {};

  const denialStream = new Promise<Socket>((resolve, reject) => {
    rejectStream = reject;
    server = createServer((socket) => {
      settled = true;
      acceptedSocket = socket;
      // Stop listening after the first (and only expected)
      // connection -- this pipe is private to one wxc-exec run.
      server?.close();
      resolve(socket);
    });

    server.on('error', (err) => {
      if (!closed && !settled) {
        settled = true;
        reject(err);
      }
    });

    server.listen(fullPath, () => {
      // listening; resolve happens on first accept above.
    });
  });

  return {
    pipeName,
    denialStream,
    close() {
      if (closed) return;
      closed = true;
      // If no client ever connected, settle the promise so callers
      // awaiting `denialStream` observe the shutdown instead of
      // hanging forever.
      if (!settled) {
        settled = true;
        rejectStream(
          new Error(
            'createDenialPipeServer: closed before a client connected',
          ),
        );
      }
      try {
        acceptedSocket?.destroy();
      } catch {
        /* ignore */
      }
      try {
        server?.close();
      } catch {
        /* ignore */
      }
    },
  };
}
