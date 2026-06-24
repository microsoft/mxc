// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * Denial channel — cross-platform captureDenials transport.
 *
 * Cross-platform wire transport for `DeniedResource` events:
 *
 * - {@link ./stream | `./stream`} — NDJSON parser + types + dedupe.
 *   The parser is stream-agnostic (reads any `Readable`), so the
 *   "stderr transport" is currently implicit: callers pass
 *   `child.stderr` directly.
 * - {@link ./transports/named-pipe | `./transports/named-pipe`} —
 *   Windows named-pipe server, used when the workload owns the
 *   PTY and the denial stream needs its own channel.
 *
 * Re-exported by the package root so external callers can write
 * `import { parseDenialStream } from '@microsoft/mxc-sdk'`; this
 * file exists to make the subdirectory a coherent unit for
 * internal callers.
 */

export * from './stream.js';
export * from './transports/named-pipe.js';
