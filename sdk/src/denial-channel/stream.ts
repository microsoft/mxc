// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * captureDenials streaming protocol — TypeScript consumer side.
 *
 * When `ContainerConfig.captureDenials` is true, the native binary
 * (`wxc-exec`) captures access denials from the sandboxed process and
 * writes one NDJSON line per captured denial to its own stderr,
 * prefixed with the ASCII Record Separator byte (0x1E):
 *
 * ```text
 * \x1e{"type":"denial","path":"...","resourceType":"...","accessType":"...","pid":N,"filetime":N}\n
 * ...
 * \x1e{"type":"summary","exitCode":N,"totalDenials":N,"deniedResourcesTruncated":bool}\n
 * ```
 *
 * The 0x1E prefix is what makes this safely embeddable in stderr
 * alongside the workload's own stderr writes: the byte is
 * non-printable and effectively never appears in real workload
 * output. Consumers split stderr on 0x1E and parse each non-empty
 * segment as JSON.
 *
 * Scope: filesystem/registry denials only. Network denials have a
 * different shape and are not yet captured; the `DeniedResource`
 * discriminated union is designed so adding a `kind: "network"`
 * variant later is additive.
 */

import type { Readable } from 'stream';

/** ASCII Record Separator. Sentinel byte that prefixes every line in the stream. */
export const DENIAL_STREAM_MARKER = 0x1e;

/** Kind of access the sandboxed process attempted on a denied resource. */
export type DenialAccessType = 'read' | 'write' | 'execute' | 'unknown';

/**
 * Type of resource that was denied. `file` covers both files and
 * directories; `registry` covers Windows registry keys (which are
 * reported by the kernel with the `\REGISTRY\...` namespace prefix).
 * `other` is a fallback for object-manager namespaces we haven't
 * specifically categorised yet.
 */
export type DenialResourceType = 'file' | 'registry' | 'network' | 'other';

/**
 * A single captured access-denial event, in the shape the SDK
 * surfaces to callers. Discriminated union on `kind` so adding new
 * resource families (network, IPC, …) later is additive: existing
 * code that handles `kind === 'file'` keeps working.
 */
export type DeniedResource =
  | {
      kind: 'file';
      /** User-visible path. May still carry `\??\` NT-DOS-namespace prefix if filters are disabled. */
      path: string;
      /** Whether this was a registry key (vs filesystem file/dir). */
      resourceType: Extract<DenialResourceType, 'file' | 'registry' | 'other'>;
      /** Access kind the workload attempted. */
      accessType: DenialAccessType;
      /** PID of the workload process inside the sandbox. */
      pid: number;
      /**
       * Kernel timestamp when the denial was logged (on Windows, a
       * `FILETIME`: 100-ns ticks since 1601). Carried on the wire as a
       * decimal string and surfaced here as a `bigint` so the full
       * 64-bit value round-trips without the precision loss a JS
       * `number` would incur past 2^53-1.
       */
      filetime: bigint;
    };
// (Future: { kind: 'network'; host: string; port: number; protocol: 'tcp'|'udp'|'icmp'; direction: 'outbound'|'inbound'; ... })

/**
 * Summary terminator emitted at the end of the captureDenials
 * stream. Receiving this is the canonical end-of-stream signal for
 * the captureDenials protocol (independent of process exit).
 */
export interface DenialStreamSummary {
  exitCode: number;
  /**
   * Number of *unique* `(path, accessType)` pairs the native binary
   * streamed during the run. Matches the number of `DeniedResource`
   * events a consumer parsed (before applying noise filters).
   */
  totalDenials: number;
  /**
   * True if the internal capture buffer hit its cap and dropped
   * events. Indicates the resource list is incomplete.
   */
  deniedResourcesTruncated: boolean;
  /**
   * True when the runner successfully activated denial capture for
   * this invocation. False when capture was requested
   * (`captureDenials: true` on the config) but the runner couldn't
   * activate it.
   *
   * SDK consumers should check this before treating
   * `totalDenials: 0` as "the workload didn't trip any denials"; an
   * inactive capture also produces 0 streamed denials, but it means
   * something completely different (the feature isn't working).
   */
  captureDenialsActive: boolean;
  /**
   * Best-effort count of distinct child-process PIDs the runner
   * observed under the workload during the run, via a 500-ms
   * poll loop.
   *
   * When descendant tracking is active, denials from descendant PIDs
   * flow into the same stream as the root's. `childProcessesObserved`
   * remains a useful cross-check (it can sometimes catch descendants
   * the primary path missed due to start/exit races, since the two
   * mechanisms have different timing).
   *
   * Very short-lived children that start and exit between polls
   * won't appear here. It is a best-effort signal, not a
   * guarantee.
   */
  childProcessesObserved: number;
  /**
   * Authoritative count of descendant PIDs the runner successfully
   * attached denial capture to. Each descendant that successfully
   * joined is counted once; descendants the runner saw but failed to
   * attach are excluded.
   *
   * Use this rather than `childProcessesObserved` when surfacing a
   * "captured M denials across N descendants" message to the user.
   */
  descendantPidsCovered: number;
  /**
   * Pre-dedupe kernel event count. Only present when the workload
   * was launched with `MXC_DENIAL_VERBOSE=1` in its environment;
   * undefined otherwise. Useful for diagnosing chatty workloads.
   */
  rawEventCount?: number;
}

/**
 * Predicate that returns true to keep a streamed denial and false
 * to drop it. Composed with `defaultDenialFilters` to build the
 * effective filter chain for {@link parseDenialStream}.
 */
export type DenialFilter = (resource: DeniedResource) => boolean;

/**
 * Default filter chain applied to streamed denials unless
 * `filters: 'none'` is passed to {@link parseDenialStream}.
 *
 * These filters remove the bulk of the sandbox "background hum" —
 * access checks the OS records for every sandboxed process regardless
 * of what the workload is actually doing (locale/config probes,
 * loader library searches in system directories, etc.). Callers who
 * need the full unfiltered stream (e.g. for diagnostics or building a
 * noise allow-list) can pass `filters: 'none'`.
 */
export const defaultDenialFilters: readonly DenialFilter[] = [
  // 1. Drop AppContainer-default registry probes
  //    (\REGISTRY\USER\.DEFAULT\Control Panel\*, Software\Classes\*, …).
  //    These are system noise, not workload intent.
  (r) =>
    !(
      r.kind === 'file' &&
      /^\\REGISTRY\\USER\\\.DEFAULT\\/i.test(r.path)
    ),

  // 2. Drop kernel-loader DLL/MUI/MUN/CAT probes under
  //    C:\Windows\System32. These are emitted by the OS loader for
  //    every newly-spawned process and are never something the
  //    workload would prompt the user about.
  (r) =>
    !(
      r.kind === 'file' &&
      /^(?:\\\?\?\\)?C:\\Windows\\System32\\.*\.(?:dll|mui|mun|cat|cdf-ms|nls)$/i.test(
        r.path,
      )
    ),
];

/**
 * Strip the `\??\` NT-DOS-device-namespace prefix that the kernel
 * uses internally so paths surface to the user in the familiar
 * `C:\…` form. No-op for paths that don't carry the prefix
 * (registry keys, already-stripped paths).
 */
export function stripNtPrefix(path: string): string {
  return path.startsWith('\\??\\') ? path.slice(4) : path;
}

/**
 * Outcome of consuming a captureDenials stream end-to-end.
 */
export interface DenialStreamResult {
  /**
   * All resources that survived the filter chain, in arrival order.
   * Already deduped by `(path, accessType)` upstream by the native
   * binary.
   */
  denials: DeniedResource[];
  /**
   * The terminator summary line, if one was observed. Absent only
   * when the stream ended abnormally (process killed before the
   * summary was emitted).
   */
  summary?: DenialStreamSummary;
  /**
   * Count of streamed lines we couldn't parse as JSON. Non-zero
   * indicates a wire-format mismatch (likely a native-binary version
   * skew); consumers should log and continue.
   */
  parseErrors: number;
}

/**
 * Options for {@link parseDenialStream}.
 */
export interface ParseDenialStreamOptions {
  /**
   * Filter chain. Defaults to {@link defaultDenialFilters}. Pass
   * `'none'` to receive the full unfiltered stream, or an array of
   * {@link DenialFilter} predicates to apply in order (all must
   * return true for the resource to be kept).
   */
  filters?: readonly DenialFilter[] | 'none';
  /**
   * If true, strip the `\??\` NT-DOS-device prefix from file paths
   * before they reach the callback / result. Defaults to true —
   * `C:\Users\Foo` reads more naturally than `\??\C:\Users\Foo`.
   */
  stripNtPrefix?: boolean;
  /**
   * Called for every denial that passes the filter chain, in the
   * order the native binary streamed them. Use this to drive
   * mid-run UX (e.g. prompt the user to grant access). The same
   * resources are also accumulated into the final result.
   */
  onDenial?: (resource: DeniedResource) => void;
  /**
   * Called when the summary terminator line is observed. Receiving
   * this means the captureDenials stream is finished (the process
   * may still be alive briefly afterwards).
   */
  onSummary?: (summary: DenialStreamSummary) => void;
  /**
   * Optional hook for stderr bytes that are *not* part of the
   * captureDenials protocol (i.e. anything between 0x1E markers,
   * including the workload's own stderr writes and wxc-exec's error
   * envelopes). Receives raw chunks as they arrive so callers can
   * forward them to their own stderr or to a log.
   */
  onPassthrough?: (chunk: Buffer) => void;
}

/**
 * Consume a `wxc-exec` stderr stream end-to-end, demultiplexing
 * captureDenials NDJSON lines (prefixed with 0x1E) from the
 * workload's own stderr writes.
 *
 * Returns a Promise that resolves when the stream closes, with all
 * parsed denials (already filtered + path-normalised by default)
 * plus the terminator summary line.
 *
 * @example
 * ```typescript
 * import { spawnSandboxFromConfig } from '@microsoft/mxc-sdk';
 * import { parseDenialStream, stripNtPrefix } from '@microsoft/mxc-sdk';
 *
 * const config = createConfigFromPolicy(policy, 'process');
 * config.captureDenials = true;
 * config.process!.commandLine = 'cat /path/to/file.txt';
 *
 * const child = spawnSandboxFromConfig(config, { usePty: false });
 * const result = await parseDenialStream(child.stderr!, {
 *   onDenial: (r) => console.log('Denied:', r.path),
 * });
 * console.log(`Survived filters: ${result.denials.length}`);
 * console.log(`Exit: ${result.summary?.exitCode}`);
 * ```
 *
 * @param stderr - The stderr stream from a `wxc-exec` child process
 *   spawned with `usePty: false`. PTY mode merges stdout+stderr and
 *   is not supported.
 * @param options - {@link ParseDenialStreamOptions} controlling
 *   filtering, path normalisation, and event callbacks.
 */
export function parseDenialStream(
  stderr: Readable,
  options: ParseDenialStreamOptions = {},
): Promise<DenialStreamResult> {
  const filterChain =
    options.filters === 'none'
      ? []
      : options.filters ?? defaultDenialFilters;
  const stripPrefix = options.stripNtPrefix !== false;
  const result: DenialStreamResult = { denials: [], parseErrors: 0 };

  return new Promise<DenialStreamResult>((resolve, reject) => {
    // Accumulator for bytes between 0x1E and \n when a segment
    // straddles chunks. Cleared every time we successfully flush a
    // segment.
    let pending: Buffer = Buffer.alloc(0);
    let inSegment = false;

    const flushSegment = (segment: Buffer) => {
      // A segment ends at the next 0x1E (handled by caller) or at
      // stream close. We trim the trailing newline the native side
      // appends after the JSON.
      let text = segment.toString('utf8');
      if (text.endsWith('\n')) text = text.slice(0, -1);
      if (text.length === 0) return;

      let parsed: unknown;
      try {
        parsed = JSON.parse(text);
      } catch {
        result.parseErrors += 1;
        return;
      }

      if (!parsed || typeof parsed !== 'object') {
        result.parseErrors += 1;
        return;
      }
      const obj = parsed as Record<string, unknown>;

      if (obj.type === 'denial') {
        const resource = denialFromWire(obj);
        if (!resource) {
          result.parseErrors += 1;
          return;
        }
        const normalized = stripPrefix
          ? { ...resource, path: stripNtPrefix(resource.path) }
          : resource;
        for (const f of filterChain) {
          if (!f(normalized)) return;
        }
        result.denials.push(normalized);
        options.onDenial?.(normalized);
        return;
      }

      if (obj.type === 'summary') {
        const summary = summaryFromWire(obj);
        if (!summary) {
          result.parseErrors += 1;
          return;
        }
        result.summary = summary;
        options.onSummary?.(summary);
        return;
      }

      // Unknown envelope type — count as a parse error so a future
      // native-binary version that adds new envelope types is
      // visible to callers rather than silently dropped.
      result.parseErrors += 1;
    };

    stderr.on('data', (chunkRaw: Buffer | string) => {
      // A Readable with an encoding set (e.g. setEncoding('utf8'))
      // emits string chunks; coerce to Buffer so the byte-wise scan
      // and 0x1E comparisons below stay correct.
      const chunk = Buffer.isBuffer(chunkRaw)
        ? chunkRaw
        : Buffer.from(chunkRaw);
      // State machine:
      //   not-in-segment + 0x1E  -> enter segment
      //   not-in-segment + byte  -> passthrough byte
      //   in-segment + '\n'      -> close segment (flush), exit segment
      //   in-segment + byte      -> accumulate
      //
      // We walk the chunk once, batching consecutive passthrough or
      // segment bytes into a single slice per call to minimize copies.
      let i = 0;
      while (i < chunk.length) {
        const byte = chunk[i];
        if (!inSegment) {
          if (byte === DENIAL_STREAM_MARKER) {
            inSegment = true;
            i += 1;
            continue;
          }
          // Run-length scan for the next 0x1E and emit everything
          // before it as a single passthrough chunk.
          let j = i + 1;
          while (j < chunk.length && chunk[j] !== DENIAL_STREAM_MARKER) j += 1;
          if (options.onPassthrough) {
            options.onPassthrough(chunk.subarray(i, j));
          }
          i = j;
          continue;
        }
        // In segment: scan for terminating newline.
        let j = i;
        while (j < chunk.length && chunk[j] !== 0x0a) j += 1;
        if (j < chunk.length) {
          // Found '\n'. Combine with pending bytes from prior chunks
          // (if any) and flush.
          const segment =
            pending.length > 0
              ? Buffer.concat([pending, chunk.subarray(i, j)])
              : chunk.subarray(i, j);
          flushSegment(segment);
          pending = Buffer.alloc(0);
          inSegment = false;
          i = j + 1; // skip the newline itself
        } else {
          // Segment continues into next chunk; buffer what we have.
          pending = Buffer.concat([pending, chunk.subarray(i)]);
          i = chunk.length;
        }
      }
    });

    stderr.on('end', () => {
      // Flush any pending in-segment bytes as a final record. This
      // handles the (legal) case where the writer didn't append a
      // trailing newline after the summary line.
      if (inSegment && pending.length > 0) {
        flushSegment(pending);
        pending = Buffer.alloc(0);
      }
      resolve(result);
    });

    stderr.on('error', (err) => reject(err));
  });
}

/**
 * Convert a wire-format `denial` JSON envelope into a typed
 * {@link DeniedResource}. Returns null when required fields are
 * missing or have the wrong type so the parser can count the line
 * as a parseError rather than throwing.
 */
function denialFromWire(obj: Record<string, unknown>): DeniedResource | null {
  if (typeof obj.path !== 'string') return null;
  if (typeof obj.pid !== 'number') return null;
  // filetime is carried as a decimal string (see model.rs) to preserve
  // full 64-bit precision. Accept a number too for forward/backward
  // tolerance, but coerce both to bigint.
  let filetime: bigint;
  try {
    if (typeof obj.filetime === 'string') {
      filetime = BigInt(obj.filetime);
    } else if (typeof obj.filetime === 'number' && Number.isInteger(obj.filetime)) {
      filetime = BigInt(obj.filetime);
    } else {
      return null;
    }
  } catch {
    return null;
  }

  const resourceTypeStr = typeof obj.resourceType === 'string' ? obj.resourceType : 'other';
  const accessTypeStr = typeof obj.accessType === 'string' ? obj.accessType : 'unknown';

  const resourceType: DeniedResource['resourceType'] =
    resourceTypeStr === 'file' || resourceTypeStr === 'registry' ? resourceTypeStr : 'other';
  const accessType: DenialAccessType =
    accessTypeStr === 'read' || accessTypeStr === 'write' || accessTypeStr === 'execute'
      ? accessTypeStr
      : 'unknown';

  return {
    kind: 'file',
    path: obj.path,
    resourceType,
    accessType,
    pid: obj.pid,
    filetime,
  };
}

/**
 * Convert a wire-format `summary` JSON envelope into a typed
 * {@link DenialStreamSummary}. Returns null when required fields
 * are missing or have the wrong type.
 */
function summaryFromWire(obj: Record<string, unknown>): DenialStreamSummary | null {
  if (typeof obj.exitCode !== 'number') return null;
  if (typeof obj.totalDenials !== 'number') return null;
  if (typeof obj.deniedResourcesTruncated !== 'boolean') return null;
  // captureDenialsActive landed in a later native-binary version. We
  // accept its absence (treat as true) so older binaries that don't
  // emit the field don't trip the parser; new binaries always emit
  // it.
  const captureDenialsActive =
    typeof obj.captureDenialsActive === 'boolean' ? obj.captureDenialsActive : true;
  // Same forward-compat policy for childProcessesObserved -- older
  // binaries that don't yet poll for children get treated as if no
  // children were observed (the conservative answer).
  const childProcessesObserved =
    typeof obj.childProcessesObserved === 'number' ? obj.childProcessesObserved : 0;
  // descendantPidsCovered landed in Phase E of the descendant-tracking
  // work. Older `wxc-exec` builds (everything before Phase E) don't
  // emit the field; treat its absence as 0 so a recent SDK against an
  // older runner stays sane.
  const descendantPidsCovered =
    typeof obj.descendantPidsCovered === 'number' ? obj.descendantPidsCovered : 0;
  const summary: DenialStreamSummary = {
    exitCode: obj.exitCode,
    totalDenials: obj.totalDenials,
    deniedResourcesTruncated: obj.deniedResourcesTruncated,
    captureDenialsActive,
    childProcessesObserved,
    descendantPidsCovered,
  };
  if (typeof obj.rawEventCount === 'number') {
    summary.rawEventCount = obj.rawEventCount;
  }
  return summary;
}
