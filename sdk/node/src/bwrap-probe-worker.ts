// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { spawn, ChildProcessByStdio } from 'node:child_process';
import { Readable } from 'node:stream';
import { workerData } from 'node:worker_threads';

// Strip NODE_OPTIONS so a host's loader/inspector/require flags cannot
// interfere with the anchor's minimal, trusted probe supervision.
const spawnEnv = { ...process.env };
delete spawnEnv.NODE_OPTIONS;

interface ProbeWorkerData {
  shared: SharedArrayBuffer;
  anchorPath: string;
  helperPath: string;
  probeTimeoutMs: number;
  publishTimeoutMs: number;
  outputLimit: number;
}

const data = workerData as ProbeWorkerData;
const header = new Int32Array(data.shared, 0, 3);
const payload = new Uint8Array(data.shared, 12);
let anchor: ChildProcessByStdio<null, Readable, null> | undefined;
let output = '';
let finished = false;
let anchorExited = false;
let anchorClosed = false;
let completionRequested = false;
let pendingResult: unknown;
let timeout: NodeJS.Timeout | undefined;

function stopAnchor(): void {
  const pid = anchor?.pid;
  if (!pid || anchorExited) return;
  try {
    process.kill(pid, 'SIGTERM');
  } catch {
    // The process may have exited between the ownership check and the signal.
  }
}

function publish(result: unknown): void {
  if (finished) return;
  finished = true;
  if (timeout) clearTimeout(timeout);
  let encoded = Buffer.from(JSON.stringify(result));
  if (encoded.length > payload.length) {
    encoded = Buffer.from(JSON.stringify({
      kind: 'spawnError',
      detail: 'probe helper result exceeded its bound',
    }));
  }
  payload.set(encoded);
  Atomics.store(header, 1, encoded.length);
  if (Atomics.compareExchange(header, 0, 0, 1) === 0) {
    Atomics.notify(header, 0);
  }
}

function completeAfterCleanup(result: unknown, stop = false): void {
  if (finished || completionRequested) return;
  completionRequested = true;
  pendingResult = result;
  if (stop) stopAnchor();
  if (!anchor || anchorClosed) publish(pendingResult);
}

function handleFatalWorkerError(error: unknown): void {
  const detail = error instanceof Error ? error.message : String(error);
  completeAfterCleanup(
    { kind: 'spawnError', detail: `probe worker failed: ${detail}` },
    true,
  );
}

process.once('uncaughtException', handleFatalWorkerError);
process.once('unhandledRejection', handleFatalWorkerError);

if (Atomics.load(header, 0) === 0) {
  try {
    const spawnedAnchor = spawn(
      process.execPath,
      [
        data.anchorPath,
        data.helperPath,
        String(data.probeTimeoutMs),
        String(data.outputLimit),
      ],
      { detached: true, stdio: ['ignore', 'pipe', 'ignore'], env: spawnEnv },
    );
    anchor = spawnedAnchor;
    const anchorPid = spawnedAnchor.pid;
    if (anchorPid === undefined) {
      completeAfterCleanup({
        kind: 'spawnError',
        detail: 'probe anchor did not receive a process id',
      });
    } else {
      Atomics.store(header, 2, anchorPid);
    }
    if (Atomics.load(header, 0) !== 0) {
      stopAnchor();
    }
    spawnedAnchor.stdout.setEncoding('utf8');
    spawnedAnchor.stdout.on('data', (chunk: string) => {
      output += chunk;
      const newline = output.indexOf('\n');
      if (newline !== -1) {
        try {
          completeAfterCleanup(JSON.parse(output.slice(0, newline)));
        } catch (error) {
          const detail = error instanceof Error ? error.message : String(error);
          completeAfterCleanup(
            { kind: 'spawnError', detail: `invalid probe helper result: ${detail}` },
            true,
          );
        }
      }
    });
    spawnedAnchor.on('error', (error) => {
      completeAfterCleanup({ kind: 'spawnError', detail: error.message }, true);
    });
    spawnedAnchor.on('exit', () => {
      anchorExited = true;
    });
    spawnedAnchor.on('close', () => {
      anchorClosed = true;
      publish(
        completionRequested
          ? pendingResult
          : { kind: 'spawnError', detail: 'probe helper exited without a result' },
      );
    });
    // Ask the anchor to stop inside the caller's budget. Publication waits for
    // close so the result cannot escape before group teardown and reaping.
    timeout = setTimeout(
      () => completeAfterCleanup({ kind: 'timeout' }, true),
      data.publishTimeoutMs,
    );
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    publish({ kind: 'spawnError', detail });
  }
}
