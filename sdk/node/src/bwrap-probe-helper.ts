// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { spawn, ChildProcessByStdio } from 'node:child_process';
import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import { Readable } from 'node:stream';

type HelperResult =
  | { kind: 'completed'; status: number | null; signal: NodeJS.Signals | null; stdout: string; stderr: string }
  | { kind: 'notFound' }
  | { kind: 'timeout' }
  | { kind: 'overflow' }
  | { kind: 'spawnError'; detail: string };

const timeoutMs = Number(process.argv[2]);
const outputLimit = Number(process.argv[3]);
let child: ChildProcessByStdio<null, Readable, Readable> | undefined;
let finished = false;
let classifyingSpawnError = false;
let timer: NodeJS.Timeout | undefined;
let stdoutLength = 0;
let stderrLength = 0;
const stdoutChunks: Buffer[] = [];
const stderrChunks: Buffer[] = [];
const hold = setInterval(() => {}, 0x3fffffff);

setTimeout(() => {
  if (child) {
    try {
      child.kill('SIGKILL');
    } catch {
      // The child may already have exited.
    }
  }
  process.exit(1);
}, timeoutMs + 1000).unref();

function capture(chunks: Buffer[], chunk: Buffer, currentLength: number): number {
  const remaining = Math.max(0, outputLimit - currentLength);
  if (remaining > 0) chunks.push(chunk.subarray(0, remaining));
  return currentLength + chunk.length;
}

function emit(result: HelperResult): void {
  if (finished) return;
  finished = true;
  if (timer) clearTimeout(timer);
  process.stdout.write(`${JSON.stringify(result)}\n`);
}

async function handleSpawnError(error: NodeJS.ErrnoException): Promise<void> {
  if (error.code !== 'ENOENT') {
    emit({ kind: 'spawnError', detail: error.message });
    return;
  }
  for (const entry of (process.env.PATH ?? '').split(path.delimiter)) {
    const candidate = path.join(entry, 'bwrap');
    try {
      if ((await fs.stat(candidate)).isFile()) {
        emit({
          kind: 'spawnError',
          detail: `${candidate} was found but could not be executed; check for a missing interpreter or loader`,
        });
        return;
      }
    } catch (statError) {
      const error = statError as NodeJS.ErrnoException;
      if (error.code !== 'ENOENT' && error.code !== 'ENOTDIR') {
        emit({ kind: 'spawnError', detail: `failed to inspect ${candidate}: ${error.message}` });
        return;
      }
    }
  }
  emit({ kind: 'notFound' });
}

try {
  child = spawn('bwrap', ['--version'], {
    detached: false,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
} catch (error) {
  void handleSpawnError(error as NodeJS.ErrnoException);
}

if (child) {
  child.stdout.on('data', (chunk: Buffer) => {
    stdoutLength = capture(stdoutChunks, chunk, stdoutLength);
    if (stdoutLength > outputLimit) emit({ kind: 'overflow' });
  });
  child.stderr.on('data', (chunk: Buffer) => {
    stderrLength = capture(stderrChunks, chunk, stderrLength);
    if (stderrLength > outputLimit) emit({ kind: 'overflow' });
  });
  child.on('error', (error: NodeJS.ErrnoException) => {
    classifyingSpawnError = true;
    void handleSpawnError(error);
  });
  child.on('close', (status, signal) => {
    if (classifyingSpawnError) return;
    emit({
      kind: 'completed',
      status,
      signal,
      stdout: Buffer.concat(stdoutChunks).toString('utf8'),
      stderr: Buffer.concat(stderrChunks).toString('utf8'),
    });
  });
  timer = setTimeout(() => emit({ kind: 'timeout' }), timeoutMs);
}

void hold;
