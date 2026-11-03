// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { spawn, ChildProcessByStdio } from 'node:child_process';
import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import { Readable } from 'node:stream';

type HelperResult =
  | {
      kind: 'completed';
      path: string;
      status: number | null;
      signal: NodeJS.Signals | null;
      stdout: string;
      stderr: string;
    }
  | { kind: 'notFound' }
  | { kind: 'timeout' }
  | { kind: 'overflow' }
  | { kind: 'spawnError'; detail: string };

const timeoutMs = Number(process.argv[2]);
const outputLimit = Number(process.argv[3]);
const fallbackDirectories = (process.argv[4] ?? '').split(path.delimiter);
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

function searchDirectories(): string[] {
  const directories: string[] = [];
  for (const directory of [...(process.env.PATH ?? '').split(path.delimiter), ...fallbackDirectories]) {
    // Empty and relative entries resolve against the current directory, which
    // bwrap must never come from.
    if (path.isAbsolute(directory) && !directories.includes(directory)) {
      directories.push(directory);
    }
  }
  return directories;
}

type BwrapLookup =
  | { kind: 'found'; path: string }
  | { kind: 'notExecutable'; path: string }
  | { kind: 'notFound' };

async function findBwrap(): Promise<BwrapLookup> {
  let notExecutable: string | undefined;
  for (const directory of searchDirectories()) {
    // path.join would collapse `..` before the kernel follows symlinks, so it
    // could check a different file than the native lookup.
    const separator = directory.endsWith(path.sep) ? '' : path.sep;
    const candidate = `${directory}${separator}bwrap`;
    try {
      if (!(await fs.stat(candidate)).isFile()) continue;
    } catch {
      continue;
    }
    try {
      await fs.access(candidate, fs.constants.X_OK);
      return { kind: 'found', path: candidate };
    } catch {
      notExecutable ??= candidate;
    }
  }
  return notExecutable === undefined
    ? { kind: 'notFound' }
    : { kind: 'notExecutable', path: notExecutable };
}

async function handleSpawnError(executable: string, error: NodeJS.ErrnoException): Promise<void> {
  if (error.code !== 'ENOENT') {
    emit({ kind: 'spawnError', detail: error.message });
    return;
  }
  try {
    await fs.stat(executable);
  } catch {
    emit({ kind: 'notFound' });
    return;
  }
  emit({
    kind: 'spawnError',
    detail: `${executable} was found but could not be executed; check for a missing interpreter or loader`,
  });
}

async function probe(): Promise<void> {
  const bwrap = await findBwrap();
  if (finished) return;
  if (bwrap.kind === 'notFound') {
    emit({ kind: 'notFound' });
    return;
  }
  if (bwrap.kind === 'notExecutable') {
    emit({ kind: 'spawnError', detail: `\`bwrap\` was found at ${bwrap.path} but is not executable` });
    return;
  }

  let running: ChildProcessByStdio<null, Readable, Readable>;
  try {
    running = spawn(bwrap.path, ['--version'], {
      detached: false,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
  } catch (error) {
    await handleSpawnError(bwrap.path, error as NodeJS.ErrnoException);
    return;
  }
  child = running;
  running.stdout.on('data', (chunk: Buffer) => {
    stdoutLength = capture(stdoutChunks, chunk, stdoutLength);
    if (stdoutLength > outputLimit) emit({ kind: 'overflow' });
  });
  running.stderr.on('data', (chunk: Buffer) => {
    stderrLength = capture(stderrChunks, chunk, stderrLength);
    if (stderrLength > outputLimit) emit({ kind: 'overflow' });
  });
  running.on('error', (error: NodeJS.ErrnoException) => {
    classifyingSpawnError = true;
    void handleSpawnError(bwrap.path, error);
  });
  running.on('close', (status, signal) => {
    if (classifyingSpawnError) return;
    emit({
      kind: 'completed',
      path: bwrap.path,
      status,
      signal,
      stdout: Buffer.concat(stdoutChunks).toString('utf8'),
      stderr: Buffer.concat(stderrChunks).toString('utf8'),
    });
  });
}

// Started before the lookup, so a stalled filesystem counts against the
// deadline too.
timer = setTimeout(() => emit({ kind: 'timeout' }), timeoutMs);
probe().catch((error: unknown) => {
  emit({ kind: 'spawnError', detail: error instanceof Error ? error.message : String(error) });
});

void hold;
