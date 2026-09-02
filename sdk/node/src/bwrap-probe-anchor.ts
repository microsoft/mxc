// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { spawn } from 'node:child_process';

// Strip NODE_OPTIONS so a host's loader/inspector/require flags cannot
// interfere with the helper's minimal, trusted `bwrap --version` probe.
const spawnEnv = { ...process.env };
delete spawnEnv.NODE_OPTIONS;

const helperPath = process.argv[2];
const timeoutMs = Number(process.argv[3]);
const outputLimit = process.argv[4];
let resultWritten = false;
let resultFlushed = false;
let shuttingDown = false;
let helperClosed = false;
let output = '';
const hold = setInterval(() => {}, 0x3fffffff);

function terminateHelper(): void {
  if (shuttingDown) return;
  shuttingDown = true;
  const pid = helperProcess.pid;
  if (pid && !helperClosed) {
    try {
      process.kill(pid, 'SIGKILL');
    } catch {
      // The helper may already have exited.
    }
  }
}

function terminateOwnedGroup(): void {
  try {
    process.kill(-process.pid, 'SIGKILL');
  } catch {
    process.exit(1);
  }
}

function finishIfReady(): void {
  if (!helperClosed || !resultFlushed) return;
  clearTimeout(watchdog);
  clearInterval(hold);
  // The anchor is still the unreaped group leader. The helper has already
  // been reaped, so terminating the owned group cannot target a recycled ID.
  terminateOwnedGroup();
}

const watchdog = setTimeout(() => {
  terminateHelper();
  setTimeout(terminateOwnedGroup, 500).unref();
}, timeoutMs + 1000);
watchdog.unref();

process.on('SIGTERM', () => {
  terminateHelper();
});

function emitFailure(detail: string): void {
  if (resultWritten) return;
  resultWritten = true;
  process.stdout.write(`${JSON.stringify({ kind: 'spawnError', detail })}\n`, () => {
    resultFlushed = true;
    finishIfReady();
  });
}

const helperProcess = spawn(
  process.execPath,
  [helperPath, String(timeoutMs), outputLimit],
  { detached: false, stdio: ['ignore', 'pipe', 'ignore'], env: spawnEnv },
);
helperProcess.stdout.setEncoding('utf8');
helperProcess.stdout.on('data', (chunk: string) => {
  output += chunk;
  const newline = output.indexOf('\n');
  if (!resultWritten && newline !== -1) {
    resultWritten = true;
    process.stdout.write(output.slice(0, newline + 1), () => {
      resultFlushed = true;
      finishIfReady();
    });
    terminateHelper();
  }
});
helperProcess.on('error', (error) => emitFailure(error.message));
helperProcess.on('close', () => {
  helperClosed = true;
  emitFailure('probe helper exited without a result');
  finishIfReady();
});
