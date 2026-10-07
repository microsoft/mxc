// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import os from 'node:os';
import type { Readable, Writable } from 'node:stream';
import {
  MxcError,
  spawn,
  type ContainerRequest,
} from '@microsoft/mxc-sdk/v1';

// The process handle exposes live standard streams before the workload exits.
const sampleCommand = os.platform() === 'win32'
  ? 'powershell.exe -NoProfile -NonInteractive -Command "Write-Output first; Start-Sleep -Milliseconds 750; Write-Output second"'
  : 'sh -c "printf \'first\\n\'; sleep 1; printf \'second\\n\'"';

async function forward(
  stream: Readable | null,
  destination: Writable,
): Promise<void> {
  if (stream === null) {
    return Promise.reject(
      new Error('The selected backend did not provide an expected output stream.'),
    );
  }
  return new Promise<void>((resolve, reject) => {
    stream.on('data', (chunk) => destination.write(chunk));
    stream.once('end', resolve);
    stream.once('error', reject);
  });
}

async function main(): Promise<number> {
  const request: ContainerRequest = {
    command: sampleCommand,
    timeoutMs: 30_000,
  };
  const containerProcess = await spawn(request);

  try {
    const stdout = forward(containerProcess.standardOutput, process.stdout);
    const stderr = forward(containerProcess.standardError, process.stderr);
    const result = await containerProcess.wait();
    await Promise.all([stdout, stderr]);

    for (const warning of containerProcess.warnings) {
      console.error(`warning: ${warning}`);
    }

    if (result.timedOut) {
      console.error('workload timed out');
      return 124;
    }
    return result.exitCode;
  } finally {
    containerProcess.dispose();
  }
}

try {
  process.exitCode = await main();
} catch (error) {
  if (error instanceof MxcError) {
    console.error(`MXC error [${error.code}]: ${error.message}`);
  } else {
    console.error(error);
  }
  process.exitCode = 1;
}
