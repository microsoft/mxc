// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { once } from 'node:events';
import os from 'node:os';
import {
  MxcError,
  spawnWithPty,
  type ContainerRequest,
} from '@microsoft/mxc-sdk/v1';

async function main(): Promise<number> {
  if (!process.stdin.isTTY || !process.stdout.isTTY) {
    throw new Error('Run this sample from an interactive terminal.');
  }

  const windows = os.platform() === 'win32';
  console.error('Starting a contained shell. Type `exit` to leave.');
  const request: ContainerRequest = {
    command: windows ? 'powershell.exe -NoLogo' : 'sh',
    containment: windows
      ? { type: 'isolation_session' }
      : { type: 'process' },
    ...(windows
      ? {
          network: {
            egress: { default: 'allow' },
            ingress: { default: 'allow', hostLoopback: 'allow' },
          },
        }
      : {}),
  };
  const terminal = await spawnWithPty(request);
  const wasRaw = process.stdin.isRaw;

  try {
    const outputEnded = once(terminal.output, 'end');
    terminal.output.pipe(process.stdout, { end: false });
    process.stdin.pipe(terminal.input);
    process.stdin.setRawMode(true);
    process.stdin.resume();

    const result = await terminal.wait();
    await outputEnded;
    for (const warning of terminal.warnings) {
      console.error(`warning: ${warning}`);
    }

    if (result.timedOut) {
      console.error('workload timed out');
      return 124;
    }
    return result.exitCode;
  } finally {
    process.stdin.unpipe(terminal.input);
    if (process.stdin.isTTY) {
      process.stdin.setRawMode(wasRaw);
    }
    process.stdin.pause();
    terminal.dispose();
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
