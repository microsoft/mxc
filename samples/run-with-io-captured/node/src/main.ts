// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import assert from 'node:assert/strict';
import os from 'node:os';
import {
  MxcError,
  run,
  type ContainerRequest,
} from '@microsoft/mxc-sdk/v1';

const sampleCommand = os.platform() === 'win32'
  ? 'cmd.exe /d /s /c "echo hello from MXC"'
  : 'sh -c "printf \'hello from MXC\\n\'"';

async function main(): Promise<number> {
  const request: ContainerRequest = {
    command: sampleCommand,
    timeoutMs: 30_000,
  };
  const result = await run(request);

  // The process has finished, so these strings contain its complete output.
  process.stdout.write(result.stdout);
  process.stderr.write(result.stderr);
  for (const warning of result.warnings) {
    console.error(`warning: ${warning}`);
  }

  if (result.timedOut) {
    console.error('workload timed out');
    return 124;
  }
  assert.match(result.stdout, /hello from MXC/);
  return result.exitCode;
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
