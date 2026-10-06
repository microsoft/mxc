// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import os from 'node:os';
import {
  MxcError,
  getPlatformSupport,
  run,
  type ContainerRequest,
} from '@microsoft/mxc-sdk/v1';

const sampleCommand = os.platform() === 'win32'
  ? 'cmd.exe /d /s /c "echo hello from %MXC_SAMPLE_NAME%"'
  : 'sh -c "printf \'hello from %s\\n\' \\"$MXC_SAMPLE_NAME\\""';

async function main(): Promise<number> {
  const support = getPlatformSupport();
  if (!support.isSupported) {
    throw new Error(`MXC is not supported: ${support.reason ?? 'unknown reason'}`);
  }

  const request: ContainerRequest = {
    command: sampleCommand,
    containment: { type: 'process' },
    timeoutMs: 30_000,
    environment: {
      MXC_SAMPLE_NAME: 'transient-container',
    },
    inheritDefaultEnvironment: true,
  };
  const result = await run(request);

  process.stdout.write(result.stdout);
  process.stderr.write(result.stderr);
  for (const warning of result.warnings) {
    console.error(`warning: ${warning}`);
  }

  if (result.timedOut) {
    console.error('workload timed out');
    return 124;
  }
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
