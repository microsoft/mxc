// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import os from 'node:os';
import path from 'node:path';
import {
  MxcError,
  run,
  type ContainerRequest,
} from '@microsoft/mxc-sdk/v1';

async function main(): Promise<number> {
  if (os.platform() !== 'win32') {
    throw new Error(
      'Denial capture is available only with Windows ProcessContainer.',
    );
  }

  const deniedPath = path.resolve('../denied.txt');
  const request: ContainerRequest = {
    command: 'cmd.exe /d /s /c "type \\"%MXC_DENIED_FILE%\\" >nul 2>&1 & '
      + 'if errorlevel 1 (exit /b 0) else '
      + '(echo ERROR: denied file was readable 1>&2 & exit /b 1)"',
    containment: {
      type: 'processcontainer',
      config: {
        captureDenials: {},
      },
    },
    filesystem: {
      deniedPaths: [deniedPath],
    },
    environment: {
      MXC_DENIED_FILE: deniedPath,
    },
    inheritDefaultEnvironment: true,
    timeoutMs: 30_000,
  };
  const result = await run(request);

  for (const warning of result.warnings) {
    console.error(`warning: ${warning}`);
  }
  if (result.timedOut) {
    console.error('workload timed out');
    return 124;
  }
  if (result.exitCode !== 0) {
    return result.exitCode;
  }
  if (result.outputMetadata?.captureDenialsError !== undefined) {
    throw new Error(result.outputMetadata.captureDenialsError.message);
  }
  const capture = result.outputMetadata?.captureDenials;
  if (capture === undefined) {
    throw new Error('Denial capture returned no report.');
  }
  if (capture.totalDenials === 0) {
    throw new Error('Denial capture returned an empty report.');
  }

  console.log(
    `captured ${capture.totalDenials} denial(s) in ${capture.outputPath}`,
  );
  return 0;
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
