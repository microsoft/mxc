// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import os from 'node:os';
import path from 'node:path';
import {
  MxcError,
  run,
  type ContainerRequest,
} from '@microsoft/mxc-sdk/v1';

const sampleDirectory = path.resolve('..');
const sampleCommand = os.platform() === 'win32'
  ? 'cmd.exe /d /s /c "echo unexpected>blocked.txt 2>nul & if exist blocked.txt (del blocked.txt & echo ERROR: write unexpectedly succeeded & exit /b 1) else (type input.txt & echo write access blocked by policy)"'
  : 'sh -c "if printf unexpected > blocked.txt 2>/dev/null; then rm -f blocked.txt; echo \'ERROR: write unexpectedly succeeded\' >&2; exit 1; fi; cat input.txt; printf \'write access blocked by policy\\n\'"';

async function main(): Promise<number> {
  const request: ContainerRequest = {
    command: sampleCommand,
    containment: { type: 'process' },
    filesystem: {
      readonlyPaths: [sampleDirectory],
    },
    workingDirectory: sampleDirectory,
    timeoutMs: 30_000,
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
