// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import os from 'node:os';
import net from 'node:net';
import {
  MxcError,
  run,
  type ContainerRequest,
} from '@microsoft/mxc-sdk/v1';

async function main(): Promise<number> {
  const server = net.createServer((socket) => {
    socket.end('HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK');
  });
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });

  try {
    const address = server.address();
    if (address === null || typeof address === 'string') {
      throw new Error('Failed to determine the test endpoint port.');
    }
    const sampleCommand = os.platform() === 'win32'
      ? `powershell.exe -NoProfile -Command "$curl = (Get-Command curl.exe -ErrorAction Stop).Source; & $curl --silent --fail --max-time 3 http://127.0.0.1:${address.port}/ *> $null; if ($LASTEXITCODE -eq 0) { Write-Error 'network access unexpectedly succeeded'; exit 1 }; Write-Output 'network access blocked by policy'"`
      : `sh -c "command -v curl >/dev/null || { echo 'curl is required' >&2; exit 2; }; if curl --silent --fail --max-time 3 http://127.0.0.1:${address.port}/ >/dev/null 2>&1; then echo 'ERROR: network access unexpectedly succeeded' >&2; exit 1; fi; printf 'network access blocked by policy\\n'"`;
    const request: ContainerRequest = {
      command: sampleCommand,
      containment: { type: 'process' },
      network: {
        egress: {
          default: 'deny',
        },
        ingress: {
          default: 'deny',
          hostLoopback: 'deny',
        },
      },
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
  } finally {
    server.close();
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
