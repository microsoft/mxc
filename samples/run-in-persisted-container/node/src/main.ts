// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import os from 'node:os';
import {
  MxcError,
  deprovisionContainer,
  provisionContainer,
  runInContainer,
  startContainer,
  stopContainer,
  type ContainerId,
} from '@microsoft/mxc-sdk/v1';

async function main(): Promise<number> {
  if (os.platform() !== 'win32') {
    throw new Error('The persisted IsolationSession sample requires Windows.');
  }

  let containerId: ContainerId<'isolation_session'> | undefined;
  let started = false;
  let operationError: unknown;
  const cleanupErrors: unknown[] = [];
  let exitCode = 1;

  try {
    const provisioned = await provisionContainer({
      containment: 'isolation_session',
      network: {
        egress: { default: 'allow' },
        ingress: { default: 'allow', hostLoopback: 'allow' },
      },
    });
    containerId = provisioned.containerId;
    console.log(`provisioned: ${containerId}`);

    await startContainer(containerId);
    started = true;

    const result = await runInContainer(containerId, {
      command: 'cmd.exe /d /s /c "echo hello from persisted container"',
      timeoutMs: 30_000,
    });
    process.stdout.write(result.stdout);
    process.stderr.write(result.stderr);
    for (const warning of result.warnings) {
      console.error(`warning: ${warning}`);
    }
    exitCode = result.timedOut ? 124 : result.exitCode;
  } catch (error) {
    operationError = error;
  } finally {
    if (containerId !== undefined) {
      if (started) {
        try {
          await stopContainer(containerId);
        } catch (error) {
          console.error('cleanup error while stopping container:', error);
          cleanupErrors.push(error);
        }
      }

      try {
        await deprovisionContainer(containerId);
      } catch (error) {
        console.error('cleanup error while deprovisioning container:', error);
        cleanupErrors.push(error);
      }
    }
  }

  if (operationError !== undefined) {
    throw operationError;
  }
  if (cleanupErrors.length > 0) {
    throw new AggregateError(cleanupErrors, 'container cleanup failed');
  }
  return exitCode;
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
