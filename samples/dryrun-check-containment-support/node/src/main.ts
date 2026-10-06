// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import os from 'node:os';
import {
  MxcError,
  getAvailableBackends,
  getPlatformSupport,
  probe,
  type ContainerRequest,
} from '@microsoft/mxc-sdk/v1';

function main(): number {
  const support = getPlatformSupport();
  console.log(`platform supported: ${support.isSupported}`);
  if (support.reason !== undefined) {
    console.log(`reason: ${support.reason}`);
  }

  const backends = getAvailableBackends();
  if (backends.length === 0) {
    console.log('no containment backends are currently available');
  }
  for (const backend of backends) {
    console.log(`backend: ${backend.backend}`);
    if (backend.capabilities.length > 0) {
      console.log(`  capabilities: ${backend.capabilities.join(', ')}`);
    }
    for (const warning of backend.warnings) {
      console.log(`  warning: ${warning}`);
    }
  }

  if (os.platform() === 'win32') {
    const request: ContainerRequest = {
      command: 'cmd.exe /d /s /c "echo support check only"',
    };
    const result = probe(request);
    for (const warning of result.warnings) {
      console.log(`probe warning: ${warning}`);
    }
    if (result.error !== undefined) {
      console.error(`probe error: ${result.error}`);
      return 1;
    }
  }

  return support.isSupported ? 0 : 1;
}

try {
  process.exitCode = main();
} catch (error) {
  if (error instanceof MxcError) {
    console.error(`MXC error [${error.code}]: ${error.message}`);
  } else {
    console.error(error);
  }
  process.exitCode = 1;
}
