// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { ContainerConfig } from '@microsoft/mxc-sdk/dist/types';

/**
 * Helper function to create a minimal valid configuration
 */
export function createMinimalConfig(code: string, version: string = '0.4.0-alpha'): ContainerConfig {
  return {
    version,
    process: {
      commandLine: code,
    },
  };
}

/**
 * Helper function to create a configuration with network restrictions
 */
export function createNetworkRestrictedConfig(
  code: string,
  allow: string[],
  version: string = '0.4.0-alpha'
): ContainerConfig {
  return {
    version,
    process: {
      commandLine: code,
    },
    network: {
      defaultPolicy: 'block',
      enforcementMode: 'capabilities',
    }
  };
}

/**
 * Helper function to create a configuration with filesystem restrictions
 */
export function createFilesystemRestrictedConfig(
  code: string,
  readonlyPaths: string[],
  readwritePaths: string[],
  deniedPaths: string[] = [],
  version: string = '0.4.0-alpha'
): ContainerConfig {
  return {
    version,
    process: {
      commandLine: code,
    },
    filesystem: {
      readonlyPaths: readonlyPaths,
      readwritePaths: readwritePaths,
      deniedPaths: deniedPaths
    }
  };
}
