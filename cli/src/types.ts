import { WxcConfiguration } from '@microsoft/mxc-sdk/dist/types';

/**
 * Helper function to create a minimal valid configuration
 */
export function createMinimalConfig(code: string): WxcConfiguration {
  return {
    process: { commandLine: code }
  };
}

/**
 * Helper function to create a configuration with network restrictions
 */
export function createNetworkRestrictedConfig(
  code: string,
  allow: string[]
): WxcConfiguration {
  return {
    process: { commandLine: code },
    network: {
      defaultPolicy: 'block',
      enforcementMode: 'capabilities'
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
  deniedPaths: string[] = []
): WxcConfiguration {
  return {
    process: { commandLine: code },
    filesystem: {
      readonlyPaths: readonlyPaths,
      readwritePaths: readwritePaths,
      deniedPaths: deniedPaths
    }
  };
}
