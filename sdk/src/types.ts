// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * MXC SDK Types
 * These types match the wxc-exec JSON configuration schema
 */


/**
 * Process execution settings
 */
export interface ProcessConfig {
  /** Complete command line to execute (e.g., "python -c \"print('hello')\"") */
  commandLine: string;
  /** Working directory for the process */
  cwd?: string;
  /** Environment variables as KEY=VALUE strings */
  env?: string[];
  /** Execution timeout in milliseconds (default: 0 = no timeout) */
  timeout?: number;
}

/**
 * Container lifecycle settings shared across all backends
 */
export interface LifecycleConfig {
  /** Destroy the container after execution completes (default: true) */
  destroyOnExit?: boolean;
  /** Retain filesystem and network policies after execution (default: false) */
  preservePolicy?: boolean;
}

/**
 * AppContainer configuration for Windows sandbox
 */
export interface AppContainerConfig {
  /** AppContainer profile name (default: "CLI"). Deprecated: use containerId instead. */
  name?: string;
  /** Use least privilege mode with PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT (default: false) */
  leastPrivilege?: boolean;
  /** Additional AppContainer capabilities (e.g., "registryRead", "internetClient") */
  capabilities?: string[];
}

/**
 * Filesystem access configuration
 */
export interface FilesystemConfig {
  /** Paths the script can read and write */
  readwritePaths?: string[];
  /** Paths the script can read but not write */
  readonlyPaths?: string[];
  /** Paths the script cannot access */
  deniedPaths?: string[];
  /** Automatically remove file access policy after execution (default: true) */
  clearPolicyOnExit?: boolean;
}

/**
 * Network access configuration
 */
export interface NetworkConfig {
  /**
   * Network enforcement mode:
   * - "capabilities": Use AppContainer capabilities only (no admin required)
   * - "firewall": Use Windows Firewall rules (requires admin)
   * - "both": Use both capabilities and firewall rules (requires admin)
   * (default: "both")
   */
  enforcementMode?: 'capabilities' | 'firewall' | 'both';
  /** Default network policy: "allow" or "block" (default: "allow") */
  defaultPolicy?: 'allow' | 'block';
  /** Hostnames or IP addresses/CIDR blocks to allow (firewall mode only) */
  allowedHosts?: string[];
  /** Hostnames or IP addresses to block (firewall mode only) */
  blockedHosts?: string[];
  /** Proxy configuration (currently appcontainer only, requires elevation) */
  proxy?: { builtinTestServer: true } | { localhost: number };
  /** Automatically remove firewall rules after execution (default: true). Deprecated: use lifecycle.preservePolicy. */
  removeRulesOnExit?: boolean;
}

/**
 * WSLC SDK configuration for Linux containers from Windows
 */
export interface WslcConfig {
  /** OCI container image name (default: "alpine:latest") */
  image?: string;
  /** Storage path for WSLC session image store */
  storagePath?: string;
}

/**
 * Main WXC configuration
 */
export interface ContainerConfig {
  /** MXC config schema version. Required. */
  version: string;
  /** Externally assigned container identifier */
  containerId?: string;
  /** Containment backend */
  containment?: 'appcontainer' | 'sandbox' | 'wslc' | 'lxc' | 'vm' | 'nanvix';
  /** Container lifecycle settings */
  lifecycle?: LifecycleConfig;
  /** Process execution settings (required) */
  process?: ProcessConfig;
  /** AppContainer configuration */
  appContainer?: AppContainerConfig;
  /** WSLC SDK configuration */
  wslc?: WslcConfig;
  /** LXC container configuration (Linux only) */
  lxc?: LxcConfig;
  /** Filesystem access configuration */
  filesystem?: FilesystemConfig;
  /** Network access configuration */
  network?: NetworkConfig;
}

/**
 * The main sandbox policy configuration interface for external consumers
 * to define sandboxed execution environments.
 */
export type SandboxPolicy = {
  /** Policy version (semver). */
  version: string;
  /** Filesystem access restrictions */
  filesystem?: {
      /** Paths that are granted read and write access */
      readwritePaths?: string[];
      /** Paths that are granted read-only access */
      readonlyPaths?: string[];
      /** Paths that are explicitly denied all access */
      deniedPaths?: string[];
      /** Whether to clear the filesystem policy when the shell exits. (default: true)*/
      clearPolicyOnExit?: boolean;
  };
  /** Network access restrictions */
  network?: {
      /** Whether to allow outbound connections to the Internet. (default: false) */
      allowOutbound?: boolean;
      /** Whether to allow connections to local networks. (default: false) */
      allowLocalNetwork?: boolean;
      /**
       * Proxy configuration for the container (temporarily Windows only, temporarily requires elevation).
       * Only one option may be specified:
       * - `builtinTestServer`: Use the built-in test proxy server
       * - `localhost`: Forward traffic through a proxy on the specified localhost port
       */
      proxy?: { builtinTestServer: true } | { localhost: number }
  };
}

/**
 * LXC container configuration for Linux sandbox
 */
export interface LxcConfig {
  /** Container name (default: auto-generated) */
  containerName?: string;
  /** Linux distribution for container rootfs (default: "alpine") */
  distribution?: string;
  /** Distribution release version (default: "3.19") */
  release?: string;
  /** Whether to destroy the container after execution (default: true) */
  destroyOnExit?: boolean;
}

/**
 * Sandboxing methods available on the platform
 */
export type SandboxingMethod = 'appcontainer' | 'sandbox' | 'wslc' | 'lxc' | 'vm' | 'nanvix';

/**
 * Platform support information
 */
export interface PlatformSupport {
  /** Whether WXC is supported on the current platform */
  isSupported: boolean;
  /** Reason why the platform is not supported (if applicable) */
  reason?: string;
  /** Available sandboxing methods on this platform */
  availableMethods: SandboxingMethod[];
}