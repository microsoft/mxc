/**
 * WXC SDK Types
 * These types match the wxc-exec JSON configuration schema
 */


/**
 * AppContainer configuration for Windows sandbox
 */
export interface WxcAppContainerConfig {
  /** AppContainer profile name (default: "CLI") */
  name?: string;
  /** Use least privilege mode with PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT (default: false) */
  leastPrivilege?: boolean;
  /** Additional AppContainer capabilities (e.g., "registryRead", "internetClient") */
  capabilities?: string[];
}

/**
 * Filesystem access configuration
 */
export interface WxcFilesystemConfig {
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
export interface WxcNetworkConfig {
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
  /** Automatically remove firewall rules after execution (default: true) */
  removeRulesOnExit?: boolean;
}

/**
 * Main WXC configuration
 */
export interface WxcConfiguration {
  /** Complete command line to execute (e.g., "python -c \"print('hello')\"") */
  script: string;
  /** Optional working directory for the script */
  workingDirectory?: string;
  /** Script execution timeout in milliseconds (default: 0 = no timeout) */
  timeout?: number;
  /** AppContainer configuration */
  appContainer?: WxcAppContainerConfig;
  /** Filesystem access configuration */
  filesystem?: WxcFilesystemConfig;
  /** Network access configuration */
  network?: WxcNetworkConfig;
}

/**
 * The main sandbox policy configuration interface for external consumers
 * to define sandboxed execution environments.
 */
export type SandboxPolicy = {
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
  };
}

/**
 * Sandboxing methods available on the platform
 */
export type SandboxingMethod = 'appcontainer';

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