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
 * Abstract containment intent. Names the *kind* of isolation the caller
 * wants. The native binary (or the SDK as a fallback) resolves this to a
 * concrete {@link ContainmentBackend} at run time based on what the host
 * supports.
 *
 * Today's intents:
 * - "process": OS-native process-level isolation. Resolves to AppContainer
 *   (Windows) or LXC (Linux).
 * - "microvm": lightweight-VM isolation. Resolves to the current MicroVM
 *   runner (Windows only, experimental); intended to expand as additional
 *   microvm backends (e.g. NanVix) are added.
 *
 * Concrete-only backends (such as `"wslc"`) live on
 * {@link ContainmentBackend} until there is a meaningful abstraction over
 * multiple implementations of the same kind.
 */
export type ContainmentType = "process" | "microvm";

/**
 * Concrete containment backend. Each value names a specific runner
 * implementation in the native binary. Prefer a {@link ContainmentType}
 * value unless you specifically need to force a particular backend.
 */
export type ContainmentBackend =
  | 'appcontainer'
  | 'windows_sandbox'
  | 'wslc'
  | 'lxc'
  | 'microvm';

/**
 * Containment values (abstract intent or concrete backend) that require
 * the `--experimental` flag.
 */
export const ExperimentalBackends: readonly (ContainmentType | ContainmentBackend)[] = ['microvm', 'wslc'];

/**
 * Clipboard access policy levels
 */
export type ClipboardPolicy = "none" | "read" | "write" | "all";

/**
 * Cross-platform UI configuration in ContainerConfig.
 * Mapped from SandboxPolicy.ui by createConfigFromPolicy.
 */
export interface UiConfig {
  /** Whether UI is disabled (no visible windows). Maps from !policy.ui.allowWindows. */
  disable: boolean;
  /** Clipboard access level */
  clipboard: ClipboardPolicy;
  /** Whether input injection is allowed */
  injection: boolean;
}

/**
 * BaseProcess-specific UI configuration (Windows only).
 * Lives under appContainer.ui in ContainerConfig.
 */
export interface BaseProcessUiConfig {
  /** UI isolation level for the desktop */
  isolation: "desktop" | "handles" | "atoms" | "container";
  /** Whether desktop system control is allowed */
  desktopSystemControl: boolean;
  /** System settings access level */
  systemSettings: string;
  /** Whether IME (Input Method Editor) is allowed */
  ime: boolean;
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
  /** BaseProcess-specific UI settings (Windows only) */
  ui?: BaseProcessUiConfig;
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
  /** Proxy configuration (Windows only) */
  proxy?: { builtinTestServer: true } | { localhost: number } | { url: string };
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
  /** Target OS for the container (default: "linux") */
  targetOs?: string;
  /** Number of CPUs allocated to the WSLC session */
  cpuCount?: number;
  /** Memory in MB allocated to the WSLC session */
  memoryMb?: number;
  /** Enable GPU passthrough to the container (default: false) */
  gpu?: boolean;
  /** Path to a local tar file to import as the container image */
  imageTarPath?: string;
  /** Host↔container port mappings (TCP only) */
  portMappings?: PortMapping[];
}

/**
 * Port mapping for host↔container port forwarding
 */
export interface PortMapping {
  /** Port on the Windows host */
  windowsPort: number;
  /** Port inside the Linux container */
  containerPort: number;
  /** Protocol: "tcp" or "udp" (default: "tcp") */
  protocol?: string;
}

/**
 * Main WXC configuration
 */
export interface ContainerConfig {
  /** MXC config schema version. Required. */
  version: string;
  /** Externally assigned container identifier */
  containerId?: string;
  /** Containment intent (preferred) or concrete backend (override). */
  containment?: ContainmentType | ContainmentBackend;
  /** Container lifecycle settings */
  lifecycle?: LifecycleConfig;
  /** Process execution settings (required) */
  process?: ProcessConfig;
  /** AppContainer configuration */
  appContainer?: AppContainerConfig;
  /** LXC container configuration (Linux only) */
  lxc?: LxcConfig;
  /** Filesystem access configuration */
  filesystem?: FilesystemConfig;
  /** Network access configuration */
  network?: NetworkConfig;
  /** Experimental features (only applied when --experimental flag is set) */
  experimental?: {
    /** WSLC SDK configuration for Linux containers from Windows */
    wslc?: WslcConfig;
  };
  /** Cross-platform UI configuration */
  ui?: UiConfig;
}

/**
 * The main sandbox policy configuration interface for external consumers
 * to define sandboxed execution environments.
 *
 * Policy describes *what* the caller wants restricted. Cross-platform.
 * No OS-specific content. Omitted fields = most restrictive (default-deny).
 */
export type SandboxPolicy = {
  /** Policy version (semver). Must match a supported schema version. */
  version: string;
  /** Filesystem access restrictions */
  filesystem?: {
      /** Paths that are granted read and write access */
      readwritePaths?: string[];
      /** Paths that are granted read-only access */
      readonlyPaths?: string[];
      /** Paths that are explicitly denied all access */
      deniedPaths?: string[];
      /** Whether to clear the filesystem policy when the shell exits. (default: true) */
      clearPolicyOnExit?: boolean;
  };
  /** Network access restrictions. All flags default to false (no network access). */
  network?: {
      /** Whether to allow outbound connections to the Internet. (default: false) */
      allowOutbound?: boolean;
      /** Whether to allow connections to local networks. (default: false) */
      allowLocalNetwork?: boolean;
      /** When set, ONLY these outbound hosts are reachable. Requires allowOutbound. */
      allowedHosts?: string[];
      /** Hosts to block even when outbound is allowed. Requires allowOutbound. */
      blockedHosts?: string[];
      /**
       * Proxy configuration. Routes all traffic through this proxy.
       * Cannot be combined with other network flags.
       */
      proxy?: { builtinTestServer: true } | { localhost: number } | { url: string };
  };
  /** UI access restrictions. All flags default to denied. */
  ui?: {
      /** Whether the sandbox may create visible windows. (default: false) */
      allowWindows?: boolean;
      /** Clipboard access level. (default: "none") */
      clipboard?: ClipboardPolicy;
      /** Whether the sandbox may inject keyboard/mouse input. (default: false) */
      allowInputInjection?: boolean;
  };
  /** Execution timeout in milliseconds. Omitted = no timeout. */
  timeoutMs?: number;
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
 * Sandboxing methods available on the platform.
 *
 * @deprecated Prefer {@link ContainmentBackend} (concrete) or
 * {@link ContainmentType} (abstract). This alias is retained for
 * backward compatibility and may be removed in a future minor release.
 */
export type SandboxingMethod = ContainmentType | ContainmentBackend;

/**
 * Platform support information
 */
export interface PlatformSupport {
  /** Whether WXC is supported on the current platform */
  isSupported: boolean;
  /** Reason why the platform is not supported (if applicable) */
  reason?: string;
  /** Available sandboxing methods on this platform */
  availableMethods: ContainmentBackend[];
}