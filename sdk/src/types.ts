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
 * wants; the native binary resolves it to a concrete
 * {@link ContainmentBackend} per host capability.
 *
 * Today's intents:
 * - "process": OS-native process-level isolation. Resolves to
 *   `processcontainer` (Windows), `bubblewrap` (Linux), or `seatbelt`
 *   (macOS). On Linux, `lxc` remains available as an explicit concrete
 *   backend but is no longer the default for the abstract `"process"`
 *   intent.
 * - "vm": full hardware-virtualised VM isolation. Resolves to
 *   `windows_sandbox` on Windows; no concrete VM backend exists on other
 *   platforms today.
 * - "microvm": lightweight-VM isolation. Resolves to the current MicroVM
 *   runner (Windows only, experimental); intended to expand as additional
 *   microvm backends (e.g. NanVix) are added.
 *
 * Concrete-only backends (such as `"wslc"`) live on
 * {@link ContainmentBackend} until there is a meaningful abstraction over
 * multiple implementations of the same kind.
 */
export type ContainmentType = "process" | "vm" | "microvm";

/**
 * Runtime list of {@link ContainmentType} values. Kept in sync with the
 * `ContainmentType` union via the type annotation. Use this to recognise
 * abstract intents at run time (the union itself only exists at compile
 * time).
 */
export const ContainmentTypes: readonly ContainmentType[] = ['process', 'vm', 'microvm'];

/**
 * Deprecated containment wire values, mapped to their canonical
 * {@link ContainmentBackend} replacement. The native binary (wxc-exec) accepts
 * the deprecated form via serde aliases; this map mirrors that behavior in
 * the SDK validator so legacy configs are not rejected before reaching the
 * binary.
 *
 * The map is intentionally partial: only deprecated keys appear. Use a
 * presence check (e.g. `LegacyContainmentAliases[value] ?? value`) rather
 * than indexing blindly.
 *
 * The wire payload is forwarded to wxc-exec unchanged — the Rust parser
 * performs the final mapping at runtime. Resolution here is purely so the
 * SDK's experimental-mode, platform-support, and availability checks see
 * the canonical backend.
 *
 * Internal to the SDK; not part of the public API. Subject to removal in a
 * future minor release once the deprecation window closes.
 */
export const LegacyContainmentAliases: Readonly<Partial<Record<string, ContainmentBackend>>> = {
  appcontainer: 'processcontainer',
  macos_sandbox: 'seatbelt',
};

/**
 * Concrete containment backend. Each value names a specific runner
 * implementation in the native binary. Prefer a {@link ContainmentType}
 * value unless you specifically need to force a particular backend.
 */
export type ContainmentBackend =
  | 'processcontainer'
  | 'windows_sandbox'
  | 'wslc'
  | 'lxc'
  | 'microvm'
  | 'hyperlight'
  | 'seatbelt'
  | 'isolation_session'
  | 'bubblewrap';

/**
 * Containment values (abstract intent or concrete backend) that require
 * the `--experimental` flag.
 */
export const ExperimentalBackends: readonly (ContainmentType | ContainmentBackend)[] = ['microvm', 'windows_sandbox', 'hyperlight', 'wslc', 'seatbelt', 'isolation_session'];

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
 * Lives under processContainer.ui in ContainerConfig.
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
 * ProcessContainer configuration for the Windows process-level backend.
 *
 * `processcontainer` is the abstraction layer; the runner picks between
 * the legacy AppContainer implementation (which honors `capabilities`,
 * `leastPrivilege`) and the newer BaseContainer implementation (which
 * honors `ui`) at run time based on the host OS and the `--experimental`
 * flag.
 */
export interface ProcessContainerConfig {
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
  /** Default network policy: "allow" or "block" (default: "block") */
  defaultPolicy?: 'allow' | 'block';
  /**
   * Whether to allow inbound connections to local IP listeners (i.e. the
   * sandboxed process may call `bind()` + `listen()` and accept incoming
   * TCP/UDP). Independent of `defaultPolicy`. (default: false)
   */
  allowLocalNetwork?: boolean;
  /** Hostnames or IP addresses/CIDR blocks to allow (firewall mode only) */
  allowedHosts?: string[];
  /** Hostnames or IP addresses to block (firewall mode only) */
  blockedHosts?: string[];
  /** Proxy configuration (supported on Windows ProcessContainer and Linux Bubblewrap) */
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
  /** ProcessContainer configuration */
  processContainer?: ProcessContainerConfig;
  /**
   * Legacy alias of {@link processContainer}. Retained so callers
   * migrating from pre-0.6 SDK versions can keep their existing code
   * compiling; the native binary parses both names into the same slot
   * via a serde alias.
   *
   * @deprecated Use {@link processContainer} instead. This alias may be
   * removed in a future minor release.
   */
  appContainer?: ProcessContainerConfig;
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
    /** macOS sandbox configuration (macOS only) */
    seatbelt?: SeatbeltConfig;
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
 * macOS Seatbelt sandbox configuration (experimental). Used under
 * `experimental.seatbelt` when containment is `'seatbelt'`.
 */
export interface SeatbeltConfig {
  /**
   * Optional override of the generated TinyScheme sandbox profile.
   */
  profileOverride?: string;
  /**
   * Allow the inner process to allocate its own pseudo-terminals via
   * `posix_openpt` (needed by tests, `git`, `gh`, REPLs, and any tool
   * that wraps commands in a pty). Adds `(allow pseudo-tty)` and
   * read/write/ioctl on `/dev/ptmx` to the generated profile. Defaults
   * to `true`; set to `false` for the tightest possible sandbox when
   * the inner command does not need to allocate new ttys.
   */
  nestedPty?: boolean;
  /**
   * Allow the inner process to use the macOS Keychain (e.g. via
   * `keytar` or `Security.framework`) end-to-end. Adds Mach lookup for
   * `securityd`, `trustd`, `ocspd`, `cfprefsd`, `xpcd`, and the
   * `com.apple.lsd.*` family; read access to `/private/var/db/mds` and
   * `/private/var/protected/trustd`; and read+write access to
   * `~/Library/Keychains` and `/private/var/folders` (XPC cache).
   * Defaults to `false`; opt in only when the inner workload genuinely
   * needs Keychain access.
   */
  keychainAccess?: boolean;
  /**
   * Additional Mach service global-names to allow `mach-lookup` for.
   * Escape hatch for callers that need a specific system service the
   * baseline doesn't cover (e.g. opt-in agent integrations). Each entry
   * is rendered as `(global-name "...")` inside a single
   * `(allow mach-lookup ...)` form.
   */
  extraMachLookups?: string[];
}

/**
 * Sandboxing methods available on the platform
 *
 * @deprecated Prefer {@link ContainmentBackend} (concrete) or
 * {@link ContainmentType} (abstract). This alias is retained for
 * backward compatibility and may be removed in a future minor release.
 */
export type SandboxingMethod = ContainmentType | ContainmentBackend;

/**
 * Isolation tier selected by the runtime fallback detector.
 *
 * - `base-container`: full BaseContainer (Experimental_CreateProcessInSandbox)
 * - `appcontainer-bfs`: AppContainer + BFS filesystem isolation
 * - `appcontainer-dacl`: AppContainer + host DACL augmentation (last-resort fallback)
 */
export type IsolationTier =
  | 'base-container'
  | 'appcontainer-bfs'
  | 'appcontainer-dacl';

/**
 * Host support for enforcing sandbox UI restrictions.
 *
 * The fields describe platform-agnostic restriction intents, not the
 * OS-specific primitive used to enforce them. For example, Windows derives
 * these values from `JOB_OBJECT_UILIMIT_*` support. The SDK currently
 * receives this object only from the Windows native probe; other platforms
 * omit `PlatformSupport.uiCapabilities` until they expose equivalent probe
 * data.
 */
export interface UiCapabilitySupport {
  /** Whether the host can block reads from the clipboard. */
  canBlockClipboardRead: boolean;
  /** Whether the host can block writes to the clipboard. */
  canBlockClipboardWrite: boolean;
  /** Whether the host can block synthetic keyboard/mouse input. */
  canBlockInputInjection: boolean;
  /** Whether the host can block input method / IME changes. */
  canBlockInputMethodChanges: boolean;
  /** Whether the host can block access to external UI object handles. */
  canBlockExternalUiObjects: boolean;
  /** Whether the host can block access to global UI namespaces. */
  canBlockGlobalUiNamespace: boolean;
  /** Whether the host can block desktop switching. */
  canBlockDesktopSwitching: boolean;
  /** Whether the host can block logoff or shutdown requests. */
  canBlockLogoffOrShutdown: boolean;
  /** Whether the host can block system parameter changes. */
  canBlockSystemParameterChanges: boolean;
  /** Whether the host can block display settings changes. */
  canBlockDisplaySettingsChanges: boolean;
}

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
  /**
   * Tier that would be selected for an empty policy on this system.
   * Omitted on non-Windows platforms or when the probe fails.
   */
  isolationTier?: IsolationTier;
  /**
   * Tier degradation warnings (one per fall-through during selection).
   * Omitted on non-Windows platforms or when the probe fails.
   */
  isolationWarnings?: string[];
  /**
   * Host UI-restriction capabilities. Omitted when the backend probe cannot
   * determine them, including on Linux and macOS today.
   */
  uiCapabilities?: UiCapabilitySupport;
}
