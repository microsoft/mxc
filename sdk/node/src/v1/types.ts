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
  /**
   * Environment variables as KEY=VALUE strings.
   *
   * Omit this field to give the child the backend's default environment (on
   * Windows, the user's profile block). Supply it -- including as an empty
   * array -- and it is used **verbatim**: MXC adds nothing to it, so an
   * environment missing what the platform requires will fail the launch.
   * Set {@link ProcessConfig.inheritDefaultEnv} to layer these on the
   * default environment instead of replacing it.
   */
  env?: string[];
  /**
   * Start from the backend's default environment and layer {@link
   * ProcessConfig.env} on top of it, rather than replacing it (default false).
   *
   * Use this when you want "the usual environment, plus these": on Windows the
   * default is the user's profile block, which only the OS can produce, so it
   * cannot be assembled by a caller. Note this is a different set from the
   * calling process's `process.env`, which you can still pass explicitly.
   */
  inheritDefaultEnv?: boolean;
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
 * {@link ContainmentBackend} replacement. Historical v0 contracts accept
 * these spellings via serde aliases; v1 contracts reject them.
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
 * Internal to the SDK; not part of the public API.
 */
export const LegacyContainmentAliases: Readonly<Partial<Record<string, ContainmentBackend>>> = {
  appcontainer: 'processcontainer',
  macos_sandbox: 'seatbelt',
};

/** @internal Network fields the stable V1 mapper must reject rather than omit. */
export const UnsupportedV1NetworkFields = [
  'allowOutbound',
  'defaultPolicy',
  'enforcementMode',
  'allowLocalNetwork',
  'allowedHosts',
  'blockedHosts',
  'proxy',
  'removeRulesOnExit',
] as const;

const LegacyConfigAliasVersions: Readonly<Record<string, readonly string[]>> = {
  appcontainer: ['0.9.0-alpha'],
  appContainer: ['0.9.0-alpha'],
  macos_sandbox: ['0.9.0-alpha'],
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
 * Containment choices available to the v1 high-level policy API.
 *
 * Raw {@link ContainerConfig} values retain the full exact-contract
 * containment union.
 */
export type ContainmentChoice =
  | 'process'
  | 'processcontainer'
  | 'wslc'
  | 'lxc'
  | 'seatbelt'
  | 'isolation_session'
  | 'bubblewrap';

/**
 * Containment values (abstract intent or concrete backend) that require
 * the `--experimental` flag.
 */
export const ExperimentalBackends: readonly (ContainmentType | ContainmentBackend)[] = ['microvm', 'windows_sandbox', 'hyperlight'];

/**
 * Clipboard access policy levels
 */
export type ClipboardPolicy = "none" | "read" | "write" | "all";

/**
 * Cross-platform UI configuration in ContainerConfig.
 * Mapped from ContainerRequest.ui by the V1 request adapter.
 */
export interface UiConfig {
  /** Whether UI is disabled (no visible windows). */
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
 * the legacy AppContainer implementation (which honors `capabilities`)
 * and the newer BaseContainer implementation (which
 * honors `ui`) at run time based on the host OS and the `--experimental`
 * flag.
 */
export interface ProcessContainerConfig {
  /** AppContainer profile name (default: "CLI"). Deprecated: use containerId instead. */
  name?: string;
  /**
   * Enable deny-and-record learning mode. Failed access checks are logged while
   * accesses remain denied and containment remains enforced.
   */
  learningMode?: boolean;
  /**
   * Additional AppContainer capabilities (e.g., "registryRead", "internetClient").
   * Each entry must contain one capability name and must not contain a comma.
   * The reserved learning-mode capability names must not be supplied directly.
   */
  capabilities?: string[];
  /** Optional denial-capture configuration. */
  captureDenials?: {
    /** Whether denied accesses remain blocked or are temporarily allowed. */
    mode?: 'block' | 'allow';
    /** Optional destination for the generated denial report. */
    outputPath?: string;
    /** Preserve the captured ETL trace after analysis. */
    retainEtl?: boolean;
  };
  /** BaseProcess-specific UI settings (Windows only) */
  ui?: BaseProcessUiConfig;
  /** ProcessContainer-specific filesystem settings. */
  filesystem?: {
    /** Paths the script can enumerate without reading file contents. */
    enumeratePaths?: string[];
  };
  /** ProcessContainer-specific networking settings. */
  network?: {
    /** Package family name or AppContainer profile authorized as the loopback proxy peer. */
    allowedProxyPeer?: string;
  };
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
 * Network access configuration. Legacy fields remain for TypeScript source
 * compatibility only; every registered exact contract rejects them. Use
 * directional fields and runtimeConfig.networkProxy instead.
 */
export interface NetworkConfig extends DirectionalNetworkConfig {
  /**
   * Retired enforcement selector; registered contracts reject this field.
   * @deprecated Use directional network policy instead.
   */
  enforcementMode?: 'capabilities' | 'firewall' | 'both';
  /** @deprecated Use egress.default instead; registered contracts reject this field. */
  defaultPolicy?: 'allow' | 'block';
  /**
   * @deprecated Use ingress.default instead; registered contracts reject this field.
   */
  allowLocalNetwork?: boolean;
  /** @deprecated Use numeric CIDR egress rules or proxy-side hostname filtering. */
  allowedHosts?: string[];
  /** @deprecated Use numeric CIDR egress rules or proxy-side hostname filtering. */
  blockedHosts?: string[];
  /** @deprecated Registered contracts reject network.proxy. Use
   * runtimeConfig.networkProxy with the backend's supported policy posture. */
  proxy?: { builtinTestServer: true } | { localhost: number } | { url: string };
  /** @deprecated Use lifecycle.preservePolicy; registered contracts reject this field. */
  removeRulesOnExit?: boolean;
}

/** Directional network policy used by provisioning. */
export interface DirectionalNetworkConfig {
  /** Outbound network policy. */
  egress?: NetworkEgressConfig;
  /** Inbound and host-loopback network policy. */
  ingress?: NetworkIngressConfig;
}

/** Network settings accepted when creating a container request. */
export interface NetworkPolicy extends DirectionalNetworkConfig {
  /** Runtime values supplied separately from container policy. */
  runtimeConfig?: NetworkRuntimeConfig;
}

/** Allow or deny network action. */
export type NetworkAction = 'allow' | 'deny';

/** Transport protocol selector. */
export type NetworkProtocol = 'tcp' | 'udp' | 'icmp' | 'any';

/** CIDR network peer. */
export interface NetworkPeerConfig {
  /** IPv4 or IPv6 CIDR. */
  cidr: string;
  /** CIDRs excluded from this peer. */
  except?: string[];
}

/** Protocol and destination-port selector. */
export interface NetworkPortConfig {
  /** Transport protocol. Defaults to "any". */
  protocol?: NetworkProtocol;
  /** Destination port. Omission matches every port. */
  port?: number;
  /** Inclusive end of a destination-port range. Requires `port`. */
  endPort?: number;
}

/** Outbound network rule. */
export interface NetworkRuleConfig {
  /** Destination CIDRs. Omission matches both IP families; an explicit array must be non-empty. */
  to?: NetworkPeerConfig[];
  /** Destination protocols and ports. Omission matches all; an explicit array must be non-empty. */
  ports?: NetworkPortConfig[];
}

/** Outbound network policy. */
export interface NetworkEgressConfig {
  /** Action used when no explicit rule matches. Defaults to "deny". */
  default?: NetworkAction;
  /** Explicit allow rules. */
  allow?: NetworkRuleConfig[];
  /** Explicit deny rules. Deny rules take precedence. */
  deny?: NetworkRuleConfig[];
}

/** Inbound and host-loopback network policy. */
export interface NetworkIngressConfig {
  /** Default action for LAN/private-network inbound traffic. */
  default?: NetworkAction;
  /** Bidirectional host-loopback connectivity action. */
  hostLoopback?: NetworkAction;
}

/** Runtime values supplied separately from sandbox policy. */
export interface NetworkRuntimeConfig {
  /**
   * HTTP/S proxy URL. Host-loopback restrictions are backend-specific.
   * WSLC accepts a URL reachable from inside the guest, including guest-loopback
   * URLs such as `http://127.0.0.1:8888`.
   */
  networkProxy?: string;
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
  /**
   * Host↔container port mappings.
   *
   * Only TCP is currently supported by the WSLC SDK runtime. UDP is declared
   * in the SDK header but the shipped runtime returns `E_NOTIMPL` when UDP is
   * actually requested, so the parser hard-rejects `"udp"` with a clear
   * message at spawn time. The `protocol` field defaults to `"tcp"` when
   * omitted.
   */
  portMappings?: PortMapping[];
}

/**
 * Hyperlight backend configuration
 */
export interface HyperlightConfig {
  /** Guest runtime that `process.commandLine` is source for (default: "agent") */
  runtime?: 'agent' | 'python' | 'python-shell' | 'node' | 'bash' | 'dotnet-jit';
}

/**
 * Port mapping for host↔container port forwarding.
 */
export interface PortMapping {
  /** Port on the Windows host */
  windowsPort: number;
  /** Port inside the Linux container */
  containerPort: number;
  /**
   * Transport protocol. Only `"tcp"` is currently supported; `"udp"` is
   * rejected by the parser because the WSLC SDK runtime returns `E_NOTIMPL`
   * for UDP even though the header declares it. Defaults to `"tcp"` when
   * omitted.
   */
  protocol?: 'tcp';
}

/**
 * Telemetry configuration for TraceLogging ETW support.
 */
export interface TelemetryConfig {
  /**
   * Per-invocation telemetry opt-in.
   *
   * `true` requests telemetry for this invocation; emission is still gated by
   * persisted user consent and administrative policy. `false` (or `undefined`)
   * disables telemetry for this invocation.
   */
  enabled?: boolean;
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
   * Legacy alias of {@link processContainer}. Only the registered exact
   * v0.9 contract accepts this spelling; exact v1 rejects it.
   *
   * @deprecated Use {@link processContainer} instead.
   */
  appContainer?: ProcessContainerConfig;
  /** LXC container configuration (Linux only) */
  lxc?: LxcConfig;
  /** Filesystem access configuration */
  filesystem?: FilesystemConfig;
  /** Network access configuration */
  network?: NetworkConfig;
  /** Runtime values supplied separately from sandbox policy. */
  runtimeConfig?: NetworkRuntimeConfig;
  /** Telemetry configuration for TraceLogging ETW support */
  telemetry?: TelemetryConfig;
  /** WSLC SDK configuration for Linux containers from Windows */
  wslc?: WslcConfig;
  /** Hyperlight backend configuration */
  hyperlight?: HyperlightConfig;
  /** macOS Seatbelt sandbox configuration (macOS only) */
  seatbelt?: SeatbeltConfig;
  /** Cross-platform UI configuration */
  ui?: UiConfig;
}

/** @internal Returns an actionable error when a raw config uses a retired alias. */
export function legacyConfigAliasUnsupportedReason(config: ContainerConfig): string | undefined {
  const rawContainment = config.containment as string | undefined;
  if (
    rawContainment !== undefined
    && LegacyContainmentAliases[rawContainment] !== undefined
    && !LegacyConfigAliasVersions[rawContainment]?.includes(config.version)
  ) {
    return `Schema ${config.version} does not support legacy containment alias '${rawContainment}'; use '${LegacyContainmentAliases[rawContainment]}' instead`;
  }

  if (
    config.appContainer !== undefined
    && !LegacyConfigAliasVersions.appContainer.includes(config.version)
  ) {
    return `Schema ${config.version} does not support legacy field 'appContainer'; use 'processContainer' instead`;
  }

  const legacySeatbelt = (config as ContainerConfig & { macos_sandbox?: unknown }).macos_sandbox;
  if (
    legacySeatbelt !== undefined
    && !LegacyConfigAliasVersions.macos_sandbox.includes(config.version)
  ) {
    return `Schema ${config.version} does not support legacy field 'macos_sandbox'; use 'seatbelt' instead`;
  }

  return undefined;
}

/** Per-operation controls for the V1 in-process APIs. */
export interface MxcOptions {
  /** Enable runtime-gated experimental behavior where supported. */
  experimental?: boolean;
  /** Validate a lifecycle request without performing the operation. */
  dryRun?: boolean;
}

/** Closed SDK-owned containment choices for container creation requests. */
export namespace Containment {
  export interface Process {
    type: 'process';
  }

  export interface ProcessContainer {
    type: 'processcontainer';
    config?: ProcessContainerConfig;
  }

  export interface Wslc {
    type: 'wslc';
    config?: WslcConfig;
  }

  export interface Lxc {
    type: 'lxc';
    config?: LxcConfig;
  }

  export interface Seatbelt {
    type: 'seatbelt';
    config?: SeatbeltConfig;
  }

  export interface IsolationSession {
    type: 'isolation_session';
  }

  export interface Bubblewrap {
    type: 'bubblewrap';
  }
}

export type Containment =
  | Containment.Process
  | Containment.ProcessContainer
  | Containment.Wslc
  | Containment.Lxc
  | Containment.Seatbelt
  | Containment.IsolationSession
  | Containment.Bubblewrap;

/** Cross-backend filesystem access restrictions. */
export interface FilesystemPolicy {
  /** Paths the workload can read and write. */
  readwritePaths?: string[];
  /** Paths the workload can read but not write. */
  readonlyPaths?: string[];
  /** Paths the workload cannot access. */
  deniedPaths?: string[];
  /** Clear filesystem policy on exit; defaults to true. */
  clearPolicyOnExit?: boolean;
}

/** Cross-backend UI access restrictions. Omitted access remains denied. */
export interface UiPolicy {
  /** Whether UI is disabled. */
  disable: boolean;
  /** Clipboard access level. */
  clipboard?: ClipboardPolicy;
  /** Whether input injection is allowed. */
  allowInputInjection?: boolean;
}

/**
 * Complete container request. The SDK selects its exact wire contract; callers
 * provide cross-backend restrictions and backend configuration rather than a
 * raw versioned config.
 */
export interface ContainerRequest {
  /** Command line to execute. */
  command: string;
  /** Filesystem access restrictions. Omitted paths remain restricted. */
  filesystem?: FilesystemPolicy;
  /** Directional network access restrictions. */
  network?: NetworkPolicy;
  /** UI access restrictions. Omitted access remains denied. */
  ui?: UiPolicy;
  /** Execution timeout in milliseconds. Omitted = no timeout. */
  timeoutMs?: number;
  /** Backend configuration; defaults to the host's native process backend. */
  containment?: Containment;
  /** Optional caller-selected container name. */
  containerName?: string;
  /** Optional working directory inside the container. */
  workingDirectory?: string;
  /** Optional child environment. Omission uses the backend default. */
  environment?: { [key: string]: string | undefined };
  /** Layer `environment` over the backend's default environment. */
  inheritDefaultEnvironment?: boolean;
}

/** Structured outputs produced by optional container features. */
export interface ExecutionMetadata {
  captureDenials?: CaptureDenialsResult;
  captureDenialsError?: CaptureDenialsError;
}

/** Location and summary of a captureDenials output document. */
export interface CaptureDenialsResult {
  type: 'captureDenials';
  outputPath: string;
  exitCode: number;
  totalDenials: number;
  deniedResourcesTruncated: boolean;
  /** Retained ETL file; delete the file after use, not its parent directory. */
  etlPath?: string;
}

/** Failure details and retained trace location when capture finalization fails. */
export interface CaptureDenialsError {
  message: string;
  /** Retained ETL file; delete the file after use, not its parent directory. */
  etlPath: string;
}

/** Captured output and terminal outcome of a completed workload. */
export interface ExecutionResult {
  stdout: string;
  stderr: string;
  exitCode: number;
  timedOut: boolean;
  warnings: string[];
  outputMetadata?: ExecutionMetadata;
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
 * macOS Seatbelt sandbox configuration. Used under the top-level
 * `seatbelt` key when `containment == "seatbelt"`.
 */
export interface SeatbeltConfig {
  /**
   * Optional override of the generated TinyScheme sandbox profile.
   */
  profileOverride?: string;
  /** Allow GUI applications to access the macOS WindowServer and related services. */
  guiAccess?: boolean;
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
 * - `base-container`: full BaseContainer (process security environment)
 * - `appcontainer-bfs`: AppContainer + BFS filesystem isolation
 * - `appcontainer-dacl`: AppContainer + host DACL augmentation (last-resort fallback)
 */
export type IsolationTier =
  | 'base-container'
  | 'appcontainer-bfs'
  | 'appcontainer-dacl';

/** Optional capability reported by native backend discovery. */
export type BackendCapability =
  | 'captureDenials'
  | 'filesystemDeniedPaths'
  | 'filesystemEnumeratePaths'
  | 'ingressHostLoopbackAllow'
  | 'proxyEnforcement'
  | 'unknown';

/** One host-available backend and its native capabilities. */
export interface AvailableBackend {
  /** Unknown names from a newer native library map to 'unknown'. */
  backend: ContainmentBackend | 'unknown';
  /** Omitted when the backend has no isolation-tier ladder. */
  tier?: IsolationTier | 'unknown';
  /** Empty when no optional capability was reported. */
  capabilities: BackendCapability[];
  /** Diagnostics for optional capabilities that are unavailable. */
  warnings: string[];
}

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
 * Result of probing which Windows ProcessContainer tier can serve a config.
 */
export interface ProbeOutput {
  /** Selected tier, omitted when detection failed. */
  tier?: IsolationTier;
  /** Whether the selected tier needs DACL deny augmentation. */
  needsDaclAugmentation?: boolean;
  /** Tier degradation warnings. */
  warnings: string[];
  /** Raw host facts used by tier selection. */
  probes: ProbeFacts;
  /** Detector failure, present when detection failed and omitted on success. */
  error?: string;
}

/** Raw host facts gathered before request tier selection. */
export interface ProbeFacts {
  baseContainerApiPresent: boolean;
  nativeCaptureAvailable: boolean;
  guardedCaptureAvailable: boolean;
  bfscfgPresent: boolean;
  bfsCompiledIn: boolean;
  baseContainerSupportsDenyPaths: boolean;
  baseContainerSupportsEnumeratePaths: boolean;
  baseContainerSupportsIngressHostLoopbackAllow: boolean;
  /** True when this executor includes IsolationSession and the host can activate it. */
  isolationSessionAvailable: boolean;
  /** True when this executor includes Hyperlight and its host runtime is available. */
  hyperlightAvailable: boolean;
  uiCapabilities: UiCapabilitySupport;
}

/**
 * Host support for enforcing Bubblewrap proxy-only egress.
 *
 * Schema `0.9.0-alpha`+ proxy policies run the sandbox in a private network
 * namespace and default-drop everything except the proxy endpoint. That
 * requires host tooling (slirp4netns, util-linux unshare, nsenter, the
 * iptables family) plus unprivileged user and network namespaces the kernel
 * will actually grant; see `docs/bwrap-support/bubblewrap-backend.md` for the
 * full list. There is deliberately no fallback to the weaker shared-host-network
 * model, so a request that cannot configure private networking fails rather
 * than silently degrading. This reports, before launching, whether the host
 * can satisfy such a policy.
 */
export interface BubblewrapNetworkSupport {
  /** Whether proxy-only egress can be enforced on this host. */
  proxyEnforcement: 'supported' | 'unsupported';
  /** Why enforcement is unsupported. Empty when it is supported. */
  warnings: string[];
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
   * Why individual Linux backends are unavailable, whether or not another
   * backend keeps Linux supported. Omitted on other platforms and when no
   * Linux backend failures were observed.
   */
  unavailableReasons?: Partial<Record<ContainmentBackend, string>>;
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
  /**
   * Bubblewrap host network capability. Omitted on non-Linux platforms and
   * when bubblewrap itself is unavailable. Reported fail-closed: if the probe
   * cannot run, `proxyEnforcement` is `'unsupported'`, never absent.
   */
  bubblewrapNetwork?: BubblewrapNetworkSupport;
}
