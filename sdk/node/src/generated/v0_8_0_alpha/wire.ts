// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/* eslint-disable */
/**
 * GENERATED FILE — DO NOT EDIT BY HAND.
 *
 * Emitted from the exact MXC 0.8.0-alpha development contract by
 * mxc_schema_gen. This is a drift oracle, not public API, and is not exported
 * from the SDK.
 *
 * Regenerate with:
 *   cargo run --manifest-path src/Cargo.toml -p mxc_schema_gen -- types --version 0.8.0-alpha --out sdk/node/src/generated/v0_8_0_alpha/wire.ts
 */
/**
 * Windows denial-capture settings.
 */
export interface CaptureDenials {
  /**
   * How each ungranted access is handled while it is recorded.
   */
  mode?: CaptureDenialsMode;
  /**
   * Optional destination for the generated denial report.
   */
  outputPath?: string;
  /**
   * Whether to retain the sealed ETL trace after analysis. Retained traces can contain sensitive resource paths and identifiers; callers are responsible for deleting them.
   */
  retainEtl?: boolean;
}

export type CaptureDenialsMode = "block" | "allow";

export type DefaultNetworkPolicy = "allow" | "block";

/**
 * Experimental settings accepted by the `deprovision` phase.
 */
export interface DeprovisionExperimental {
  /**
   * Optional telemetry override.
   */
  telemetry?: Telemetry;
}

export type DeprovisionPhase = "deprovision";

/**
 * A complete state-aware `deprovision` request.
 */
export interface DeprovisionRequest {
  /**
   * Optional JSON Schema reference for editor validation.
   */
  $schema?: string;
  /**
   * Optional human-readable annotation ignored by the runtime.
   */
  _comment?: unknown;
  /**
   * Optional correlation vector relayed from provision.
   */
  correlationVector?: string;
  /**
   * Optional closed post-provision experimental settings.
   */
  experimental?: DeprovisionExperimental;
  /**
   * Exact `deprovision` phase marker.
   */
  phase: DeprovisionPhase;
  /**
   * Identifier of the sandbox to deprovision.
   */
  sandboxId: string;
  /**
   * Exact development contract version.
   */
  version: Version;
}

/**
 * Experimental settings accepted by the `exec` phase.
 */
export interface ExecExperimental {
  /**
   * Optional telemetry override.
   */
  telemetry?: Telemetry;
}

export type ExecPhase = "exec";

/**
 * A complete state-aware `exec` request.
 */
export interface ExecRequest {
  /**
   * Optional JSON Schema reference for editor validation.
   */
  $schema?: string;
  /**
   * Optional human-readable annotation ignored by the runtime.
   */
  _comment?: unknown;
  /**
   * Optional correlation vector relayed from provision.
   */
  correlationVector?: string;
  /**
   * Optional closed exec experimental settings.
   */
  experimental?: ExecExperimental;
  /**
   * Optional per-execution network settings.
   */
  network?: Network;
  /**
   * Exact `exec` phase marker.
   */
  phase: ExecPhase;
  /**
   * Process to execute in the sandbox.
   */
  process: Process;
  /**
   * Identifier of the sandbox to execute in.
   */
  sandboxId: string;
  /**
   * Exact development contract version.
   */
  version: Version;
}

/**
 * Operator consent for containment fallback behavior.
 */
export interface Fallback {
  /**
   * Whether the runtime may mutate host filesystem DACLs as a fallback.
   */
  allowDaclMutation?: boolean;
}

/**
 * Filesystem access policy.
 */
export interface Filesystem {
  /**
   * Optional paths denied access.
   */
  deniedPaths?: string[];
  /**
   * Optional paths granted read-only access.
   */
  readonlyPaths?: string[];
  /**
   * Optional paths granted read-write access.
   */
  readwritePaths?: string[];
}

export type IsolationSessionContainment = "isolation_session";

/**
 * The exact unrestricted-network acknowledgment required when provisioning an IsolationSession.
 */
export interface IsolationSessionNetwork {
  /**
   * Required acknowledgment that local network access is allowed.
   */
  allowLocalNetwork: True;
  /**
   * Exact `allow` default network policy marker.
   */
  defaultPolicy: IsolationSessionNetworkDefaultPolicy;
}

export type IsolationSessionNetworkDefaultPolicy = "allow";

/**
 * IsolationSession settings accepted during provisioning.
 */
export interface IsolationSessionProvision {
  /**
   * Optional application identifier carried by the sandbox identity.
   */
  appId?: string;
}

/**
 * Experimental settings accepted by an IsolationSession provision request.
 */
export interface IsolationSessionProvisionExperimental {
  /**
   * Optional IsolationSession backend settings.
   */
  isolation_session?: StateAwareIsolationSession;
  /**
   * Optional telemetry override.
   */
  telemetry?: Telemetry;
}

/**
 * A complete state-aware `provision` request for isolation_session
 */
export interface IsolationSessionProvisionRequest {
  /**
   * Optional JSON Schema reference for editor validation.
   */
  $schema?: string;
  /**
   * Optional human-readable annotation ignored by the runtime.
   */
  _comment?: unknown;
  /**
   * Exact `isolation_session` containment marker.
   */
  containment: IsolationSessionContainment;
  /**
   * Optional closed experimental settings.
   */
  experimental?: IsolationSessionProvisionExperimental;
  /**
   * Required unrestricted-network acknowledgment.
   */
  network: IsolationSessionNetwork;
  /**
   * Exact `provision` phase marker.
   */
  phase: ProvisionPhase;
  /**
   * Exact development contract version.
   */
  version: Version;
}

export type LaunchMethod = "exec" | "open";

/**
 * Container lifecycle settings.
 */
export interface Lifecycle {
  /**
   * Whether to destroy the container when execution ends.
   */
  destroyOnExit?: boolean;
  /**
   * Whether to preserve applied policy after execution ends.
   */
  preservePolicy?: boolean;
}

/**
 * Linux LXC distribution settings.
 */
export interface Lxc {
  /**
   * The Linux distribution name.
   */
  distribution: string;
  /**
   * The distribution release.
   */
  release: string;
}

/**
 * Network access policy shared by the stable containment backends.
 */
export interface Network {
  /**
   * Optional permission to bind and accept local network connections.
   */
  allowLocalNetwork?: boolean;
  /**
   * Optional hosts allowed when the default policy blocks access.
   */
  allowedHosts?: string[];
  /**
   * Optional hosts blocked when the default policy allows access.
   */
  blockedHosts?: string[];
  /**
   * Optional default network posture.
   */
  defaultPolicy?: DefaultNetworkPolicy;
  /**
   * Optional outbound network rules.
   */
  egress?: NetworkEgress;
  /**
   * Optional network enforcement mechanism.
   */
  enforcementMode?: NetworkEnforcementMode;
  /**
   * Optional inbound and host-loopback network rules.
   */
  ingress?: NetworkIngress;
  /**
   * Optional proxy configuration.
   */
  proxy?: NetworkProxy;
}

export type NetworkAction = "allow" | "deny";

/**
 * Outbound network policy.
 */
export interface NetworkEgress {
  /**
   * Optional explicit allow rules.
   */
  allow?: NetworkRule[];
  /**
   * Optional action applied when no explicit rule matches.
   */
  default?: NetworkAction;
  /**
   * Optional explicit deny rules. Deny takes precedence over allow.
   */
  deny?: NetworkRule[];
}

export type NetworkEnforcementMode = "capabilities" | "firewall" | "both";

/**
 * Inbound and host-loopback network policy.
 */
export interface NetworkIngress {
  /**
   * Optional default action for private-network inbound traffic.
   */
  default?: NetworkAction;
  /**
   * Optional bidirectional host-loopback connectivity action.
   */
  hostLoopback?: NetworkAction;
}

/**
 * A CIDR destination, optionally excluding narrower ranges within it.
 */
export interface NetworkPeer {
  /**
   * The IPv4 or IPv6 CIDR this destination matches.
   */
  cidr: string;
  /**
   * Optional CIDRs excluded from this destination.
   */
  except?: string[];
}

/**
 * A protocol and destination-port selector.
 */
export interface NetworkPort {
  /**
   * Optional inclusive end of a destination-port range. Requires `port`.
   */
  endPort?: number;
  /**
   * Optional destination port. Omission matches every port.
   */
  port?: number;
  /**
   * Optional transport protocol. Defaults to `any`.
   */
  protocol?: NetworkProtocol;
}

export type NetworkProtocol = "tcp" | "udp" | "icmp" | "any";

/**
 * One of the proxy configurations accepted by the `0.8.0-alpha` contract.
 */
export type NetworkProxy = { localhost: number; builtinTestServer?: never; url?: never } | { builtinTestServer: True; localhost?: never; url?: never } | { url: string; builtinTestServer?: never; localhost?: never };

/**
 * One outbound rule, matching destinations and ports.
 */
export interface NetworkRule {
  /**
   * Optional destination protocols and ports. Omission matches all.
   */
  ports?: NetworkPort[];
  /**
   * Optional destination CIDRs. Omission matches both IP families.
   */
  to?: NetworkPeer[];
}

export type NonEmptyString = string;

export type OneShotContainment = "process" | "processcontainer" | "appcontainer" | "lxc" | "bubblewrap" | "seatbelt" | "macos_sandbox" | "vm" | "windows_sandbox" | "microvm" | "hyperlight" | "wslc" | "isolation_session";

/**
 * Experimental settings.
 */
export interface OneShotExperimental {
  /**
   * Optional telemetry override.
   */
  telemetry?: Telemetry;
  /**
   * Optional placeholder test feature.
   */
  test?: TestFeature;
  /**
   * Optional one-shot Windows Sandbox compatibility settings.
   */
  windows_sandbox?: OneShotWindowsSandbox;
  /**
   * Optional one-shot WSLC backend settings.
   */
  wslc?: OneShotWslc;
}

/**
 * A complete one-shot `0.8.0-alpha` configuration request.
 */
export type OneShotRequest = {
  /**
   * Optional JSON Schema reference for editor validation.
   */
  $schema?: string;
  /**
   * Optional human-readable annotation ignored by the runtime.
   */
  _comment?: unknown;
  /**
   * Optional ProcessContainer settings. The legacy `appContainer` spelling is accepted as an alias.
   */
  appContainer?: ProcessContainer;
  /**
   * Optional externally assigned container identifier.
   */
  containerId?: string;
  /**
   * Optional containment selection.
   */
  containment?: OneShotContainment;
  /**
   * Optional experimental settings.
   */
  experimental?: OneShotExperimental;
  /**
   * Optional fallback consent.
   */
  fallback?: Fallback;
  /**
   * Optional filesystem policy.
   */
  filesystem?: Filesystem;
  /**
   * Optional lifecycle settings.
   */
  lifecycle?: Lifecycle;
  /**
   * Optional LXC distribution settings.
   */
  lxc?: Lxc;
  /**
   * Optional macOS Seatbelt configuration.
   */
  macos_sandbox?: Seatbelt;
  /**
   * Optional network policy.
   */
  network?: Network;
  /**
   * The process to execute.
   */
  process: Process;
  /**
   * Optional ProcessContainer settings. The legacy `appContainer` spelling is accepted as an alias.
   */
  processContainer?: ProcessContainer;
  /**
   * Optional runtime configuration settings.
   */
  runtimeConfig?: RuntimeConfig;
  /**
   * Optional macOS Seatbelt configuration.
   */
  seatbelt?: Seatbelt;
  /**
   * Optional cross-platform user-interface policy.
   */
  ui?: Ui;
  /**
   * The exact contract version marker.
   */
  version: Version;
} & ({ processContainer?: never } | { appContainer?: never }) & ({ seatbelt?: never } | { macos_sandbox?: never });

/**
 * Compatibility settings accepted for one-shot Windows Sandbox requests.
 */
export interface OneShotWindowsSandbox {
  /**
   * Optional daemon named-pipe override.
   */
  daemonPipeName?: string;
  /**
   * Legacy idle-timeout field retained for compatibility.
   */
  idleTimeout?: number;
  /**
   * Idle timeout before teardown, in milliseconds.
   */
  idleTimeoutMs?: number;
}

/**
 * One-shot WSLC backend settings.
 */
export interface OneShotWslc {
  /**
   * Requested virtual CPU count.
   */
  cpuCount?: number;
  /**
   * Whether GPU passthrough is enabled.
   */
  gpu?: boolean;
  /**
   * Container image reference.
   */
  image?: string;
  /**
   * Path to a local image tarball to import.
   */
  imageTarPath?: string;
  /**
   * Requested memory limit in megabytes.
   */
  memoryMb?: number;
  /**
   * Optional host-to-container TCP port mappings.
   */
  portMappings?: PortMapping[];
  /**
   * Optional storage path override.
   */
  storagePath?: string;
  /**
   * Target operating system inside the container.
   */
  targetOs?: string;
}

/**
 * A host-to-container WSLC port mapping.
 */
export interface PortMapping {
  /**
   * Non-zero TCP port inside the container.
   */
  containerPort: number;
  /**
   * Optional transport protocol. Only TCP is currently supported.
   */
  protocol?: TransportProtocol;
  /**
   * Non-zero TCP port on the Windows host.
   */
  windowsPort: number;
}

/**
 * Process execution settings.
 */
export interface Process {
  /**
   * The non-empty command line to execute.
   */
  commandLine: NonEmptyString;
  /**
   * Optional working directory.
   */
  cwd?: string;
  /**
   * Optional environment entries encoded as `KEY=VALUE` strings.
   */
  env?: string[];
  /**
   * Optional execution timeout in milliseconds.
   */
  timeout?: number;
}

/**
 * ProcessContainer-specific settings.
 */
export interface ProcessContainer {
  /**
   * Optional AppContainer capability names. Each entry must contain one name; commas are rejected because BaseContainer uses them as its wire delimiter. `learningModeLogging` and `permissiveLearningMode` are reserved; use `learningMode`, `--audit`, or `captureDenials` instead.
   */
  capabilities?: ProcessContainerCapability[];
  /**
   * Optional capture-denials policy.
   */
  captureDenials?: CaptureDenials;
  /**
   * Optional learning-mode (deny-and-record)
   */
  learningMode?: boolean;
  /**
   * Whether least-privilege mode is enabled.
   */
  leastPrivilege?: boolean;
  /**
   * Optional ProcessContainer-specific network settings.
   */
  network?: ProcessContainerNetwork;
  /**
   * Optional ProcessContainer-specific user-interface policy.
   */
  ui?: ProcessContainerUi;
}

export type ProcessContainerCapability = string;

/**
 * ProcessContainer-specific network settings.
 */
export interface ProcessContainerNetwork {
  /**
   * Optional loopback peer the contained process may reach in addition to the configured runtime proxy. Requires `runtimeConfig.networkProxy`.
   */
  allowedProxyPeer?: string;
}

/**
 * ProcessContainer-specific user-interface policy.
 */
export interface ProcessContainerUi {
  /**
   * Whether desktop system control is allowed.
   */
  desktopSystemControl?: boolean;
  /**
   * Whether Input Method Editor access is allowed.
   */
  ime?: boolean;
  /**
   * Optional desktop-resource isolation level.
   */
  isolation?: ProcessContainerUiIsolation;
  /**
   * Optional system-settings access level.
   */
  systemSettings?: string;
}

export type ProcessContainerUiIsolation = "container" | "desktop" | "handles" | "atoms";

export type ProvisionPhase = "provision";

/**
 * Runtime configuration supplied alongside the sandbox policy.
 */
export interface RuntimeConfig {
  /**
   * Optional loopback proxy the runtime configures for the sandbox. Must address localhost, and requires an egress policy.
   */
  networkProxy?: string;
}

/**
 * macOS Seatbelt backend settings.
 */
export interface Seatbelt {
  /**
   * Additional Mach service global names the process may resolve.
   */
  extraMachLookups?: string[];
  /**
   * Whether GUI application access is allowed.
   */
  guiAccess?: boolean;
  /**
   * Whether macOS Keychain access is allowed.
   */
  keychainAccess?: boolean;
  /**
   * Optional method used to launch the contained process.
   */
  launchMethod?: LaunchMethod;
  /**
   * Whether the contained process may allocate nested pseudo-terminals.
   */
  nestedPty?: boolean;
  /**
   * Optional override of the generated sandbox profile.
   */
  profileOverride?: string;
}

/**
 * Experimental settings accepted by the `start` phase.
 */
export interface StartExperimental {
  /**
   * Optional telemetry override.
   */
  telemetry?: Telemetry;
}

export type StartPhase = "start";

/**
 * A complete state-aware `start` request.
 */
export interface StartRequest {
  /**
   * Optional JSON Schema reference for editor validation.
   */
  $schema?: string;
  /**
   * Optional human-readable annotation ignored by the runtime.
   */
  _comment?: unknown;
  /**
   * Optional correlation vector relayed from provision.
   */
  correlationVector?: string;
  /**
   * Optional closed post-provision experimental settings.
   */
  experimental?: StartExperimental;
  /**
   * Exact `start` phase marker.
   */
  phase: StartPhase;
  /**
   * Identifier returned by the provision phase.
   */
  sandboxId: string;
  /**
   * Exact development contract version.
   */
  version: Version;
}

/**
 * State-aware IsolationSession experimental settings.
 */
export interface StateAwareIsolationSession {
  /**
   * Optional provision-phase settings.
   */
  provision?: IsolationSessionProvision;
}

/**
 * State-aware WSLC experimental settings.
 */
export interface StateAwareWslc {
  /**
   * Optional provision-phase settings.
   */
  provision?: WslcProvision;
}

/**
 * Experimental settings accepted by the `stop` phase.
 */
export interface StopExperimental {
  /**
   * Optional telemetry override.
   */
  telemetry?: Telemetry;
}

export type StopPhase = "stop";

/**
 * A complete state-aware `stop` request.
 */
export interface StopRequest {
  /**
   * Optional JSON Schema reference for editor validation.
   */
  $schema?: string;
  /**
   * Optional human-readable annotation ignored by the runtime.
   */
  _comment?: unknown;
  /**
   * Optional correlation vector relayed from provision.
   */
  correlationVector?: string;
  /**
   * Optional closed post-provision experimental settings.
   */
  experimental?: StopExperimental;
  /**
   * Exact `stop` phase marker.
   */
  phase: StopPhase;
  /**
   * Identifier returned by the provision phase.
   */
  sandboxId: string;
  /**
   * Exact development contract version.
   */
  version: Version;
}

/**
 * One-shot telemetry override.
 */
export interface Telemetry {
  /**
   * Whether telemetry is enabled.
   */
  enabled?: boolean;
}

/**
 * Placeholder feature used to exercise experimental configuration plumbing.
 */
export interface TestFeature {
  /**
   * The message for the test feature.
   */
  message?: string;
}

export type TransportProtocol = "tcp";

export type True = true;

/**
 * Cross-platform user-interface policy.
 */
export interface Ui {
  /**
   * Optional clipboard access level.
   */
  clipboard?: UiClipboard;
  /**
   * Whether visible user interface is disabled.
   */
  disable?: boolean;
  /**
   * Whether keyboard and mouse input injection is allowed.
   */
  injection?: boolean;
}

export type UiClipboard = "none" | "read" | "write" | "all";

export type Version = "0.8.0-alpha";

export type WindowsSandboxContainment = "windows_sandbox";

/**
 * Experimental settings accepted by a Windows Sandbox provision request.
 */
export interface WindowsSandboxExperimental {
  /**
   * Optional telemetry override.
   */
  telemetry?: Telemetry;
}

/**
 * A complete state-aware `provision` request for windows_sandbox
 */
export interface WindowsSandboxProvisionRequest {
  /**
   * Optional JSON Schema reference for editor validation.
   */
  $schema?: string;
  /**
   * Optional human-readable annotation ignored by the runtime.
   */
  _comment?: unknown;
  /**
   * Exact `windows_sandbox` containment marker.
   */
  containment: WindowsSandboxContainment;
  /**
   * Optional closed experimental settings.
   */
  experimental?: WindowsSandboxExperimental;
  /**
   * Optional filesystem policy.
   */
  filesystem?: Filesystem;
  /**
   * Exact `provision` phase marker.
   */
  phase: ProvisionPhase;
  /**
   * Exact development contract version.
   */
  version: Version;
}

export type WslcContainment = "wslc";

/**
 * WSLC settings accepted during provisioning.
 */
export interface WslcProvision {
  /**
   * Optional container image reference.
   */
  image?: string;
  /**
   * Optional path to a local container image archive.
   */
  imageTarPath?: string;
}

/**
 * Experimental settings accepted by a WSLC provision request.
 */
export interface WslcProvisionExperimental {
  /**
   * Optional telemetry override.
   */
  telemetry?: Telemetry;
  /**
   * Optional WSLC backend settings.
   */
  wslc?: StateAwareWslc;
}

/**
 * A complete state-aware `provision` request for wslc
 */
export interface WslcProvisionRequest {
  /**
   * Optional JSON Schema reference for editor validation.
   */
  $schema?: string;
  /**
   * Optional human-readable annotation ignored by the runtime.
   */
  _comment?: unknown;
  /**
   * Exact `wslc` containment marker.
   */
  containment: WslcContainment;
  /**
   * Optional closed experimental settings.
   */
  experimental?: WslcProvisionExperimental;
  /**
   * Optional filesystem policy fixed at provision time.
   */
  filesystem?: Filesystem;
  /**
   * Optional network policy fixed at provision time.
   */
  network?: Network;
  /**
   * Exact `provision` phase marker.
   */
  phase: ProvisionPhase;
  /**
   * Exact development contract version.
   */
  version: Version;
}

/**
 * Exact mutable MXC development configuration contract.
 */
export type MXCConfiguration = OneShotRequest | DeprovisionRequest | StopRequest | ExecRequest | StartRequest | WslcProvisionRequest | IsolationSessionProvisionRequest | WindowsSandboxProvisionRequest;
