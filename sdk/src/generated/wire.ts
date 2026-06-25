// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/* eslint-disable */
/**
 * GENERATED FILE — DO NOT EDIT BY HAND.
 *
 * Emitted from the generated JSON Schema (itself generated from the Rust wire
 * model `wxc_common::wire`) by the `mxc_schema_gen --ts` TypeScript emitter
 * (`wxc_common::ts_emit`). This is a drift oracle, not public API: it is never
 * exported from the SDK. The conformance test asserts the hand-written public
 * types in `../types.ts` still match these. CI gate:
 * `scripts/versioning/check-sdk-types-codegen.js`.
 *
 * Regenerate with:
 *   cargo run --manifest-path src/Cargo.toml -p mxc_schema_gen -- --ts sdk/src/generated/wire.ts
 */
/**
 * BaseProcessContainer UI isolation settings.
 */
export interface BaseProcessUi {
  /**
   * Whether desktop system control is allowed.
   */
  desktopSystemControl?: boolean | null;
  /**
   * Whether the IME (Input Method Editor) is allowed.
   */
  ime?: boolean | null;
  /**
   * UI isolation level.
   */
  isolation?: UiIsolation | null;
  /**
   * System settings access level.
   */
  systemSettings?: string | null;
}

/**
 * Clipboard access level.
 */
export type ClipboardPolicy = "none" | "read" | "write" | "all";

/**
 * Containment backend (abstract intent or concrete backend).
 */
export type Containment = "process" | "processcontainer" | "vm" | "windows_sandbox" | "lxc" | "microvm" | "hyperlight" | "wslc" | "seatbelt" | "isolation_session" | "bubblewrap";

/**
 * Experimental features (only honored with `--experimental`). This block is intentionally **permissive** (no `deny_unknown_fields`): experimental backends are in flux, so the schema documents the known shapes for editor help without rejecting in-progress fields. The strict, closed contract is the stable (top-level) surface.
 */
export interface Experimental {
  /**
   * IsolationSession backend config (Windows).
   */
  isolation_session?: IsolationSession | null;
  /**
   * Seatbelt backend config (pre-promotion alias).
   */
  seatbelt?: Seatbelt | null;
  /**
   * Placeholder feature for testing experimental infrastructure.
   */
  test?: TestFeature | null;
  /**
   * Windows Sandbox backend config.
   */
  windows_sandbox?: WindowsSandbox | null;
  /**
   * WSL container backend config.
   */
  wslc?: Wslc | null;
  [k: string]: unknown;
}

/**
 * AppContainer DACL-mutation fallback policy.
 */
export interface Fallback {
  /**
   * Allow the runner to mutate DACLs as a fallback.
   */
  allowDaclMutation?: boolean | null;
}

/**
 * Filesystem access policy.
 */
export interface Filesystem {
  /**
   * Paths explicitly denied (override broader allow rules).
   */
  deniedPaths?: string[] | null;
  /**
   * Paths the process can read but not write.
   */
  readonlyPaths?: string[] | null;
  /**
   * Paths the process can read and write.
   */
  readwritePaths?: string[] | null;
}

/**
 * IsolationSession sizing profile.
 */
export type IsolationConfigurationId = "small" | "medium" | "large" | "composable";

/**
 * IsolationSession backend config. Carries both the one-shot fields (`configurationId`, `user`) and the per-phase state-aware nesting (`provision` / `start` / `stop` / `deprovision`).
 */
export interface IsolationSession {
  /**
   * Sizing profile (one-shot).
   */
  configurationId?: IsolationConfigurationId | null;
  /**
   * State-aware deprovision-phase configuration.
   */
  deprovision?: IsolationSessionPhase | null;
  /**
   * State-aware provision-phase configuration.
   */
  provision?: IsolationSessionPhase | null;
  /**
   * State-aware start-phase configuration.
   */
  start?: IsolationSessionPhase | null;
  /**
   * State-aware stop-phase configuration.
   */
  stop?: IsolationSessionPhase | null;
  /**
   * Optional Entra cloud-agent user bundle (one-shot).
   */
  user?: IsolationUser | null;
  [k: string]: unknown;
}

/**
 * Per-phase IsolationSession configuration (state-aware lifecycle).
 */
export interface IsolationSessionPhase {
  /**
   * Sizing profile for this phase.
   */
  configurationId?: IsolationConfigurationId | null;
  /**
   * Entra cloud-agent user bundle for this phase.
   */
  user?: IsolationUser | null;
  [k: string]: unknown;
}

/**
 * Entra cloud-agent user bundle. Reachable only under the permissive `experimental` surface, so unknown fields are tolerated (forward-compat).
 */
export interface IsolationUser {
  /**
   * User principal name.
   */
  upn: string;
  /**
   * Short-lived WAM bearer token (passed verbatim to the OS service).
   */
  wamToken: string;
  [k: string]: unknown;
}

/**
 * Seatbelt inner-process launch method.
 */
export type LaunchMethod = "exec" | "open";

/**
 * Container lifecycle settings.
 */
export interface Lifecycle {
  /**
   * Destroy the container when the process exits (default true).
   */
  destroyOnExit?: boolean | null;
  /**
   * Preserve the applied policy after exit (default false).
   */
  preservePolicy?: boolean | null;
}

/**
 * LXC container settings.
 */
export interface Lxc {
  /**
   * Distribution image (e.g. `alpine`).
   */
  distribution?: string | null;
  /**
   * Distribution release (e.g. `3.23`).
   */
  release?: string | null;
}

/**
 * Network access policy.
 */
export interface Network {
  /**
   * Allow binding/listening on local IPs and accepting inbound connections.
   */
  allowLocalNetwork?: boolean | null;
  /**
   * Hosts explicitly allowed.
   */
  allowedHosts?: string[] | null;
  /**
   * Hosts explicitly blocked.
   */
  blockedHosts?: string[] | null;
  /**
   * Default outbound policy when no host rule matches.
   */
  defaultPolicy?: NetworkPolicy | null;
  /**
   * How the policy is enforced.
   */
  enforcementMode?: NetworkEnforcement | null;
  /**
   * Proxy configuration (one of localhost / builtinTestServer / url).
   */
  proxy?: Proxy | null;
}

/**
 * Network enforcement mechanism.
 */
export type NetworkEnforcement = "capabilities" | "firewall" | "both";

/**
 * Default network policy.
 */
export type NetworkPolicy = "allow" | "block";

/**
 * State-aware lifecycle phase.
 */
export type Phase = "provision" | "start" | "exec" | "stop" | "deprovision";

/**
 * A single host → container port forward. Reachable only under the permissive `experimental` surface, so unknown fields are tolerated (forward-compat).
 */
export interface PortMapping {
  /**
   * Container port.
   */
  containerPort: number;
  /**
   * Transport protocol for the mapping. Only `tcp` is currently supported.
   */
  protocol?: TransportProtocol | null;
  /**
   * Host (Windows) port.
   */
  windowsPort: number;
  [k: string]: unknown;
}

/**
 * Process execution settings.
 */
export interface Process {
  /**
   * Command line (or script) to execute.
   */
  commandLine?: string | null;
  /**
   * Working directory for the process.
   */
  cwd?: string | null;
  /**
   * Environment variables as `"KEY=VALUE"` strings.
   */
  env?: string[] | null;
  /**
   * Wall-clock timeout in milliseconds.
   */
  timeout?: number | null;
}

/**
 * ProcessContainer-specific settings.
 */
export interface ProcessContainer {
  /**
   * AppContainer capabilities (e.g. `internetClient`, `registryRead`).
   */
  capabilities?: string[] | null;
  /**
   * AppContainer permissive learning mode.
   */
  learningMode?: boolean | null;
  /**
   * Enforce least-privilege mode.
   */
  leastPrivilege?: boolean | null;
  /**
   * BaseProcessContainer UI settings (Windows).
   */
  ui?: BaseProcessUi | null;
}

/**
 * Proxy configuration. Exactly one variant applies.
 */
export interface Proxy {
  /**
   * Have wxc launch its own built-in test proxy.
   */
  builtinTestServer?: boolean | null;
  /**
   * External localhost proxy port.
   */
  localhost?: number | null;
  /**
   * Proxy URL (parsed into host:port).
   */
  url?: string | null;
}

/**
 * macOS Seatbelt backend configuration.
 */
export interface Seatbelt {
  /**
   * Additional Mach service global-names the inner process may resolve.
   */
  extraMachLookups?: string[] | null;
  /**
   * Allow GUI (WindowServer) access.
   */
  guiAccess?: boolean | null;
  /**
   * Allow Keychain access.
   */
  keychainAccess?: boolean | null;
  /**
   * Inner process launch method.
   */
  launchMethod?: LaunchMethod | null;
  /**
   * Attach the inner process to a nested pty (default true).
   */
  nestedPty?: boolean | null;
  /**
   * Replace the generated profile entirely (advanced/testing escape hatch).
   */
  profileOverride?: string | null;
}

/**
 * Placeholder experimental feature.
 */
export interface TestFeature {
  /**
   * Message to log when the feature is applied.
   */
  message?: string | null;
  [k: string]: unknown;
}

/**
 * Port-forward transport protocol. Only `tcp` is currently supported by the vendored WSLC SDK runtime; `udp` is rejected at parse time.
 */
export type TransportProtocol = "tcp";

/**
 * Cross-platform UI isolation policy.
 */
export interface Ui {
  /**
   * Clipboard access level.
   */
  clipboard?: ClipboardPolicy | null;
  /**
   * Disable all UI access (default true).
   */
  disable?: boolean | null;
  /**
   * Allow UI injection.
   */
  injection?: boolean | null;
}

/**
 * Desktop UI isolation level.
 */
export type UiIsolation = "desktop" | "handles" | "atoms" | "container";

/**
 * Windows Sandbox backend config.
 */
export interface WindowsSandbox {
  /**
   * Daemon named-pipe override.
   */
  daemonPipeName?: string | null;
  /**
   * Idle timeout (legacy seconds field).
   */
  idleTimeout?: number | null;
  /**
   * Idle timeout before teardown (ms).
   */
  idleTimeoutMs?: number | null;
  [k: string]: unknown;
}

/**
 * WSL container backend config.
 */
export interface Wslc {
  /**
   * vCPU count.
   */
  cpuCount?: number | null;
  /**
   * Enable GPU passthrough.
   */
  gpu?: boolean | null;
  /**
   * Container image reference.
   */
  image?: string | null;
  /**
   * Path to a local image tarball.
   */
  imageTarPath?: string | null;
  /**
   * Memory limit (MB).
   */
  memoryMb?: number | null;
  /**
   * Host → container port forwards. Only TCP is currently supported by the vendored WSLC SDK runtime (Microsoft.WSL.Containers 2.8.1); the parser rejects `udp` because the shipped runtime returns `E_NOTIMPL`.
   */
  portMappings?: PortMapping[] | null;
  /**
   * Storage path override.
   */
  storagePath?: string | null;
  /**
   * OS inside the WSL container.
   */
  targetOs?: string | null;
  [k: string]: unknown;
}

/**
 * MXC container execution configuration. Defines the recommended config format for both one-shot and state-aware sandbox lifecycle requests. A few deprecated field spellings not listed here are also accepted via serde aliases.
 */
export interface MXCConfiguration {
  /**
   * Optional JSON Schema reference for editor validation. Accepted but ignored by the parser.
   */
  $schema?: string | null;
  /**
   * Optional human-readable annotation. Accepted but ignored by the parser.
   */
  _comment?: unknown;
  /**
   * Externally assigned container identifier.
   */
  containerId?: string | null;
  /**
   * Containment backend to use for execution. Accepts abstract intents (`process`, `vm`) and concrete backends; the binary resolves intents to a concrete backend per host at run time.
   */
  containment?: Containment | null;
  /**
   * Experimental features. Only honored when `--experimental` is passed.
   */
  experimental?: Experimental | null;
  /**
   * AppContainer DACL-mutation fallback policy (Windows).
   */
  fallback?: Fallback | null;
  /**
   * Filesystem access policy. Shared across all backends.
   */
  filesystem?: Filesystem | null;
  /**
   * Container lifecycle settings.
   */
  lifecycle?: Lifecycle | null;
  /**
   * LXC container settings (Linux). Used when containment is `lxc`.
   */
  lxc?: Lxc | null;
  /**
   * Network access policy. Shared across all backends.
   */
  network?: Network | null;
  /**
   * State-aware lifecycle phase. When present, the request is a state-aware request (`sandboxId` is required for non-provision phases); when absent, the request is one-shot.
   */
  phase?: Phase | null;
  /**
   * Process to execute and its environment.
   */
  process?: Process | null;
  /**
   * ProcessContainer-specific settings (Windows). Used when containment is `processcontainer`.
   */
  processContainer?: ProcessContainer | null;
  /**
   * Sandbox identifier returned by a prior provision request. Required for non-provision state-aware phases.
   */
  sandboxId?: string | null;
  /**
   * macOS Seatbelt backend configuration. Used when containment is `seatbelt`.
   */
  seatbelt?: Seatbelt | null;
  /**
   * Cross-platform UI isolation policy.
   */
  ui?: Ui | null;
  /**
   * MXC config schema version (semver), e.g. `"0.8.0-alpha"`.
   */
  version?: string | null;
}

