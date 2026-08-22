// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/* eslint-disable */
/**
 * GENERATED FILE — DO NOT EDIT BY HAND.
 *
 * Emitted from the generated JSON Schema (itself generated from the Rust wire
 * model `wxc_common::wire`) by the `mxc_schema_gen types --legacy-wire`
 * TypeScript emitter (`mxc_schema_support`). This is a drift oracle, not public
 * API: it is never
 * exported from the SDK. The conformance test asserts the hand-written public
 * types in `../types.ts` still match these. CI gate:
 * `scripts/versioning/check-sdk-types-codegen.js`.
 *
 * Regenerate with:
 *   cargo run --manifest-path src/Cargo.toml -p mxc_schema_gen -- types --legacy-wire --out sdk/node/src/generated/wire.ts
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
 * Windows denial-capture settings. The presence of the `captureDenials` object enables capture; all fields are optional. Native capture requires the complete compatible PSEC plus V2 Learning Mode API set. Requests that native capture cannot represent use guarded WPR with a compatible legacy SBOX or AppContainer containment tier.
 */
export interface CaptureDenials {
  /**
   * How each ungranted access check is handled while it is recorded. Both modes log every access the policy does not grant to the ETL trace; the mode only decides whether that access is blocked or allowed. Defaults to `block` when omitted.
   */
  mode?: CaptureDenialsMode | null;
  /**
   * Absolute path where the JSON denials output file is written — the deliverable a consuming application reads to learn what the workload was denied. It is a single JSON document `{ "denials": [...], "summary": {...} }`. A per-run identifier (process id plus random suffix) is inserted into the file stem (e.g. `denials.json` -> `denials.<run-id>.json`) so concurrent and sequential captures do not collide; the actual path is reported on stderr. When omitted, MXC writes it to a managed per-run temporary file and prints its path on stderr. The parent directory must already exist. (The intermediate ETL trace is an internal, runner-managed file in a protected per-run directory. Retained traces use `%LOCALAPPDATA%\Microsoft\MXC\capture-denials\retained`; non-retained traces use the system temporary directory.)
   */
  outputPath?: string | null;
  /**
   * Keep the sealed ETL trace after analysis and report its path in output metadata. Defaults to `false`, which deletes the trace after analysis. Retention requires a terminal wait; abandoning the process handle deletes the internal trace. If post-seal analysis fails, the failure and retained path are exposed through `captureDenialsError` output metadata. Retained traces can contain sensitive resource paths and identifiers; callers are responsible for deleting them.
   */
  retainEtl?: boolean | null;
}

/**
 * How `captureDenials` handles each ungranted access check while recording it.
 */
export type CaptureDenialsMode = "block" | "allow";

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
   * Telemetry configuration.
   */
  telemetry?: Telemetry | null;
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
 * IsolationSession backend config. Carries only the per-phase state-aware nesting for the phases that take config (`provision`). The one-shot surface takes no backend configuration at all. `start`, `stop`, `deprovision`, and `exec` take no per-phase config payload: `start`, `stop` and `deprovision` are invoked with only the top-level `phase` and `sandboxId`, and `exec` additionally carries the top-level `process` block.
 */
export interface IsolationSession {
  /**
   * State-aware provision-phase configuration.
   */
  provision?: IsolationSessionProvisionPhase | null;
  [k: string]: unknown;
}

/**
 * Provision-phase IsolationSession configuration (state-aware lifecycle).
 * 
 * The only phase that takes a per-phase payload, so it is its own type rather than a shared one: a shared type would advertise its fields on every phase in the generated schema. The domain configs and the SDK types are already split per phase; this keeps the wire model aligned with them.
 */
export interface IsolationSessionProvisionPhase {
  /**
   * Optional identifier for the calling application.
   * 
   * **A packaged application must supply its Package Family Name in the form `PFN:<packageFamilyName>`** (for example `PFN:Contoso.App_8wekyb3d8bbwe`). An unpackaged application may pass any string. Carried inside the `sandboxId` so later lifecycle phases can recover it without the caller re-supplying it.
   */
  appId?: string | null;
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
   * Outbound network policy.
   */
  egress?: NetworkEgress | null;
  /**
   * How the policy is enforced.
   */
  enforcementMode?: NetworkEnforcement | null;
  /**
   * Inbound and host-loopback network policy.
   */
  ingress?: NetworkIngress | null;
  /**
   * Proxy configuration (one of localhost / builtinTestServer / url).
   */
  proxy?: Proxy | null;
}

/**
 * Allow or deny network action.
 */
export type NetworkAction = "allow" | "deny";

/**
 * Outbound network policy.
 */
export interface NetworkEgress {
  /**
   * Explicit allow rules.
   */
  allow?: NetworkRule[] | null;
  /**
   * Action used when no explicit rule matches. Defaults to `deny`.
   */
  default?: NetworkAction | null;
  /**
   * Explicit deny rules. Deny rules take precedence over allow rules.
   */
  deny?: NetworkRule[] | null;
}

/**
 * Network enforcement mechanism.
 */
export type NetworkEnforcement = "capabilities" | "firewall" | "both";

/**
 * Inbound and host-loopback network policy.
 */
export interface NetworkIngress {
  /**
   * Default action for LAN/private-network inbound traffic.
   */
  default?: NetworkAction | null;
  /**
   * Bidirectional host-loopback connectivity action.
   */
  hostLoopback?: NetworkAction | null;
}

/**
 * CIDR network peer.
 */
export interface NetworkPeer {
  /**
   * IPv4 or IPv6 CIDR.
   */
  cidr: string;
  /**
   * CIDRs excluded from this peer.
   */
  except?: string[] | null;
}

/**
 * Default network policy.
 */
export type NetworkPolicy = "allow" | "block";

/**
 * Protocol and destination-port selector.
 */
export interface NetworkPort {
  /**
   * Inclusive end of a destination-port range. Requires `port`.
   */
  endPort?: number | null;
  /**
   * Destination port. Omission matches every port.
   */
  port?: number | null;
  /**
   * Transport protocol. Defaults to `any`.
   */
  protocol?: NetworkProtocol | null;
}

/**
 * Transport protocol selector.
 */
export type NetworkProtocol = "tcp" | "udp" | "icmp" | "any";

/**
 * Outbound network rule.
 */
export interface NetworkRule {
  /**
   * Destination protocols and ports. Omission matches all.
   */
  ports?: NetworkPort[] | null;
  /**
   * Destination CIDRs. Omission matches both IP families.
   */
  to?: NetworkPeer[] | null;
}

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
   * Working directory for the process. When omitted, backends substitute a directory the sandbox can use rather than inheriting the launcher's cwd: Windows ProcessContainer picks the first `readwritePaths` entry that is an existing directory, else the first such `readonlyPaths` entry, else the system drive root; Seatbelt applies the same precedence with a `/` fallback; LXC/WSL use the container root; NanVix and Hyperlight reject a working directory outright. See `docs/schema.md` ("Working Directory").
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
   * AppContainer capabilities (e.g. `internetClient`, `registryRead`). Each array entry must contain exactly one capability name; commas are rejected because BaseContainer uses commas as its wire delimiter. `learningModeLogging` and `permissiveLearningMode` are reserved and rejected here; use `learningMode`, `--audit`, or the dedicated denial capture configuration instead.
   */
  capabilities?: string[] | null;
  /**
   * Windows denial capture. When present, the runner records the sandboxed process's access attempts to a learning-mode ETL trace for later inspection. MXC prefers native PSEC plus V2 Learning Mode when that API set can fully honor the request. Otherwise it retains the highest compatible legacy containment tier and uses guarded WPR capture, so `leastPrivilege`, `network.proxy`, and deny-path policies can remain enforced without weakening the request.
   */
  captureDenials?: CaptureDenials | null;
  /**
   * AppContainer learning mode (deny-and-record): failed access checks are logged for diagnostics while the accesses stay denied; containment is unchanged. Distinct from the allow-all `permissiveLearningMode` capability, which is injected internally by the `--audit` CLI flag or dedicated denial-capture configuration.
   */
  learningMode?: boolean | null;
  /**
   * Enforce least-privilege mode.
   */
  leastPrivilege?: boolean | null;
  /**
   * ProcessContainer-specific network configuration.
   */
  network?: ProcessContainerNetwork | null;
  /**
   * BaseProcessContainer UI settings (Windows).
   */
  ui?: BaseProcessUi | null;
}

/**
 * ProcessContainer-specific network configuration.
 */
export interface ProcessContainerNetwork {
  /**
   * Installed package family name or AppContainer profile allowed to host the configured loopback proxy.
   */
  allowedProxyPeer?: string | null;
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
 * Runtime values supplied alongside, but separate from, sandbox policy.
 */
export interface RuntimeConfig {
  /**
   * HTTP/S loopback proxy URL.
   */
  networkProxy?: string | null;
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
 * Telemetry configuration (`experimental.telemetry`).
 */
export interface Telemetry {
  /**
   * Explicit telemetry override. `true` = force on, `false` = force off, omitted = disabled (default off).
   */
  enabled?: boolean | null;
  [k: string]: unknown;
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
   * Host → container port forwards. Only TCP is currently supported; the parser rejects `udp` because the WSLC SDK runtime returns `E_NOTIMPL` for UDP port mappings.
   */
  portMappings?: PortMapping[] | null;
  /**
   * State-aware provision-phase configuration (`experimental.wslc.provision`). Carries the container-creation knobs for the state-aware lifecycle; the flat sibling fields above remain the one-shot surface. Absent on one-shot configs and non-provision phases.
   */
  provision?: WslcProvisionPhase | null;
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
 * Per-phase WSLc **provision** configuration (state-aware lifecycle), nested under `experimental.wslc.provision`. Carries only what the amortized daemon session honors: the container image (or a local tarball to import).
 * 
 * Filesystem mounts and network mode derive from the top-level `policy` section (readwrite / readonly paths, network), not from here. The one-shot-only sizing knobs (`cpuCount` / `memoryMb` / `gpu` / `storagePath` / `portMappings`) are deliberately absent: the daemon shares a single session across sandboxes and does not apply per-sandbox sizing. start / exec / stop / deprovision carry no backend-specific config (the exec command flows through the top-level `process` section), so they have no phase struct.
 */
export interface WslcProvisionPhase {
  /**
   * Container image reference (e.g. `alpine:latest`). Defaults to `alpine:latest` when omitted.
   */
  image?: string | null;
  /**
   * Path to a local image tarball to import instead of pulling.
   */
  imageTarPath?: string | null;
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
   * Microsoft Correlation Vector (MS-CV) seeded at `provision` and returned in the provision result. The client relays it verbatim into every later state-aware phase so all phases of one lifecycle share a telemetry base prefix (emitted under `__TlgCV__`). The executor is the trust boundary: on each non-provision phase it validates the relayed value and *spins* a fresh child element off a mutable base (so multiple invocations of one phase stay distinct), passes an already-frozen vector through unchanged, and reseeds a brand-new base if the relayed value is absent or malformed — so a missing or hostile relay never reaches telemetry unvalidated. Ignored unless experimental telemetry is enabled; not valid on one-shot requests.
   */
  correlationVector?: string | null;
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
   * Runtime values supplied alongside, but separate from, sandbox policy.
   */
  runtimeConfig?: RuntimeConfig | null;
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
   * MXC config schema version (semver), e.g. `"0.9.0-alpha"`.
   */
  version?: string | null;
}

