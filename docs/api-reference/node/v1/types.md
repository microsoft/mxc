# Node V1 types

> **Audience:** MXC consumers

Public entrypoint: `@microsoft/mxc-sdk/v1`. [Operations](api.md) | [Overview](README.md)

Declarations include public fields, variants, constructors, and members.
Comments clarify field meaning, defaults, ownership, and platform applicability
where the signature alone is insufficient. Private constructors, native
drivers, and other implementation-only members are omitted.

## `@microsoft/mxc-sdk/v1::AvailableBackend`

One native host-available backend. Absent capability/warning lists become
empty arrays. New native backend, tier, or capability names map to `unknown`.

```typescript
export interface AvailableBackend {
  /** Canonical backend name, or unknown for a newer native value. */
  backend: ContainmentBackend | 'unknown';
  /** Effective isolation tier; omitted for backends without a tier ladder. */
  tier?: IsolationTier | 'unknown';
  /** Optional features supported by this backend and tier. */
  capabilities: BackendCapability[];
  /** Diagnostics for unavailable optional capabilities. */
  warnings: string[];
}
```

## `@microsoft/mxc-sdk/v1::BackendCapability`

An optional capability reported by native backend discovery.

```typescript
export type BackendCapability =
  | 'captureDenials' // Windows only.
  | 'filesystemDeniedPaths' // Windows only.
  | 'filesystemEnumeratePaths' // Windows only.
  | 'ingressHostLoopbackAllow' // Windows only.
  | 'proxyEnforcement' // Linux Bubblewrap only.
  | 'identitylessLoopbackProxy' // Windows only.
  | 'unknown';
```

## `@microsoft/mxc-sdk/v1::BaseProcessUiConfig`

BaseProcess-specific UI configuration (Windows only).

```typescript
export interface BaseProcessUiConfig {
  isolation: "desktop" | "handles" | "atoms" | "container";
  desktopSystemControl: boolean;
  systemSettings: string;
  ime: boolean;
}
```

## `@microsoft/mxc-sdk/v1::ContainmentBackend`

A canonical containment backend name.

```typescript
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
```


## `@microsoft/mxc-sdk/v1::BubblewrapNetworkSupport`

Host support for enforcing Bubblewrap proxy-only egress.

```typescript
export interface BubblewrapNetworkSupport {
  proxyEnforcement: 'supported' | 'unsupported';
  warnings: string[];
}
```


## `@microsoft/mxc-sdk/v1::ClipboardPolicy`

Clipboard access policy levels.

```typescript
export type ClipboardPolicy = "none" | "read" | "write" | "all";
```


## `@microsoft/mxc-sdk/v1::ContainerId`

Branded container identifier returned by provisionContainer and routed back to the same backend by subsequent phases.

```typescript
export type ContainerId<C extends LifecycleContainmentKind = LifecycleContainmentKind> = string & {
  readonly __mxcBrand: 'ContainerId';
  readonly __mxcBackend: C;
};
```


## `@microsoft/mxc-sdk/v1::ContainerMetadata`

Per-backend per-phase metadata bundle.

```typescript
export type ContainerMetadata = DefineContainerMetadataRegistry<{
  isolation_session: {
    provision?: IsolationSessionProvisionMetadata;
  };
  wslc: Record<never, never>;
}>;
```


## `@microsoft/mxc-sdk/v1::NetworkPolicy`

Network settings accepted when creating a container request.

```typescript
export interface NetworkPolicy extends DirectionalNetworkConfig {
  runtimeConfig?: NetworkRuntimeConfig;
}
```


## `@microsoft/mxc-sdk/v1::ContainerRequest`

Complete container request.

```typescript
export interface ContainerRequest {
  /** Command line executed as the container's workload. */
  command: string;
  /** Cross-backend filesystem restrictions. */
  filesystem?: FilesystemPolicy;
  /** Cross-backend network policy and runtime network values. */
  network?: NetworkPolicy;
  /** Cross-backend UI restrictions. */
  ui?: UiPolicy;
  /** Workload timeout in milliseconds. */
  timeoutMs?: number;
  /** Backend selection; defaults to the platform-native process backend. */
  containment?: Containment;
  /** Optional backend-visible container name. */
  containerName?: string;
  /** Initial workload working directory. */
  workingDirectory?: string;
  /** Explicit environment entries. */
  environment?: {
    [key: string]: string | undefined;
  };
  /** Whether backend default environment variables are inherited. */
  inheritDefaultEnvironment?: boolean;
}
```


## `@microsoft/mxc-sdk/v1::Containment`

Closed union and SDK-owned containment choices for container creation requests.

```typescript
export type Containment = Containment.Process | Containment.ProcessContainer | Containment.Wslc | Containment.Lxc | Containment.Seatbelt | Containment.IsolationSession | Containment.Bubblewrap;

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
```


## `@microsoft/mxc-sdk/v1::FilesystemPolicy`

Cross-backend filesystem access restrictions.

```typescript
export interface FilesystemPolicy {
  readwritePaths?: string[];
  readonlyPaths?: string[];
  deniedPaths?: string[];
  clearPolicyOnExit?: boolean;
}
```


## `@microsoft/mxc-sdk/v1::UiPolicy`

Cross-backend UI access restrictions. Omitted access remains denied.

```typescript
export interface UiPolicy {
  disable: boolean;
  clipboard?: ClipboardPolicy;
  allowInputInjection?: boolean;
}
```



## `@microsoft/mxc-sdk/v1::DeprovisionOptions`

Invocation controls for releasing a container.

```typescript
export interface DeprovisionOptions {
  telemetry?: TelemetryConfig;
}
```



## `@microsoft/mxc-sdk/v1::DirectionalNetworkConfig`

Directional network policy used by provisioning.

```typescript
export interface DirectionalNetworkConfig {
  egress?: NetworkEgressConfig;
  ingress?: NetworkIngressConfig;
}
```


## `@microsoft/mxc-sdk/v1::ErrorCode`

Closed set of MXC wire-format error codes.

```typescript
export type ErrorCode = 'malformed_request' | 'unsupported_containment' | 'unsupported_phase' | 'backend_unavailable' | 'malformed_id' | 'stale_id' | 'not_provisioned' | 'not_started' | 'already_started' | 'already_stopped' | 'policy_validation' | 'backend_error';
```


## `@microsoft/mxc-sdk/v1::ExecutionMetadata`

Structured outputs produced by optional container features.
Live process metadata is populated after terminal settling.

```typescript
export interface ExecutionMetadata {
  captureDenials?: CaptureDenialsResult;
  captureDenialsError?: CaptureDenialsError;
}
```


## `@microsoft/mxc-sdk/v1::CaptureDenialsResult`

Location and summary of a captureDenials output document.
When `etlPath` is present, delete that retained file after use, not its parent directory.

```typescript
export interface CaptureDenialsResult {
  type: 'captureDenials';
  outputPath: string;
  exitCode: number;
  totalDenials: number;
  deniedResourcesTruncated: boolean;
  etlPath?: string;
}
```


## `@microsoft/mxc-sdk/v1::CaptureDenialsError`

Failure details and retained ETL location when capture finalization fails.
Delete the retained ETL file after use, not its parent directory.

```typescript
export interface CaptureDenialsError {
  message: string;
  etlPath: string;
}
```


## `@microsoft/mxc-sdk/v1::ValidationResult`

Warnings returned by validating an operation without executing it.
Omitted native warnings become an empty array; malformed warnings fail.

```typescript
export interface ValidationResult {
  warnings: string[];
}
```


## `@microsoft/mxc-sdk/v1::ExecutionResult`

Captured output and terminal outcome of a completed workload.

```typescript
export interface ExecutionResult {
  /** Captured standard output. */
  stdout: string;
  /** Captured standard error. */
  stderr: string;
  /** Workload exit code. */
  exitCode: number;
  /** Whether MXC terminated the workload after its configured timeout. */
  timedOut: boolean;
  /** Policy and operational diagnostics. */
  warnings: string[];
  /** Structured output from optional features such as denial capture. */
  outputMetadata?: ExecutionMetadata;
}
```


## `@microsoft/mxc-sdk/v1::FilesystemConfig`

Filesystem access configuration.

```typescript
export interface FilesystemConfig {
  readwritePaths?: string[];
  readonlyPaths?: string[];
  deniedPaths?: string[];
  clearPolicyOnExit?: boolean;
}
```


## `@microsoft/mxc-sdk/v1::policy.filesystem.FilesystemPolicyResult`

A composable fragment of filesystem policy.

```typescript
export interface FilesystemPolicyResult {
  readonlyPaths: string[];
  readwritePaths: string[];
}
```


## `@microsoft/mxc-sdk/v1::IsolationSessionNetworkConfig`

The only network posture IsolationSession can truthfully provide.

```typescript
export interface IsolationSessionNetworkConfig {
  egress: {
    default: 'allow';
    allow?: never;
    deny?: never;
  };
  ingress: {
    default: 'allow';
    hostLoopback: 'allow';
  };
}
```


## `@microsoft/mxc-sdk/v1::IsolationSessionProvisionMetadata`

IsolationSession's provision-phase metadata surfaced to the caller: the per-instance agent user account name minted for this container, the agent user's SID, and the ephemeral workspace directory shared between the caller and this isolated user (through which the caller can stage files into the session; deleted when the container is deprovisioned).

```typescript
export interface IsolationSessionProvisionMetadata {
  agentUserName: string;
  agentUserSid: string;
  ephemeralWorkspacePath: string;
}
```


## `@microsoft/mxc-sdk/v1::IsolationTier`

Isolation tier selected by the runtime fallback detector.

```typescript
export type IsolationTier = 'base-container' | 'appcontainer-bfs' | 'appcontainer-dacl';
```


## `@microsoft/mxc-sdk/v1::LifecycleContainmentKind`

Subset of ContainmentBackend that supports persistent containers.

```typescript
export type LifecycleContainmentKind = Extract<ContainmentBackend, 'isolation_session' | 'wslc'>;
```


## `@microsoft/mxc-sdk/v1::LxcConfig`

LXC container configuration for Linux container.

```typescript
export interface LxcConfig {
  containerName?: string;
  distribution?: string;
  release?: string;
  destroyOnExit?: boolean;
}
```


## `@microsoft/mxc-sdk/v1::MxcError`

Typed error thrown by the MXC SDK in response to a wire-format error envelope.

```typescript
export class MxcError extends Error {
  readonly code: ErrorCode;
  readonly operation?: string;
  readonly nativeCode?: string;
  readonly remediation?: string;
  readonly details?: Record<string, unknown>;
  constructor(fields: MxcErrorFields);
  constructor(code: ErrorCode, message: string, details?: Record<string, unknown>);
  constructor(codeOrFields: ErrorCode | MxcErrorFields, message?: string, details?: Record<string, unknown>);
}
```


## `@microsoft/mxc-sdk/v1::MxcErrorFields`

Every field an `MxcError` can carry. `operation`, `nativeCode`, and
`remediation` are top-level fields rather than entries in `details`.

```typescript
export interface MxcErrorFields {
  code: ErrorCode;
  message: string;
  operation?: string;
  nativeCode?: string;
  remediation?: string;
  details?: Record<string, unknown>;
}
```


## `@microsoft/mxc-sdk/v1::MxcProcess`

A container process whose stdio is backed by native Node streams.

```typescript
export class MxcProcess {
  /** Native process identifier. */
  readonly id: number;
  /** Writable standard input, or null when unavailable. */
  get standardInput(): Writable | null;
  /** Readable standard output, or null when unavailable. */
  get standardOutput(): Readable | null;
  /** Readable standard error, or null when unavailable. */
  get standardError(): Readable | null;
  /** Native policy and operational warnings. */
  get warnings(): readonly string[];
  /** Optional structured feature output, populated after completion. */
  get outputMetadata(): ExecutionMetadata | undefined;
  /** Wait for process completion. */
  wait(): Promise<WaitResult>;
  /** Request process termination. */
  kill(): void;
  /** Release native and stream resources. */
  dispose(): void;
}
```


## `@microsoft/mxc-sdk/v1::MxcPtyProcess`

A container process attached to an MXC-owned pseudo-terminal.

```typescript
export class MxcPtyProcess extends MxcProcess {
  /** Writable terminal input. */
  get input(): Writable;
  /** Readable merged terminal output. */
  get output(): Readable;
  /** Change the terminal dimensions. */
  resize(size: MxcPtySize): void;
}
```


## `@microsoft/mxc-sdk/v1::MxcPtySize`

Initial or updated terminal dimensions.

```typescript
export interface MxcPtySize {
  rows: number;
  columns: number;
}
```


## `@microsoft/mxc-sdk/v1::NetworkEgressConfig`

Outbound network policy.

```typescript
export interface NetworkEgressConfig {
  default?: NetworkAction;
  allow?: NetworkRuleConfig[];
  deny?: NetworkRuleConfig[];
}
```


## `@microsoft/mxc-sdk/v1::NetworkIngressConfig`

Inbound and host-loopback network policy.

```typescript
export interface NetworkIngressConfig {
  default?: NetworkAction;
  hostLoopback?: NetworkAction;
}
```


## `@microsoft/mxc-sdk/v1::NetworkPeerConfig`

CIDR network peer.

```typescript
export interface NetworkPeerConfig {
  cidr: string;
  except?: string[];
}
```


## `@microsoft/mxc-sdk/v1::NetworkPortConfig`

Protocol and destination-port selector.

```typescript
export interface NetworkPortConfig {
  protocol?: NetworkProtocol;
  port?: number;
  endPort?: number;
}
```


## `@microsoft/mxc-sdk/v1::NetworkRuleConfig`

Outbound network rule.

```typescript
export interface NetworkRuleConfig {
  to?: NetworkPeerConfig[];
  ports?: NetworkPortConfig[];
}
```


## `@microsoft/mxc-sdk/v1::PlatformSupport`

Platform support information.

```typescript
export interface PlatformSupport {
  isSupported: boolean; // All platforms: at least one SDK backend can launch.
  reason?: string; // All platforms: why no SDK backend can launch.
  availableMethods: ContainmentBackend[]; // All platforms.
  unavailableReasons?: Partial<Record<ContainmentBackend, string>>; // Linux only.
  isolationTier?: IsolationTier; // Windows only: empty-policy ProcessContainer tier.
  isolationWarnings?: string[]; // Windows only: tier degradation warnings.
  uiCapabilities?: UiCapabilitySupport; // Windows only.
  bubblewrapNetwork?: BubblewrapNetworkSupport; // Linux only.
}
```


## `@microsoft/mxc-sdk/v1::ProbeFacts`

Raw Windows host facts gathered before ProcessContainer tier selection.

```typescript
export interface ProbeFacts {
  baseContainerApiPresent: boolean; // Windows only.
  nativeCaptureAvailable: boolean; // Windows only.
  guardedCaptureAvailable: boolean; // Windows only.
  bfscfgPresent: boolean; // Windows only.
  bfsCompiledIn: boolean; // Windows only.
  baseContainerSupportsDenyPaths: boolean; // Windows only.
  baseContainerSupportsEnumeratePaths: boolean; // Windows only.
  baseContainerSupportsIngressHostLoopbackAllow: boolean; // Windows only.
  baseContainerSupportsIdentitylessLoopbackProxy: boolean; // Windows only.
  isolationSessionAvailable: boolean; // Windows only.
  hyperlightAvailable: boolean; // Windows only.
  uiCapabilities: UiCapabilitySupport; // Windows only.
}
```


## `@microsoft/mxc-sdk/v1::ProbeOutput`

Result of probing which Windows ProcessContainer tier can serve a config.

```typescript
export interface ProbeOutput {
  tier?: IsolationTier;
  needsDaclAugmentation?: boolean;
  warnings: string[];
  probes: ProbeFacts;
  error?: string;
}
```


## `@microsoft/mxc-sdk/v1::ProcessContainerConfig`

ProcessContainer configuration for the Windows process-level backend.

```typescript
export interface ProcessContainerConfig {
  name?: string;
  learningMode?: boolean;
  capabilities?: string[];
  captureDenials?: {
    mode?: 'block' | 'allow';
    outputPath?: string;
    retainEtl?: boolean;
  };
  ui?: BaseProcessUiConfig;
  filesystem?: {
    enumeratePaths?: string[];
  };
  network?: {
    allowedProxyPeer?: string;
  };
}
```


## `@microsoft/mxc-sdk/v1::ProcessNetworkConfig`

Runtime network values accepted when executing in an MXC-provisioned container.

```typescript
export interface ProcessNetworkConfig {
  runtimeConfig?: NetworkRuntimeConfig;
}
```


## `@microsoft/mxc-sdk/v1::ExecutionRequest`

Process settings for a workload in a container created by
`provisionContainer`.

```typescript
export interface ExecutionRequest<C extends LifecycleContainmentKind = LifecycleContainmentKind> {
  /** Command line executed inside the MXC-provisioned container. */
  command: string;
  /** Initial workload working directory. */
  workingDirectory?: string;
  /** Explicit environment entries. */
  environment?: Record<string, string>;
  /** Whether backend default environment variables are inherited. */
  inheritDefaultEnvironment?: boolean;
  /** Workload timeout in milliseconds. */
  timeoutMs?: number;
  /** WSLC execution-time network values; other lifecycle backends reject it. */
  network?: C extends 'wslc' ? ProcessNetworkConfig : never;
  /** Per-invocation telemetry preference; consent and policy still apply. */
  telemetry?: TelemetryConfig;
}
```


## `@microsoft/mxc-sdk/v1::ProvisionMetadata`

Selects the metadata returned by a backend's provision phase.

```typescript
export type ProvisionMetadata<C extends LifecycleContainmentKind = LifecycleContainmentKind> =
  C extends LifecycleContainmentKind ? MetadataForPhase<C, 'provision'> : never;
```


## `@microsoft/mxc-sdk/v1::ProvisionOptions`

Invocation controls for provisioning a container.

```typescript
export interface ProvisionOptions {
  /** Per-invocation telemetry preference; consent and policy still apply. */
  telemetry?: TelemetryConfig;
}
```


## `@microsoft/mxc-sdk/v1::ProvisionRequest`

Closed backend-specific request for provisioning a container.

```typescript
export type ProvisionRequest<C extends LifecycleContainmentKind = LifecycleContainmentKind> = C extends LifecycleContainmentKind ? ProvisionConfigFor<C> & {
  containment: C;
} : never;
```


## `@microsoft/mxc-sdk/v1::ProvisionResult`

Container identifier and optional metadata returned after provisioning.

```typescript
export interface ProvisionResult<C extends LifecycleContainmentKind> {
  /** Opaque identity for subsequent lifecycle operations. */
  containerId: ContainerId<C>;
  /** Backend-specific provision metadata. */
  metadata?: ProvisionMetadata<C>;
  /** Policy and operational diagnostics. */
  warnings: string[];
}
```


## `@microsoft/mxc-sdk/v1::RunInContainerOptions`

Invocation controls for captured execution in an MXC-provisioned container.

```typescript
export interface RunInContainerOptions {
  /** Per-invocation telemetry preference; consent and policy still apply. */
  telemetry?: TelemetryConfig;
}
```


## `@microsoft/mxc-sdk/v1::RunOptions`

Invocation controls for run.

```typescript
export interface RunOptions {
  /** Per-invocation telemetry preference; consent and policy still apply. */
  telemetry?: TelemetryConfig;
}
```


## `@microsoft/mxc-sdk/v1::NetworkRuntimeConfig`

Runtime values supplied separately from container policy.

```typescript
export interface NetworkRuntimeConfig {
  /** HTTP/S proxy URL reachable from inside the selected backend. */
  networkProxy?: string;
}
```


## `@microsoft/mxc-sdk/v1::SDK_CONTRACT_VERSION`

SDK-owned exact container-request contract used by the V1 high-level API.

```typescript
const SDK_CONTRACT_VERSION: "1.0.0" = '1.0.0' as const;
```


## `@microsoft/mxc-sdk/v1::SeatbeltConfig`

macOS Seatbelt container configuration.

```typescript
export interface SeatbeltConfig {
  profileOverride?: string;
  guiAccess?: boolean;
  nestedPty?: boolean;
  keychainAccess?: boolean;
  extraMachLookups?: string[];
}
```


## `@microsoft/mxc-sdk/v1::SpawnInContainerOptions`

Invocation controls for live execution in an MXC-provisioned container.

```typescript
export interface SpawnInContainerOptions {
  /** Per-invocation telemetry preference; consent and policy still apply. */
  telemetry?: TelemetryConfig;
}
```


## `@microsoft/mxc-sdk/v1::SpawnInContainerWithPtyOptions`

Invocation controls for terminal execution in an MXC-provisioned container.

```typescript
export interface SpawnInContainerWithPtyOptions {
  /** Per-invocation telemetry preference; consent and policy still apply. */
  telemetry?: TelemetryConfig;
  /** Initial terminal dimensions; defaults to 24 rows by 80 columns. */
  size?: MxcPtySize;
}
```


## `@microsoft/mxc-sdk/v1::SpawnOptions`

Invocation controls for spawn.

```typescript
export interface SpawnOptions {
  /** Per-invocation telemetry preference; consent and policy still apply. */
  telemetry?: TelemetryConfig;
}
```


## `@microsoft/mxc-sdk/v1::SpawnWithPtyOptions`

Invocation controls for spawning a caller-controlled terminal.

```typescript
export interface SpawnWithPtyOptions {
  /** Per-invocation telemetry preference; consent and policy still apply. */
  telemetry?: TelemetryConfig;
  /** Initial terminal dimensions; defaults to 24 rows by 80 columns. */
  size?: MxcPtySize;
}
```



## `@microsoft/mxc-sdk/v1::StartOptions`

Invocation controls for starting a container.

```typescript
export interface StartOptions {
  telemetry?: TelemetryConfig;
}
```




## `@microsoft/mxc-sdk/v1::StopOptions`

Invocation controls for stopping a container.

```typescript
export interface StopOptions {
  telemetry?: TelemetryConfig;
}
```



## `@microsoft/mxc-sdk/v1::TelemetryConfig`

Telemetry configuration for TraceLogging ETW support.

```typescript
export interface TelemetryConfig {
  enabled?: boolean;
}
```


## `@microsoft/mxc-sdk/v1::TelemetryConsentDecision`

Decision returned by the telemetry consent presenter.

```typescript
export type TelemetryConsentDecision = (typeof TELEMETRY_CONSENT_DECISIONS)[number];
```


## `@microsoft/mxc-sdk/v1::TelemetryConsentMessage`

Localized label or message shown in a telemetry consent prompt.

```typescript
export interface TelemetryConsentMessage {
  id: string;
  text: string;
}
```


## `@microsoft/mxc-sdk/v1::TelemetryConsentOutcome`

Outcome and resulting state of a telemetry consent operation.

```typescript
export interface TelemetryConsentOutcome {
  action: 'request' | 'withdraw';
  result: TelemetryConsentResult;
  storedState: TelemetryConsentState;
  effectiveState: TelemetryConsentState;
  policy: TelemetryPolicyState;
  needsPrompt: boolean;
}
```


## `@microsoft/mxc-sdk/v1::TelemetryConsentPresenter`

Callback that presents a consent prompt and returns the user's decision.

```typescript
export type TelemetryConsentPresenter = (prompt: TelemetryConsentPrompt, signal?: AbortSignal) => TelemetryConsentDecision | Promise<TelemetryConsentDecision>;
```


## `@microsoft/mxc-sdk/v1::TelemetryConsentPrompt`

Localized prompt content presented when requesting telemetry consent.

```typescript
export interface TelemetryConsentPrompt {
  resourceVersion: number;
  locale: string;
  title: TelemetryConsentMessage;
  body: TelemetryConsentMessage;
  affirmativeLabel: TelemetryConsentMessage;
  negativeLabel: TelemetryConsentMessage;
  learnMoreLabel: TelemetryConsentMessage;
  learnMoreUrl: string;
}
```


## `@microsoft/mxc-sdk/v1::TelemetryConsentStatus`

Stored, effective, and policy state returned by a consent query.

```typescript
export interface TelemetryConsentStatus {
  state: TelemetryConsentState;
  storedState: TelemetryConsentState;
  effectiveState: TelemetryConsentState;
  needsPrompt: boolean;
  policy: TelemetryPolicyState;
  error?: string;
}
```


## `@microsoft/mxc-sdk/v1::TelemetryConsentResult`

Result code returned by a telemetry consent operation.

```typescript
export type TelemetryConsentResult = (typeof TELEMETRY_CONSENT_RESULTS)[number];
```


## `@microsoft/mxc-sdk/v1::TelemetryConsentState`

Stored or effective telemetry consent state.

```typescript
export type TelemetryConsentState = (typeof TELEMETRY_CONSENT_STATES)[number];
```


## `@microsoft/mxc-sdk/v1::TelemetryPolicyState`

Administrative policy state governing telemetry consent.

```typescript
export type TelemetryPolicyState = (typeof TELEMETRY_POLICY_STATES)[number];
```


## `@microsoft/mxc-sdk/v1::policy.filesystem.ToolsPolicyOptions`

Options for getAvailableToolsPolicy.

```typescript
export interface ToolsPolicyOptions {
  containerType?: 'processcontainer';
}
```


## `@microsoft/mxc-sdk/v1::UiCapabilitySupport`

Host support for enforcing container UI restrictions.

```typescript
export interface UiCapabilitySupport {
  canBlockClipboardRead: boolean;
  canBlockClipboardWrite: boolean;
  canBlockInputInjection: boolean;
  canBlockInputMethodChanges: boolean;
  canBlockExternalUiObjects: boolean;
  canBlockGlobalUiNamespace: boolean;
  canBlockDesktopSwitching: boolean;
  canBlockLogoffOrShutdown: boolean;
  canBlockSystemParameterChanges: boolean;
  canBlockDisplaySettingsChanges: boolean;
}
```


## `@microsoft/mxc-sdk/v1::WaitResult`

Exit status and timeout state reported after waiting for a process.

```typescript
export interface WaitResult {
  exitCode: number;
  timedOut: boolean;
}
```


## `@microsoft/mxc-sdk/v1::WslcConfig`

WSLC SDK configuration for Linux containers from Windows.

```typescript
export interface WslcConfig {
  image?: string;
  storagePath?: string;
  targetOs?: string;
  cpuCount?: number;
  memoryMb?: number;
  gpu?: boolean;
  imageTarPath?: string;
  portMappings?: PortMapping[];
}
```

## `@microsoft/mxc-sdk/v1::LifecycleResult`

Warnings returned by starting, stopping, or deprovisioning a container.

```typescript
export interface LifecycleResult {
  warnings: string[];
}
```
