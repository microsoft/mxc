# Node V1 types

Public entrypoint: `@microsoft/mxc-sdk/v1`. [Operations](api.md) | [Overview](README.md)

Declarations include public fields, variants, constructors, and members. Inherited SDK members remain defined on their base type; implementation-only helpers and external framework APIs are not expanded.

## `@microsoft/mxc-sdk/v1::AvailableBackend`

One native host-available backend. Absent capability/warning lists become
empty arrays. New native backend, tier, or capability names map to `unknown`.

```typescript
export interface AvailableBackend {
  backend: ContainmentBackend | 'unknown';
  tier?: IsolationTier | 'unknown';
  capabilities: BackendCapability[];
  warnings: string[];
}
```

## `@microsoft/mxc-sdk/v1::BackendCapability`

An optional capability reported by native backend discovery.

```typescript
export type BackendCapability =
  | 'captureDenials'
  | 'filesystemDeniedPaths'
  | 'filesystemEnumeratePaths'
  | 'ingressHostLoopbackAllow'
  | 'proxyEnforcement'
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
  command: string;
  filesystem?: FilesystemPolicy;
  network?: NetworkPolicy;
  ui?: UiPolicy;
  timeoutMs?: number;
  containment?: Containment;
  containerName?: string;
  workingDirectory?: string;
  environment?: {
    [key: string]: string | undefined;
  };
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
  stdout: string;
  stderr: string;
  exitCode: number;
  timedOut: boolean;
  warnings: string[];
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

Every field an MxcError can carry, in the same flat shape as the wire error envelope â€” operation, nativeCode and remediation sit alongside code and message, not nested inside details.

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
  readonly id: number;
  constructor(private readonly driver: NativeLifecycleDriver, timeoutMs?: number, private readonly scheduler: LifecycleScheduler = defaultScheduler, private readonly reportBackgroundError: BackgroundErrorReporter = defaultBackgroundErrorReporter);
  get standardInput(): Writable | null;
  get standardOutput(): Readable | null;
  get standardError(): Readable | null;
  get warnings(): readonly string[];
  get outputMetadata(): ExecutionMetadata | undefined;
  wait(): Promise<WaitResult>;
  kill(): void;
  dispose(): void;
}
```


## `@microsoft/mxc-sdk/v1::MxcPtyProcess`

A container process attached to an MXC-owned pseudo-terminal.

```typescript
export class MxcPtyProcess extends MxcProcess {
  constructor(driver: NativeLifecycleDriver, private readonly resizePty: ResizePty, timeoutMs?: number, scheduler?: LifecycleScheduler);
  get input(): Writable;
  get output(): Readable;
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
  isSupported: boolean;
  reason?: string;
  availableMethods: ContainmentBackend[];
  unavailableReasons?: Partial<Record<ContainmentBackend, string>>;
  isolationTier?: IsolationTier;
  isolationWarnings?: string[];
  uiCapabilities?: UiCapabilitySupport;
  bubblewrapNetwork?: BubblewrapNetworkSupport;
}
```


## `@microsoft/mxc-sdk/v1::ProbeFacts`

Raw host facts gathered before request tier selection.

```typescript
export interface ProbeFacts {
  baseContainerApiPresent: boolean;
  nativeCaptureAvailable: boolean;
  guardedCaptureAvailable: boolean;
  bfscfgPresent: boolean;
  bfsCompiledIn: boolean;
  baseContainerSupportsDenyPaths: boolean;
  baseContainerSupportsEnumeratePaths: boolean;
  baseContainerSupportsIngressHostLoopbackAllow: boolean;
  isolationSessionAvailable: boolean;
  hyperlightAvailable: boolean;
  uiCapabilities: UiCapabilitySupport;
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

Runtime network values accepted by existing-container execution.

```typescript
export interface ProcessNetworkConfig {
  runtimeConfig?: NetworkRuntimeConfig;
}
```


## `@microsoft/mxc-sdk/v1::ExecutionRequest`

Process settings for a workload in an existing container.

```typescript
export interface ExecutionRequest<C extends LifecycleContainmentKind = LifecycleContainmentKind> {
  command: string;
  workingDirectory?: string;
  environment?: Record<string, string>;
  inheritDefaultEnvironment?: boolean;
  timeoutMs?: number;
  network?: C extends 'wslc' ? ProcessNetworkConfig : never;
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
  containerId: ContainerId<C>;
  metadata?: ProvisionMetadata<C>;
  warnings: string[];
}
```


## `@microsoft/mxc-sdk/v1::RunInContainerOptions`

Invocation controls for captured execution in an existing container.

```typescript
export interface RunInContainerOptions {
  telemetry?: TelemetryConfig;
}
```


## `@microsoft/mxc-sdk/v1::RunOptions`

Invocation controls for run.

```typescript
export interface RunOptions {
  telemetry?: TelemetryConfig;
}
```


## `@microsoft/mxc-sdk/v1::NetworkRuntimeConfig`

Runtime values supplied separately from container policy.

```typescript
export interface NetworkRuntimeConfig {
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

Invocation controls for live execution in an existing container.

```typescript
export interface SpawnInContainerOptions {
  telemetry?: TelemetryConfig;
}
```


## `@microsoft/mxc-sdk/v1::SpawnInContainerWithPtyOptions`

Invocation controls for a terminal in an existing container.

```typescript
export interface SpawnInContainerWithPtyOptions {
  telemetry?: TelemetryConfig;
  size?: MxcPtySize;
}
```


## `@microsoft/mxc-sdk/v1::SpawnOptions`

Invocation controls for spawn.

```typescript
export interface SpawnOptions {
  telemetry?: TelemetryConfig;
}
```


## `@microsoft/mxc-sdk/v1::SpawnWithPtyOptions`

Invocation controls for spawning a caller-controlled terminal.

```typescript
export interface SpawnWithPtyOptions {
  telemetry?: TelemetryConfig;
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
