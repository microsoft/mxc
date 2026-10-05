# Rust V1 types

Public entrypoint: `mxc_sdk::v1`. [Operations](api.md) | [Overview](README.md)

Declarations include public fields, variants, constructors, and members. Inherited SDK members remain defined on their base type; implementation-only helpers and external framework APIs are not expanded.

## `mxc_sdk::v1::AvailableBackend`

One host-available backend, plus its effective isolation tier (if any).

```rust
pub struct AvailableBackend {
  pub backend: String,
  pub tier: Option<String>,
  pub capabilities: Vec<BackendCapability>,
  pub warnings: Vec<String>,
}
```


## `mxc_sdk::v1::BackendCapability`

Optional feature supported by a containment backend on the current host.

```rust
pub enum BackendCapability {
  CaptureDenials,
  FilesystemDeniedPaths,
  FilesystemEnumeratePaths,
  IngressHostLoopbackAllow,
  ProxyEnforcement,
}
```


## `mxc_sdk::v1::BubblewrapNetworkSupport`

Bubblewrap host network capability, with the reason when it is unsupported.

```rust
pub struct BubblewrapNetworkSupport {
  pub proxy_enforcement: ProxyEnforcement,
  pub warnings: Vec<String>,
}
```


## `mxc_sdk::v1::CaptureDenialsError`

Structured diagnostics for a failed captureDenials finalization.

```rust
pub struct CaptureDenialsError {
  pub message: String,
  pub etl_path: String,
}
```


## `mxc_sdk::v1::CaptureDenialsResult`

Location and summary of a captureDenials output document.

```rust
pub struct CaptureDenialsResult {
  pub kind: String,
  pub output_path: String,
  pub exit_code: i32,
  pub total_denials: usize,
  pub denied_resources_truncated: bool,
  pub etl_path: Option<String>,
}

impl CaptureDenialsResult {
  pub const KIND: &'static str = "captureDenials";
}
```


## `mxc_sdk::v1::ClipboardPolicy`, `mxc_sdk::v1::policy::ClipboardPolicy`

Clipboard access level, mirroring the SDK ClipboardPolicy ("none" | "read" | "write" | "all").

```rust
pub enum ClipboardPolicy {
  #[default]
  None,
  Read,
  Write,
  All,
}
```


## `mxc_sdk::v1::ContainerId`

Opaque identity returned for a provisioned container.

```rust
pub struct ContainerId(/* opaque storage; use public constructors/accessors */);

impl ContainerId {
  pub fn parse(value: impl Into<String>) -> Result<Self, Error>;
  pub fn as_str(&self) -> &str;
}

impl AsRef<str> for ContainerId {
  fn as_ref(&self) -> &str;
}

impl fmt::Display for ContainerId {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result;
}
```


## `mxc_sdk::v1::ContainerRequest`

A complete single-request request with shared restrictions and backend settings.

```rust
pub struct ContainerRequest {
  pub command: String,
  pub filesystem: Option<FilesystemPolicy>,
  pub network: Option<NetworkPolicy>,
  pub ui: Option<UiPolicy>,
  pub timeout_ms: Option<u32>,
  pub containment: Containment,
  pub container_name: Option<String>,
  pub working_directory: Option<String>,
  pub environment: Option<Vec<(String, String)>>,
  pub inherit_default_environment: Option<bool>,
}

impl ContainerRequest {
  pub fn new(command: impl Into<String>) -> Self;
}
```


## `mxc_sdk::v1::Containment`, `mxc_sdk::v1::policy::Containment`

The closed backend choice carried by `ContainerRequest`. Select a variant with
its typed configuration; the native engine validates backend and policy support.

```rust
pub enum Containment {
  #[default]
  Process,
  ProcessContainer(ProcessContainerConfig),
  Seatbelt(crate::configs::SeatbeltConfig),
  Lxc(crate::configs::LxcConfig),
  Bubblewrap,
  Wslc(WslcConfig),
  IsolationSession,
}
```


## `mxc_sdk::v1::DeprovisionOptions`

Invocation controls for releasing a container.

```rust
pub struct DeprovisionOptions {
  pub experimental: bool,
  pub telemetry: Option<TelemetryConfig>,
}
```


## `mxc_sdk::v1::Error`

An error returned by the SDK's fallible operations (spawn_execution_request).

```rust
pub struct Error {
  pub code: ErrorCode,
  pub message: String,
  pub operation: Option<String>,
  pub native_code: Option<String>,
  pub remediation: Option<String>,
}

impl Error {
  pub fn new(code: ErrorCode, message: impl Into<String>) -> Self;
}

impl std::fmt::Display for Error {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result;
}

impl From<MxcError> for Error {
  fn from(error: MxcError) -> Self;
}
```


## `mxc_sdk::v1::ErrorCode`

Closed set of error codes the SDK can return.

```rust
pub enum ErrorCode {
  MalformedRequest,
  UnsupportedContainment,
  UnsupportedPhase,
  BackendUnavailable,
  MalformedId,
  StaleId,
  NotProvisioned,
  NotStarted,
  AlreadyStarted,
  AlreadyStopped,
  PolicyValidation,
  BackendError,
}

impl ErrorCode {
  pub fn as_str(self) -> &'static str;
}

impl std::fmt::Display for ErrorCode {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result;
}

impl From<MxcErrorCode> for ErrorCode {
  fn from(code: MxcErrorCode) -> Self;
}
```


## `mxc_sdk::v1::ExecutionResult`

The captured result of running a [MxcProcess] to completion via wait_with_output.

```rust
pub struct ExecutionResult {
  pub outcome: WaitResult,
  pub warnings: Vec<String>,
  pub stdout: Vec<u8>,
  pub stderr: Vec<u8>,
  pub output_metadata: Option<ExecutionMetadata>,
}
```


## `mxc_sdk::v1::FilesystemPolicy`, `mxc_sdk::v1::policy::FilesystemPolicy`

Filesystem section of a [ContainerPolicy].

```rust
pub struct FilesystemPolicy {
  pub readwrite_paths: Vec<String>,
  pub readonly_paths: Vec<String>,
  pub denied_paths: Vec<String>,
  pub clear_policy_on_exit: Option<bool>,
}
```


## `mxc_sdk::v1::policy::filesystem::FilesystemPolicyResult`

A composable fragment of filesystem policy.

```rust
pub struct FilesystemPolicyResult {
  pub readonly_paths: Vec<String>,
  pub readwrite_paths: Vec<String>,
}
```


## `mxc_sdk::v1::IsolationSessionProvisionMetadata`

IsolationSession metadata returned by a successful provision.

```rust
pub struct IsolationSessionProvisionMetadata {
  pub agent_user_name: String,
  pub agent_user_sid: String,
  pub ephemeral_workspace_path: String,
}
```


## `mxc_sdk::v1::LifecycleResult`

Result of successfully starting, stopping, or deprovisioning a container.

```rust
pub struct LifecycleResult {
  pub warnings: Vec<String>,
}
```


## `mxc_sdk::v1::MxcProcess`

A live container process, returned by `v1::spawn` and
`v1::container::spawn_in_container`.

```rust
pub struct MxcProcess {

}

impl MxcProcess {
  pub fn warnings(&self) -> Vec<String>;
  pub fn output_metadata(&self) -> Option<&ExecutionMetadata>;
  pub fn take_stdin(&mut self) -> Option<Box<dyn Write + Send>>;
  pub fn take_stdout(&mut self) -> Option<Box<dyn Read + Send>>;
  pub fn take_stderr(&mut self) -> Option<Box<dyn Read + Send>>;
  pub fn take_native_stdio(&mut self) -> std::io::Result<Option<NativeStdio>>;
  pub fn stdout_closer(&self) -> Option<StreamCloser>;
  pub fn stderr_closer(&self) -> Option<StreamCloser>;
  pub fn try_wait(&mut self) -> std::io::Result<Option<i32>>;
  pub fn id(&self) -> u32;
  pub fn kill(&mut self) -> std::io::Result<()>;
  pub fn kill_for_timeout(&mut self) -> std::io::Result<()>;
  pub fn wait(&mut self) -> std::io::Result<WaitResult>;
  pub fn wait_with_output(mut self) -> std::io::Result<ExecutionResult>;
}
```


## `mxc_sdk::v1::MxcPtyProcess`

A live container process attached to a caller-controlled pseudo-terminal.

```rust
pub struct MxcPtyProcess {

}

impl std::fmt::Debug for MxcPtyProcess {
  fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result;
}

impl MxcPtyProcess {
  pub fn id(&self) -> u32;
  pub fn warnings(&self) -> Vec<String>;
  pub fn output_metadata(&self) -> Option<ExecutionMetadata>;
  pub fn try_wait(&self) -> std::io::Result<Option<i32>>;
  pub fn kill(&self) -> std::io::Result<()>;
  pub fn kill_for_timeout(&self) -> std::io::Result<()>;
  pub fn wait(&self) -> std::io::Result<WaitResult>;
  pub fn try_clone_reader(&self) -> std::io::Result<Box<dyn Read + Send>>;
  pub fn stdout_closer(&self) -> Option<StreamCloser>;
  pub fn take_writer(&self) -> std::io::Result<Box<dyn Write + Send>>;
  pub fn resize(&self, size: MxcPtySize) -> std::io::Result<()>;
  pub fn size(&self) -> std::io::Result<MxcPtySize>;
  pub fn take_native_stdio(&mut self) -> std::io::Result<Option<NativeStdio>>;
}
```


## `mxc_sdk::v1::MxcPtySize`

Dimensions of an [MxcPtyProcess].

```rust
pub struct MxcPtySize {
  pub rows: u16,
  pub cols: u16,
  pub pixel_width: u16,
  pub pixel_height: u16,
}

impl MxcPtySize {
  pub fn validate(self) -> Result<(), Error>;
}

impl Default for MxcPtySize {
  fn default() -> Self;
}
```


## `mxc_sdk::v1::NetworkAction`, `mxc_sdk::v1::policy::NetworkAction`

Allow or deny a network action.

```rust
pub enum NetworkAction {
  Allow,
  #[default]
  Deny,
}
```


## `mxc_sdk::v1::NetworkEgressPolicy`, `mxc_sdk::v1::policy::NetworkEgressPolicy`

Outbound network policy.

```rust
pub struct NetworkEgressPolicy {
  pub default: Option<NetworkAction>,
  pub allow: Option<Vec<NetworkRulePolicy>>,
  pub deny: Option<Vec<NetworkRulePolicy>>,
}
```


## `mxc_sdk::v1::NetworkIngressPolicy`, `mxc_sdk::v1::policy::NetworkIngressPolicy`

Inbound and host-loopback network policy.

```rust
pub struct NetworkIngressPolicy {
  pub default: Option<NetworkAction>,
  pub host_loopback: Option<NetworkAction>,
}
```


## `mxc_sdk::v1::NetworkPeerPolicy`, `mxc_sdk::v1::policy::NetworkPeerPolicy`

CIDR network peer.

```rust
pub struct NetworkPeerPolicy {
  pub cidr: String,
  pub except: Option<Vec<String>>,
}

impl NetworkPeerPolicy {
  pub fn new(cidr: impl Into<String>) -> Self;
}
```


## `mxc_sdk::v1::NetworkPolicy`, `mxc_sdk::v1::policy::NetworkPolicy`

Network section of a ContainerPolicy.

```rust
pub struct NetworkPolicy {
  pub egress: Option<NetworkEgressPolicy>,
  pub ingress: Option<NetworkIngressPolicy>,
  pub runtime_config: Option<NetworkRuntimeConfig>,
}
```


## `mxc_sdk::v1::NetworkPortPolicy`, `mxc_sdk::v1::policy::NetworkPortPolicy`

Protocol and destination-port selector.

```rust
pub struct NetworkPortPolicy {
  pub protocol: Option<NetworkProtocol>,
  pub port: Option<u16>,
  pub end_port: Option<u16>,
}
```


## `mxc_sdk::v1::NetworkProtocol`, `mxc_sdk::v1::policy::NetworkProtocol`

Transport protocol selector.

```rust
pub enum NetworkProtocol {
  Tcp,
  Udp,
  Icmp,
  Any,
}
```


## `mxc_sdk::v1::NetworkRulePolicy`, `mxc_sdk::v1::policy::NetworkRulePolicy`

Outbound network rule.

```rust
pub struct NetworkRulePolicy {
  pub to: Option<Vec<NetworkPeerPolicy>>,
  pub ports: Option<Vec<NetworkPortPolicy>>,
}
```


## `mxc_sdk::v1::NetworkRuntimeConfig`, `mxc_sdk::v1::policy::NetworkRuntimeConfig`

Runtime values supplied separately from container policy.

```rust
pub struct NetworkRuntimeConfig {
  pub network_proxy: Option<String>,
}
```


## `mxc_sdk::v1::ExecutionMetadata`

Structured outputs produced by optional container features.

```rust
pub struct ExecutionMetadata {
  pub capture_denials: Option<CaptureDenialsResult>,
  pub capture_denials_error: Option<CaptureDenialsError>,
}
```


## `mxc_sdk::v1::PlatformSupport`

Platform support information — the Rust analogue of the SDK PlatformSupport type.

```rust
pub struct PlatformSupport {
  pub is_supported: bool,
  pub reason: Option<String>,
  pub available_methods: Vec<String>,
  pub bubblewrap_network: Option<BubblewrapNetworkSupport>,
}
```


## `mxc_sdk::v1::ProbeFacts`

Raw machine facts gathered prior to running tier selection.

```rust
pub struct ProbeFacts {
  pub base_container_api_present: bool,
  pub native_capture_available: bool,
  pub guarded_capture_available: bool,
  pub bfscfg_present: bool,
  pub bfs_compiled_in: bool,
  pub base_container_supports_deny_paths: bool,
  pub base_container_supports_enumerate_paths: bool,
  pub base_container_supports_ingress_host_loopback_allow: bool,
  pub isolation_session_available: bool,
  pub hyperlight_available: bool,
  pub ui_capabilities: UiCapabilitySupport,
}
```


## `mxc_sdk::v1::ProbeOutput`

JSON output emitted by wxc-execution --probe.

```rust
pub struct ProbeOutput {
  pub tier: Option<&'static str>,
  pub needs_dacl_augmentation: Option<bool>,
  pub warnings: Vec<String>,
  pub probes: ProbeFacts,
  pub error: Option<String>,
}
```


## `mxc_sdk::v1::ProcessNetworkPolicy`

Runtime network settings available to an existing-container execution.

```rust
pub struct ProcessNetworkPolicy {
  pub runtime_config: Option<NetworkRuntimeConfig>,
}
```


## `mxc_sdk::v1::ExecutionRequest`

Process settings for a workload in an existing container.

```rust
pub struct ExecutionRequest {
  pub command: String,
  pub working_directory: Option<String>,
  pub environment: Option<Vec<(String, String)>>,
  pub inherit_default_environment: Option<bool>,
  pub timeout_ms: Option<u32>,
  pub network: Option<ProcessNetworkPolicy>,
  pub telemetry: Option<TelemetryConfig>,
}

impl ExecutionRequest {
  pub fn new(command: impl Into<String>) -> Self;
}
```


## `mxc_sdk::v1::TelemetryConfig`

Per-invocation telemetry preference, subject to consent and policy.

```rust
pub struct TelemetryConfig {
  pub enabled: Option<bool>,
}
```

## `mxc_sdk::v1::policy::filesystem::ToolsPolicyOptions`

Optional tool-policy filtering controls.

```rust
pub struct ToolsPolicyOptions {
  pub container_type: Option<ToolsPolicyContainerType>,
}

pub enum ToolsPolicyContainerType {
  ProcessContainer,
}
```

## `mxc_sdk::v1::ProvisionMetadata`

Backend-specific metadata returned by a typed lifecycle call.

```rust
pub enum ProvisionMetadata {
  IsolationSessionProvision(IsolationSessionProvisionMetadata),
}
```


## `mxc_sdk::v1::ProvisionOptions`

Invocation controls for provisioning a container.

```rust
pub struct ProvisionOptions {
  pub experimental: bool,
  pub telemetry: Option<TelemetryConfig>,
}
```


## `mxc_sdk::v1::ProvisionRequest`

Typed lifecycle provision request.

```rust
pub struct ProvisionRequest {

}

impl ProvisionRequest {
  pub fn isolation_session(app_id: Option<String>) -> Self;
  pub fn wslc(image: Option<String>, image_tar_path: Option<String>) -> Self;
  pub fn set_filesystem(&mut self, filesystem: FilesystemPolicy) -> &mut Self;
  pub fn set_network(&mut self, network: NetworkPolicy) -> &mut Self;
  pub fn set_telemetry(&mut self, telemetry: TelemetryConfig) -> &mut Self;
}
```


## `mxc_sdk::v1::ProvisionResult`

Result of successfully provisioning a container.

```rust
pub struct ProvisionResult {
  pub container_id: ContainerId,
  pub metadata: Option<ProvisionMetadata>,
  pub warnings: Vec<String>,
}
```


## `mxc_sdk::v1::ProxyEnforcement`

Whether the host can enforce Bubblewrap proxy-only egress.

```rust
pub enum ProxyEnforcement {
  Supported,
  Unsupported,
}
```


## `mxc_sdk::v1::RunInContainerOptions`

Invocation controls for captured execution in an existing container.

```rust
pub struct RunInContainerOptions {
  pub experimental: bool,
  pub telemetry: Option<TelemetryConfig>,
}
```


## `mxc_sdk::v1::RunOptions`

Invocation controls for captured container execution.

```rust
pub struct RunOptions {
  pub experimental: bool,
  pub telemetry: Option<TelemetryConfig>,
}
```


## `mxc_sdk::v1::SpawnInContainerOptions`

Invocation controls for live execution in an existing container.

```rust
pub struct SpawnInContainerOptions {
  pub experimental: bool,
  pub telemetry: Option<TelemetryConfig>,
}
```


## `mxc_sdk::v1::SpawnInContainerWithPtyOptions`

Invocation controls for a terminal in an existing container.

```rust
pub struct SpawnInContainerWithPtyOptions {
  pub experimental: bool,
  pub telemetry: Option<TelemetryConfig>,
  pub size: MxcPtySize,
}
```


## `mxc_sdk::v1::SpawnOptions`

Invocation controls for spawning a live process.

```rust
pub struct SpawnOptions {
  pub experimental: bool,
  pub telemetry: Option<TelemetryConfig>,
}
```


## `mxc_sdk::v1::SpawnWithPtyOptions`

Invocation controls for spawning a caller-controlled terminal.

```rust
pub struct SpawnWithPtyOptions {
  pub experimental: bool,
  pub telemetry: Option<TelemetryConfig>,
  pub size: MxcPtySize,
}
```


## `mxc_sdk::v1::StartOptions`

Invocation controls for starting a container.

```rust
pub struct StartOptions {
  pub experimental: bool,
  pub telemetry: Option<TelemetryConfig>,
}
```


## `mxc_sdk::v1::StopOptions`

Invocation controls for stopping a container.

```rust
pub struct StopOptions {
  pub experimental: bool,
  pub telemetry: Option<TelemetryConfig>,
}
```


## `mxc_sdk::v1::StreamCloser`

Closes one of a [MxcProcess]'s streams, unblocking a read parked on it without killing the process.

```rust
pub struct StreamCloser {

}

impl StreamCloser {
  pub fn close(&self);
}
```


## `mxc_sdk::v1::UiCapabilitySupport`

Host support for enforcing container UI restrictions.

```rust
pub struct UiCapabilitySupport {
  pub can_block_clipboard_read: bool,
  pub can_block_clipboard_write: bool,
  pub can_block_input_injection: bool,
  pub can_block_input_method_changes: bool,
  pub can_block_external_ui_objects: bool,
  pub can_block_global_ui_namespace: bool,
  pub can_block_desktop_switching: bool,
  pub can_block_logoff_or_shutdown: bool,
  pub can_block_system_parameter_changes: bool,
  pub can_block_display_settings_changes: bool,
}

impl From<EffectiveUiRestrictions> for UiCapabilitySupport {
  fn from(value: EffectiveUiRestrictions) -> Self;
}
```


## `mxc_sdk::v1::UiPolicy`, `mxc_sdk::v1::policy::UiPolicy`

UI section of a [ContainerPolicy].

```rust
pub struct UiPolicy {
  pub disable: bool,
  pub clipboard: ClipboardPolicy,
  pub allow_input_injection: bool,
}

impl Default for UiPolicy {
  fn default() -> Self;
}
```


## `mxc_sdk::v1::ValidationResult`

Result of validating an operation without executing it.

```rust
pub struct ValidationResult {
  pub warnings: Vec<String>,
}
```


## `mxc_sdk::v1::WaitResult`

The outcome of waiting on a [MxcProcess] (see [MxcProcess::wait]).

```rust
pub enum WaitResult {
  Exited(i32),
  TimedOut,
}
```


## `mxc_sdk::v1::configs::CaptureDenials`

ProcessContainer denial-capture settings.

```rust
pub struct CaptureDenials {
  pub mode: CaptureDenialsMode,
  pub output_path: Option<String>,
  pub retain_etl: bool,
}
```


## `mxc_sdk::v1::configs::CaptureDenialsMode`

How denial capture handles ungranted access checks.

```rust
pub enum CaptureDenialsMode {
  #[default]
  Block,
  Allow,
}
```


## `mxc_sdk::v1::configs::LxcConfig`

Linux LXC distribution settings.

```rust
pub struct LxcConfig {
  pub distribution: String,
  pub release: String,
}

impl Default for LxcConfig {
  fn default() -> Self;
}
```


## `mxc_sdk::v1::configs::ProcessContainerConfig`

ProcessContainer settings.

```rust
pub struct ProcessContainerConfig {
  pub learning_mode: bool,
  pub capabilities: Vec<String>,
  pub capture_denials: Option<CaptureDenials>,
  pub ui: Option<ProcessContainerUi>,
  pub filesystem: Option<ProcessContainerFilesystem>,
  pub network: Option<ProcessContainerNetwork>,
}

impl Default for ProcessContainerConfig {
  fn default() -> Self;
}
```


## `mxc_sdk::v1::configs::ProcessContainerFilesystem`

ProcessContainer-specific filesystem settings.

```rust
pub struct ProcessContainerFilesystem {
  pub enumerate_paths: Vec<String>,
}
```


## `mxc_sdk::v1::configs::ProcessContainerNetwork`

ProcessContainer-specific network settings.

```rust
pub struct ProcessContainerNetwork {
  pub allowed_proxy_peer: Option<String>,
}
```


## `mxc_sdk::v1::configs::ProcessContainerSystemSettings`

System-settings access level for BaseProcessContainer.

```rust
pub enum ProcessContainerSystemSettings {
  All,
  Parameters,
  Display,
  #[default]
  None,
}
```


## `mxc_sdk::v1::configs::ProcessContainerUi`

BaseProcessContainer user-interface settings.

```rust
pub struct ProcessContainerUi {
  pub isolation: ProcessContainerUiIsolation,
  pub desktop_system_control: bool,
  pub system_settings: ProcessContainerSystemSettings,
  pub ime: bool,
}

impl Default for ProcessContainerUi {
  fn default() -> Self;
}
```


## `mxc_sdk::v1::configs::ProcessContainerUiIsolation`

Desktop-resource isolation level for BaseProcessContainer.

```rust
pub enum ProcessContainerUiIsolation {
  Desktop,
  Handles,
  Atoms,
  #[default]
  Container,
}
```


## `mxc_sdk::v1::configs::SeatbeltConfig`

macOS Seatbelt settings.

```rust
pub struct SeatbeltConfig {
  pub profile_override: Option<String>,
  pub gui_access: bool,
  pub nested_pty: bool,
  pub keychain_access: bool,
  pub extra_mach_lookups: Vec<String>,
}

impl Default for SeatbeltConfig {
  fn default() -> Self;
}
```


## `mxc_sdk::v1::configs::WslcConfig`

WSL Container settings carried by [crate::v1::Containment::Wslc].

```rust
pub struct WslcConfig {
  pub image: String,
  pub image_tar_path: Option<String>,
  pub cpu_count: Option<u32>,
  pub memory_mb: Option<u64>,
  pub gpu: bool,
  pub storage_path: Option<String>,
  pub port_mappings: Vec<(u16, u16)>,
}

impl Default for WslcConfig {
  fn default() -> Self;
}
```


## `mxc_sdk::v1::telemetry::ConsentActionOutcome`

Consent action result with resulting status and policy.

```rust
pub struct ConsentActionOutcome {
  pub result: ConsentActionResult,
  pub status: ConsentStatus,
  pub policy: PolicyState,
}

impl From<inner_consent::ConsentActionOutcome> for ConsentActionOutcome {
  fn from(value: inner_consent::ConsentActionOutcome) -> Self;
}
```


## `mxc_sdk::v1::telemetry::ConsentActionResult`

Result of a presenter request or withdrawal.

```rust
pub enum ConsentActionResult {
  Granted,
  Denied,
  Dismissed,
  Withdrawn,
  AlreadyGranted,
  PolicyBlocked,
  NotApplicable,
}

impl ConsentActionResult {
  pub fn as_str(&self) -> &'static str;
}

impl From<inner_consent::ConsentActionResult> for ConsentActionResult {
  fn from(value: inner_consent::ConsentActionResult) -> Self;
}
```


## `mxc_sdk::v1::telemetry::ConsentDecision`

Explicit result returned by a host consent presenter.

```rust
pub enum ConsentDecision {
  Yes,
  No,
  Dismissed,
}
```


## `mxc_sdk::v1::telemetry::ConsentError`

Failure to present or persist telemetry consent.

```rust
pub enum ConsentError {
  Presenter(String),
  Persist(String),
}

impl fmt::Display for ConsentError {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result;
}

impl From<inner_consent::ConsentActionError> for ConsentError {
  fn from(value: inner_consent::ConsentActionError) -> Self;
}
```


## `mxc_sdk::v1::telemetry::ConsentMessage`

One independently localizable canonical consent message.

```rust
pub struct ConsentMessage {
  pub id: &'static str,
  pub text: &'static str,
}
```


## `mxc_sdk::v1::telemetry::ConsentPrompt`

Canonical consent resource supplied to a host presenter.

```rust
pub struct ConsentPrompt {
  pub resource_version: u32,
  pub locale: &'static str,
  pub title: ConsentMessage,
  pub body: ConsentMessage,
  pub affirmative_label: ConsentMessage,
  pub negative_label: ConsentMessage,
  pub learn_more_label: ConsentMessage,
  pub learn_more_url: &'static str,
}

impl From<&wxc_common::telemetry::consent_prompt::ConsentPrompt> for ConsentPrompt {
  fn from(value: &wxc_common::telemetry::consent_prompt::ConsentPrompt) -> Self;
}
```


## `mxc_sdk::v1::telemetry::ConsentState`

A stored or effective telemetry consent state.

```rust
pub enum ConsentState {
  Granted,
  Denied,
  Undetermined,
  NotApplicable,
}

impl ConsentState {
  pub fn as_str(&self) -> &'static str;
  pub fn allows_collection(&self) -> bool;
  pub fn needs_prompt(&self) -> bool;
}

impl From<inner_consent::ConsentState> for ConsentState {
  fn from(value: inner_consent::ConsentState) -> Self;
}
```


## `mxc_sdk::v1::telemetry::ConsentStatus`

Stored and effective consent returned by read-only status APIs.

```rust
pub struct ConsentStatus {
  pub stored_state: ConsentState,
  pub effective_state: ConsentState,
  pub reason: Option<ConsentStatusReason>,
}

impl From<inner_consent::ConsentStatus> for ConsentStatus {
  fn from(value: inner_consent::ConsentStatus) -> Self;
}
```


## `mxc_sdk::v1::telemetry::ConsentStatusReason`

Why stored consent is not currently effective.

```rust
pub enum ConsentStatusReason {
  NoRecord,
  StoreUnreadable,
  StoreMalformed,
  ConsentSchemaUnsupported,
  PromptVersionMissing,
  PromptVersionUnsupported,
  NotApplicable,
}

impl ConsentStatusReason {
  pub fn as_str(&self) -> &'static str;
}

impl From<inner_consent::ConsentStatusReason> for ConsentStatusReason {
  fn from(value: inner_consent::ConsentStatusReason) -> Self;
}
```


## `mxc_sdk::v1::telemetry::PolicyState`

The administrative telemetry policy for this machine.

```rust
pub enum PolicyState {
  Unrestricted,
  Allowed,
  Blocked,
  NotApplicable,
}

impl PolicyState {
  pub fn as_str(&self) -> &'static str;
  pub fn allows_collection(&self) -> bool;
}

impl From<inner_policy::PolicyState> for PolicyState {
  fn from(value: inner_policy::PolicyState) -> Self;
}
```
