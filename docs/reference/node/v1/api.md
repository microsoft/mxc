# Node V1 operation signatures

Public entrypoint: `@microsoft/mxc-sdk/v1`. [Types](types.md) | [Overview](README.md)

Signatures describe the typed consumer API and omit implementation bodies.
Callers do not supply JSON or a schema version.

## Choosing a launch operation

| Output | Create and run a container | Run in an existing container | Result |
|---|---|---|---|
| Capture stdout and stderr | `run` | `runInContainer` | `Promise<ExecutionResult>` |
| Live standard pipes | `spawn` | `spawnInContainer` | `Promise<MxcProcess>` |
| Interactive terminal | `spawnWithPty` | `spawnInContainerWithPty` | `Promise<MxcPtyProcess>` |

Creation takes `ContainerRequest` and operation options. Existing-container
execution takes the `ContainerId` returned by provision, `ExecutionRequest`,
and operation options. PTY operations are asynchronous. One-shot PTY support
covers IsolationSession, Bubblewrap, LXC, and Seatbelt direct execution.
Existing-container PTY support remains IsolationSession-only. Seatbelt PTY
rejects `guiAccess` and legacy `launchMethod: "open"`.
Terminal handles give the caller explicit input, output, resize, and process
ownership; there is no separate attached-console or raw-JSON launch API.

## Discovery and validation

| Operation | Use it to |
|---|---|
| `getPlatformSupport` | Check whether the SDK can launch on this host and which backends it supports. |
| `getAvailableBackends` | Discover native host-available backends, capabilities, tiers, and warnings. Availability is advisory; not every reported backend has a V1 creation API. |
| `probe` (Windows) | Evaluate an optional ProcessContainer request, including the isolation tier and request-specific compatibility diagnostics, without creating a container. |
| `validate*` | Perform native dry-run validation for a typed lifecycle operation without provisioning, starting, executing, stopping, or deprovisioning a container. |

Validation returns `ValidationResult` with warnings, not execution output.
It does not guarantee that a later operation will succeed on a changed host.

## `@microsoft/mxc-sdk/v1::deprovisionContainer`

Releases all backend resources associated with a provisioned container.

```typescript
export async function deprovisionContainer<C extends LifecycleContainmentKind>(containerId: ContainerId<C>, options: DeprovisionOptions = {}): Promise<LifecycleResult>;
```


## `@microsoft/mxc-sdk/v1::policy.filesystem.getAvailableToolsPolicy`

Discover tool and SDK directories from the environment and return them as policy paths.

```typescript
export function getAvailableToolsPolicy(environment?: {
  [key: string]: string | undefined;
}, options?: ToolsPolicyOptions): FilesystemPolicyResult;
```


## `@microsoft/mxc-sdk/v1::getPlatformSupport`

Get platform support information.

```typescript
export function getPlatformSupport(): PlatformSupport;
```

## `@microsoft/mxc-sdk/v1::getAvailableBackends`

Read every native host-available backend, including its isolation tier,
capabilities, and warnings. Host availability is advisory and does not imply
that V1 creation can launch every reported backend. Native failures and
malformed payloads throw.

```typescript
export function getAvailableBackends(): AvailableBackend[];
```


## `@microsoft/mxc-sdk/v1::policy.filesystem.getTemporaryFilesPolicy`

Return the existing host temporary directory as read-write policy; no directories are created.

```typescript
export function getTemporaryFilesPolicy(environment?: {
  [key: string]: string | undefined;
}): FilesystemPolicyResult;
```


## `@microsoft/mxc-sdk/v1::policy.filesystem.getUserProfilePolicy`

Build read-only policy for standard user profile application data locations.

```typescript
export function getUserProfilePolicy(environment?: { [key: string]: string | undefined }): FilesystemPolicyResult;
```


## `@microsoft/mxc-sdk/v1::mxcErrorFromCode`

Constructs an MxcError from a wire-format error code.

```typescript
export function mxcErrorFromCode(code: string, message: string, details?: Record<string, unknown>): MxcError;
```


## `@microsoft/mxc-sdk/v1::probe`

Probe which Windows ProcessContainer tier can serve an optional request.

```typescript
export function probe(request?: ContainerRequest): ProbeOutput;
```


## `@microsoft/mxc-sdk/v1::provisionContainer`

Provision a container from a closed backend-specific request.

```typescript
export async function provisionContainer<C extends LifecycleContainmentKind>(request: ProvisionRequest<C> & {
  containment: C;
}, options: ProvisionOptions = {}): Promise<ProvisionResult<C>>;
```


## `@microsoft/mxc-sdk/v1::getTelemetryConsentStatus`

Read persisted/effective consent and policy without blocking the event loop.

```typescript
export async function getTelemetryConsentStatus(): Promise<TelemetryConsentStatus>;
```


## `@microsoft/mxc-sdk/v1::requestTelemetryConsent`

Request consent with the versioned canonical consent resource.

```typescript
export async function requestTelemetryConsent(presenter: TelemetryConsentPresenter, locale?: string): Promise<TelemetryConsentOutcome>;
```


## `@microsoft/mxc-sdk/v1::run`

Run a container request asynchronously and capture its output.

```typescript
export async function run(request: ContainerRequest, options: RunOptions = {}): Promise<ExecutionResult>;
```


## `@microsoft/mxc-sdk/v1::runInContainer`

Execute in an existing IsolationSession or WSLC container and capture output.
Dispatch failures reject with `MxcError`; workload exit codes and timeouts are
returned in `ExecutionResult`.

```typescript
export async function runInContainer<C extends PipedExecuteBackend>(containerId: ContainerId<C>, request: ExecutionRequest<C>, options?: RunInContainerOptions): Promise<ExecutionResult>;
```


## `@microsoft/mxc-sdk/v1::spawn`

Create a container request and asynchronously return its live process.

```typescript
export async function spawn(request: ContainerRequest, options: SpawnOptions = {}): Promise<MxcProcess>;
```


## `@microsoft/mxc-sdk/v1::spawnInContainer`

Spawn a workload asynchronously inside a started IsolationSession or WSLC
container with live standard pipes.

```typescript
export async function spawnInContainer<C extends PipedExecuteBackend>(containerId: ContainerId<C>, request: ExecutionRequest<C>, options: SpawnInContainerOptions = {}): Promise<MxcProcess>;
```


## `@microsoft/mxc-sdk/v1::spawnInContainerWithPty`

Execute a request in an existing container with an MXC-owned PTY.

```typescript
export async function spawnInContainerWithPty<C extends LifecycleContainmentKind>(containerId: ContainerId<C>, request: ExecutionRequest<C>, options: SpawnInContainerWithPtyOptions = {}): Promise<MxcPtyProcess>;
```


## `@microsoft/mxc-sdk/v1::spawnWithPty`

Create a container request attached to an MXC-owned pseudo-terminal.

```typescript
export async function spawnWithPty(request: ContainerRequest, options: SpawnWithPtyOptions = {}): Promise<MxcPtyProcess>;
```


## `@microsoft/mxc-sdk/v1::startContainer`

Starts a previously provisioned container.

```typescript
export async function startContainer<C extends LifecycleContainmentKind>(containerId: ContainerId<C>, options: StartOptions = {}): Promise<LifecycleResult>;
```


## `@microsoft/mxc-sdk/v1::stopContainer`

Stops a started container without releasing its provision-side resources.

```typescript
export async function stopContainer<C extends LifecycleContainmentKind>(containerId: ContainerId<C>, options: StopOptions = {}): Promise<LifecycleResult>;
```


## `@microsoft/mxc-sdk/v1::validateDeprovision`

Validate deprovision without releasing the container.

```typescript
export async function validateDeprovision<C extends LifecycleContainmentKind>(containerId: ContainerId<C>, options: DeprovisionOptions = {}): Promise<ValidationResult>;
```


## `@microsoft/mxc-sdk/v1::validateProcess`

Validate a process request without starting a workload.

```typescript
export async function validateProcess<C extends LifecycleContainmentKind>(containerId: ContainerId<C>, request: ExecutionRequest<C>, options: SpawnInContainerOptions = {}): Promise<ValidationResult>;
```


## `@microsoft/mxc-sdk/v1::validateProvision`

Validate provision without allocating a container or returning an identity.

```typescript
export async function validateProvision<C extends LifecycleContainmentKind>(request: ProvisionRequest<C> & {
  containment: C;
}, options: ProvisionOptions = {}): Promise<ValidationResult>;
```


## `@microsoft/mxc-sdk/v1::validateStart`

Validate a start request without starting the container.

```typescript
export async function validateStart<C extends LifecycleContainmentKind>(containerId: ContainerId<C>, options: StartOptions = {}): Promise<ValidationResult>;
```


## `@microsoft/mxc-sdk/v1::validateStop`

Validate a stop request without stopping the container.

```typescript
export async function validateStop<C extends LifecycleContainmentKind>(containerId: ContainerId<C>, options: StopOptions = {}): Promise<ValidationResult>;
```


## `@microsoft/mxc-sdk/v1::withdrawTelemetryConsent`

Idempotently withdraw telemetry consent without blocking the event loop.

```typescript
export async function withdrawTelemetryConsent(): Promise<TelemetryConsentOutcome>;
```
