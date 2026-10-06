# `@microsoft/mxc-sdk`

> **Audience:** MXC consumers

Node.js / TypeScript SDK for MXC (Microsoft eXecution Containers). The
versioned public request, execution, and lifecycle APIs are exported from
`@microsoft/mxc-sdk/v1`, including platform discovery, errors, and telemetry consent.
The package root exports no public APIs. These APIs use the SDK-owned V1 contract; callers
do not select the wire version.

```bash
npm install @microsoft/mxc-sdk
```

Node.js 24 or later is required. On Windows, native stdio transfer requires
Node.js 24.21.0 or later within the Node.js 24 release line, or Node.js 26.8.0
or later.

## Run to completion

```typescript
import { getPlatformSupport } from '@microsoft/mxc-sdk/v1';
import { run } from '@microsoft/mxc-sdk/v1';
import type { ContainerRequest } from '@microsoft/mxc-sdk/v1';

if (!getPlatformSupport().isSupported) {
  throw new Error('MXC is not available on this host');
}

const request: ContainerRequest = {
  filesystem: { readonlyPaths: [process.cwd()] },
  network: { egress: { default: 'deny' } },
  timeoutMs: 30_000,
  command: 'node -e "console.log(\'hello from container\')"',
};

const output = await run(request);
console.log(output.stdout, output.exitCode);

```

`run` returns a `Promise<ExecutionResult>` containing captured stdout, stderr,
the workload exit code, timeout state, warnings, and optional output metadata.

## Spawn with streaming output

```typescript
import { spawn } from '@microsoft/mxc-sdk/v1';

const processHandle = await spawn({
  command: 'node -e "console.log(\'hello from container\')"',
  timeoutMs: 30_000,
});
try {
  processHandle.standardOutput?.on('data', (chunk) => process.stdout.write(chunk));
  processHandle.standardError?.on('data', (chunk) => process.stderr.write(chunk));
  console.log(await processHandle.wait());
} finally {
  processHandle.dispose();
}
```

`spawn` returns a `Promise<MxcProcess>` with standard pipes, wait, termination,
and disposal operations. Access output streams before awaiting completion; any
untaken streams are drained internally to avoid pipe-buffer deadlocks.
Each operation accepts its own optional options type: `RunOptions`,
`SpawnOptions`, or `SpawnWithPtyOptions`.
Execution options do not support `dryRun`.

`ContainerRequest` holds the command, cross-backend filesystem, network, and UI
settings, and the selected backend's typed configuration. The SDK selects its
exact V1 contract; callers do not provide a schema version or raw executor
configuration.

When UI settings are supplied, `ui.disable` explicitly controls whether UI is
disabled; clipboard and input-injection permissions remain separate.

## Spawn with a caller-controlled terminal

PTY execution supports all backends except WSLc.

```typescript
import { spawnWithPty } from '@microsoft/mxc-sdk/v1';

const terminal = await spawnWithPty({
  containment: { type: 'isolation_session' },
  command: 'cmd.exe',
  network: {
    egress: { default: 'allow' },
    ingress: { default: 'allow', hostLoopback: 'allow' },
  },
  timeoutMs: 30_000,
}, { size: { rows: 24, columns: 80 } });
try {
  terminal.output.on('data', (chunk) => process.stdout.write(chunk));
  terminal.input.end('echo hello from terminal\r\nexit\r\n');
  console.log(await terminal.wait());
} finally {
  terminal.dispose();
}
```

`spawnWithPty` returns a `Promise<MxcPtyProcess>` with merged terminal output
and resizing support. Initial dimensions default to 24 rows by 80 columns.
Terminal stderr is merged into `output`. Closing `input` requests terminal EOF
when supported; raw-mode applications must use their own completion protocol.
Seatbelt rejects PTY mode with `guiAccess` or legacy `launchMethod: "open"`.
Unsupported combinations are rejected before sandbox creation.

## Lifecycle API

`ProvisionResult<C>.metadata` uses `ProvisionMetadata<C>` to select the
backend's metadata type. IsolationSession returns
`IsolationSessionProvisionMetadata`; WSLC returns no provision metadata.

The V1 lifecycle API provisions and controls supported persistent backends.
`provisionContainer` returns a branded `ContainerId`; use it for later phases
without inspecting its runtime string.

```typescript
import {
  deprovisionContainer,
  runInContainer,
  provisionContainer,
  startContainer,
  stopContainer,
} from '@microsoft/mxc-sdk/v1';

const { containerId } = await provisionContainer({
  containment: 'isolation_session',
  network: {
    egress: { default: 'allow' },
    ingress: { default: 'allow', hostLoopback: 'allow' },
  },
});
try {
  await startContainer(containerId);
  try {
    const result = await runInContainer(containerId, {
      command: 'echo hello from lifecycle',
      timeoutMs: 30_000,
    });
    console.log(result.stdout, result.exitCode);
  } finally {
    await stopContainer(containerId);
  }
} finally {
  await deprovisionContainer(containerId);
}
```

`spawnInContainer` returns a `Promise<MxcProcess>` with live standard pipes;
`runInContainer` returns a `Promise<ExecutionResult>` with captured output.
`spawnInContainerWithPty(containerId, request, options?)` starts an
IsolationSession exec with a caller-driven terminal and returns a
`Promise<MxcPtyProcess>`. Set `options.size` for initial dimensions; it defaults
to 24 rows by 80 columns.
IsolationSession provision requires an explicit unrestricted directional
network posture; WSLC network posture is fixed at provision. See the
[IsolationSession](https://github.com/microsoft/mxc/blob/main/docs/isolation-session/state-aware-typescript.md) and
[WSLC](https://github.com/microsoft/mxc/blob/main/docs/wsl/wslc-state-aware.md) guides for backend and phase
requirements.

Provisioning takes a discriminated `ProvisionRequest` and optional
`ProvisionOptions`. Start, stop, and deprovision take the identity followed by
their own `StartOptions`, `StopOptions`, or `DeprovisionOptions`.
Existing-container execution takes the identity, a flat `ExecutionRequest`, and
`SpawnInContainerOptions` or `RunInContainerOptions`; PTY execution carries
initial dimensions on `SpawnInContainerWithPtyOptions`. Process settings use
`command`, `workingDirectory`, `environment`, `inheritDefaultEnvironment`, and
`timeoutMs`, just as creation does.

Lifecycle and existing-container options can override request telemetry.
`validateProvision`, `validateStart`, `validateStop`, `validateDeprovision`,
and `validateProcess` perform native dry-run validation without creating a
container or returning an execution result. They return `ValidationResult`
with a `warnings` array and use the corresponding
operation options.
Existing-container execution accepts runtime-only network settings at
`network.runtimeConfig`; it cannot change the container's provision-time
network policy.
The runtime values are typed as `NetworkRuntimeConfig`.

The creation containment types are compile-time-only choices under the
`Containment` namespace, such as `Containment.Process` and
`Containment.ProcessContainer`. `Containment` is also their closed union;
the SDK does not create runtime containment objects or factories.

`ContainerRequest` uses the named `FilesystemPolicy`, `NetworkPolicy`, and
`UiPolicy` types for cross-backend restrictions. Backend-specific settings
remain on the selected containment configuration.

## Public V1 types

| Purpose | TypeScript type |
| --- | --- |
| Creation request and cross-backend restrictions | `ContainerRequest` |
| Persistent container identity | `ContainerId` |
| Persistent container provision input | `ProvisionRequest` |
| Existing-container workload | `ExecutionRequest` |
| Live process with standard pipes | `MxcProcess` |
| Live process with a terminal | `MxcPtyProcess` |
| Terminal dimensions | `MxcPtySize` |
| Captured execution | `ExecutionResult` |
| Terminal process outcome | `WaitResult` |
| Validation warnings | `ValidationResult` |
| Provisioned identity, optional metadata, and warnings | `ProvisionResult<C>` |
| Start, stop, and deprovision warnings | `LifecycleResult` |
| Structured execution outputs | `ExecutionMetadata` |
| Denial-capture output and failure | `CaptureDenialsResult`, `CaptureDenialsError` |
| Runtime network values | `NetworkRuntimeConfig` |
| Native host backend and optional capability | `AvailableBackend`, `BackendCapability` |
| Consent status and operation result | `TelemetryConsentStatus`, `TelemetryConsentOutcome` |
| Host consent presenter | `TelemetryConsentPresenter` |

Network policy details are in the
[networking guide](https://github.com/microsoft/mxc/blob/main/docs/sandbox-policy/0.8.0/networking/networking.md);
host-specific behavior and supported capabilities are documented in the
backend guides under [`docs/`](https://github.com/microsoft/mxc/tree/main/docs).
See the [SDK API reference](https://github.com/microsoft/mxc/blob/main/docs/reference/README.md)
for complete signatures and types.

## Errors, warnings, and telemetry

Native errors are surfaced as `MxcError` with a typed error code and optional
operation, native status, and remediation. Security and operational warnings
are returned in `ExecutionResult.warnings` and `MxcProcess.warnings`.
Captured `stdout` and `stderr` are workload output; warnings and structured
denial-capture metadata are not appended to those streams.
Validation warnings are returned in `ValidationResult.warnings`.
Provision warnings are returned in `ProvisionResult.warnings`; start, stop,
and deprovision return `LifecycleResult.warnings`. Omitted native warnings
become an empty array; malformed warnings fail explicitly. When provision
metadata is present for IsolationSession, all three fields are required:
`agentUserName`, `agentUserSid`, and `ephemeralWorkspacePath`.
`ExecutionResult.outputMetadata`, `MxcProcess.outputMetadata`, and the inherited
PTY property expose optional `ExecutionMetadata`. Live-process metadata is
available after terminal settling; denial-capture fields are populated only
when the backend produces them.

Creation telemetry is supplied through `telemetry: { enabled: true }` on
`RunOptions`, `SpawnOptions`, or `SpawnWithPtyOptions`, not on `ContainerRequest`.
Omission leaves telemetry disabled; `enabled: false` explicitly disables it.
Opt-in remains subject to MXC's persisted user consent and administrative policy. Telemetry consent
APIs and `getPlatformSupport` are exported from `@microsoft/mxc-sdk/v1`.

`getTelemetryConsentStatus` reads stored/effective consent and policy,
`requestTelemetryConsent` accepts an application-owned presenter, and
`withdrawTelemetryConsent` withdraws consent. Each returns a Promise. These
operations are Windows-only and report `not-applicable` on other platforms.

`getAvailableBackends()` reads native host availability, isolation tiers,
capabilities, and warnings through in-process `mxc_ffi`. It returns
`AvailableBackend[]`; a reported host backend is not necessarily launchable
through V1 creation. Discovery is advisory, and launch-time validation still
applies. Native failures and malformed discovery results throw rather than
reporting an unsupported host.

Filesystem discovery helpers and their result/options types are grouped under
`policy.filesystem` from `@microsoft/mxc-sdk/v1`. They take an optional
`environment` map; omission uses
`process.env`, and `{}` stays empty. `getAvailableToolsPolicy` also accepts
`ToolsPolicyOptions`; set `containerType: 'processcontainer'` to exclude
directories with ALL APPLICATION PACKAGES access on Windows. ACL inspection
is bounded to five seconds per directory; failures retain the directory and
emit a diagnostic warning. `getUserProfilePolicy` uses the supplied environment,
and `getTemporaryFilesPolicy` returns existing temporary storage without creating
directories.
