# `@microsoft/mxc-sdk`

Node.js / TypeScript SDK for MXC (Microsoft eXecution Containers). The
versioned public request, execution, and lifecycle APIs are exported from
`@microsoft/mxc-sdk/v1`; platform discovery, errors, and telemetry consent
remain at the package root. These APIs use the SDK-owned V1 contract; callers
do not select the wire version.

```bash
npm install @microsoft/mxc-sdk
```

Node.js 24 or later is required. On Windows, native stdio transfer requires
Node.js 24.21.0 or later within the Node.js 24 release line, or Node.js 26.8.0
or later.

## One-shot execution

```typescript
import { getPlatformSupport } from '@microsoft/mxc-sdk';
import { runAsync, spawn } from '@microsoft/mxc-sdk/v1';
import type { ContainerRequest } from '@microsoft/mxc-sdk/v1';

if (!getPlatformSupport().isSupported) {
  throw new Error('MXC is not available on this host');
}

const request: ContainerRequest = {
  filesystem: { readonlyPaths: [process.cwd()] },
  network: { egress: { default: 'deny' } },
  timeoutMs: 30_000,
  command: 'node -e "console.log(\\'hello from sandbox\\')"',
};

const output = await runAsync(request);
console.log(output.stdout, output.exitCode);

const processHandle = spawn(request);
processHandle.standardOutput?.on('data', (chunk) => process.stdout.write(chunk));
const outcome = await processHandle.waitAsync();
processHandle.dispose();
```

`run` / `runAsync` capture stdout and stderr in an `Output`. `spawn` /
`spawnAsync` return an `MxcProcess` with standard pipes, wait, termination, and
disposal operations. Access output streams before awaiting completion; any
untaken streams are drained internally to avoid pipe-buffer deadlocks.
Each operation accepts an optional `MxcOptions` argument containing
`experimental` and `dryRun` booleans. `experimental` is forwarded to the native
runtime. `dryRun: true` is supported by state-aware operations that return a
completed response, but rejected by one-shot and live-process operations.

`ContainerRequest` holds the command, cross-backend filesystem, network, and UI
settings, and the selected backend's typed configuration. The SDK selects its
exact V1 contract; callers do not provide a schema version or raw executor
configuration.

`spawnWithPty(request, size?)` starts a one-shot request with a caller-driven
terminal and returns a `Promise<MxcPtyProcess>`. PTY support is currently
available for IsolationSession requests.

## Existing containers

The V1 lifecycle API provisions and controls supported persistent backends.
`provisionSandbox` returns a branded `ContainerId`; use it for later phases
without inspecting its runtime string.

```typescript
import {
  deprovisionSandbox,
  execInSandboxAsync,
  provisionSandbox,
  startSandbox,
  stopSandbox,
} from '@microsoft/mxc-sdk/v1';

const { containerId } = await provisionSandbox('wslc', {
  image: 'alpine:latest',
});
await startSandbox(containerId);
const result = await execInSandboxAsync(containerId, {
  process: { commandLine: 'echo hello' },
});
console.log(result.stdout, result.exitCode);
await stopSandbox(containerId);
await deprovisionSandbox(containerId);
```

`execInSandbox` returns a live pipe-backed `MxcProcess`;
`execInSandboxAsync` captures output. `execInSandboxAttached` synchronously
relays execution through the host terminal and returns a `WaitOutcome`; both
host stdin and stdout must be terminals. `spawnInContainer` and
`runInContainer` are the corresponding existing-container operation names.
`spawnInContainerWithPty(containerId, request, size?)` starts an
IsolationSession exec with a caller-driven terminal and returns a
`Promise<MxcPtyProcess>`.
IsolationSession provision requires an explicit unrestricted directional
network posture; WSLC network posture is fixed at provision. See the
[IsolationSession](../../docs/isolation-session/state-aware-typescript.md) and
[WSLC](../../docs/wsl/wslc-state-aware.md) guides for backend and phase
requirements.

## Public V1 types

| Purpose | TypeScript type |
| --- | --- |
| One-shot request and cross-backend restrictions | `ContainerRequest` |
| Persistent container identity | `ContainerId` |
| Existing-container workload | `ExecRequest` |
| Live process with standard pipes | `MxcProcess` |
| Live process with a terminal | `MxcPtyProcess` |
| Terminal dimensions | `MxcPtySize` |
| Captured execution | `Output` |
| Terminal process outcome | `WaitOutcome` |

Network policy details are in the
[networking guide](../../docs/sandbox-policy/0.8.0/networking/networking.md);
host-specific behavior and supported capabilities are documented in the
backend guides under [`docs/`](../../docs/).

## Errors, warnings, and telemetry

Native errors are surfaced as `MxcError` with a typed error code and optional
operation, native status, and remediation. Security and operational warnings
are returned in `Output.warnings` and `MxcProcess.warnings`.

Telemetry is disabled unless requested per operation and remains subject to
MXC's persisted user consent and administrative policy. The package root
exports the telemetry consent APIs and `getPlatformSupport`.
