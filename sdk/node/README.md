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
import type { ContainerPolicy, ContainerRequest } from '@microsoft/mxc-sdk/v1';

if (!getPlatformSupport().isSupported) {
  throw new Error('MXC is not available on this host');
}

const policy: ContainerPolicy = {
  filesystem: { readonlyPaths: [process.cwd()] },
  network: { egress: { default: 'deny' } },
  timeoutMs: 30_000,
};
const request: ContainerRequest = {
  policy,
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

`ContainerRequest` contains a `ContainerPolicy`, command, and optional
containment, container name, working directory, and environment settings. The
SDK selects its exact V1 contract; callers do not provide a schema version or
raw executor configuration. Use the typed `Containment` options to select a
supported backend explicitly.

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

`execInSandbox` returns a live pipe-backed `MxcProcess`; `execInSandboxAsync`
captures output. `spawnInContainer` and `runInContainer` are the corresponding
existing-container operation names. IsolationSession provision requires an
explicit unrestricted directional network posture; WSLC network posture is
fixed at provision. See the
[IsolationSession](../../docs/isolation-session/state-aware-typescript.md) and
[WSLC](../../docs/wsl/wslc-state-aware.md) guides for backend and phase
requirements.

## Public V1 types

| Purpose | TypeScript type |
| --- | --- |
| Container restrictions | `ContainerPolicy` |
| One-shot workload | `ContainerRequest` |
| Persistent container identity | `ContainerId` |
| Existing-container workload | `ExecRequest` |
| Live process with standard pipes | `MxcProcess` |
| Captured execution | `Output` |
| Terminal process outcome | `WaitOutcome` |

PTY operations are not part of this V1 API. Network policy details are in the
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
