# `@microsoft/mxc-sdk`

> Node.js / TypeScript SDK for **MXC** (Microsoft eXecution Containers).

> **Status: Public Preview.** Schemas and APIs may change before 1.0.

```bash
npm install @microsoft/mxc-sdk
```

## Quick start

```typescript
import {
  spawnSandboxAsync,
  getAvailableToolsPolicy,
  getTemporaryFilesPolicy,
  getPlatformSupport,
} from '@microsoft/mxc-sdk';

const support = getPlatformSupport();
if (!support.isSupported) {
  throw new Error(support.reason ?? 'MXC is not available on this host');
}

const tools = getAvailableToolsPolicy(process.env);
const temp = getTemporaryFilesPolicy();

const result = await spawnSandboxAsync(
  'python -c "print(\'hello from sandbox\')"',
  {
    version: '0.8.0-alpha',
    filesystem: {
      readonlyPaths: tools.readonlyPaths,
      readwritePaths: temp.readwritePaths,
    },
    network: { allowOutbound: false },
    timeoutMs: 30_000,
  },
);

console.log(result.stdout);
```

## Runtime model

The Node SDK now runs **in process through the native runtime**.

The npm package no longer ships the standalone executor binaries
(`wxc-exec.exe`, `lxc-exec`, `mxc-exec-mac`) or the executor-only
`unix-test-proxy`. Those executables remain available in
`mxc-release-binaries`.

- **One-shot APIs:** `spawnSandboxAsync`, `spawnSandbox`,
  `spawnSandboxFromConfig`
- **State-aware APIs:** `provisionSandbox`, `startSandbox`,
  `execInSandboxProcess`, `execInSandboxAsync`, `stopSandbox`,
  `deprovisionSandbox`
- **Conversion utilities:** `createConfigFromPolicy`, `buildSandboxPayload`

`createConfigFromPolicy` and `buildSandboxPayload` still produce
`ContainerConfig` objects for inspection, customization, and execution.
`spawnSandboxFromConfig` converts that established public model to the private
native request only at the binding boundary.

The native library is resolved from:

1. `MXC_FFI_DIR`
2. the packaged `bin/<arch>/` directory
3. local Cargo outputs under `src/target/...` during development

The npm package keeps the native shared library and the backend runtime dependencies it needs,
such as Windows Sandbox, WSLC, PLM, and NanVix assets when present.

## Compatibility

**Policy / config schema versions**

| Version | Status |
| --- | --- |
| `0.6.0-alpha` | Stable, minimum supported |
| `0.7.0-alpha` | Stable |
| `0.8.0-alpha` | Stable, recommended for new code |
| `0.9.0-alpha` | Dev / experimental surface |

Stable schemas live in
[`schemas/stable/`](https://github.com/microsoft/mxc/tree/main/schemas/stable);
development schemas live in
[`schemas/dev/`](https://github.com/microsoft/mxc/tree/main/schemas/dev).

**Platforms**

| Platform | Default one-shot backend | Notes |
| --- | --- | --- |
| Windows 11 24H2+ | `processcontainer` | `windows_sandbox`, `wslc`, `microvm`, `isolation_session`, and `hyperlight` remain experimental |
| Linux x64 / ARM64 | `bubblewrap` | `lxc` remains available natively, but not through the Node one-shot API |
| macOS ARM64 (`0.7.0-alpha`+) | `seatbelt` | One-shot Node API uses the default process backend only |

`getPlatformSupport()` reports backend availability. On Linux it also reports
per-backend `unavailableReasons` when Bubblewrap or LXC probing fails.

## One-shot APIs

### `spawnSandboxAsync`

`spawnSandboxAsync()` is the buffered run-to-completion entry point. It returns
separate `stdout`, `stderr`, and `exitCode`.

```typescript
import { spawnSandboxAsync } from '@microsoft/mxc-sdk';

const result = await spawnSandboxAsync(
  'node -e "console.log(process.version)"',
  { version: '0.8.0-alpha' },
);

console.log(result.stdout);
```

### `spawnSandbox`

`spawnSandbox()` keeps the sandbox live and exposes Node streams through
`MxcSandboxProcess`.

```typescript
import { spawnSandbox } from '@microsoft/mxc-sdk';

const proc = spawnSandbox(
  'python -c "print(\'hello\')"',
  { version: '0.8.0-alpha' },
);

proc.stdout?.on('data', (chunk) => process.stdout.write(chunk));
const status = await proc.wait();
console.log(status.exitCode);
proc.dispose();
```

It now returns `MxcSandboxProcess` rather than the executor-backed `IPty`.

### Config-based execution

`createConfigFromPolicy()` and `buildSandboxPayload()` preserve the existing
configuration workflow. Customize the resulting `ContainerConfig`, then pass
it to `spawnSandboxFromConfig()`:

```typescript
import {
  buildSandboxPayload,
  spawnSandboxFromConfig,
} from '@microsoft/mxc-sdk';

const payload = buildSandboxPayload(
  'python app.py',
  {
    version: '0.8.0-alpha',
    network: { allowOutbound: true },
  },
  'C:\\work',
  'sample',
  'processcontainer',
);

payload.processContainer!.learningMode = true;
const proc = spawnSandboxFromConfig(payload);
const status = await proc.wait();
```

The SDK converts `ContainerConfig` into its private native request internally.
That transport shape is not part of the public Node API.

### One-shot limitations

The in-process Node one-shot surface intentionally does **not** preserve the
old executor-only features:

- No PTY / `node-pty` surface
- No one-shot `dryRun`
- No `debug`, `logDir`, `executablePath`, `ptyOptions`, `usePty`,
  `allowTestingFeatures`, or `skipPlatformCheck`
- No `network.proxy.builtinTestServer`

Only `experimental` and `signal` remain in `SandboxSpawnOptions`.

### Migrating from `IPty`

The Node-only `IPty` contract is replaced by the same pipe-based process model
used by the C# SDK:

| Previous `IPty` operation | In-process replacement |
| --- | --- |
| `pty.onData(handler)` | Listen to `proc.stdout` and `proc.stderr` separately |
| `pty.write(data)` | `proc.stdin?.write(data)` |
| `pty.onExit(handler)` | `await proc.wait()` |
| `pty.kill()` | `proc.kill()` |
| `pty.resize(columns, rows)` | No replacement |

Programs receive ordinary pipes rather than a terminal. Interactive shells,
terminal editors, curses applications, and programs that require terminal
resize or terminal-mode negotiation are not supported by these Node APIs.

## State-aware sandboxes

Use the state-aware lifecycle for long-lived sandboxes that you provision once
and exec many times.

```typescript
import {
  provisionSandbox,
  startSandbox,
  execInSandboxAsync,
  execInSandboxProcess,
  stopSandbox,
  deprovisionSandbox,
} from '@microsoft/mxc-sdk';

const options = { experimental: true };

const { sandboxId } = await provisionSandbox(
  'isolation_session',
  { network: { defaultPolicy: 'allow', allowLocalNetwork: true } },
  options,
);

await startSandbox(sandboxId, undefined, options);

const first = await execInSandboxAsync(
  sandboxId,
  { process: { commandLine: 'echo hello' } },
  options,
);
console.log(first.stdout);

const live = execInSandboxProcess(
  sandboxId,
  { process: { commandLine: 'echo streamed' } },
  options,
);
live.stdout?.on('data', (chunk) => process.stdout.write(chunk));
await live.wait();
live.dispose();

await stopSandbox(sandboxId, undefined, options);
await deprovisionSandbox(sandboxId, undefined, options);
```

Supported backends today:

- `isolation_session`
- `windows_sandbox`
- `wslc`

All three are currently Windows-only and require `{ experimental: true }`.

## Policy discovery helpers

The SDK includes helpers for building portable filesystem policy:

```typescript
import {
  getAvailableToolsPolicy,
  getUserProfilePolicy,
  getTemporaryFilesPolicy,
} from '@microsoft/mxc-sdk';

const tools = getAvailableToolsPolicy(process.env);
const profile = getUserProfilePolicy();
const temp = getTemporaryFilesPolicy();

const policy = {
  version: '0.8.0-alpha',
  filesystem: {
    readonlyPaths: [...tools.readonlyPaths, ...profile.readonlyPaths],
    readwritePaths: temp.readwritePaths,
  },
};
```

Each helper returns `{ readonlyPaths, readwritePaths }`.

## Common pitfalls

### UI is blocked by default

`ui.allowWindows` defaults to `false`. On Windows, shells such as
`powershell.exe` and `pwsh.exe` may need UI access during startup.

```typescript
const result = await spawnSandboxAsync(
  'powershell.exe -NoProfile -Command "Get-Date"',
  {
    version: '0.8.0-alpha',
    ui: { allowWindows: true },
  },
);
```

### `workingDirectory` does not grant filesystem access

Setting a working directory does not add that path to `readonlyPaths` or
`readwritePaths`. Grant access explicitly.

### Default deny still applies

No writable paths means no writes to temp directories. No network policy means
default-deny network behavior. Use the discovery helpers to compose a usable
baseline.

### Legacy executor options are hard failures

If you pass a removed option such as `usePty`, `debug`, or `executablePath`,
the SDK throws `MxcError { code: 'malformed_request' }` instead of silently
falling back.

## Troubleshooting

| Error | Cause | Fix |
| --- | --- | --- |
| `native library was not found...` | The SDK could not resolve its native shared library. | Stage the packaged `bin/<arch>/` files, set `MXC_FFI_DIR`, or build the native library under `src/target`. |
| `'<backend>' containment requires experimental mode` | You selected an experimental backend without opt-in. | Pass `{ experimental: true }`. |
| `...no longer supports legacy option...` | Caller passed an executor-only option to an in-process API. | Remove the option and use `spawnSandboxAsync`, `spawnSandbox`, or the state-aware process APIs directly. |
| `builtinTestServer is not supported by the in-process Node SDK` | The request used the removed testing-only proxy shape. | Use `network.proxy: { localhost: <port> }`, `network.proxy: { url: ... }`, or `runtimeConfig.networkProxy` as appropriate. |

For backend-specific behavior, see the backend guides under
[`docs/`](https://github.com/microsoft/mxc/tree/main/docs).

## API surface

```typescript
createConfigFromPolicy(policy, containment?, containerName?) => ContainerConfig
buildSandboxPayload(script, policy, workingDirectory?, containerName?, containment?) => ContainerConfig

spawnSandboxAsync(script, policy, options?, workingDirectory?, containerName?) => Promise<{ stdout, stderr, exitCode }>
spawnSandbox(script, policy, options?, workingDirectory?, containerName?, environment?) => MxcSandboxProcess
spawnSandboxFromConfig(config, options?, workingDirectory?, environment?) => MxcSandboxProcess

provisionSandbox(containment, config, options?) => Promise<ProvisionResult>
startSandbox(sandboxId, config?, options?) => Promise<StartResult>
execInSandboxProcess(sandboxId, config, options?) => MxcSandboxProcess
execInSandboxAsync(sandboxId, config, options?) => Promise<ExecResult>
stopSandbox(sandboxId, config?, options?) => Promise<StopResult>
deprovisionSandbox(sandboxId, config?, options?) => Promise<DeprovisionResult>

getPlatformSupport() => PlatformSupport
getAvailableToolsPolicy(env?, options?) => FilesystemPolicyResult
getUserProfilePolicy() => FilesystemPolicyResult
getTemporaryFilesPolicy(env?) => FilesystemPolicyResult

queryTelemetryConsentAsync() => Promise<TelemetryConsentQuery>
requestTelemetryConsent(presenter, locale?) => Promise<TelemetryConsentOutcome>
withdrawTelemetryConsentAsync() => Promise<TelemetryConsentOutcome>

ErrorCode, MxcError, MxcErrorFields, mxcErrorFromCode(...)
```

## Telemetry consent

Telemetry is Windows-only and always opt-in. The SDK exposes:

- `queryTelemetryConsentAsync()`
- `requestTelemetryConsent(...)`
- `withdrawTelemetryConsentAsync()`

Consent, administrative policy, and the request-level `telemetry.enabled`
switch must all allow telemetry before anything is emitted. See:

- [`docs/telemetry/telemetry-consent-design.md`](https://github.com/microsoft/mxc/blob/main/docs/telemetry/telemetry-consent-design.md)
- [`docs/telemetry/telemetry-administrative-policy.md`](https://github.com/microsoft/mxc/blob/main/docs/telemetry/telemetry-administrative-policy.md)
- [`docs/telemetry/telemetry.md`](https://github.com/microsoft/mxc/blob/main/docs/telemetry/telemetry.md)

## Further reading

- [`docs/schema.md`](https://github.com/microsoft/mxc/blob/main/docs/schema.md)
- [`docs/versioning.md`](https://github.com/microsoft/mxc/blob/main/docs/versioning.md)
- [`docs/examples.md`](https://github.com/microsoft/mxc/blob/main/docs/examples.md)
- [`docs/state-aware-lifecycle/`](https://github.com/microsoft/mxc/tree/main/docs/state-aware-lifecycle/)
- Backend-specific guides under [`docs/`](https://github.com/microsoft/mxc/tree/main/docs)

## License

[MIT](https://github.com/microsoft/mxc/blob/main/sdk/node/LICENSE.md)
