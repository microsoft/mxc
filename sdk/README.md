# `@microsoft/mxc-sdk`

> Node.js / TypeScript SDK for **MXC** (Microsoft eXecution Containers) — a policy-driven sandbox for running untrusted code (model output, plugins, tools) on Windows, Linux, and macOS.

> **Status: Public Preview.** Schemas and APIs may change between minor versions until 1.0.

```bash
npm install @microsoft/mxc-sdk
```

```typescript
import {
  spawnSandboxFromConfig, createConfigFromPolicy,
  getAvailableToolsPolicy, getTemporaryFilesPolicy,
  getPlatformSupport,
} from '@microsoft/mxc-sdk';

if (!getPlatformSupport().isSupported) {
  throw new Error('MXC not available on this host');
}

// Discover host tools (python, node, etc.) and a writable temp dir.
const tools = getAvailableToolsPolicy(process.env);
const temp  = getTemporaryFilesPolicy();

const config = createConfigFromPolicy({
  version: '0.6.0-alpha',
  filesystem: {
    readonlyPaths:  tools.readonlyPaths,    // PATH, PYTHONPATH, JAVA_HOME, …
    readwritePaths: temp.readwritePaths,    // %TEMP% / $TMPDIR
  },
  network: { allowOutbound: false },
  timeoutMs: 30_000,
});
config.process!.commandLine = 'python -c "print(\'hello from sandbox\')"';

const child = spawnSandboxFromConfig(config, { usePty: false });
child.stdout!.on('data', (d) => process.stdout.write(d));
child.on('close', (code) => console.log('exit:', code));
```

---

## Compatibility

<!--
  Keep this section in sync with:
    - sdk/src/sandbox.ts          (SUPPORTED_VERSION / MIN_VERSION)
    - sdk/src/platform.ts         (availableMethods per platform)
    - schemas/{stable,dev}/*.json (supported policy.version values)
  When a new schema graduates or a new backend ships, update only this block.
-->

**Policy / config schema versions:**

| Version | Status | Schema file |
| --- | --- | --- |
| `0.4.0-alpha` | Retired — below the `0.6.0-alpha` floor (no longer accepted) | [`schemas/stable/mxc-config.schema.0.4.0-alpha.json`](https://github.com/microsoft/mxc/blob/main/schemas/stable/mxc-config.schema.0.4.0-alpha.json) |
| `0.5.0-alpha` | Retired — below the `0.6.0-alpha` floor (no longer accepted) | [`schemas/stable/mxc-config.schema.0.5.0-alpha.json`](https://github.com/microsoft/mxc/blob/main/schemas/stable/mxc-config.schema.0.5.0-alpha.json) |
| `0.6.0-alpha` | Stable (minimum supported) | [`schemas/stable/mxc-config.schema.0.6.0-alpha.json`](https://github.com/microsoft/mxc/blob/main/schemas/stable/mxc-config.schema.0.6.0-alpha.json) |
| `0.7.0-alpha` | Stable (current) | [`schemas/stable/mxc-config.schema.0.7.0-alpha.json`](https://github.com/microsoft/mxc/blob/main/schemas/stable/mxc-config.schema.0.7.0-alpha.json) |
| `0.8.0-alpha` | Dev (experimental backends, the `experimental.*` block, state-aware sandbox lifecycle) | [`schemas/dev/mxc-config.schema.0.8.0-dev.json`](https://github.com/microsoft/mxc/blob/main/schemas/dev/mxc-config.schema.0.8.0-dev.json) |

Pick `0.7.0-alpha` for new code on any supported platform.

> **Stable schemas document only the non-experimental surface.** Experimental backends (`windows_sandbox`, `wslc`, `microvm`, `hyperlight`, `isolation_session`), the `experimental.*` block, and state-aware lifecycle live in `0.8.0-dev`. The parser still accepts them when paired with `--experimental` regardless of which schema your config validates against — schema choice affects editor validation, not runtime behavior.

> **Network host allow/block lists are not implemented on Windows.** `network.allowedHosts` / `network.blockedHosts` have no enforcement on this platform — use `network.defaultPolicy` (`allow` / `block`) or `network.proxy` to constrain network access.

**Platforms:**

| Platform | Default backend | Other backends | Minimum build |
| --- | --- | --- | --- |
| Windows 11 24H2+ (verified on 25H2) | `processcontainer` | `windows_sandbox`, `wslc`, `microvm`, `isolation_session` | `processcontainer`: 26100 (24H2)<br>`isolation_session`: 26300.8553 ([Insider Preview](https://learn.microsoft.com/en-us/windows-insider/release-notes/experimental/preview-build-26300-8553)) |
| Linux x64 / ARM64 | `bubblewrap` | `lxc` | — |
| macOS ARM64 (schema `0.7.0-alpha`+) | `seatbelt` | — | — |

The default `processcontainer`, `bubblewrap`, `lxc`, and `seatbelt` backends work out of the box. **Experimental backends** (`windows_sandbox`, `wslc`, `microvm`, `isolation_session`, `hyperlight`) require `{ experimental: true }` in `SandboxSpawnOptions` when you spawn — see [Choosing a Backend](#choosing-a-backend).

> **Hyperlight** is an opt-in build flavor (Linux x64 and Windows x64) gated by the `--with-hyperlight` cargo feature. Default shipped binaries do not include it; build from source with `build.bat --with-hyperlight` (Windows) or the equivalent cargo invocation on Linux.

`getPlatformSupport()` reports backend availability and, when the native probe can determine it, `uiCapabilities`: a platform-neutral view of which UI restrictions the host can enforce. This is currently populated only by the Windows native probe, where it is derived from `JOB_OBJECT_UILIMIT_*` support; Linux and macOS omit the field until their probes expose equivalent data.

**Node.js:** ≥ 18.

---

## Three Ways to Spawn

The SDK provides three entry points. **Prefer the config-based path** (`createConfigFromPolicy` + `spawnSandboxFromConfig`) — it gives you backend selection, backend-specific tuning, and (with `usePty: false`) separated stdout/stderr.

### 1. Config-based — recommended

```typescript
import {
  createConfigFromPolicy, spawnSandboxFromConfig,
  getAvailableToolsPolicy, getTemporaryFilesPolicy,
} from '@microsoft/mxc-sdk';

const tools = getAvailableToolsPolicy(process.env);
const temp  = getTemporaryFilesPolicy();

const config = createConfigFromPolicy(
  {
    version: '0.6.0-alpha',
    filesystem: {
      readonlyPaths:  tools.readonlyPaths,
      readwritePaths: temp.readwritePaths,
    },
    network: { allowOutbound: true },
    timeoutMs: 30_000,
  },
  'process', // intent: "process" | "vm" | "microvm"
);

// Add the script and any backend-specific runtime settings on the returned config.
config.process!.commandLine = 'python script.py';

// PTY mode (default) — IPty, merged stdout+stderr
const pty = spawnSandboxFromConfig(config);
pty.onData((d) => process.stdout.write(d));
pty.onExit(({ exitCode }) => console.log('exit:', exitCode));

// Pipe mode — ChildProcess with separated stdout/stderr + reliable exit codes
const child = spawnSandboxFromConfig(config, { usePty: false });
child.stdout!.on('data', (d) => process.stdout.write(d));
child.stderr!.on('data', (d) => process.stderr.write(d));
child.on('close', (code) => console.log('exit:', code));
```

### 2. `spawnSandbox(script, policy, ...)` — convenience

Quick path for **process-isolation only** (`processcontainer` on Windows, `lxc` on Linux, `seatbelt` on macOS). Returns a `node-pty` `IPty` with merged stdout/stderr.

```typescript
import {
  spawnSandbox,
  getAvailableToolsPolicy, getTemporaryFilesPolicy,
} from '@microsoft/mxc-sdk';

const tools = getAvailableToolsPolicy(process.env);
const temp  = getTemporaryFilesPolicy();

const pty = spawnSandbox('python script.py', {
  version: '0.6.0-alpha',
  filesystem: {
    readonlyPaths:  tools.readonlyPaths,
    readwritePaths: temp.readwritePaths,
  },
  timeoutMs: 30_000,
});
pty.onData((d) => process.stdout.write(d));
pty.onExit(({ exitCode }) => console.log('exit:', exitCode));
```

### 3. `spawnSandboxAsync(script, policy, ...)` — promise-style

The `await`-friendly version of `spawnSandbox`. Same arguments, same restriction (process-isolation only), but resolves with `{ stdout, stderr, exitCode }` instead of returning an `IPty`. `stderr` is always `''` because the underlying PTY merges streams.

```typescript
import {
  spawnSandboxAsync,
  getAvailableToolsPolicy, getTemporaryFilesPolicy,
} from '@microsoft/mxc-sdk';

const tools = getAvailableToolsPolicy(process.env);
const temp  = getTemporaryFilesPolicy();

const result = await spawnSandboxAsync(
  'python -c "import sys; print(sys.version)"',
  {
    version: '0.6.0-alpha',
    filesystem: {
      readonlyPaths:  tools.readonlyPaths,
      readwritePaths: temp.readwritePaths,
    },
    timeoutMs: 30_000,
  },
);
console.log(result.stdout);
```

> **Tip:** for agentic workloads, prefer **multiple narrow sandboxes** (one policy per task step) over a single broad policy. Add task-specific paths on top of the discovered base (e.g. a scoped output directory in `readwritePaths`, a project source tree in `readonlyPaths`, secrets in `deniedPaths`).

---

## Choosing a Backend

<details>
<summary>Table of all backends and links to per-backend guides — click to expand.</summary>

`SandboxPolicy` is cross-platform. The backend is selected by the second argument to `createConfigFromPolicy(policy, containment)`. Pass an **abstract intent** (`"process"`, `"vm"`, `"microvm"`) whenever possible — the SDK and native binary resolve it to the right concrete backend for the host. Pass a **concrete backend name** when you need a specific runner.

| Backend | Intent | Platforms | Stable? | Guide |
| --- | --- | --- | --- | --- |
| `processcontainer` | `process` | Windows | ✅ | [`docs/process-container/guide.md`](https://github.com/microsoft/mxc/blob/main/docs/process-container/guide.md) |
| `bubblewrap` | `process` | Linux | ✅ | [`docs/bwrap-support/bubblewrap-backend.md`](https://github.com/microsoft/mxc/blob/main/docs/bwrap-support/bubblewrap-backend.md) |
| `lxc` | (concrete only) | Linux | ✅ | [`docs/lxc-support/lxc-backend.md`](https://github.com/microsoft/mxc/blob/main/docs/lxc-support/lxc-backend.md) |
| `seatbelt` | `process` | macOS | ✅ (schema `0.7.0-alpha`+) | [`docs/macos-support/seatbelt-backend.md`](https://github.com/microsoft/mxc/blob/main/docs/macos-support/seatbelt-backend.md) |
| `windows_sandbox` | `vm` | Windows | Experimental | [`docs/windows-sandbox/windows-sandbox.md`](https://github.com/microsoft/mxc/blob/main/docs/windows-sandbox/windows-sandbox.md) |
| `microvm` | `microvm` | Windows | Experimental | [`docs/nanvix-microvm/nanvix.md`](https://github.com/microsoft/mxc/blob/main/docs/nanvix-microvm/nanvix.md) — MicroVM via NanVix on Windows Hypervisor Platform |
| `wslc` | (concrete only) | Windows | Experimental | [`docs/wsl/wsl-container-getting-started.md`](https://github.com/microsoft/mxc/blob/main/docs/wsl/wsl-container-getting-started.md) |
| `isolation_session` | (concrete only) | Windows | Experimental | [`docs/isolation-session/initial-bringup-plan.md`](https://github.com/microsoft/mxc/blob/main/docs/isolation-session/initial-bringup-plan.md) |

Experimental backends require `{ experimental: true }` in `SandboxSpawnOptions`:

```typescript
const config = createConfigFromPolicy(policy, 'vm'); // → windows_sandbox on Windows
config.process!.commandLine = 'cmd /c whoami';
const pty = spawnSandboxFromConfig(config, { experimental: true });
```

Backend-specific tuning lives on the returned `ContainerConfig`. The full set of fields per backend is in the JSON schemas — they're the source of truth:

- Stable backends: [`schemas/stable/`](https://github.com/microsoft/mxc/tree/main/schemas/stable/)
- Experimental backends: [`schemas/dev/`](https://github.com/microsoft/mxc/tree/main/schemas/dev/)

Open the schema file matching your `policy.version` (e.g. `mxc-config.schema.0.6.0-alpha.json`) and look up `processContainer`, `lxc`, `experimental.wslc`, `experimental.windows_sandbox`, etc.

</details>

## State-Aware Sandboxes

<details>
<summary>Provision once, exec many, tear down (long-lived workflows) — click to expand.</summary>

For long-lived sandboxes where you provision once, exec many times, and tear down at the end (e.g. agentic loops), use the state-aware lifecycle.

> **Backend support:** the state-aware lifecycle is currently only implemented for `isolation_session` (Windows). The one-shot spawn APIs (`spawnSandbox` / `spawnSandboxFromConfig`) are the supported path for every other backend.

```typescript
import {
  provisionSandbox, startSandbox, execInSandboxAsync,
  stopSandbox, deprovisionSandbox,
} from '@microsoft/mxc-sdk';

const { sandboxId } = await provisionSandbox('isolation_session');
await startSandbox(sandboxId);

const r1 = await execInSandboxAsync(sandboxId, { process: { commandLine: 'echo hello' } });
const r2 = await execInSandboxAsync(sandboxId, { process: { commandLine: 'whoami' } });

await stopSandbox(sandboxId);
await deprovisionSandbox(sandboxId);
```

Full design and API: [`docs/state-aware-lifecycle/`](https://github.com/microsoft/mxc/tree/main/docs/state-aware-lifecycle/).

</details>

## Policy Discovery Helpers

<details>
<summary>Auto-enumerate host tools, profile, and temp dirs — click to expand.</summary>

The SDK ships helpers that enumerate the host environment so your policy stays portable:

```typescript
import {
  getAvailableToolsPolicy, getUserProfilePolicy, getTemporaryFilesPolicy,
} from '@microsoft/mxc-sdk';

const tools   = getAvailableToolsPolicy(process.env); // PATH, PYTHONPATH, JAVA_HOME, …
const profile = getUserProfilePolicy();               // %LOCALAPPDATA%\Programs, ~/.local/*
const tmp     = getTemporaryFilesPolicy();            // %TEMP% / $TMPDIR

const policy = {
  version: '0.6.0-alpha',
  filesystem: {
    readonlyPaths: [...tools.readonlyPaths, ...profile.readonlyPaths],
    readwritePaths: tmp.readwritePaths,
  },
  network: { allowOutbound: false },
};
```

Each helper returns `{ readonlyPaths, readwritePaths }` — merge what you want into `SandboxPolicy.filesystem`.

</details>

---

## Common Pitfalls

### UI is blocked by default on 0.5.0+ — some shells need it

The `policy.ui` block is enforced on all supported schema versions, and `policy.ui.allowWindows` defaults to `false`. Most non-interactive command-line tools work fine, but on Windows some shells make win32k system calls during startup and fail without UI access. **All versions of PowerShell are affected** — both Windows PowerShell 5.1 (`powershell.exe`) and PowerShell 7 (`pwsh.exe`). Set `ui.allowWindows: true` when launching a shell:

```typescript
import { spawnSandboxFromConfig, createConfigFromPolicy } from '@microsoft/mxc-sdk';

const config = createConfigFromPolicy({
  version: '0.6.0-alpha',
  ui: { allowWindows: true },     // ← required for powershell.exe to start
});
config.process!.commandLine = 'powershell.exe -NoProfile -Command "Get-Date"';

const child = spawnSandboxFromConfig(config, { usePty: false });
```

### PTY APIs merge stdout and stderr

`spawnSandbox` and `spawnSandboxAsync` use a PTY, so `stderr` is always empty in their result. Use `spawnSandboxFromConfig(config, { usePty: false })` for separated streams.

### `createConfigFromPolicy` leaves `commandLine` empty

You must set `config.process!.commandLine = '…'` before calling `spawnSandboxFromConfig`.

### Default-deny applies to everything

No `network` field → no network. No `readwritePaths` → process can't write `%TEMP%`. No `ui` → no GUI. Use the discovery helpers to compose a sensible baseline.

### `process.cwd` doesn't grant filesystem access

Setting `cwd` (or the `workingDirectory` argument) does **not** add that path to the policy. Add it to `readonlyPaths` / `readwritePaths` explicitly.

---

## Troubleshooting

<details>
<summary>Common errors and what they mean — click to expand.</summary>

| Error | Cause | Fix |
| --- | --- | --- |
| `MXC is not supported on this platform` | `getPlatformSupport()` returned `isSupported: false`. On Linux: neither LXC nor Bubblewrap on PATH. On macOS: schema version < `0.6.0-alpha`. | Install LXC/Bubblewrap, or switch to schema `0.6.0-alpha` (or `0.7.0-alpha` if you need state-aware lifecycle). |
| `wxc-exec.exe not found` / `lxc-exec not found` | The SDK couldn't locate the native binary. | Set `MXC_BIN_DIR=<dir>` so `<dir>/<arch>/wxc-exec.exe` (or `lxc-exec`) exists, or pass `options.executablePath` explicitly. |
| `Invalid containment value '<x>'` | `containment` field doesn't match the parser's accepted values. | Use one of the abstract intents (`process`, `vm`, `microvm`) or a concrete backend listed in [Choosing a Backend](#choosing-a-backend). |
| `'<x>' containment requires experimental mode` | A `windows_sandbox` / `wslc` / `microvm` / `isolation_session` / `hyperlight` backend was selected without the flag. | Pass `{ experimental: true }` in `SandboxSpawnOptions`. |
| `process.commandLine starts with an unquoted Windows path containing a space` | `wxc-exec` rejects unquoted paths with spaces at parse time. | Quote the executable: `'"C:\\Program Files\\…\\foo.exe" args'`. |
| `Experimental_CreateProcessInSandbox failed: WIN32_ERROR(...)` | Native sandbox API returned an OS-level error, e.g. `448` = device feature not supported (Windows build / WIP feature not enabled). Note `120` (call not implemented / BaseContainer disabled) is now handled automatically — the default `process` backend falls back to AppContainer+DACL, so it no longer surfaces here. | Check the Windows build / WIP requirements for the backend you selected. |
| Process exits `-1` / `4294967295` with no stdout | Native binary terminated abnormally. | Re-run with `options.debug: true` (or `options.logDir: '<dir>'`) to capture diagnostic logs. |
| `policy.version '<x>' is older than supported` / `newer than supported` | Version is outside the SDK's accepted range. | Use `0.6.0-alpha`, `0.7.0-alpha`, or `0.8.0-alpha`. See [Compatibility](#compatibility). |

For backend-specific errors, see the per-backend guide linked from the [Choosing a Backend](#choosing-a-backend) table.

</details>

---

## API Surface

<details>
<summary>Every export at a glance — click to expand.</summary>

```typescript
// Spawn — config-based (recommended)
createConfigFromPolicy(policy, containment?, containerName?) → ContainerConfig
spawnSandboxFromConfig(config, options?, workingDirectory?, env?) → IPty | ChildProcess

// Spawn — convenience (process containment only)
spawnSandbox(script, policy, options?, workingDirectory?, containerName?, env?) → IPty
spawnSandboxAsync(script, policy, ...) → Promise<{ stdout, stderr, exitCode }>

// State-aware lifecycle (currently only `isolation_session` on Windows)
provisionSandbox(containment, config?, options?) → Promise<ProvisionResult>
startSandbox(sandboxId, config?, options?)       → Promise<StartResult>
execInSandbox(sandboxId, config, options?)       → IPty             // streaming
execInSandboxAsync(sandboxId, config, options?)  → Promise<ExecResult>
stopSandbox(sandboxId, config?, options?)        → Promise<StopResult>
deprovisionSandbox(sandboxId, config?, options?) → Promise<DeprovisionResult>

// Platform & policy discovery
getPlatformSupport() → PlatformSupport
getAvailableToolsPolicy(env?, options?) → FilesystemPolicyResult
getUserProfilePolicy()                  → FilesystemPolicyResult
getTemporaryFilesPolicy(env?)           → FilesystemPolicyResult

// Capability types
UiCapabilitySupport

// Errors (typed wire-format errors from wxc-exec)
ErrorCode, MxcError, mxcErrorFromCode(code)
```

Full TypeScript definitions ship with the package (`dist/index.d.ts`). All exports are named exports from `@microsoft/mxc-sdk`.

</details>

---

## Further Reading

- [`docs/schema.md`](https://github.com/microsoft/mxc/blob/main/docs/schema.md) — full configuration schema reference
- [`docs/versioning.md`](https://github.com/microsoft/mxc/blob/main/docs/versioning.md) — schema versioning model and experimental-feature lifecycle
- [`docs/examples.md`](https://github.com/microsoft/mxc/blob/main/docs/examples.md) — annotated configuration examples
- [`docs/sandbox-policy/v1/policy.md`](https://github.com/microsoft/mxc/blob/main/docs/sandbox-policy/v1/policy.md) — policy specification
- Backend-specific guides linked in the [Choosing a Backend](#choosing-a-backend) section above.

---

## License

[MIT](https://github.com/microsoft/mxc/blob/main/sdk/LICENSE.md). Contributions welcome — see the main [MXC repository](https://github.com/microsoft/mxc).
