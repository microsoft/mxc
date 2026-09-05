# WSLC Getting Started — Running Linux Containers from Windows via MXC

This guide walks you through setting up the WSL Container (WSLC) backend for
MXC, which lets you run Linux containers on Windows using the WSLC SDK.

> **Note:** WSLC is an **experimental** feature. It requires the `--experimental`
> CLI flag, `{ experimental: true }` in TypeScript SDK spawn options, or
> `SandboxRequest::set_experimental(true)` in the Rust SDK.

## Prerequisites

| Requirement | Details |
|---|---|
| **Windows 11** | Required for WSL2 and the WSLC SDK |
| **WSL 2.9.9+** | The installed WSL runtime package must meet the WSLC minimum; see Step 1 below for installation |
| **WSLC SDK** | `wslcsdk.dll` is a separate client SDK and must be in the same directory as the running executable (`wxc-exec.exe`, or your own binary when using the Rust SDK) |
| **Container images** | Pre-pulled or available from a registry with network access |

## Step 1 — Install WSL 2.9.9+

The WSLC SDK requires WSL version 2.9.9 or later. Update WSL to the latest
version. Note that 2.9.9 may only be available on the pre-release channel
until it reaches the default Store channel, so include `--pre-release`:

```powershell
wsl --update --pre-release
```

Verify your WSL version after updating:

```powershell
wsl --version
```

The WSL version should be **2.9.9.0 or later**. If `wsl --update --pre-release`
does not bring you to the required version, build WSL from the `master`
branch:

```powershell
git clone https://github.com/microsoft/WSL.git
cd WSL
git checkout master
```

Follow the build instructions in the WSL repository README to build and install.

> **Note:** Building the WSL repo installs the **WSL runtime** (the system
> service). This is separate from `wslcsdk.dll`, which is the client SDK
> library. The DLL is bundled in the MXC repo under `external/wslc-sdk/` and
> is automatically extracted when you build MXC with `--with-wslc` (Step 2).

## Step 2 — Build MXC with WSLC support

Build `wxc-exec.exe` with the `wslc` feature flag. This compiles the WSLC
backend and copies `wslcsdk.dll` next to the binary:

```powershell
cd <repo-root>
.\build.bat --with-wslc
```

Verify the binary starts without errors:

```powershell
.\src\target\x86_64-pc-windows-msvc\release\wxc-exec.exe --help
```

> **Note:** `wxc-exec.exe` does **not** require `wslcsdk.dll` at startup. The
> DLL is loaded at runtime only when the WSLC backend is invoked. All other
> backends (Process Container, Windows Sandbox) work without it.

## Step 3 — Pre-pull container images

MXC is an execution layer and does **not** pull container images at run
time. Pre-pull each image you intend to use into the WSLC SDK cache
before invoking a config that references it:

```powershell
cd <repo-root>
.\scripts\setup-wslc.ps1 -Image alpine:latest, python:3.12-alpine
```

Or pull a single image directly:

```powershell
.\src\target\x86_64-pc-windows-msvc\release\wxc-exec.exe `
    --setup-wslc --image alpine:latest
```

Pulled images persist in the cache until you remove them — pay the
cost once per image, not once per run.

> **Storage path consistency:** the cache lives under the WSLC
> `storage_path` (default `%TEMP%\mxc-wslc-sessions`). If your runtime
> configs override `experimental.wslc.storagePath`, pass the same
> value here with `-StoragePath` (or `--storage-path` on
> `wxc-exec.exe`), otherwise the runner will not find what you just
> pulled.

If you forget this step, the next `wxc-exec.exe` invocation will fail
fast with an actionable error pointing back at the `--setup-wslc`
command — your image name pre-filled — so the first-time stumble is
self-correcting.

## Step 4 — Verify WSLC is working

Run the included hello world example config from the repo root:

```powershell
cd <repo-root>
.\src\target\x86_64-pc-windows-msvc\release\wxc-exec.exe --experimental --debug examples\wslc_hello_world.json
```

Expected output:

```
Hello from WSL Container!
Linux <hostname> 6.6.x-microsoft-standard-WSL2 ... x86_64 Linux
```

## Two-step lifecycle

Once setup is done, the day-to-day flow is two distinct commands:

```powershell
# (one-time per image) pre-pull into the SDK cache
.\scripts\setup-wslc.ps1 -Image <image>

# (any number of times) execute against the cached image
.\src\target\x86_64-pc-windows-msvc\release\wxc-exec.exe `
    --experimental my-config.json
```

This separation keeps `wxc-exec.exe` hermetic and fast at run time —
the runner never reaches for the network, never blocks on a pull, and
its failure modes are decoupled from registry availability.

## Usage

### TypeScript SDK

Use `createConfigFromPolicy()` to build a config, then customize WSLC-specific
fields before spawning:

```typescript
import { createConfigFromPolicy, spawnSandboxFromConfig } from '@microsoft/mxc-sdk';

const policy = {
  version: '0.6.0-alpha',
  network: { allowOutbound: true },
};

const config = createConfigFromPolicy(policy, 'wslc');
config.process!.commandLine = 'python3 -c "print(\'Hello from WSLC\')"';
config.experimental!.wslc!.image = 'python:3.12-alpine';
config.experimental!.wslc!.cpuCount = 2;
config.experimental!.wslc!.memoryMb = 1024;

// PTY mode (interactive terminal):
const ptyProcess = spawnSandboxFromConfig(config, { experimental: true });

// Non-PTY mode (reliable exit codes, separate stdout/stderr):
const child = spawnSandboxFromConfig(config, { experimental: true, usePty: false });
child.stdout?.on('data', (data) => console.log(data.toString()));
child.on('close', (code) => console.log('Exit code:', code));
```

### Rust SDK

The Rust SDK (`mxc-sdk`) runs WSLC **in-process** — it does not spawn
`wxc-exec.exe`. Build the crate with its `wslc` feature, select the backend with
`build_request_with_containment`, and opt into experimental features on the
request (the library-side equivalent of `--experimental`):

```toml
# Cargo.toml
[target.'cfg(target_os = "windows")'.dependencies]
mxc-sdk = { path = "…/src/core/mxc-sdk", features = ["wslc"] }
```

```rust
use mxc_sdk::{
    build_request_with_containment, run, spawn_sandbox, Containment, SandboxPolicy, WslcSection,
};

let policy = SandboxPolicy {
    version: "0.7.0-alpha".to_string(),
    filesystem: None,
    network: None,
    ui: None,
    timeout_ms: None,
};

let wslc = WslcSection {
    image: "python:3.12-alpine".to_string(),
    cpu_count: Some(2),
    memory_mb: Some(1024),
    ..Default::default()
};

let mut request = build_request_with_containment(&policy, &Containment::Wslc(wslc), "python3 -c \"print('Hello from WSLC')\"", None)?;
request
    .set_experimental(true);

// Run to completion, capturing output…
let output = run(request.clone())?;
println!("{}", String::from_utf8_lossy(&output.stdout));

// …or stream it live (read stdout/stderr while it runs, kill it, wait).
let mut sandbox = spawn_sandbox(request)?;
let stdout = sandbox.take_stdout().expect("stdout");
```

`WslcSection` mirrors the `experimental.wslc` block below;
`WslcSection::default()` matches the SDK default (`alpine:latest`). Settings go
through the same parser the executor uses, so a rejected value (e.g. a port
mapping with a zero or duplicated host port) fails at
`build_request_with_containment` rather than at spawn.

Notes and limits:

- **Windows only.** Selecting `Containment::Wslc` on Linux/macOS, or without the
  `wslc` feature, fails with `ErrorCode::UnsupportedContainment`.
- **No stdin.** The WSLC SDK exposes no process-input API, so
  `Sandbox::take_stdin()` returns `None` for a WSL container.
- **No host pid.** The process runs inside the WSL VM, so `Sandbox::id()` is `0`;
  use `kill()` (which stops the container and everything in it) to terminate it.
- **Discovery.** `platform_support()` lists `"wslc"` in `available_methods` only
  when this host can actually run it (`wslcsdk.dll` loads and the WSLC runtime
  reports no missing components).

## Configuration Reference

### JSON config

WSLC-specific settings go under `experimental.wslc` in the JSON config:

| Field | Type | Default | Description |
|---|---|---|---|
| `image` | string | `"alpine:latest"` | Container image (DockerHub, GHCR, MCR, etc.) |
| `cpuCount` | number | Host default | Number of CPU cores for the container |
| `memoryMb` | number | Host default | Memory limit in MB |
| `gpu` | boolean | `false` | Enable GPU passthrough |
| `storagePath` | string | System default | Host path for container storage (VHD) |
| `imageTarPath` | string | — | Path to a local tar file to import as the image |

### Image sources

> **All three sources require pre-pulling/importing before the runner
> can use them.** The runner only checks the local cache; see
> [Step 3](#step-3--pre-pull-container-images) for the setup commands.

**1. Pre-pulled from DockerHub (default registry):**

```powershell
.\scripts\setup-wslc.ps1 -Image alpine:latest
```

```json
"experimental": { "wslc": { "image": "alpine:latest" } }
```

**2. Pre-pulled from a custom registry (no auth):**

```powershell
.\scripts\setup-wslc.ps1 -Image ghcr.io/linuxserver/baseimage-alpine:3.21
```

```json
"experimental": { "wslc": { "image": "ghcr.io/linuxserver/baseimage-alpine:3.21" } }
```

Tested registries: DockerHub, `mcr.microsoft.com`, `ghcr.io`, `quay.io`.

**3. Import from a local tar file (no pre-pull needed):**

```json
"experimental": {
  "wslc": {
    "image": "my-image:latest",
    "imageTarPath": "C:\\path\\to\\image.tar"
  }
}
```

Both `docker export` (rootfs) and `docker save` (image archive) formats are
supported — the format is auto-detected. Tar import happens on first use;
no separate `--setup-wslc` step is required.

### Network configuration

| Policy | WSLC Behavior |
|---|---|
| `"allowOutbound": true` | Bridged networking (full access) |
| `"allowOutbound": false` | No networking (isolated) |

> **`allowedHosts` / `blockedHosts` do not work on WSLC today.** They are
> accepted by the config builders (for parity across the SDKs), but the backend
> enforces them with in-container `iptables`, and the container is not granted
> `CAP_NET_ADMIN` — so the rules cannot be installed and the run **fails at
> spawn** rather than silently going unenforced. Express WSLC network intent
> with `allowOutbound` until enforcement moves to a VM-level network policy API.

### Network proxy (cooperative, unprivileged)

WSLC supports a **cooperative HTTP/HTTPS proxy**: setting `network.proxy`
routes a container's egress through a proxy you provide. WSLC cannot apply an
`iptables` drop-floor — the container has no `CAP_NET_ADMIN` and MXC has no
VM-level enforcement hook — so, exactly like the Bubblewrap backend,
enforcement is *cooperative*, applied by handing the workload proxy environment
variables that well-behaved clients honor.

**How it works**

1. When `network.proxy` is set, the runner translates it into the
   `HTTP_PROXY`, `HTTPS_PROXY`, `http_proxy`, and `https_proxy` environment
   variables inside the container (via `WslcSetProcessSettingsEnvVariables`).
   Any caller-supplied values for these keys — including `NO_PROXY` /
   `no_proxy` — are **stripped** from the *initial* process environment first.
   Because WSLC merges the process environment onto the image's baked-in
   `ENV`, the runner also sets `NO_PROXY` / `no_proxy` to the **empty string**,
   so an image-baked exemption (e.g. `ENV NO_PROXY=*`) cannot silently disable
   the proxy. This sanitizes the process's *starting* environment only; see the
   cooperative-model caveat below.
2. Cooperative tools (curl, wget, Python `requests`, Node `https`, etc.) honor
   the env vars and their traffic flows through the proxy.

**Only the `url` form is supported.** A WSLC container runs in its own network
namespace (a separate WSL system VM), so a host- or distro-loopback proxy is
**not reachable** from inside the container. The proxy must be a routable
address the container can reach:

```json
{
  "version": "0.6.0-alpha",
  "containment": "wslc",
  "process": { "commandLine": "curl -fsSL https://example.com && echo OK" },
  "network": {
    "defaultPolicy": "allow",
    "proxy": { "url": "http://proxy.example:8080" }
  },
  "experimental": { "wslc": { "image": "alpine:latest" } }
}
```

The `localhost` and `builtinTestServer` proxy forms are **rejected at
config-parse time** for WSLC (they imply a host-loopback / MXC-run proxy that
the container cannot reach). The proxy also requires `defaultPolicy: "allow"`
and no `allowedHosts` / `blockedHosts`: the container must have outbound
networking to reach the proxy, and host lists are not forwarded to it — configs
that combine the proxy with a `block` default or host lists are **rejected**.

### Per-host filtering is not supported

WSLC **cannot** enforce per-host egress filtering. `allowedHosts` with
`defaultPolicy: "block"` (an allowlist) or `blockedHosts` with
`defaultPolicy: "allow"` (a blocklist) would require in-container `iptables`
rules, but a WSLC container runs **without** `CAP_NET_ADMIN` (the SDK's
`Privileged` flag does not grant it), so those rules cannot be applied — and MXC
has no VM-level enforcement hook either (WSLC cannot expose one without breaking
other security promises such as MDE). Rather than fail the run at exec time,
such configs are **rejected at config-parse time**:

```
WSLc: per-host egress filtering (allowedHosts with defaultPolicy='block', or
blockedHosts with defaultPolicy='allow') is not supported. ...
```

Use `network.proxy` (with `defaultPolicy: "allow"`) for cooperative host
filtering at the proxy layer, or remove the host lists. The bare
`defaultPolicy` forms with **no** host lists remain supported: `"block"` is a
full network cutoff and `"allow"` is full outbound (NAT).

### `enforcementMode` must be `capabilities`

`network.enforcementMode: "firewall"` (or `"both"`) is **rejected** for the same
reason as per-host filtering: both ask for per-rule firewall enforcement inside a
container that has no `CAP_NET_ADMIN` to apply it with. The default
`"capabilities"` is accepted — it is an honest description of WSLC's
all-or-nothing network, so an explicitly supplied `"capabilities"` is accepted
rather than refused merely for being present.

### Inbound: `allowLocalNetwork` is not supported

`network.allowLocalNetwork: true` (a blanket grant to bind/listen and accept
inbound connections) is **rejected at config-parse time** for WSLC. A WSLC
container runs in the NAT'd WSL2 VM and MXC does not honor a blanket
inbound-listen grant — only explicit host→container forwards via
`experimental.wslc` `portMappings` have any inbound effect, so accepting the
flag would silently promise reachability the backend never delivers. Expose
specific ports with `portMappings` instead. (`allowLocalNetwork: false`, the
default, is a no-op and is accepted.)

**Caveats**

- **Cooperative model, not enforcement.** Only clients that honor the proxy
  env vars are routed through the proxy. Tools that bypass them (raw sockets,
  custom HTTP clients, statically-linked binaries that ignore the env) are
  **not** contained. WSLC cannot provide a hard network floor — the container
  has no `CAP_NET_ADMIN` and MXC has no VM-level enforcement hook. For strict
  network isolation, use `"allowOutbound": false` (no networking) instead.
- **Consumer-provided proxy.** MXC does not start a proxy for WSLC; you supply
  a reachable one via `url`. Any host filtering is the proxy's responsibility —
  the runner does not forward `allowedHosts` / `blockedHosts` to it.

### Filesystem mounts

Paths in `filesystem.readwritePaths` and `filesystem.readonlyPaths` are mounted
into the container. Host path `C:\workspace` becomes `/mnt/c/workspace` inside
the container.

### `ui` is not supported

A `ui` section is **rejected** — the backend has no mechanism to enforce UI
restrictions on a container.

The check is on **presence, not value**. `ui`'s defaults are full lockdown, so
an explicitly supplied lockdown `ui` is indistinguishable *by value* from an
absent one — a value-based check would let the single most restrictive request
you can write through unenforced. Omit the section entirely.

### `lifecycle`: only `destroyOnExit: true` is supported

`lifecycle.destroyOnExit: true` (the default) is honored: it selects the SDK's
`WSLC_CONTAINER_FLAG_AUTO_REMOVE`, and teardown stops and deletes the container.

`lifecycle.destroyOnExit: false` is **rejected**. It asks for the container to
outlive the run, which a one-shot invocation cannot deliver: the container is
scoped to a session this process owns, terminating that session at the end of
the run reaps the container regardless of the AutoRemove flag, and the WSLC SDK
has no cross-process re-attach. Use the state-aware lifecycle if you need a
container to persist — its daemon holds the session open across phase processes.

`lifecycle.preservePolicy: true` is **rejected** — WSLC has no
policy-persistence primitive, so there is nothing for the flag to select.

Note the state-aware surface differs: it rejects the whole `lifecycle` section
at parse time, because a multi-invocation sandbox's lifetime is driven by the
explicit `provision` / `deprovision` phases rather than by per-run flags.

## Troubleshooting

| Error | Cause | Fix |
|---|---|---|
| `WSLC backend not compiled` | Binary built without `--features wslc` | Rebuild with `build.bat --with-wslc` |
| `Failed to load wslcsdk.dll` | DLL not in same directory as `wxc-exec.exe` | Copy `wslcsdk.dll` next to the binary |
| `WSLC runtime unavailable` | WSL runtime package is missing, older than 2.9.9, or the Virtual Machine Platform optional component is disabled | Update WSL with `wsl --update --pre-release`, verify the installed version with `wsl --version`, and enable the Virtual Machine Platform optional component if required. The WSLC SDK DLL is a separate dependency and does not replace the WSL runtime package. |
| `WSLC runtime unavailable. Missing components: SdkNeedsUpdate` | The opposite direction: your installed WSL is **newer** than the WSLc SDK this MXC build ships (pinned by `WSLC_SDK_VERSION` in `src/backends/wslc/common/build.rs`) | Update MXC to a build with a newer pinned SDK. Do **not** update WSL — it is already ahead, and updating it further will not clear this. |
| `WSLC image '<name>' not found locally` | Image was not pre-pulled, and no `imageTarPath` is set | Run `.\scripts\setup-wslc.ps1 -Image <name>` (or `wxc-exec.exe --setup-wslc --image <name>`); match the `-StoragePath` to your config's `experimental.wslc.storagePath` if set |
| `WSLC is an experimental feature` | Missing `--experimental` flag | Add `--experimental` to CLI or `{ experimental: true }` in SDK |
| `experimental mode` error in SDK | `SandboxSpawnOptions.experimental` not set | Pass `{ experimental: true }` to spawn functions |
| Container exits with code -1 | Process failed or timed out | Check stderr output with `--debug` flag |

## Example Configs

- [`tests/examples/wslc_hello_world.json`](../../tests/examples/wslc_hello_world.json) — Hello world with Alpine
- [`tests/configs/wslc_network_isolated.json`](../../tests/configs/wslc_network_isolated.json) — Network isolation
- [`tests/configs/wslc_network_proxy.json`](../../tests/configs/wslc_network_proxy.json) — Cooperative HTTP proxy (`network.proxy.url`)
- [`tests/configs/wslc_custom_registry_ghcr.json`](../../tests/configs/wslc_custom_registry_ghcr.json) — Pull from GitHub Container Registry
- [`tests/configs/wslc_custom_registry_quay.json`](../../tests/configs/wslc_custom_registry_quay.json) — Pull from Quay.io
- [`tests/configs/wslc_tar_import_rootfs.json`](../../tests/configs/wslc_tar_import_rootfs.json) — Import rootfs tar
- [`tests/configs/wslc_tar_import_docker_save.json`](../../tests/configs/wslc_tar_import_docker_save.json) — Import Docker save archive
- [`tests/configs/wslc_timeout.json`](../../tests/configs/wslc_timeout.json) — Execution timeout enforcement

## Maintaining the SDK bindings

The WSLC SDK FFI bindings (`wslcsdk_sys.rs`) are **generated by bindgen** from
the SDK header and committed to the repo. For how they work and the exact
procedure to follow on every SDK version bump, see
[`wslc-sdk-bindings.md`](./wslc-sdk-bindings.md).
