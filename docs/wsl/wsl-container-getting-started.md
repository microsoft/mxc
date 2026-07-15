# WSLC Getting Started — Running Linux Containers from Windows via MXC

This guide walks you through setting up the WSL Container (WSLC) backend for
MXC, which lets you run Linux containers on Windows using the WSLC SDK.

> **Note:** WSLC is an **experimental** feature. It requires the `--experimental`
> CLI flag or `{ experimental: true }` in SDK spawn options.

## Prerequisites

| Requirement | Details |
|---|---|
| **Windows 11** | Required for WSL2 and the WSLC SDK |
| **WSL 2.8.1+** | See Step 1 below for installation |
| **WSLC SDK** | `wslcsdk.dll` must be in the same directory as `wxc-exec.exe` |
| **Container images** | Pre-pulled or available from a registry with network access |

## Step 1 — Install WSL 2.8.1+

The WSLC SDK requires WSL version 2.8.1 or later. Update WSL to the latest
version:

```powershell
wsl --update
```

Verify your WSL version after updating:

```powershell
wsl --version
```

The WSL version should be **2.8.1.0 or later**. If `wsl --update` does not
bring you to the required version, build WSL from the `master`
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

## Configuration Reference

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

### Filesystem mounts

Paths in `filesystem.readwritePaths` and `filesystem.readonlyPaths` are mounted
into the container. Host path `C:\workspace` becomes `/mnt/c/workspace` inside
the container.

## Troubleshooting

| Error | Cause | Fix |
|---|---|---|
| `WSLC backend not compiled` | Binary built without `--features wslc` | Rebuild with `build.bat --with-wslc` |
| `Failed to load wslcsdk.dll` | DLL not in same directory as `wxc-exec.exe` | Copy `wslcsdk.dll` next to the binary |
| `WSLC runtime not available` | WSL version too old or missing components | Update WSL with `wsl --update` or build from the [WSL repo](https://github.com/microsoft/WSL/tree/feature/wsl-for-apps) |
| `WSLC image '<name>' not found locally` | Image was not pre-pulled, and no `imageTarPath` is set | Run `.\scripts\setup-wslc.ps1 -Image <name>` (or `wxc-exec.exe --setup-wslc --image <name>`); match the `-StoragePath` to your config's `experimental.wslc.storagePath` if set |
| `WSLC is an experimental feature` | Missing `--experimental` flag | Add `--experimental` to CLI or `{ experimental: true }` in SDK |
| `experimental mode` error in SDK | `SandboxSpawnOptions.experimental` not set | Pass `{ experimental: true }` to spawn functions |
| Container exits with code -1 | Process failed or timed out | Check stderr output with `--debug` flag |

## Example Configs

- [`tests/examples/wslc_hello_world.json`](../../tests/examples/wslc_hello_world.json) — Hello world with Alpine
- [`tests/configs/wslc_network_isolated.json`](../../tests/configs/wslc_network_isolated.json) — Network isolation
- [`tests/configs/wslc_custom_registry_ghcr.json`](../../tests/configs/wslc_custom_registry_ghcr.json) — Pull from GitHub Container Registry
- [`tests/configs/wslc_custom_registry_quay.json`](../../tests/configs/wslc_custom_registry_quay.json) — Pull from Quay.io
- [`tests/configs/wslc_tar_import_rootfs.json`](../../tests/configs/wslc_tar_import_rootfs.json) — Import rootfs tar
- [`tests/configs/wslc_tar_import_docker_save.json`](../../tests/configs/wslc_tar_import_docker_save.json) — Import Docker save archive
- [`tests/configs/wslc_timeout.json`](../../tests/configs/wslc_timeout.json) — Execution timeout enforcement
