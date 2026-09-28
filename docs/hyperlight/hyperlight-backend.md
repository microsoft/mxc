# Hyperlight Backend

Runs source for a guest runtime inside a [Hyperlight](https://github.com/hyperlight-dev/hyperlight)
micro-VM booting a [Unikraft](https://unikraft.org/) unikernel, driven
in-process by the [`hyperlight-unikraft`](https://github.com/hyperlight-dev/hyperlight-unikraft)
crate. One code path serves Linux (KVM) and Windows (WHP).

## At a glance

| | |
|---|---|
| **Binary** | `lxc-exec` (Linux), `wxc-exec.exe` (Windows) |
| **Config value** | `"containment": "hyperlight"` |
| **Schema** | `0.10.0-alpha`, with `--experimental` |
| **Requires** | x86_64; `/dev/kvm` readable and writable, or WHP enabled; a build with `--with-hyperlight` |
| **Isolation** | Hardware virtualization; the guest is a unikernel with its own filesystem |
| **Guest** | One of the runtimes below, restored from a warm snapshot on every run |

## Quick start

```sh
./build.sh --with-hyperlight        # Linux; build.bat --with-hyperlight on Windows
lxc-exec --setup-hyperlight               # once per machine: installs the default runtime
lxc-exec --setup-hyperlight=python,node   # installs others; any of the names below
```

```json
{
    "version": "0.10.0-alpha",
    "process": {
        "commandLine": "import pandas as pd\nprint(pd.DataFrame({'x': [1, 2]}).sum().to_dict())",
        "timeout": 30000
    },
    "containment": "hyperlight"
}
```

```sh
lxc-exec --experimental pandas.json
```

`commandLine` is source for the guest runtime, passed to it as is, and the
guest's output goes straight to the process's stdout. The runtime is
`agent` unless the request names another:

```json
{
    "version": "0.10.0-alpha",
    "process": { "commandLine": "console.log(`hello from node ${process.version}`)" },
    "containment": "hyperlight",
    "hyperlight": { "runtime": "node" }
}
```

## Guest runtimes

Each runtime is one of hyperlight-unikraft's published images, named as
upstream names it. All take source through a driver that is parked warm
in the snapshot, and all return the script's exit status.

| `runtime` | Guest | Scratch |
|---|---|---|
| `agent` (default) | CPython 3.12 with numpy, pandas, scipy, scikit-learn, matplotlib and Pillow imported; pydantic, PyYAML, Jinja2, BeautifulSoup, lxml, cryptography, requests, httpx and pip present | 1536 MiB |
| `python` | CPython 3.12 | 256 MiB |
| `python-shell` | CPython 3.12 with a BusyBox shell | 256 MiB |
| `node` | Node.js 22 | 512 MiB |
| `bash` | A BusyBox POSIX shell, under the name upstream gives the image | 256 MiB |
| `dotnet-jit` | .NET with the JIT | 768 MiB |

`subprocess` and `fs`-style access to mounts work in every guest. The
compiled images upstream also publishes (C, Go, Rust, .NET AOT) run a
program baked into the rootfs rather than source, so they are not
selectable here.

## The image home

Setup fills one directory per runtime under the image home, each with
three things:

| Entry | Purpose |
|---|---|
| `initrd.cpio` | The guest rootfs, pulled from `ghcr.io/hyperlight-dev/hyperlight-unikraft/<runtime>` at the release the crate is pinned to |
| `snapshot/` | The guest, booted once and captured with the runtime warm; every run restores it |
| `VERSION` | The rootfs release the directory holds |

The kernel is embedded in the crate, so nothing else is downloaded. The
pull talks to the registry directly; no container runtime is involved.

The runner looks for a home in this order and takes the first whose
runtime directory holds a snapshot this build loads, or a rootfs of this
release to warm one from:

1. `$MXC_HYPERLIGHT_HOME`
2. `~/.local/share/mxc-hyperlight/` on Linux, `%LOCALAPPDATA%\mxc-hyperlight\` on Windows
3. `<exe dir>/mxc-hyperlight/`
4. `<cwd>/.mxc-hyperlight/`

Setup writes to the first or second of these. The rootfs is needed only
to warm, so a directory trimmed to just its snapshot still runs.

A snapshot loads only under the build that saved it (the crate keys it by
its kernel and host contract), and a rootfs only boots on its own
release's kernel. After a crate upgrade, `--setup-hyperlight` rebuilds a
runtime directory from another release, and a run warms a fresh snapshot
by itself when only the snapshot is stale. `--force` rewarms one that is
already current, for example after dropping in a rootfs of your own.

## How a run works

Every request restores the warm snapshot with its own mounts, so
consecutive runs are hermetic. A runner reused within one process rewinds
to the snapshot between calls.

| Aspect | Behaviour |
|---|---|
| Exit code | The script's: `sys.exit(N)`, `process.exit(N)` or `exit N` gives `N`, an uncaught exception gives `1`, a runner error gives `-1` with the reason in `error_message` |
| Timeout | `process.timeout` bounds the run; a guest that overruns is interrupted and the run reports `execution timed out` |
| stdout / stderr | Inherited by the guest; `ScriptResponse.standard_out` stays empty, so capture at the process level |

## Configuration

| Field | Behaviour |
|---|---|
| `process.commandLine` | Source for the guest runtime |
| `hyperlight.runtime` | A name from the table above; `agent` when omitted |
| `process.timeout` | Run timeout in milliseconds |
| `filesystem.readwritePaths` | Each directory appears in the guest at `/host/<basename>` |
| `filesystem.readonlyPaths` | The same, mounted read-only; the guest kernel and the host both enforce it |
| `filesystem.deniedPaths` | Checked at preflight against the two lists above |
| `network` | Rejected at preflight in this release: the guest runs without networking. The backend's host-proxied sockets take a host allow or block list; wiring the `0.10.0-alpha` egress model onto them is the next step |
| `workingDirectory` | Rejected at preflight; the guest has its own filesystem |

Mount directories are created when their parent exists. A basename may not
contain whitespace, `:` or brackets, and two mounts may not share one.

## Design notes

- **In process.** Hyperlight is a Rust library and the executors are Rust
  binaries, so the backend links it and boots the VM in the executor's own
  process.
- **A containment value of its own.** The backend needs a warmed snapshot
  in place before the first run, executes source rather than a command
  line, and forwards host directories to the guest live, so it is
  selected explicitly rather than resolved from `vm` or `microvm`.
- **One directory per runtime.** A runtime is a rootfs, a scratch size
  and a snapshot; the runner keys a booted guest on its directory, so
  runtimes install, upgrade and run independently.
- **Images come from upstream.** The rootfs is built and published by
  hyperlight-unikraft's pipeline, and the kernel ships inside the crate.
  Adding a package to a guest is a change to the image there.
- **Experimental.** The backend sits behind `--experimental`; its own
  settings live in the `hyperlight` section of the development contract.

## Troubleshooting

| Message | Meaning |
|---|---|
| `no hyperlight image found for the <runtime> runtime` | No home holds that runtime; run `--setup-hyperlight=<runtime>`, or set `MXC_HYPERLIGHT_HOME` |
| `holds a rootfs from another hyperlight-unikraft release` | The directory predates the crate the binary was built with; `--setup-hyperlight=<runtime>` rebuilds it |
| `Hyperlight requires KVM` / `Hyperlight requires Windows Hypervisor Platform` | No hypervisor for this process (error code `backend_unavailable`): on Linux `/dev/kvm` is missing or not readable and writable, on Windows WHP is not enabled |
| `execution timed out after N s` | The script overran `process.timeout` |

Run with `--debug` to see the home chosen, restore and call timings, and
the reason behind any runner error.
