# Kata Containers Backend

> **Audience:** MXC consumers and developers

Runs a command in a [Kata Containers](https://katacontainers.io/) microVM.
MXC starts the Kata shim, `containerd-shim-kata-v2`, and drives it directly
over its ttrpc interface (the containerd shim v2 Task API). It needs no
containerd daemon, Kubernetes, or CRI.

> **Status:** Experimental. Linux only. Available in the `1.1.0-alpha`
> development contract and requires `--experimental` (or the SDK's experimental
> opt-in for raw JSON requests).

## At a glance

| | |
|---|---|
| **Binary** | `lxc-exec` for create-and-run execution. Streaming and container lifecycle operations go through the native library's exact JSON entry points (`mxc_spawn_json`, `mxc_run_state_aware_json`, `mxc_exec_state_aware_json`). |
| **Config value** | `"containment": "kata"` with a `kata` section |
| **Schema** | `1.1.0-alpha`, with `--experimental` |
| **Requires** | Root, `/dev/kvm` readable and writable, a Kata Containers install that provides the `runtime-rs` shim, and a root filesystem (below) |
| **Tested with** | Kata Containers 4.3.1 (static release, `runtime-rs`) on Linux x86-64 |
| **Hypervisors** | `qemu`, `clh` (Cloud Hypervisor), `firecracker`, `dragonball` |
| **Isolation** | Hardware virtualization. Each sandbox is its own VM with its own kernel. |
| **Network** | No network interface in the VM. Only a deny-all policy can be enforced. |

## Quick start

1. Install Kata Containers with the `runtime-rs` shim and make `/dev/kvm`
   available. The static release tarball unpacks to `/opt/kata`.
2. Provide a root filesystem, for example Alpine:

   ```sh
   mkdir rootfs
   podman export "$(podman create docker.io/library/alpine:latest true)" | sudo tar -x -C rootfs
   ```

3. Run a command:

   ```json
   {
       "version": "1.1.0-alpha",
       "containment": "kata",
       "kata": { "rootfs": "/srv/rootfs", "hypervisor": "qemu" },
       "process": { "commandLine": "uname -r" }
   }
   ```

   ```sh
   sudo MXC_KATA_ROOT=/opt/kata lxc-exec --experimental config.json
   ```

   The command prints the guest kernel's release, not the host's. A start takes
   about 7 seconds: the VM boots, the command runs, and the VM is removed.

## Locating Kata

The library does not assume where Kata is installed. The host names it with
environment variables:

| Variable | Meaning |
|---|---|
| `MXC_KATA_ROOT` | Install prefix. The shim is `<root>/runtime-rs/bin/containerd-shim-kata-v2` (or `<root>/bin/...`), and configuration files are in `<root>/share/defaults/kata-containers/runtime-rs`. Without it, the shim is looked up on `PATH` and configuration files in `/usr/share/defaults/kata-containers/runtime-rs`. |
| `MXC_KATA_HYPERVISOR` | Hypervisor to use when the request names none. Default `qemu`. |
| `MXC_KATA_CONFIG_QEMU`, `MXC_KATA_CONFIG_CLH`, `MXC_KATA_CONFIG_FIRECRACKER`, `MXC_KATA_CONFIG_DRAGONBALL` | A Kata configuration file to use for that hypervisor instead of the shipped one. |
| `MXC_KATA_STATE_DIR` | Directory for sandbox state. Default `/run/mxc-kata`. |

A request cannot name a configuration file or an install path, so a caller of
MXC cannot choose which binary runs as root.

The hypervisor is selected by passing the configuration file to the shim in the
runtime options of its create request. `KATA_CONF_FILE` is not used.

> **Firecracker configuration.** The `configuration-rs-fc.toml` shipped with
> Kata 4.3.1 fails the shim's validation: its `dial_timeout_ms` (45000) is larger
> than the default reconnect timeout (3000). Copy the file, set
> `dial_timeout_ms = 100` (the tests do), and point `MXC_KATA_CONFIG_FIRECRACKER`
> at the copy.

## The `kata` section

| Field | Type | Meaning |
|---|---|---|
| `rootfs` | string, required | Absolute host path of the guest root filesystem: a directory, or an ext4 image file |
| `hypervisor` | string, optional | `qemu`, `clh` (also spelled `cloud-hypervisor`), `firecracker`, or `dragonball`. Defaults to `MXC_KATA_HYPERVISOR`, then `qemu`. |

The VM's CPU count and memory come from the Kata configuration file.
`containerId` is a label; the backend names its sandboxes itself.

## Root filesystem

MXC never writes to the root filesystem you name. Each sandbox gets its own
writable layer, which is discarded when the sandbox is deprovisioned.

| `rootfs` is | How the guest sees it | Writes |
|---|---|---|
| A directory | Read-only lower layer of an overlay, shared into the VM | Go to a tmpfs capped at 512 MiB of host memory |
| An ext4 image | A copy of the image, attached as a block device | Go to the copy; its size is the limit |

The directory form needs a hypervisor that shares directories (`qemu`, `clh`,
`dragonball`). Firecracker has no shared filesystem, so with `firecracker` the
rootfs must be an ext4 image; a directory is rejected with the command to build
one:

```sh
mke2fs -t ext4 -d rootfs rootfs.ext4 256M
```

The image is attached to a loop device that the kernel releases when the VM
exits. The root filesystem needs `/bin/sh`: commands run as `/bin/sh -c`.

## Policy

Anything the backend cannot enforce is rejected before a VM exists.

### Filesystem

`readwritePaths` and `readonlyPaths` bind the host path into the guest at the
same path. `deniedPaths` hide a path: a denied directory is replaced by an empty
directory and a denied file reads as empty. The denial wins over a grant for a
path inside it, and the most specific entry wins, as for the other Linux
backends.

Firecracker cannot share host directories. With `firecracker`, requests with
`readwritePaths` or `readonlyPaths` are rejected. `deniedPaths` still apply to
paths inside the guest's own root filesystem.

A denied entry's name can still appear in its parent's listing; its contents
cannot be read.

### Network

The VM has no network interface, so default deny is enforced in both
directions: the guest sees only a loopback device and an empty route table.
Omitting `network`, or spelling out deny-all, is accepted:

```json
"network": {
    "egress":  { "default": "deny" },
    "ingress": { "default": "deny", "hostLoopback": "deny" }
}
```

These are rejected: any `allow` default, egress allow or deny rules,
`ingress.hostLoopback: "allow"`, and `runtimeConfig.networkProxy`. MXC adds no
host firewall rules for this backend.

### Other fields

| Field | Behavior |
|---|---|
| `process.commandLine` | Run by `/bin/sh -c` |
| `process.cwd` | Working directory in the guest; `/` if omitted |
| `process.env`, `inheritDefaultEnv` | As for the other Linux backends. The default environment is `PATH`, `TERM`, and `HOME` when `cwd` is set. |
| `process.timeout` | Milliseconds. The deadline starts when the command starts, not during the VM boot. At the deadline everything in the sandbox is killed and the run reports a timeout. |
| Exit code | The command's exit code. A process killed by signal N exits `128 + N`. |
| `ui` | Rejected |
| `lifecycle.destroyOnExit: false`, `lifecycle.preservePolicy` | Rejected. Use the container lifecycle operations to keep a sandbox. |

Pseudo-terminals are not supported yet. Streaming gives separate stdin, stdout,
and stderr pipes.

## Container lifecycle

The container lifecycle operations are available through the native library's
exact JSON entry points, with `experimental` set. Typed SDK requests do not
expose Kata.

| Operation | Effect |
|---|---|
| `provision` | Allocates the sandbox's directory, network namespace, and writable layer. No VM runs. Returns `kata:<token>`. Filesystem and network policy are fixed here. |
| `start` | Boots the VM. |
| `exec` | Runs a process in the running VM. A timeout kills only that process. |
| `stop` | Shuts the VM down. The writable layer stays, so a later `start` sees the earlier files. |
| `deprovision` | Releases everything. A running sandbox must be stopped first. |

```json
{
    "version": "1.1.0-alpha",
    "phase": "provision",
    "containment": "kata",
    "kata": { "rootfs": "/srv/rootfs", "hypervisor": "clh" },
    "filesystem": { "readwritePaths": ["/work"] }
}
```

The sandbox is found again from its `kata:<token>` id alone, so a later call can
come from another process. State is kept in `MXC_KATA_STATE_DIR`. Calls on one
sandbox run one at a time. A restart reuses the sandbox's writable layer; a
sandbox is gone after `deprovision` or a host restart.

## Cleanup

Every path that creates a sandbox removes it: the VM, the shim, the network
namespace, the mounts, the loop device, and the state directory. A create-and-run
request does so when its handle finishes or is dropped, including after a
timeout, a kill, or a failed start. The tests check this after each run.

A failure to release something is reported as a warning on the run, or as the
error of `deprovision`, and the sandbox stays recorded so that `deprovision` can be
repeated.

Cleanup cannot run if the process is killed without a chance to run code (for
example by `SIGKILL`, by `SIGINT` or `SIGTERM` sent to `lxc-exec`, or by losing
power). The VM and its shim then keep running. The next create-and-run request
on the host finds that sandbox, which has no owner left, and removes it before
it starts its own. A sandbox kept by the container lifecycle operations is never
removed this way.

## Design

- **Wire protocol.** The shim serves `containerd.task.v2.Task` over ttrpc on a
  Unix socket. MXC includes a small client for it: a ttrpc frame codec, a
  protobuf encoder and decoder for the dozen messages it uses, and typed calls.
  This adds no dependencies. The generated-code crates (`ttrpc`,
  `containerd-shim-protos`) would add about 45 packages to the lock file,
  including second versions of `nix`, `thiserror`, and `syn`. The message layouts
  are checked in the tests against encodings produced from containerd's own
  `.proto` files.
- **Starting the shim.** `containerd-shim-kata-v2 -namespace mxc -id <id>
  -address <unused> -publish-binary true start`, run in the bundle directory,
  prints the socket address and leaves the shim running. The shim publishes events
  only when `TTRPC_ADDRESS` is set, which MXC unsets. On stop MXC sends
  `Shutdown` and then runs the shim's `delete` command, as containerd does.
- **One path for every request.** A create-and-run request provisions a
  sandbox, starts it, runs the command as an exec process, and stops and
  deprovisions it. The sandbox's init process is `sh -c 'read -r _'`, which
  waits on a pipe MXC holds open.
- **Streams.** Each process gets three named pipes. MXC holds the ends it needs
  before the shim opens the others, and sends the shim `CloseIO` to deliver end
  of file on stdin, because the shim keeps its own copy of that pipe open. A
  pump thread feeds stdin from a pipe whose last close sends `CloseIO`, and
  another pumps output to this process's own streams. A workload that never
  reads its input, or an output consumer that stops reading, cannot stall
  teardown.
- **Network namespace.** MXC creates an empty network namespace for each sandbox
  and passes it to the shim, which attaches only the interfaces it finds in it.
  Owning it lets MXC remove it even if the shim dies.
- **Loop devices.** Created with the kernel's auto-clear flag, so a killed VM
  cannot leak one.

## Troubleshooting

| Message | Remedy |
|---|---|
| `the Kata backend needs root` | Run as root. |
| `/dev/kvm does not exist` or `cannot open /dev/kvm` | Enable virtualization (nested virtualization on a VM) and make `/dev/kvm` accessible. |
| `the Kata shim containerd-shim-kata-v2 was not found` | Install Kata with `runtime-rs`, and set `MXC_KATA_ROOT`. |
| `the Kata configuration for <hypervisor> was not found` | Install the configuration, or set `MXC_KATA_CONFIG_<HYPERVISOR>`. |
| `the firecracker hypervisor has no shared filesystem` | Use an ext4 image for `rootfs`, and remove `readwritePaths` and `readonlyPaths`. |
| `the Kata shim could not create the ... sandbox` | The shim's message follows. Its log is in the system journal under `kata`. |
| `the 'kata' backend is experimental` | Pass `--experimental`, or set `experimental` for raw JSON requests. |

## Limitations

- Linux x86-64 only. Tested with Kata Containers 4.3.1 `runtime-rs`; other shim
  versions and the Go runtime are not tested.
- Deny-all networking only. Allowing network access needs host-side network
  plumbing that this backend does not provide.
- Host directories cannot be shared with Firecracker.
- No pseudo-terminal, resource limits, or image pulling. The root filesystem is
  supplied by the caller.
- Killing a lifecycle exec, or its timeout, ends only that process. Processes
  it started keep running in the guest.
- `deniedPaths` are resolved through symlinks on the host, not in the guest, so
  a guest root filesystem whose links differ from the host's can be masked at
  the wrong path.
- A hardware-virtualization failure inside the shim is reported by the shim's
  own message.

## Tests

`tests/scripts/run_kata_all_tests.sh` and the Rust test
`src/mxc-sdk/tests/streaming_kata.rs` run on every configured hypervisor:
streaming, the guest kernel, filesystem and network policy, timeouts, kill,
the lifecycle, and a check that nothing is left behind. The nightly Linux
validation job runs them on a host with KVM and Kata installed; see the
[validation runbook](../../development/build-and-test/ci-validation-infrastructure.md).
They read `MXC_KATA_ROOT`, `MXC_KATA_TEST_ROOTFS` (a directory),
`MXC_KATA_TEST_ROOTFS_IMAGE` (an ext4 image, for Firecracker),
`MXC_KATA_TEST_HYPERVISORS` (a comma-separated subset), and the
`MXC_KATA_CONFIG_*` variables above. With
`MXC_KATA_TESTS_REQUIRE_EXECUTION=1` a missing prerequisite fails the run instead
of skipping.
