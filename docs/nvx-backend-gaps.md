# NVX Daemon Requirements and MXC Integration Gaps

## Scope

The NVX team will provide a daemon that owns `openvmm.exe` and presents the
stable runtime interface consumed by MXC.
The intended boundary is:

```mermaid
flowchart LR
    MXC[MXC] --> Daemon[NVX daemon]
    Daemon --> OpenVMM[openvmm.exe]
    OpenVMM --> Guest[NVX guest]
```

## What NVX Already Provides

NVX already supplies the core VM foundation:

- hardware-backed Linux microVM execution through OpenVMM and Windows
  Hypervisor Platform;
- configurable memory and supported vCPU counts;
- Linux kernel and Alpine-based initramfs artifacts;
- a CPython guest-image build path;
- one host directory exported through virtio-fs;
- optional portable networking with static configuration;
- portb diagnostics and a bidirectional virtio-console device;
- guest-to-host exit reporting;
- capture-and-terminate snapshot and same-backend restore primitives;
- unit tests and microVM lifecycle scenarios across supported hypervisors.

The primary gap is turning those primitives into a stable daemon-managed
sandbox service.

## NVX Runtime Artifacts

The following sizes were observed in the current Windows NVX build and may vary
slightly between revisions:

| Artifact | Purpose | Observed size |
| --- | --- | ---: |
| `openvmm.exe` | Windows host process that creates and runs the NVX microVM through WHP. | 21.38 MiB |
| `vmlinux` | Linux kernel that runs inside the microVM. | 21.83 MiB |
| `initramfs.cpio.gz` | Compressed Alpine guest filesystem containing startup scripts, tools, and NVX utilities. | 7.12 MiB |
| `vmlinux.config` | Exact Linux kernel configuration used for the build. | 66.80 KiB |
| `initramfs.cpio.gz.packages.json` | Manifest of packages and source inputs included in the initramfs. | 22.97 KiB |

The five artifacts total approximately **50.35 MiB**. A CPython/agent
initramfs would be an additional runtime artifact and should carry its own
version and package manifest.

## Recommended Daemon API Semantics

The exact transport belongs to NVX, but the API should express the following
operations without requiring MXC to know OpenVMM details:

| Operation | Minimum result |
| --- | --- |
| `GetCapabilities` | Daemon version, protocol range, runtime version, guest-agent version, supported features, host readiness, and limitations |
| `Provision` | Opaque sandbox ID and effective immutable configuration |
| `Start` | Ready state, launch identity, guest identity, and network status |
| `Exec` | Exec ID plus handles or framed channels for stdin, stdout, and stderr |
| `WaitExec` | Exit code or timeout/cancel outcome, signal information, and duration |
| `CancelExec` | Typed acknowledgement followed by confirmed terminal state |
| `Stop` | Confirmed guest/OpenVMM shutdown or an explicit cleanup error |
| `Deprovision` | Confirmed removal of provisioned and disposable state |
| `GetStatus` | Current lifecycle state, active exec, failure information, and diagnostic correlation ID |
| `ShutdownDaemon` | Controlled service shutdown for upgrades and testing |

Long-running operations should support cancellation and deadlines. Requests
should carry correlation IDs, and retries should be idempotent where the daemon
can prove the prior result.

## Guest-Agent Requirements Behind the Daemon

The daemon needs a production guest agent; OpenVMM lifecycle control alone is
not enough.

The guest agent must provide:

1. a launch-bound, versioned readiness handshake;
2. immutable session configuration;
3. repeated process creation and supervision;
4. separate stdin, stdout, and stderr;
5. bounded flow control and backpressure;
6. stdin EOF, cancellation, timeout, and exact terminal events;
7. fixed unprivileged workload identity;
8. private process and mount isolation;
9. read-only and read-write bind-mount enforcement;
10. structured network status;
11. health, quiesce, and graceful-shutdown operations;
12. cleanup of child processes after host-channel loss.

The daemon should hide this guest protocol from MXC. MXC consumes daemon-level
operations and does not need to know whether the internal transport is
virtio-console, vsock, or another NVX mechanism.

## MXC-Side Work After the Daemon Exists

With a complete NVX daemon, the remaining MXC integration follows established
backend patterns:

| MXC area | Required work |
| --- | --- |
| Schema and model | Add the distinct `nvx` containment value and its immutable provision settings. |
| State-aware dispatch | Register `nvx:` sandbox IDs and implement a `StatefulSandboxBackend` adapter over the daemon API. |
| One-shot execution | Compose daemon provision, start, exec, stop, and deprovision using the same adapter. |
| Policy validation | Define the per-phase fail-closed honor matrix and reject unsupported fields before contacting the daemon. |
| Stream adaptation | Convert daemon streams and terminal results into MXC's `SandboxProcess` and `ExecHandle` contracts. |
| Error mapping | Map daemon error kinds to MXC errors without string matching. |
| Capability probe | Surface daemon installation, host readiness, runtime compatibility, and supported features. |
| SDKs and FFI | Add `nvx` to TypeScript, C#, Rust, and C ABI surfaces where applicable. |
| Build and packaging | Discover or install the separately distributed NVX runtime and daemon. |
| Tests and CI | Add one-shot and state-aware lifecycle, policy, failure, stream, and cleanup coverage. |


## Summary

The architectural change removes the largest host-side responsibility from
MXC: **the NVX daemon, not MXC, owns OpenVMM and the guest control plane**.

The daemon should be viewed as the production successor to the one-workload
`nanvixd` model. It must retain the same fundamental ability to launch a
microVM and propagate workload results, while adding durable lifecycle,
repeated exec, structured streams, policy configuration, guest supervision,
snapshots, diagnostics, compatibility negotiation, and crash-safe cleanup.

Once this daemon contract exists, the MXC work becomes a relatively conventional
backend adapter using patterns already established by WSLc, Windows Sandbox,
IsolationSession, and the existing `microvm` backend.

## Appendix A: Daemon Requirements (P0)

The first experimental MXC backend requires the daemon to provide the following
capabilities. More detailed acceptance requirements appear in Appendix B.

| Area | P0 requirement |
| --- | --- |
| Runtime ownership | Own `openvmm.exe`, its control endpoints, handles, logs, exit status, and cleanup. MXC must never launch OpenVMM directly or parse its console output. |
| Lifecycle | Provide deterministic provision, start, repeated exec, stop, deprovision, status, cancellation, and timeout behavior over opaque sandbox and exec IDs. |
| Guest control | Use a bounded, versioned guest-agent protocol with an authenticated launch-bound readiness handshake, separate binary-safe process streams, backpressure, EOF, and exact terminal events. |
| Workload isolation | Run workloads as a fixed unprivileged guest identity and isolate their processes and mounts. Clean up all descendants after completion or control-channel loss. |
| Filesystem | Validate immutable provision-time mappings beneath one canonical host root and enforce each declared mapping as read-only or read-write without traversal or symlink escape. |
| Network and proxy | Support no-NIC isolation and NVX portable networking, report structured readiness, and support cooperative URL-form HTTP/HTTPS proxy injection without claiming raw-socket enforcement. |
| Resources and compatibility | Validate memory and supported processor settings and reject incompatible daemon, OpenVMM, VM ABI, kernel, initramfs, guest-agent, or protocol combinations before launch. |
| Snapshots | Capture only an idle, guest-quiesced VM; bind the snapshot to the complete runtime and attachment configuration; revalidate it before restore; and require a fresh guest and network readiness handshake after restore. An untrusted or incompatible optimization snapshot must be invalidated and replaced by a cold boot. |
| Security | Restrict daemon access to authorized local clients, validate every caller-controlled value, use bounded framing and buffering, verify runtime artifacts, avoid shell command construction and unnecessary inherited handles, and run with the minimum required privileges. |
| Recovery and diagnostics | Use exact process identity and ownership evidence for orphan recovery, guarantee bounded cleanup across client, guest, OpenVMM, and daemon failures, never report success when cleanup is uncertain, and keep trusted diagnostics separate from workload output. |

## Appendix B: Required NVX Daemon Capabilities

The following capabilities are required for the first experimental MXC backend.

| Daemon capability | Requirement |
| --- | --- |
| Versioned API | Expose a stable, machine-readable API independent of OpenVMM's command-line interface. Negotiate protocol and runtime versions and reject incompatible clients, guest images, or OpenVMM builds. |
| Lifecycle operations | Provide `provision`, `start`, `exec`, `stop`, and `deprovision`, or equivalent operations with the same semantics. Provision stores immutable configuration without booting; start launches and readies the VM; exec is repeatable; stop preserves provisioned state; deprovision deletes it. |
| Stable sandbox identity | Mint an opaque sandbox ID and reject unknown, stale, malformed, or already-deprovisioned IDs with typed errors. |
| OpenVMM ownership | Be the sole owner of the OpenVMM child process, command line, control endpoints, handles, logs, exit status, and forced termination. Do not require MXC to parse OpenVMM output. |
| Explicit VM state machine | Track states such as provisioned, starting, ready, executing, stopping, stopped, failed, and deprovisioned. Reject invalid or concurrent transitions deterministically. |
| Guest readiness | Complete a versioned handshake with the guest agent and report readiness only after the agent, configured filesystem, and requested network are usable. Boot-marker text is not sufficient. |
| Repeated exec | Run multiple sequential commands in one warm VM without rebooting. The first milestone may allow only one active exec at a time, but it must support repeated exec calls. |
| Process configuration | Accept an argument vector, working directory, environment, timeout, mapping selection, and stdin mode without kernel-command-line quoting or whitespace restrictions. |
| Fixed workload identity | Launch workloads as a fixed unprivileged guest account. The daemon must not report readiness if the guest cannot enforce that identity. |
| Separate process streams | Return distinct binary-safe stdin, stdout, and stderr streams. Support stdin EOF, bounded buffering, backpressure, large output, and deterministic stream closure. |
| Wait and cancellation | Provide wait, graceful cancellation, forced termination, timeout, and exit metadata. A timeout is reported only after the workload is confirmed gone. |
| Guest-control channel | Own a framed, bounded, versioned connection to the guest agent. The channel must support request IDs, stream IDs, cancellation, flow control, terminal events, health, and shutdown. |
| Diagnostic separation | Keep kernel/OpenVMM/daemon diagnostics separate from workload stdout and stderr. Kernel panic or boot output must not corrupt guest-agent protocol traffic. |
| Filesystem configuration | Accept provision-time host mappings, validate them, attach the common virtio-fs root, and configure the guest agent to expose only declared children as read-only or read-write. |
| Filesystem immutability | Reject attempts to change filesystem mappings after provision. Reject path traversal, symlink escape, conflicting overlaps, and mappings outside the configured common root. |
| Network modes | Support an isolated mode with no NIC and an enabled mode using NVX portable networking. Report structured network readiness or a typed setup failure. |
| Exec-time proxy | Accept a URL-form HTTP/HTTPS proxy for an exec and arrange cooperative environment injection. Do not claim that this provides raw-socket enforcement. |
| Resource configuration | Accept immutable provision-time memory and processor settings, validate supported processor counts, and communicate the effective values to the caller. |
| Graceful VM shutdown | Request guest shutdown, wait for acknowledgement and process exit, then force OpenVMM termination after a bounded deadline. |
| Cleanup guarantees | Remove disposable state and close handles after normal completion, timeout, cancellation, client disconnect, guest crash, OpenVMM crash, or daemon shutdown. Never return success when cleanup status is uncertain. |
| Orphan recovery | On daemon restart, identify prior OpenVMM processes using exact process identity and ownership evidence. Reclaim only positively identified instances; never terminate a process based on PID alone. |
| Structured errors | Return stable error kinds for unavailable runtime, incompatible version, capacity, invalid transition, not provisioned, not started, busy, timeout, guest failure, OpenVMM failure, protocol failure, and uncertain cleanup. |
| Capability reporting | Report supported lifecycle operations, stream modes, network modes, filesystem restrictions, snapshot support, processor values, and protocol versions so MXC can probe the backend accurately. |
| Runtime integrity | Validate OpenVMM, kernel, initramfs, guest-agent, manifest, checksums, architecture, and compatibility before VM launch. |
