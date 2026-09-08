# NVX Backend for MXC

## Status

Approved design for an experimental MXC backend named `nvx`.

## Assumptions

1. NVX refers to `nanvix/nvx`, which boots a Linux microVM through OpenVMM and Windows Hypervisor Platform (WHP). It is distinct from MXC's existing NanVix-based `microvm` backend.
2. The first workload is a CPython-based agent image, but the execution contract remains command-oriented rather than Python-specific.
3. The first milestone supports one live NVX sandbox per user.
4. All requested host paths must be beneath one canonical common host root.
5. Correctness and observability take priority over a fixed startup-latency target. Cold-boot and warm-exec latency are measured but do not initially gate acceptance.
6. The backend remains behind `--experimental` until its limitations and policy behavior are proven.
7. VM sizing is immutable after provision. The public NVX config exposes `memoryMiB` and
   `processors`; processors accepts only NVX's supported values `1`, `2`, `4`, or `8`.

## Goal

Add NVX as a new Windows containment backend with:

- one-shot execution;
- state-aware `provision → start → exec* → stop → deprovision`;
- repeated execution in one warm microVM;
- live, binary-safe stdin/stdout/stderr;
- CPython/agent workload support;
- provision-time filesystem and network policy;
- fail-closed validation for unsupported MXC policy;
- an optional, separately versioned runtime package.

The first milestone does not require snapshot-accelerated startup, arbitrary unrelated host path mappings, multiple simultaneous sandboxes per user, or per-host network filtering.

## Current NVX Capability Baseline

The baseline was verified in the NVX `Project build` session against commit `3fed8175dbd5dd04cb06a13ed79ba7882de4053f`.

| Area | Available today |
|---|---|
| Isolation | Hardware-backed x86-64 microVM through OpenVMM on WHP |
| Host control | `python scripts\nvx.py run` foreground CLI |
| Compute | Fixed supported vCPU counts of 1, 2, 4, or 8 and configurable memory |
| Guest | Linux kernel plus Alpine initramfs |
| Filesystem | One virtio-fs export root with device-wide read-only or read-write mode |
| Network | Optional static portable network profile |
| Console | Portb plus optional bidirectional virtio-console |
| Execution | Interactive shell, kernel-command-line `nvx_exec`, and experimental single-workload sandbox bootstrap |
| Exit | Guest `nvx-exit` reports an 8-bit status through PMIO |
| Snapshot | Capture-and-terminate plus same-backend restore primitives |
| Build outputs | OpenVMM executable, kernel, initramfs, kernel config, and package manifest |
| Tests | Unit tests and WHP lifecycle coverage, plus broader declared microVM scenario matrices |

These capabilities prove the VM foundation. They do not provide a production lifecycle or repeated-exec API for MXC.

## Selected Architecture

MXC owns the host-side integration and launches OpenVMM directly. It does not invoke `scripts\nvx.py` at runtime.

```text
MXC SDK / wxc-exec
        |
        | containment: "nvx"
        v
NVX backend crate
  - schema/domain translation
  - policy validation
  - one-shot composition
        |
        | owner-only, versioned named-pipe protocol
        v
MXC NVX daemon
  - one sandbox per user
  - lifecycle state machine
  - OpenVMM process ownership
  - runtime and attachment validation
  - orphan recovery and teardown
        |
        | OpenVMM launch + dedicated virtio-console endpoint
        v
OpenVMM / WHP microVM
        |
        | versioned framed guest protocol
        v
NVX guest agent
  - readiness and health
  - repeated exec
  - stream multiplexing and backpressure
  - signals, cancellation, and exit metadata
  - mount-namespace construction
```

### Why a daemon

Each state-aware phase runs in a separate short-lived MXC process. A persistent per-user daemon must therefore own:

- the live OpenVMM process;
- the guest control endpoint;
- provisioned configuration;
- lifecycle state;
- stream and cancellation routing;
- teardown after client or VM failure.

The daemon follows the proven WSLc pattern for secure discovery, protocol-version checks, exact process-identity validation, transition locking, idle teardown, and typed errors. Its implementation is NVX-specific and does not share WSLc SDK state.

### Why dedicated virtio-console

The current NVX profile already has a bidirectional virtio-console with receive and transmit queues, host pipe/socket backends, input gating, and snapshot-aware state.

For the MXC contract:

- portb remains the kernel boot, panic, and recovery diagnostics channel;
- virtio-console is reserved exclusively for framed guest-agent traffic;
- kernel `printk` output must not be routed to the protocol console;
- a profile or contract version distinguishes the new behavior.

This is safer and smaller than adding virtio-vsock for the first milestone. It avoids the fragility and throughput limits of console scraping or portb-based workload streaming.

## Lifecycle Semantics

| Phase | Behavior |
|---|---|
| `provision` | Validate runtime compatibility, MXC policy, common-root filesystem mappings, network mode, `memoryMiB`, and `processors`. Persist provision metadata without booting the VM. Mint an `nvx:<token>` sandbox ID. |
| `start` | Launch OpenVMM with the provisioned immutable attachments. Wait for the guest agent's launch-bound, version-compatible readiness message. |
| `exec` | Run a command repeatedly in the warm VM. Stream separate stdin/stdout/stderr, honor cwd/env/timeout, support cancellation, and return exit metadata. |
| `stop` | Request graceful guest shutdown, then force termination after a bounded deadline. Preserve provisioned host-side state for a later `start`. |
| `deprovision` | Ensure the VM is stopped, delete provision metadata and disposable sandbox state, and release daemon ownership. |

The state machine rejects invalid transitions. Operations are idempotent only where success can be proven without hiding cleanup uncertainty.

### One-shot composition

One-shot execution uses the same backend and daemon primitives:

```text
provision → start → exec → stop → deprovision
```

Cleanup runs after success, workload failure, timeout, cancellation, or VM failure. This keeps policy validation, protocol behavior, error mapping, and cleanup consistent across one-shot and state-aware surfaces.

## Host-to-Daemon Protocol

The daemon protocol is internal to the MXC distribution and separate from the public JSON schema.

Requirements:

- owner-only Windows named pipe;
- exact server PID and creation-time authentication;
- length-prefixed, bounded frames;
- explicit protocol version;
- typed request and response variants;
- one request ID per operation;
- stable machine-readable daemon error kinds;
- bounded readiness and operation timeouts;
- no unbounded allocation from a peer-controlled length;
- safe behavior when a stale daemon from another MXC version is present.

Core operations:

- `Ping`
- `Provision`
- `Start`
- `ExecOpen`
- `ExecInput`
- `ExecInputClosed`
- `ExecCancel`
- `Stop`
- `Deprovision`
- daemon-to-client stream and terminal events

Only one provisioned sandbox is admitted per user in the first milestone. A second provision returns a typed busy/capacity error rather than replacing the existing sandbox.

## Guest Protocol and Agent

The guest agent is a production component in the NVX runtime image, not an extension of shell-output parsing.

### Handshake

The agent sends:

- protocol version;
- runtime image version;
- launch nonce;
- supported feature bits;
- guest boot identity.

The daemon rejects a mismatched nonce or incompatible version before marking the sandbox started.

### Exec request

An exec request carries:

- request and stream IDs;
- executable or shell command representation;
- arguments without whitespace encoding restrictions;
- working directory;
- environment variables;
- timeout metadata;
- terminal/non-terminal mode;
- stdin availability.

The initial execution identity is a fixed unprivileged guest account named `mxc`. Caller-selected UID/GID is rejected.

### Stream frames

The protocol distinguishes:

- stdin bytes;
- stdin EOF;
- stdout bytes;
- stderr bytes;
- cancellation;
- process exit;
- timeout completion;
- protocol or agent failure.

It must support binary payloads, bounded buffering, backpressure, high-volume output, and deterministic terminal delivery. A request cannot report both a timeout and a normal exit.

### Process isolation

For each exec, the agent creates the supported subset of:

- mount namespace;
- PID namespace;
- UTS namespace;
- IPC namespace;
- private `/dev`;
- read-only `/sys`;
- cgroup v2 process and memory limits;
- `no_new_privs`;
- empty capability bounding, inheritable, and ambient sets.

Execs share the VM's provisioned network namespace in the first milestone. Per-exec network
namespaces are deferred because they require a guest-side virtual network setup that NVX does not
currently provide; creating an empty namespace would silently break the accepted network policy.

Seccomp or LSM enforcement is a P1 hardening item unless a safe, tested initial profile can be included without delaying the core contract.

## Policy Honor Matrix

Every rejected field fails with `policy_validation` before daemon or VM side effects.

| Policy field | Provision | Start / stop / deprovision | Exec |
|---|---|---|---|
| `filesystem.readwritePaths` | Honored under one canonical common root | Rejected as immutable | Rejected as immutable |
| `filesystem.readonlyPaths` | Honored under one canonical common root | Rejected as immutable | Rejected as immutable |
| `filesystem.deniedPaths` | Rejected | Rejected | Rejected |
| Network default posture | `block`: no NIC; `allow`: portable NVX NIC | Rejected as immutable | Rejected as immutable |
| Allowed/blocked hosts | Rejected | Rejected | Rejected |
| `allowLocalNetwork` | Rejected | Rejected | Rejected |
| Network enforcement mode | Accept only capability-level semantics | Rejected | Rejected |
| URL-form proxy | Rejected as an exec concern | Rejected | Honored through scrubbed `HTTP_PROXY` and `HTTPS_PROXY` |
| Localhost/built-in proxy forms | Rejected | Rejected | Rejected |
| UI policy | Rejected by presence | Rejected by presence | Rejected by presence |
| Process command/args/cwd/env | Not applicable | Not applicable | Honored |
| Process timeout | Not applicable | Not applicable | Honored |
| Caller-selected user/group | Not applicable | Not applicable | Rejected |
| Lifecycle section on one-shot | Only values matching actual composed behavior may be accepted | Not applicable | Not applicable |

### Filesystem enforcement

NVX currently exposes one virtio-fs root and one device-wide access mode. The initial backend therefore requires all requested host paths to be under one canonical common root.

The root is exported read-write to enable a mixture of requested modes. The guest agent then:

1. mounts the exported root in an agent-only location;
2. creates a private workload mount namespace;
3. bind-mounts only declared child paths at their requested guest locations;
4. remounts read-only children read-only;
5. ensures the raw exported root is not reachable from the workload namespace.

The backend rejects paths outside the common root, path aliases that escape after canonicalization, overlapping mappings with conflicting modes, and requests that cannot be represented safely.

Arbitrary unrelated host paths require a future static aggregate virtio-fs contract and are P2.

### Network enforcement

At provision:

- `block` omits the virtio-net device;
- `allow` configures NVX's portable network profile and waits for guest network readiness;
- static allocation details remain daemon-internal;
- per-host filtering is rejected.

At exec, a URL-form proxy is cooperative environment injection. Documentation must state that raw sockets can bypass it when the network default is `allow`.

## Runtime Package

NVX artifacts are distributed separately from the main MXC package.

The package contains:

- version-matched `openvmm.exe`;
- NVX kernel;
- CPython/agent initramfs;
- guest-agent version;
- artifact manifest;
- cryptographic hashes;
- MXC/NVX protocol compatibility range;
- microVM profile/ABI version;
- package provenance and license metadata.

The installer or runtime resolver must:

- verify artifact integrity before use;
- probe WHP and required Windows features;
- avoid Docker as an end-user runtime dependency;
- support explicit local override for development;
- reject incompatible partial installations;
- define upgrade, rollback, and stale-daemon behavior.

The public `experimental.nvx` configuration exposes only immutable VM sizing in the first
milestone:

- `memoryMiB`, with a conservative CPython-capable default;
- `processors`, restricted to `1`, `2`, `4`, or `8`.

Runtime package resolution remains installation policy rather than a per-request production
setting. Development builds may use an environment-based local artifact override.

## Error Semantics

| Condition | MXC error/outcome |
|---|---|
| Unsupported or wrong-phase policy | `policy_validation` |
| NVX runtime missing, incompatible, corrupt, or WHP unavailable | `backend_unavailable` |
| Unknown, stale, or deprovisioned sandbox ID | `not_provisioned` |
| Exec before start | `not_started` |
| Capacity reached or invalid concurrent transition | `backend_error` with stable daemon kind |
| Daemon transport or protocol failure | `backend_error` |
| Guest protocol mismatch, agent failure, or VM crash | `backend_error` with retained diagnostics |
| Exec deadline elapsed and workload confirmed gone | `TimedOut` outcome |
| Workload exited | `Exited(code)` outcome |
| Cleanup status uncertain | Error; never a success-shaped fallback |

Diagnostics from portb, OpenVMM stderr, daemon logs, and guest-agent events must be correlated by sandbox and launch identity without mixing them into workload stdout/stderr.

## Prioritized Gaps

### P0: Required for the first experimental backend

1. Production guest agent and versioned framed protocol over dedicated virtio-console.
2. MXC-owned per-user daemon with secure discovery, lifecycle durability, one-sandbox admission, and orphan cleanup.
3. Repeated exec with separate binary-safe streams, backpressure, EOF, cancellation, timeout, exit, and typed errors.
4. NVX/OpenVMM profile adjustment that reserves virtio-console for protocol traffic and keeps diagnostics on portb.
5. Common-root filesystem validation and guest mount-namespace enforcement for declared read-only/read-write children.
6. No-NIC versus portable-NIC lifecycle integration and URL-form cooperative proxy injection.
7. Optional versioned runtime package, integrity manifest, host probe, compatibility negotiation, and installation flow.
8. MXC schema, parser, domain model, engine, SDK, FFI, probe, build, packaging, documentation, and validation wiring for `nvx` and `nvx:` IDs.
9. Fixed unprivileged workload identity and phase-specific fail-closed policy validation.

### P1: Hardening and performance follow-up

1. Structured logs, crash classification, metrics, protocol tracing, recovery diagnostics, and daemon idle teardown.
2. Snapshot orchestration for faster startup, including compatibility, storage, and garbage-collection rules.
3. Seccomp/LSM hardening, resource quotas, stress tests, failure injection, and signed distribution.

### P2: Expanded capability

1. Arbitrary independent host paths through a static aggregate virtio-fs contract.
2. Multiple simultaneous NVX sandboxes per user.
3. Per-host network egress controls.
4. Virtio-vsock if measurements show the dedicated virtio-console cannot meet product needs.

## Testing Strategy

### Unit tests

- public schema and generated type parity;
- containment and sandbox-ID routing;
- per-phase policy matrix;
- common-root canonicalization and overlap handling;
- lifecycle state transitions and idempotence;
- daemon and guest frame size limits;
- protocol version negotiation;
- stream multiplexing, buffering, EOF, and terminal-state exclusivity;
- daemon-to-MXC error mapping;
- package manifest and compatibility validation.

### Host integration tests

- real owner-only daemon named-pipe transport;
- daemon discovery, race prevention, and stale-version replacement;
- exact process identity and PID-reuse defense;
- fake guest endpoint for readiness, exec streams, cancellation, malformed frames, and disconnects;
- OpenVMM process crash and forced teardown;
- orphan recovery after phase-client or daemon restart;
- one-sandbox-per-user admission;
- idle teardown.

### Guest tests

- fixed unprivileged identity;
- repeated exec;
- command arguments containing spaces and binary data;
- cwd and environment;
- read-only/read-write mount behavior;
- raw export root is unreachable;
- proxy environment scrubbing and injection;
- high-volume stdout/stderr with backpressure;
- stdin EOF;
- graceful signal and forced cancellation;
- malformed frame handling;
- agent health and shutdown.

### WHP end-to-end tests

- one-shot CPython workload;
- full state-aware lifecycle;
- warm-state persistence across separate exec invocations;
- CPython agent workload using the optional runtime image;
- common-root read-only and read-write mappings;
- network block and allow;
- URL-form proxy;
- timeout with confirmed workload termination;
- VM crash and orphan cleanup;
- stale runtime and guest-protocol rejection;
- stop/restart and deprovision cleanup;
- measured cold-boot and warm-exec latency.

## Acceptance Criteria

The first milestone is complete when:

1. `containment: "nvx"` is available only with experimental opt-in and host capability success.
2. Both one-shot and state-aware SDK/CLI paths execute CPython agent workloads.
3. A state-aware sandbox remains warm across repeated execs from separate MXC processes.
4. Workload stdout and stderr remain separate and binary-safe; stdin, EOF, cancellation, timeout, and exit are deterministic.
5. Provisioned common-root RO/RW mappings are enforced and immutable.
6. Network block/allow and URL proxy behavior match the documented honor matrix.
7. Unsupported fields fail before any daemon or VM side effects.
8. VM, agent, client, and daemon failure tests leave no unowned OpenVMM process or undisclosed cleanup uncertainty.
9. Runtime artifact integrity and protocol/profile compatibility are validated before launch.
10. Targeted unit, daemon integration, guest, and WHP E2E suites pass.

## Deferred Decisions

The following are intentionally outside the first milestone:

- snapshot-restored startup as an acceptance requirement;
- aggregate virtio-fs and arbitrary unrelated host paths;
- multiple live sandboxes per user;
- per-host network filtering;
- virtio-vsock;
- caller-selected guest identities;
- capture-and-continue or cross-hypervisor restore.
