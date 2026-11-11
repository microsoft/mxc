# NVX MicroVM backend

> **Audience:** MXC consumers and developers

The experimental `microvm` backend uses the signed NVX agent bundle to run a
command in a Linux guest on a Windows x64 host. Enable the Cargo feature
`microvm` and authorize experimental execution at runtime. The Cargo feature
and the JSON selector `containment: "microvm"` retain their existing names.

The backend supports Windows x64 only. Windows ARM64 and Linux hosts do not have an
active MicroVM execution path; support for those platforms is
future work. Enabling the feature does not make an unsupported host available.

`v1::available_backends` checks the feature, bundle manifest/library, and active
hypervisor. Availability is advisory; execution verifies runtime requirements.

## Requirements and quick start

The host needs Windows Hypervisor Platform, hardware virtualization, and a
running hypervisor. Enable the `HypervisorPlatform` Windows optional feature
and restart the host before running a workload. In a virtualized host, nested
virtualization must also be available.

MicroVMs use a host-derived CPU profile that is not pinned and can change
after host updates. Unsupported hosts still fail at startup.

From the repository root, build the executor:

```powershell
build.bat --with-microvm
```

The `aci_edge_sandboxes` crate, pinned to `0.1.2` with `agent-bundled`,
downloads and stages its own signed agent bundle. This version pins release
`v0.2.0-build189870623` (sandbox ABI 3, guest runtime ABI
`microvm-abi-v2-edge-ramfs-v7`). Distribute the complete `aci-edge-sandboxes`
directory beside the executable, including its manifests, runtime binaries,
guest images, and provenance files. Do not substitute a standalone OpenVMM
executable or a partial bundle.

Windows x64 Azure build artifacts, release ZIPs, and VPack artifacts include
this complete directory beside the executor. The Node SDK package excludes
it because typed V1 does not support MicroVM targeting. The bundle retains the
NVX release's signatures and pinned hashes; MXC's executable-signing step does
not modify it.

During Windows x64 MicroVM builds, MXC verifies the Authenticode signatures of
`aci_edge_agent.dll`, `openvmm.exe`, and `direct-images.exe`, including Microsoft
publisher, certificate-chain, revocation and signing-timestamp checks. It also
checks the entire bundle against independently approved release hashes.
Packaged-crate and staged artifact validation retain these full checks without
starting a VM. These checks require a Windows build host and verifiable
certificate trust; unsigned, untrusted or non-Microsoft binaries are rejected.

At runtime, experimental NVX execution assumes that the approved bundle remains
unchanged after the build. MXC does not repeat signature, certificate-revocation,
checksum, inventory or fingerprint checks, and does not retain bundle-file
verification guards. Deployments must keep the complete approved bundle
unchanged and supply only trusted runtime overrides. This is an assumption, not
an immutability guarantee implemented by MXC.

The native loader and runtime retain their own digest and file-seal checks;
this change does not remove that work or make the complete execution path
hash-free. State-directory protection and native-module lifetime handling are
unchanged.

Use the development `1.1.0-alpha` request contract:

```json
{
  "version": "1.1.0-alpha",
  "containment": "microvm",
  "microvm": {
    "image": "mcr.microsoft.com/azurelinux/base/core:3.0"
  },
  "process": {
    "commandLine": "printf 'hello from the guest\\n'",
    "timeout": 30000
  }
}
```

```powershell
wxc-exec.exe --experimental config.json
```

For in-process Rust execution, pass the same JSON to `v1::dev::run_json` and
authorize the experimental backend separately:

```rust,no_run
use mxc_sdk::v1::dev::{self, JsonOptions};

let json = std::fs::read_to_string("config.json")?;
let result = dev::run_json(&json, JsonOptions { experimental: true })?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

Use `dev::spawn_json` for live stdout and stderr. The `v1::dev` JSON lifecycle
functions also support persistent provision, start, exec, stop, and
deprovision operations. MicroVM remains absent from the typed V1 request API.
Lifecycle calls use `%LOCALAPPDATA%\Microsoft\MXC\nvx` for agent state.

Commands run in the guest's POSIX shell, not in a host shell or a Python
interpreter. Every creation request requires a registry image in
`microvm.image`; there is no default or local image-file input. Include a
registry host containing a dot, `localhost`, or a host with an explicit
numeric port, followed by `/` and the image repository. For example, use
`docker.io/library/python:3.12-alpine` rather than `python:3.12-alpine` or
`library/python:3.12-alpine`. References containing whitespace or control
characters are rejected. The signed runtime validates the remaining reference
syntax and pulls the selected image on the host. Host-side image
acquisition does not grant the guest network access. MXC has no separate
registry-credentials input. The runtime registers each reference once and keeps
it by its text in the [agent state directory](#agent-state-directory), so later
requests boot it without contacting the registry, and a moving tag such as
`latest` keeps naming the content first pulled. Use a version tag or a digest
(`repository@sha256:…`) to control what a sandbox boots.

## Supported operations and policy

Schema-valid fields do not imply backend support. MXC rejects unsupported
policy before creating a VM rather than ignoring it.

The executor's `--dry-run` checks the signed bundle's capabilities and native
request validation without probing or starting a VM, so it never captures
[platform snapshot](#platform-snapshots) templates. The complete signed
bundle must be available even when only validating a request.

The table describes this MXC integration, not every capability of NVX. The
signed agent limits workloads to one hour and constrains their working
directories and environments as described below. Refusal of UI, writable
stdin, and PTY operations are restrictions of this MXC integration.
The [signed-agent documentation](https://docs.rs/aci_edge_sandboxes/0.1.2/aci_edge_sandboxes/agent/)
describes its contract; the direct OpenVMM backend uses a different guest and
does not define the limits of this integration.

| Surface | Support |
|---|---|
| Host platforms | Windows x64 with WHP. Windows ARM64 and Linux execution are unavailable. |
| Execution | Create-and-run development JSON requests with captured output or live stdout and stderr, plus persistent container lifecycle operations. |
| Rust SDK API | `v1::dev::run_json` and `v1::dev::spawn_json` support MicroVM JSON requests. The `v1::dev` JSON lifecycle functions support provision, start, captured or live exec, stop, and deprovision. Typed V1 operations do not expose MicroVM selection. |
| C ABI, Node, and .NET | Existing JSON entry points support MicroVM captured execution, streaming, and lifecycle operations with experimental authorization. Typed V1 request APIs do not expose MicroVM selection. |
| Executor | MicroVM lifecycle requests through `--operation`, including `--dry-run`, use the shared engine and require experimental authorization. `--operation provision --hold` keeps a container for the life of one executor process and runs its execs side by side. |
| Streaming and PTY | Live stdout and stderr are supported. Writable stdin and PTY operations are rejected before workload launch. |
| Container lifecycle operations | Supported through JSON entry points and the executor. Network, proxy, filesystem, image, and memory policy are fixed at provision. |
| Workload image | Required caller-selected registry reference in `microvm.image`. |
| Guest memory override | Optional positive `microvm.provision.memoryMib` on create-and-run and provision requests when the verified runtime advertises `spec.memory`; unsupported runtimes fail closed. |
| Working directory | Optional absolute POSIX guest path; see the limits below. |
| Environment | Guest default, optionally extended with additive entries; see below. |
| Process timeout | `0` means no workload timeout; nonzero values may not exceed 3,600,000 ms. |
| Captured output | Create-and-run capture and lifecycle `run_in_container_json` accept at most 64 MiB (67,108,864 bytes) combined stdout and stderr. Live streams are caller-controlled and do not have this MXC capture limit. |
| Filesystem policy | Read-only, read-write, and denied paths are mapped to the agent and require the corresponding runtime capabilities. |
| Network policy | Egress defaults and CIDR/protocol/port rules, ingress defaults, and host-loopback postures require the corresponding runtime capabilities and native validation. Host-loopback allow makes guest listeners reachable on the same host loopback port. |
| Runtime proxy | `runtimeConfig.networkProxy` requires the runtime's proxy capability and a port other than 0 or 53. Proxy environment variables remain rejected. |
| UI policy | A supplied `ui` section is rejected. |
| Legacy fallback settings | Accepted and ignored for contract compatibility; they do not enable host-DACL mutation. |
| Lifecycle options | `destroyOnExit` must be `true` and `preservePolicy` must be `false`. |

The development contract allows `microvm.provision.memoryMib` as an optional
positive integer in MiB. Null, zero, negative, and non-integer values are
rejected; omitting it or supplying `provision: {}` uses the backend default.

Backend-specific sections must match the selected backend. For example,
`processContainer.filesystem.enumeratePaths` and
`processContainer.captureDenials` cannot accompany
`containment: "microvm"`; the parser rejects that combination.

### Working directory and environment

When `process.cwd` is omitted, MXC leaves it unset in the agent request and
uses the guest's default working directory. An explicit directory is a guest
path, not a host path: it must be absolute, contain no `..` path components,
and occupy at most 4095 UTF-8 bytes. It cannot contain a null byte.

When `process.env` is present, including an empty array,
`process.inheritDefaultEnv` must be `true`. Entries extend the guest's default
environment rather than replace it. At most 256 entries and 32 KiB including
entry terminators are accepted. Entries must be `KEY=VALUE` strings with
nonempty names and no null bytes. Repeated names count as separate entries;
later entries override earlier ones.

`HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, and `NO_PROXY` are rejected
case-insensitively. MXC validates these process limits before bundle discovery,
then validates the mapped request with the native agent before probing the
host or provisioning a container.

### Output, timeout, and cleanup

For create-and-run capture, output up to the limit is returned unchanged,
including non-UTF-8 bytes. Exceeding the combined limit requests cancellation,
tears down the container, and returns `BackendError` rather than truncated output. The
limit also applies when the workload timeout is zero. Stop and deprovision
failures are reported alongside the original failure.
Explicit host-close failures are reported. An execution-release failure replaces
an otherwise successful execution outcome. A release failure accompanying an
execution error, or occurring after an unknown cancellation outcome has been
returned, may not be visible to the caller. If cancellation fails, the outcome
may be unknown and the workload may still be running; MXC reports the failure
and attempts stop and deprovision.

After requesting cancellation, MXC allows two seconds for the cancellation call
and execution result to arrive. It does not wait indefinitely for either worker.
If the result remains missing, MXC returns `BackendError` with an unknown outcome
and attempts teardown; it does not claim the workload stopped. This grace period
bounds result observation, not every native teardown call.

Before opening the agent client, MXC keeps its containing native module loaded
until process exit. This protects background execution workers that can outlive
an error return, including when cancellation and teardown fail. It does not
mean that the workload has stopped.

For lifecycle `run_in_container_json`, overflow cancels only that execution;
the caller-owned container remains provisioned and usable. The limit also
applies when the workload timeout is zero. Cleanup failures are reported
alongside the original failure.

Lifecycle envelope calls, including validation, explicitly close the native
host. A close failure after successful work returns `BackendError`; a primary
operation failure keeps its original error code and appends the close failure.
For calls on an existing container, native error details are withheld because
the call cannot determine whether the prior provision request included proxy
credentials. The error code and failed operation are still reported.

If provision succeeds but close fails, MXC retains the provisioned container
and returns its ID in Rust `Error.details.nvxRecovery.sandboxId`, with
`details.nvxRecovery.state` recording the last-known state, `"provisioned"`.
Use that ID to continue or deprovision through Rust `v1::dev` JSON; do not retry
provision. Treat the ID as sensitive; ordinary error formatting omits it.
Pre-existing error details are retained under `details.primaryDetails`.
These fields are part of the experimental Rust `v1::dev` behaviour and may
change as the development API evolves.

The existing C ABI does not expose structured `Error.details`. C-backed Node
and .NET callers therefore do not receive this recovery ID when provision
succeeds but close fails, even though the container remains provisioned.

A workload timeout preserves captured partial output and tears down the
create-and-run container. Live execution starts its workload deadline only
after the VM has started and the native exec operation begins. If a caller
takes a live output stream, MXC does not impose the capture limit; the caller
must read or close that stream. Timeout and cancellation interrupt a blocked
relay so cleanup can proceed.

On create-and-run startup failure, the returned error includes bounded tails of
the agent's VM log, boot-console log, and outcome report before teardown removes
them. Each tail is limited to 8 KiB; truncation and unavailable diagnostics are
identified without replacing the original failure. If the configured proxy
URL contains credentials, MXC withholds native error details and startup
diagnostics to avoid exposing them; the error code and failed operation are
still reported.

In the Windows executor, Ctrl-C and Ctrl-Break request cancellation and allow
VM shutdown and deprovisioning before exit code 130 is returned. A launcher
that cannot send console control events, such as one that starts the executor
without a console, can pass `--cancel-on-stdin-close` and keep the executor's
stdin open: closing it has the same effect. The executor discards anything
written to stdin. A request received during startup, including a
[platform snapshot](#platform-snapshots) template capture, is observed when
the native call returns. Closing the console or forcibly terminating the
process does not provide this cooperative-cleanup guarantee. Embedding the SDK
does not install a process-wide console handler.

### Concurrent execs and held containers

A MicroVM serves one host session at a time. One process can run up to 16
execs side by side over its session, but an `exec` from another process waits
until the process holding the session releases it, which the executor does
when it exits. Separate `wxc-exec --operation exec` calls on one container
therefore run one at a time.

To run execs side by side from the executor, hold the container in one
process with `wxc-exec --experimental --operation provision --hold`. It
provisions and starts the container, reads exec and cancel requests from
stdin as JSON lines, streams each exec's output and outcome to stdout, and
stops and deprovisions the container when stdin closes. Cancelling one exec
leaves the container and its other execs running. The container ID stays in
the executor. The [lifecycle transport](../../development/architecture/container-lifecycle.md#held-containers)
describes the requests and events. Each exec runs as its own process tree in
the guest: files persist between execs, but a process an exec started in the
background ends with that exec.

### Agent state directory

The signed agent keeps its sandbox records, VM control data, diagnostics,
registered images, and [platform snapshot](#platform-snapshots) templates in a
per-user state directory,
`%LOCALAPPDATA%\Microsoft\MXC\nvx\<bundle>`, where `<bundle>` is the first 16
hexadecimal digits of the approved bundle manifest's SHA-256, so each pinned
runtime keeps its own state. MXC obtains that digest from the pinned
`aci_edge_sandboxes` crate rather than maintaining a second runtime pin.
MXC makes the current user the directory's owner
and gives it an access list for only that user and Local SYSTEM, so the user's
elevated and non-elevated requests can share it. Every create-and-run request
reuses it, so an image is pulled once rather than for every request, and
concurrent requests share it. MXC coordinates the agent's stop and deprovision
operations and closes the client after each request; it does not maintain a
persistent container database.

To pull a reference again or reclaim disk space, delete the directory while no
MicroVM request or platform-owning SDK process is using it; the next request
creates it again and captures new templates. Lifecycle operations retain their
separate, unversioned root, `%LOCALAPPDATA%\Microsoft\MXC\nvx`, so existing
container IDs and records do not move. Removing a bundle-specific directory does
not remove lifecycle containers, registered images, or templates in that root.
An upgrade that changes the runtime file digests cannot start containers
provisioned with the previous files. Deprovision those containers and provision
them again with the selected bundle; do not move or edit their records.

If deprovisioning fails, MXC reports the failure and the directory's location.
The agent's records for that sandbox remain there rather than being deleted
while a VM might remain. Runtime files in the directory can contain sensitive
data; confirm that no VM is running before you remove the directory.

### Platform snapshots

Create-and-run MicroVMs, with captured or live output, and lifecycle `start`
operations use the agent's platform snapshot templates when the requested
resources fit. Each start creates a separate VM; a template is not a pool of
running customer VMs. MXC configures the native snapshot host for one virtual
processor and 256 MiB of memory, matching its default VM resources. A request
with another `microvm.provision.memoryMib` value cold boots with the requested
resources instead.

The pinned `aci_edge_sandboxes` crate and its bundled native agent own template
creation and selection. MXC sets the CPU and memory limits, not the template
variants.

The native library owns the platform for the SDK process's lifetime. MXC opens
stable validation and execution configurations and explicitly closes each
operation's handles; closing a handle does not discard the native platform.
The first successful execution-configuration open in a state directory can
synchronously capture templates. Later calls in that process reuse the platform,
and other processes reuse the templates on disk. Concurrent first requests
coordinate capture. Failed
initialization is retried by later requests rather than remembered as a
successful platform.

Request validation and host probing precede capture. Dry runs, lifecycle
provision, exec, stop, and deprovision do not initialize templates. The two
[state roots](#agent-state-directory) keep separate template stores. First-use
capture costs additional time and disk space; neither is a fixed latency or
allocation guarantee. The native runtime expires generations after 30 days and
quarantines faulty generations. A fresh process may synchronously recapture an
expired generation; while a generation is unavailable, individual starts may
cold boot. Reusing the SDK process does not skip MXC's per-operation bundle
verification or change certificate-revocation checks.

A running restored VM has one controlling process. Several independent VMs can
use the same template concurrently, but another process cannot exec or stop
that same VM while its controller process remains alive. Closing its SDK
handles does not release that process-owned controller. Use the same process
for those operations, or hand control to another process after the original
process exits. The runtime verifies the running VM's identity before adopting
it. Separate executor invocations can therefore perform lifecycle operations
sequentially after each preceding invocation exits.
Existing-container errors withhold native details to protect possible proxy
credentials, so a lifecycle exec or stop error with withheld details can also
mean that another live process controls the VM.

The bundled native agent reports template capture on the process's standard
error. In the executor, that stream also carries the workload's standard error.

A clone retains the template's boot-time memory state, including values created
before capture. The guest reseeds its kernel random generator with fresh
host-supplied entropy before allowing workloads; failure prevents activation.
Guest randomness generated after reseeding is fresh; values already present in
the template are retained. Reseeding does not re-randomize an existing kernel
or agent memory layout. A clone uses the guest
kernel's default CPU vulnerability mitigations, whereas the cold-boot path
passes `mitigations=off`; MXC does not change those native launch settings.
Its boot-console log has no guest boot output, so startup failure diagnostics
show less of the console.

If execution-platform initialization is unavailable, MXC uses its cold-boot
client. Create-and-run calls return a warning through the existing SDK warning
channel, and the executor prints it on standard error. Lifecycle `start` records
the fallback only in configured diagnostics, such as `--log-file`, rather than
adding it to the envelope's `result.warnings`.
Invalid configuration and handle-close failures remain errors. A start that
does not fit a template records its cold reason without an initialization
warning. With `--log-file`, create-and-run and lifecycle starts record
`bootMode` (`clone` or `cold`), `template` or `coldReason`, and
`bootMilliseconds`.

## Validation

Host-only policy and bundle-integrity checks run in normal Windows x64 PR
builds. A subprocess regression also calls the JSON API without filesystem
grants, receives a native validation error without starting a VM, releases its
DLL handle, and resumes a simulated pending worker in the retained module.
Actual VM execution runs in the unified nightly validation matrix on
Windows 25H2 x64. It consumes the same Windows build artifact, including the
compiled `nvx_e2e` tests and the complete signed bundle; the validation host
does not rebuild them.

The SDK suite covers both the executor and captured JSON execution, caller
image selection, filesystem enforcement, egress and proxy enforcement against
controlled reachable host endpoints, host-loopback TCP and UDP allow and deny,
binary stdout/stderr, exit codes, environment and working-directory settings,
timeouts, capture limits, cleanup, and the seven MicroVM config fixtures.
The SDK JSON scenario also covers live output larger than pipe capacity,
container provision/start, live and captured exec, reuse, stop and deprovision.
An isolated-console scenario interrupts a first request's template capture,
startup, and running execution, then verifies that the OpenVMM processes that
the executor started have terminated and that a later request succeeds with
the same agent state directory. A held-container scenario runs execs side by
side in a container held with `--hold`, checks that files persist between them,
cancels one while the container keeps running, and closes stdin, then checks
that the executor stopped the container's VM and never reported its ID.
Another scenario checks
that concurrent first requests for an unregistered image all succeed, and that
later concurrent requests boot it while its registry is unreachable. A third
checks that eligible create-and-run sandboxes start as clones of the platform
snapshot templates, that a streaming request captures the templates too, that
validation captures none, and that a host that cannot capture them cold boots
sandboxes. Requests that native validation rejects capture no templates.
Missing prerequisites, skipped scenarios, and empty test runs fail validation.
See the [CI validation runbook](../../development/build-and-test/ci-validation-infrastructure.md).

The seven executor configuration fixtures live in
`src/mxc-sdk/tests/fixtures/microvm` and are included in the Rust crate.
Windows x64 PR builds also compile `nvx_e2e` from the extracted crate archive
with `microvm` enabled, without running a VM.

To run the suite locally on a prepared Windows x64 host, from `src`:

```powershell
cargo build --locked -p wxc --features microvm --target x86_64-pc-windows-msvc
cargo test --locked -p mxc-sdk --features microvm --test nvx_bundle_integrity --test nvx_e2e --target x86_64-pc-windows-msvc
cargo test --locked -p mxc-sdk --features microvm --test nvx_e2e --target x86_64-pc-windows-msvc -- --include-ignored --nocapture --test-threads=1
```

## Maintainers: updating the bundled runtime

The `aci_edge_sandboxes` dependency owns bundle acquisition, ABI bindings and its
release pins. MXC separately pins the SHA-256 of the approved release's
`SHA256SUMS` file in `signature_verification.rs`. Only after checking that pin
does MXC use the list to verify the exact file inventory and every file hash
during builds and package validation.
Update the dependency and MXC's independent pin as a reviewed release change.
Obtain the new pin from an independently approved archive, never from an
unchecked override. Review capabilities and cleanup semantics, then run the
host-only and VM validation above. Do not add a second downloader or re-sign
the native binaries.

To avoid downloading the runtime bundle, set
`ACI_EDGE_SANDBOXES_AGENT_BUNDLE_DIR` to the complete **extracted directory**,
not a ZIP. The crate checks the bundle manifests and
file checksums; MXC additionally requires its independently approved contents.
This does not disable build-time certificate checks. A disconnected build or
package-validation host needs usable certificate-chain and revocation data
already cached by Windows. Missing, stale or otherwise unverifiable revocation
data causes verification to fail; provide certificate-server access to refresh
it. MXC does not repeat these checks at runtime.

To use an archive, `ACI_EDGE_SANDBOXES_AGENT_BUNDLE_URL` accepts a `file://` ZIP.
Set `ACI_EDGE_SANDBOXES_AGENT_BUNDLE_SHA256` to an independently approved
archive digest for this override. Without that value, the crate does not
compare the overridden archive against its default release hash. The archive's
own manifests and file checksums establish consistency, not its trusted origin.
MXC's separate approved-file checks still apply to every extracted file.
The runtime override `ACI_EDGE_SANDBOXES_AGENT_ARTIFACTS_DIR`
must point to a complete trusted bundle kept unchanged by the deployment.
MXC does not recheck its independent pins before loading the agent. The native
loader and runtime retain their existing checks.
