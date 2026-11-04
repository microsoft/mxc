# NVX MicroVM backend

> **Audience:** MXC consumers and developers

The experimental `microvm` backend uses the signed NVX agent bundle to run a
command in a Linux guest on a Windows x64 host. Enable the Cargo feature
`microvm` and authorize experimental execution at runtime. The Cargo feature
and the JSON selector `containment: "microvm"` retain their existing names.

The backend supports Windows x64 only. Windows ARM64 and Linux hosts do not have an
active MicroVM execution path; support for those platforms is
future work. Enabling the feature does not make an unsupported host available.

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

The `aci_edge_sandboxes` crate, pinned to `0.1.1` with `agent-bundled`,
downloads and stages its own signed agent bundle. This version pins release
`v0.1.0-build188642429` (sandbox ABI 3, guest runtime ABI
`microvm-abi-v2-edge-ramfs-v7`). Distribute the complete `aci-edge-sandboxes`
directory beside the executable, including its manifests, runtime binaries,
guest images, and provenance files. Do not substitute a standalone OpenVMM
executable or a partial bundle.

Windows x64 Azure build artifacts, release ZIPs, and VPack artifacts include
this complete directory beside the executor. The Node SDK package excludes
it because typed V1 does not support MicroVM targeting. The bundle retains the
NVX release's signatures and pinned hashes; MXC's executable-signing step does
not modify it.

MXC also checks the Authenticode signatures of `aci_edge_agent.dll`,
`openvmm.exe`, and `direct-images.exe` during Windows x64 MicroVM builds and
before opening the runtime. Windows must trust the signatures and identify
Microsoft Corporation as the publisher. Valid signing timestamps are honoured.
The existing archive, file-hash and manifest checks remain in place.
Packaged-crate and staged Windows artifact validation rerun the same signature
checks without starting a VM.

Signature validation allows certificate-server access for chain and revocation
checks. An unsigned, modified, untrusted or non-Microsoft binary is rejected;
an indeterminate trust result is not accepted. Restore the complete official
bundle and ensure the build or execution host can establish certificate trust.
Windows-targeted MicroVM builds require a Windows build host for these checks.
MXC retains read-only file handles while the runtime uses the verified binaries
to prevent writing or replacing them after validation.

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

The result contains captured stdout and stderr as bytes; it does not provide
live streams or a persistent container.

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
registry-credentials input. The runtime caches references by text within its
state root, so a tag can retain previously pulled content; use a digest when
immutable content identity is required.

## Supported operations and policy

Schema-valid fields do not imply backend support. MXC rejects unsupported
policy before creating a VM rather than ignoring it.

The executor's `--dry-run` checks the signed bundle's capabilities and native
request validation without probing or starting a VM. The complete signed
bundle must be available even when only validating a request.

The table describes this MXC integration, not every capability of NVX. The
signed agent limits workloads to one hour and constrains their working
directories and environments as described below. Captured-only execution
and refusal of UI, memory overrides, and public lifecycle operations
are restrictions of this MXC integration.
The [signed-agent documentation](https://docs.rs/aci_edge_sandboxes/0.1.1/aci_edge_sandboxes/agent/)
describes its contract; the direct OpenVMM backend uses a different guest and
does not define the limits of this integration.

| Surface | Support |
|---|---|
| Host platforms | Windows x64 with WHP. Windows ARM64 and Linux execution are unavailable. |
| Execution | Create-and-run development JSON requests with captured stdout, stderr, exit status, and timeout. |
| Rust SDK API | `v1::dev::run_json` supports captured execution with a MicroVM JSON request; typed V1 operations do not expose MicroVM selection. |
| Streaming, PTY, and container lifecycle operations | Unsupported. Requests fail explicitly before backend setup. |
| Workload image | Required caller-selected registry reference in `microvm.image`. |
| Guest memory override | The contract defines `microvm.provision.memoryMib`, but explicit overrides return `PolicyValidation` before bundle discovery. Omit it to use the runtime default. |
| Working directory | Optional absolute POSIX guest path; see the limits below. |
| Environment | Guest default, optionally extended with additive entries; see below. |
| Process timeout | `0` means no workload timeout; nonzero values may not exceed 3,600,000 ms. |
| Captured output | At most 64 MiB (67,108,864 bytes) combined stdout and stderr. |
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

Output up to the capture limit is returned unchanged, including non-UTF-8
bytes. Exceeding the combined limit requests cancellation, tears down the
container, and returns `BackendError` rather than truncated output. The
limit also applies when the workload timeout is zero. Stop and deprovision
failures are reported alongside the original failure.
Explicit host-close failures are reported. An execution-release failure replaces
an otherwise successful execution outcome. A release failure accompanying an
execution error, or occurring after an unknown cancellation outcome has been
returned, may not be visible to the caller. If cancellation fails, the outcome
may be unknown and the workload may still be running; MXC reports the failure
and attempts stop and deprovision.

Before opening the agent client, MXC keeps its containing native module loaded
until process exit. This protects background execution workers that can outlive
an error return, including when cancellation and teardown fail. It does not
mean that the workload has stopped.

A workload timeout preserves captured partial output and tears down the
container. Each create-and-run request gets fresh workload state; this phase
does not offer persistent containers or manual lifecycle operations.

On startup failure, the returned error includes bounded tails of the agent's
VM log, boot-console log, and outcome report before teardown removes them.
Each tail is limited to 8 KiB; truncation and unavailable diagnostics are
identified without replacing the original failure. If the configured proxy URL
contains credentials, MXC withholds native error details and startup diagnostics
to avoid exposing them; the error code and failed operation are still reported.

In the Windows executor, Ctrl-C and Ctrl-Break request cancellation and allow
VM shutdown, deprovisioning, and temporary-directory cleanup before exit code
130 is returned. A request received during startup is observed when the native
startup call returns. Closing the console or forcibly terminating the process
does not provide this cooperative-cleanup guarantee. Embedding the SDK does not
install a process-wide console handler.

### Temporary agent workspace

MXC allocates a private temporary directory for each create-and-run operation.
The signed agent owns the sandbox records, VM control data, diagnostics, and
image registry/cache stored there. MXC coordinates the agent's stop and
deprovision operations, closes the client, and removes the directory after
successful deprovisioning; it does not maintain a persistent container database.

If deprovisioning fails, MXC reports the failure and retains the directory,
including its location in the error. This preserves the agent's resource
records rather than deleting them while a VM might remain. Retention does not
provide automatic recovery. Retained runtime files can contain sensitive data;
protect them and confirm that the operation's VM has stopped before manually
removing retained storage.

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
An isolated-console scenario interrupts both startup and running execution,
then verifies that the owned OpenVMM process has terminated and run storage
has been removed.
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

The `aci_edge_sandboxes` dependency owns bundle acquisition, verification,
ABI bindings, and version pins. Update its exact version as a reviewed change;
check its release, runtime capabilities, validation behavior, and cleanup
semantics before running the host-only and VM validation above. Do not add a
second MXC downloader or re-sign the bundle's native binaries.

For an offline build, set `ACI_EDGE_SANDBOXES_AGENT_BUNDLE_DIR` to the complete
**extracted directory**, not a ZIP. The crate checks the bundle manifests and
file checksums; use an independently trusted bundle for this override. To use
an archive, `ACI_EDGE_SANDBOXES_AGENT_BUNDLE_URL` accepts a `file://` ZIP.
Set `ACI_EDGE_SANDBOXES_AGENT_BUNDLE_SHA256` to an independently approved
archive digest for this override. Without that value, the crate does not
compare the overridden archive against its default release hash. The archive's
own manifests and file checksums establish consistency, not its trusted origin.
Microsoft signature checks on the native binaries do not authenticate the
complete archive or guest assets.
The runtime override `ACI_EDGE_SANDBOXES_AGENT_ARTIFACTS_DIR`
names a complete staged bundle directory. The agent checks its runtime files
against the digests compiled into the crate.
