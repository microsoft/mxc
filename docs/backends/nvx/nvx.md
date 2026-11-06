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

The build stages the pinned official `aci-edge-sandboxes.zip` release
`v0.1.0-dev.0430ce79d125`, from NVX revision
`0430ce79d125203c20f0aa69243480513a774296`. Distribute the complete
`aci-edge-sandboxes` directory beside the executable, including its manifests,
runtime binaries, guest images, and provenance files. Do not substitute a
standalone OpenVMM executable or a partial bundle.

Windows x64 Azure build artifacts, release ZIPs, and VPack artifacts include
this complete directory beside the executor. The Node SDK package excludes
it because typed V1 does not support MicroVM targeting. The bundle retains the
NVX release's signatures and pinned hashes; MXC's executable-signing step does
not modify it.

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
request validation without probing or starting a VM. The complete signed
bundle must be available even when only validating a request.

The table describes this MXC integration, not every capability of NVX. The
signed agent limits workloads to one hour and constrains their working
directories and environments as described below. Refusal of UI, writable
stdin, and PTY operations are restrictions of this MXC integration.
The [signed-agent documentation](https://github.com/microsoft/nvx/blob/0430ce79d125203c20f0aa69243480513a774296/aci_edge_sandboxes/README.md#agent-backend-opt-in)
describes its contract; the direct OpenVMM backend uses a different guest and
does not define the limits of this integration.

| Surface | Support |
|---|---|
| Host platforms | Windows x64 with WHP. Windows ARM64 and Linux execution are unavailable. |
| Execution | Create-and-run development JSON requests with captured output or live stdout and stderr, plus persistent container lifecycle operations. |
| Rust SDK API | `v1::dev::run_json` and `v1::dev::spawn_json` support MicroVM JSON requests. The `v1::dev` JSON lifecycle functions support provision, start, captured or live exec, stop, and deprovision. Typed V1 operations do not expose MicroVM selection. |
| C ABI, Node, and .NET | Existing JSON entry points support MicroVM captured execution, streaming, and lifecycle operations with experimental authorization. Typed V1 request APIs do not expose MicroVM selection. |
| Executor | MicroVM lifecycle requests through `--operation`, including `--dry-run`, use the shared engine and require experimental authorization. |
| Streaming and PTY | Live stdout and stderr are supported. Writable stdin and PTY operations are rejected before workload launch. |
| Container lifecycle operations | Supported through JSON entry points and the executor. Network, proxy, filesystem, image, and memory policy are fixed at provision. |
| Workload image | Required caller-selected registry reference in `microvm.image`. |
| Guest memory override | Optional positive `microvm.provision.memoryMib` on create-and-run and provision requests when the verified runtime advertises `spec.memory`; unsupported runtimes fail closed. |
| Working directory | Optional absolute POSIX guest path; see the limits below. |
| Environment | Guest default, optionally extended with additive entries; see below. |
| Process timeout | `0` means no workload timeout; nonzero values may not exceed 3,600,000 ms. |
| Captured output | Create-and-run capture and lifecycle `run_in_container_json` accept at most 64 MiB (67,108,864 bytes) combined stdout and stderr. Live streams are caller-controlled and do not have this MXC capture limit. |
| Filesystem policy | Read-only, read-write, and denied paths are mapped to the agent and require the corresponding runtime capabilities. |
| Network policy | Directional defaults and CIDR/protocol/port rules require the corresponding runtime capabilities. Unsupported ingress or host-loopback allow postures fail closed. |
| Runtime proxy | `runtimeConfig.networkProxy` requires the runtime's proxy capability. Proxy environment variables remain rejected. |
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
bytes. For create-and-run capture, exceeding the combined limit cancels and
releases execution, tears down the container, and returns `BackendError`
rather than truncated output. For lifecycle `run_in_container_json`, overflow
cancels and releases only that execution; the caller-owned container remains
provisioned and usable. The limit also applies when the workload timeout is
zero. Cleanup failures are reported alongside the original failure.

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
VM shutdown and deprovisioning before exit code 130 is returned. A request
received during startup is observed when the native startup call returns.
Closing the console or forcibly terminating the process does not provide this
cooperative-cleanup guarantee. Embedding the SDK does not install a
process-wide console handler.

### Agent state directory

The signed agent keeps its sandbox records, VM control data, diagnostics, and
registered images in a per-user state directory,
`%LOCALAPPDATA%\Microsoft\MXC\nvx\<bundle>`, where `<bundle>` is the first 16
hexadecimal digits of the approved bundle manifest's SHA-256, so each pinned
runtime keeps its own state. MXC creates the directory with an access list for
only the current user and Local SYSTEM. Every create-and-run request reuses it,
so an image is pulled once rather than for every request, and concurrent
requests share it. MXC coordinates the agent's stop and deprovision operations
and closes the client after each request; it does not maintain a persistent
container database.

Container lifecycle operations keep their state in the parent directory,
`%LOCALAPPDATA%\Microsoft\MXC\nvx`, so removing a `<bundle>` directory does not
affect lifecycle containers.

To pull a reference again or reclaim disk space, delete the directory while no
MicroVM request is running; the next request creates it again.

If deprovisioning fails, MXC reports the failure and the directory's location.
The agent's records for that sandbox remain there rather than being deleted
while a VM might remain. Runtime files in the directory can contain sensitive
data; confirm that no VM is running before you remove the directory.

## Validation

Host-only policy and bundle-integrity checks run in normal Windows x64 PR
builds. Actual VM execution runs in the unified nightly validation matrix on
Windows 25H2 x64. It consumes the same Windows build artifact, including the
compiled `nvx_e2e` tests and the complete signed bundle; the validation host
does not rebuild them.

The SDK suite covers both the executor and captured JSON execution, caller
image selection, filesystem enforcement, directional network and proxy
enforcement against controlled reachable host endpoints, binary
stdout/stderr, exit codes, environment and working-directory settings,
timeouts, capture limits, cleanup, and the seven MicroVM config fixtures.
An isolated-console scenario interrupts both startup and running execution,
then verifies that the owned OpenVMM process has terminated and that a later
request succeeds with the same agent state directory. Another scenario checks
that later requests, including concurrent ones, boot a registered image while
its registry is unreachable.
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

Update the pinned release as one reviewed change. Do not remove verification
or accept arbitrary replacement files to get an upgrade working.

1. Select an official signed release from
   [microsoft/nvx releases](https://github.com/microsoft/nvx/releases).
   Review its signing and provenance records and confirm the supported host
   architecture and guest image. Hashing a downloaded archive alone does not
   establish its provenance.

2. Download the candidate archive and inventory its hashes. For example:

   ```powershell
   $release = 'v0.1.0-dev.0430ce79d125' # Replace with the reviewed candidate.
   $download = Join-Path $env:TEMP "mxc-nvx-$release"
   $bundle = Join-Path $download 'bundle'
   New-Item -ItemType Directory -Force -Path $download | Out-Null
   gh release download $release --repo microsoft/nvx --pattern aci-edge-sandboxes.zip --dir $download
   $archive = Join-Path $download 'aci-edge-sandboxes.zip'
   Get-FileHash -LiteralPath $archive -Algorithm SHA256
   Expand-Archive -LiteralPath $archive -DestinationPath $bundle
   Get-ChildItem -LiteralPath $bundle -File -Recurse | ForEach-Object {
       [pscustomobject]@{
           Path = $_.FullName.Substring($bundle.Length + 1).Replace('\', '/')
           SHA256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
       }
   } | Format-Table -AutoSize
   ```

3. Check the candidate's C ABI against
   `src/mxc-sdk/src/backends/nvx/abi.rs`, including
   `SANDBOX_ABI_VERSION`, required exports, request and response formats,
   status values, and ownership rules. An incompatible ABI needs adapter
   changes and coverage, not just a version-constant change.

4. Update `OFFICIAL_BUNDLE_URL`, `OFFICIAL_BUNDLE_ZIP_SHA256`, and the complete
   `OFFICIAL_BUNDLE_FILES` inventory in
   `src/mxc-sdk/build/build_nvx_bundled.rs`, including release-specific
   diagnostics. Synchronize the `APPROVED_*_SHA256` runtime pins in
   `src/mxc-sdk/src/backends/nvx/runtime.rs`. Keep every manifest, guest,
   helper, and provenance file in the inventory.

5. Update the pinned-release assertions in
   `src/mxc-sdk/tests/nvx_bundle_integrity.rs` and the release/revision
   references in this guide and `src/mxc-sdk/README.md`. Review any changed
   policy or process limits against the candidate agent before adjusting them.

6. Run the build and three validation commands above against the candidate.
   Integrity tests must still reject missing, modified, and unlisted files.
   Confirm both executor and captured JSON VM scenarios actually execute,
   including timeout, capture-limit, and cleanup checks. From the repository
   root, also run:

   ```powershell
   node --test scripts\tests\microvm-validation.test.js
   node scripts\ci\resolve-validation-test-matrix.mjs --plan nightly
   ```

For an offline build, set `ACI_EDGE_SANDBOXES_AGENT_BUNDLE_DIR` to a directory
containing the exact pinned archive or its complete extracted contents. The
build still verifies the pinned archive and/or file hashes. Stage the resulting
complete `aci-edge-sandboxes` directory with the executor, and validate the
packaged artifact on a prepared host before accepting the upgrade.

Cargo output directories may be reached through a junction or directory
symlink. Caller-supplied extracted bundle directories, including their
ancestors, must not contain links or reparse points; use a direct path to the
verified bundle instead.
