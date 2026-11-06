# ACI sandbox backend

> **Audience:** MXC consumers and developers

The experimental `aci` backend runs a command in an Azure Container Instances
(ACI) sandbox: a Hyper-V-isolated Linux micro VM that ACI hosts in a sandbox
group in Azure. MXC creates a sandbox for each request, runs one command in it,
returns the command's output, and deletes the sandbox. MXC requests a Linux
amd64 sandbox without a host-platform override, so ACI runs it on a Windows
host as a Linux container on Windows (LCOW).

Enable the Cargo feature `aci` and authorize experimental execution at
runtime. The backend supports Windows hosts only; Linux and macOS executors
reject `aci`.

## Requirements and quick start

- A Windows x64 or ARM64 host with outbound HTTPS access to
  `management.azure.com`, the sandbox group's data-plane endpoint, and the
  sandbox gateways.

- An ACI sandbox group (`Microsoft.ContainerInstance/sandboxGroups`). Sandbox
  groups are a preview feature that the ACI team enables for each
  subscription.

- An Azure account that can read the sandbox group and call its `connect`
  action, such as a Contributor on the group or its subscription.

- Credentials from the Azure CLI or a pre-acquired token; see
  [Credentials](#credentials).

From the repository root, build the executor:

```powershell
build.bat --with-aci
```

Use the development `1.1.0-alpha` request contract:

```json
{
  "version": "1.1.0-alpha",
  "containment": "aci",
  "aci": {
    "sandboxGroup": "/subscriptions/<subscription-id>/resourceGroups/<resource-group>/providers/Microsoft.ContainerInstance/sandboxGroups/<sandbox-group>",
    "image": "mcr.microsoft.com/mirror/docker/library/alpine:3.16",
    "provision": { "cpu": 1, "memoryGb": 1 }
  },
  "process": {
    "commandLine": "echo \"hello from $(uname -s)\"",
    "timeout": 60000
  }
}
```

Sign in, then run the request:

```powershell
az login
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

The result contains the command's stdout and stderr; it does not provide live
streams or a sandbox that can be reused.

## Supported operations and policy

Schema-valid fields do not imply backend support. MXC rejects policy that it
cannot enforce in an ACI sandbox before it contacts Azure. The process limits
are the same as the [NVX MicroVM backend's](../nvx/nvx.md#supported-operations-and-policy).

| Surface | Support |
|---|---|
| Host platforms | Windows x64 and ARM64. Linux and macOS are unavailable. |
| Execution | Create-and-run development JSON requests with captured stdout, stderr, exit status, and timeout. |
| Rust SDK API | `v1::dev::run_json` runs an ACI JSON request; typed V1 operations do not expose ACI selection. |
| Streaming, PTY, and container lifecycle operations | Unsupported. Requests fail before any Azure call. |
| Sandbox group | Required `aci.sandboxGroup`, the group's ARM resource ID. |
| Workload image | Required `aci.image`, a registry reference that ACI pulls. |
| Sizing | Optional `aci.provision.cpu` (whole cores) and `aci.provision.memoryGb` (whole GiB). Omitted values use the service defaults. |
| Working directory | Optional absolute POSIX guest path; see below. |
| Environment | The sandbox environment, optionally extended with additive entries; see below. |
| Process timeout | `0` means no workload timeout; nonzero values may not exceed 3,600,000 ms. |
| Captured output | Less than 4 MiB of combined stdout and stderr, returned as UTF-8 text; see below. |
| Filesystem policy | Rejected. Host paths cannot be shared with a sandbox that runs in Azure. |
| Network policy | Rejected, including an empty `network` section; see below. |
| Runtime proxy | `runtimeConfig.networkProxy` is rejected. Proxy environment variables are rejected. |
| UI policy | A supplied `ui` section is rejected. |
| Legacy fallback settings | Accepted and ignored for contract compatibility. |
| Lifecycle options | `destroyOnExit` must be `true` and `preservePolicy` must be `false`. |

`aci.sandboxGroup` must have the form
`/subscriptions/<subscription-id>/resourceGroups/<resource-group>/providers/Microsoft.ContainerInstance/sandboxGroups/<sandbox-group>`.
The subscription ID is a GUID, and the fixed segments match in any letter case.

`aci.image` must include a registry host containing a dot, `localhost`, or a
host with an explicit numeric port, followed by `/` and the image repository,
as for [NVX images](../nvx/nvx.md#requirements-and-quick-start). For example,
use `docker.io/library/python:3.12-alpine` rather than `python:3.12-alpine`.
ACI validates the rest of the reference and rejects some references that MXC
accepts, such as repositories with uppercase letters; MXC reports these as
`malformed_request`. MXC has no registry-credentials input.

`aci.provision.cpu` and `aci.provision.memoryGb` must be positive integers.
ACI enforces the upper limits; a size it cannot allocate fails the run with
`backend_error` and the service's reason.

MXC does not restrict the sandbox's network access. The sandbox group's
configuration, such as its virtual network, determines what the command can
reach. Because MXC cannot enforce `network` or `runtimeConfig.networkProxy`
policy, it rejects both rather than ignore them.

Backend-specific sections must match the selected backend. For example,
`processContainer` cannot accompany `containment: "aci"`.

### Working directory and environment

Commands run in the guest's POSIX shell as `/bin/sh -c <commandLine>`, so the
image must provide `/bin/sh`.

When `process.cwd` is omitted, the command runs in the sandbox's default
working directory. An explicit directory is a guest path: it must be absolute,
contain no `..` path components, and occupy at most 4095 UTF-8 bytes. It cannot
contain a null byte. A directory that does not exist in the image fails the run
with `backend_error` ("ACI could not start the command").

When `process.env` is present, including an empty array,
`process.inheritDefaultEnv` must be `true`. Entries extend the sandbox
environment rather than replace it. At most 256 entries and 32 KiB including
entry terminators are accepted. Entries must be `KEY=VALUE` strings with
nonempty names and no null bytes. Repeated names count as separate entries;
later entries override earlier ones. `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`,
and `NO_PROXY` are rejected case-insensitively.

The sandbox environment does not include the image's `ENV` settings, and
`PATH` is `/sbin:/usr/sbin:/bin:/usr/bin`. A program that the image installs
elsewhere, such as `python3` in `/usr/local/bin` in the official Python images,
needs its full path or a `PATH` entry:

```json
"process": {
  "commandLine": "python3 --version",
  "env": ["PATH=/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],
  "inheritDefaultEnv": true
}
```

### Output, timeout, and cleanup

The sandbox gateway returns a command's output after the command exits, so
this backend cannot stream it. The output is UTF-8 text; bytes that are not
valid UTF-8 are not preserved.

ACI limits commands in two ways that MXC cannot work around:

- Output of about 4 MiB or more, counting stdout and stderr together, fails
  with `backend_error` and the gateway's correlation ID.

- A command that writes about 60 KB or more to stderr can stop making
  progress, and the gateway then never returns its result. Such a command runs
  until `process.timeout`, or indefinitely when the timeout is `0`. Send large
  diagnostic output to stdout instead, for example by starting the command
  line with `exec 2>&1;`, or redirect stderr to a file.

MXC enforces `process.timeout`. The timeout covers the command only, not the
creation and startup of the sandbox. When it expires, MXC returns a timed-out
result without the command's output and deletes the sandbox, which ends the
command. In the executor, a timed-out command reports `ACI workload timed out`
with exit code `-1`.

Each request creates a sandbox named `mxc-<32 hexadecimal digits>` with the
tag `createdBy: mxc`. MXC deletes it after the request completes, fails, times
out, or is cancelled, including when creation failed. ACI completes the
deletion in the background, usually within a minute. If MXC cannot delete the
sandbox, the error names the sandbox and its group; delete it yourself to
release its resources.

MXC waits up to five minutes for a new sandbox to become ready, including the
image pull. ACI does not report an image it cannot pull, such as one that does
not exist; that request fails when the wait ends. The error includes the last
sandbox state that ACI reported, such as `creating`.

In the Windows executor, Ctrl-C and Ctrl-Break stop the request, delete the
sandbox, and return exit code 130. Closing the console or forcibly terminating
the process skips deletion; find leftover sandboxes in the group by their
`mxc-` name prefix and `createdBy: mxc` tag. Embedding the SDK does not install
a process-wide console handler.

### Credentials

MXC gets an access token for `https://management.azure.com/` from the first
available source:

1. The `MXC_ACI_ARM_TOKEN` environment variable, when it is set and not
   empty. Use it in automation that signs in another way, such as with a
   workload identity. MXC does not refresh this token, so it must remain valid
   for the whole request, up to the five-minute startup wait plus the process
   timeout.

2. The Azure CLI, run from an absolute `PATH` entry, for the account signed in
   with `az login`. MXC requests a token for the sandbox group's subscription.

MXC uses the token to read the sandbox group and to open a session with the
group's data plane. Tokens and sandbox connection strings do not appear in
errors. All connections use HTTPS, validate certificates against the Windows
certificate store, and go directly to Azure: MXC ignores proxy environment
variables such as `HTTPS_PROXY`. It supports only the Azure public cloud.

`--dry-run` validates the request, gets a token, reads the sandbox group, and
opens a data-plane session without creating a sandbox.

## Troubleshooting

| Error | Remedy |
|---|---|
| `backend_unavailable`: "the 'aci' backend is experimental" | Pass `--experimental`, or set `JsonOptions { experimental: true }`. |
| `backend_unavailable`: "ACI requires Windows and a build with the aci feature" or "ACI requires a build with --features aci" | Build on Windows with `build.bat --with-aci` or `--features aci`. |
| `backend_unavailable`: "ACI needs Azure credentials" | Install the Azure CLI and run `az login`, or set `MXC_ACI_ARM_TOKEN`. |
| `backend_unavailable`: "access denied" or "was not found" | Check the `aci.sandboxGroup` ID and the account's access to the group. |
| `malformed_request`: "ACI rejected the request" | Correct the value that the service's message names, such as an image reference with uppercase letters. |
| `backend_error`: "did not become ready within 300 s" | Check that the image exists and that the sandbox group can pull it. |
| `backend_error`: "ACI could not start the command" | Check `process.cwd` and that the image provides `/bin/sh`. |

## Validation

Windows PR builds run the backend's unit tests, including the gateway client
against an in-process HTTP/2 server, and the request checks in
`src/mxc-sdk/tests/aci_e2e.rs` that need no Azure access. Tests that create
sandboxes are ignored by default. Run them on a Windows host with Azure
credentials and a sandbox group, from `src`:

```powershell
$env:MXC_ACI_E2E_SANDBOX_GROUP = '<sandbox group ARM resource ID>'
cargo build -p wxc --features aci
cargo test -p mxc-sdk --features aci --test aci_e2e -- --include-ignored --test-threads=1
```

They cover the executor and `v1::dev::run_json`, stdout and stderr, exit
codes, environment entries, the working directory, sizing, timeouts, start
failures, image references that ACI rejects, `--dry-run`, Ctrl-C during startup
and during execution, and deletion of every sandbox they create.
`MXC_ACI_E2E_IMAGE` overrides the default image,
`mcr.microsoft.com/mirror/docker/library/alpine:3.16`.

Scheduled validation does not run these tests because the validation hosts
have no Azure credentials; see
[ACI validation](../../development/build-and-test/ci-validation-infrastructure.md#aci-validation).
