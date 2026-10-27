# Validation (E2E) test infrastructure

> **Audience:** MXC developers

How MXC runs its backend end-to-end suites across real operating systems, what
each job covers today, and what to change when you need to add, remove, or
retire something.

This document describes the GitHub Actions validation matrix only. PR-time
build/lint/SDK validation is covered by [`pull-requests.md`](pull-requests.md);
the individual local test scripts are documented in
[`tests/scripts/README.md`](../../../tests/scripts/README.md).

## At a glance

- Validation tests **never build from source**. They download the artifacts
  produced by `Build.Windows.Job.yml` / `Build.Linux.Job.yml` /
  `Build.MacOS.Job.yml`, and for ProcessContainer, IsolationSession, and WSLC the
  Windows SDK bundle from `Package.WindowsSdk.TestBundle.Job.yml`, in the same
  workflow run, so what gets tested is exactly what got built.
- The matrix is **declarative**. `scripts/ci/validation-test-matrix.json` is the
  only file you edit to change *what runs where*;
  `scripts/ci/resolve-validation-test-matrix.mjs` validates it and expands a
  plan into GitHub Actions matrices.
- Validation runs **on a schedule, not on PRs**.

## Moving parts

| File | Role |
|------|------|
| `.github/workflows/Validation.Tests.Scheduled.yml` | Scheduled entry point. Builds artifacts, then calls the matrix job. |
| `.github/workflows/Validation.Tests.Matrix.Job.yml` | `workflow_call`-only. Resolves the plan and runs the per-family test jobs. |
| `.github/workflows/Package.WindowsSdk.TestBundle.Job.yml` | `workflow_call`-only. Builds the Windows SDK test bundle natively on x64 and arm64 and uploads it as `windows-sdk-test-bundle-<target>`. |
| `scripts/ci/build-windows-sdk-test-bundle.ps1` | Builds the IsolationSession, ProcessContainer, and WSLC SDK test payloads and checks that each payload discovers its tests. |
| `scripts/ci/stage-isolation-session-test-helpers.ps1` | Inspects staged suites and copies the known helpers they dot-source; a required helper missing from the selected checkout fails packaging. |
| `scripts/ci/stage-nvx-validation-tests.ps1` | Stages the compiled Windows x64 SDK MicroVM tests in the existing Windows artifact and checks required test discovery. |
| `scripts/ci/Invoke-CratePackage.ps1 -VerifyMicrovmTests` | Extracts the `mxc-sdk` archive, requires its seven MicroVM fixtures, and compiles `nvx_e2e` with `microvm` on Windows x64 without running a VM. |
| `scripts/ci/validation-test-matrix.json` | The matrix: OS versions, backends, triggers, job staggering. |
| `scripts/ci/resolve-validation-test-matrix.mjs` | Matrix validator + plan expander. Emits the GitHub Actions matrices. |
| `scripts/ci/prepare-windows-host.ps1` | Per-backend Windows host preparation / prerequisite assertions, plus the `winget` repair and the workload-tooling install. Runs in Windows PowerShell, because it installs the `pwsh` the steps after it use. |
| `scripts/ci/prepare-linux-host.sh` | Per-backend Linux package install and service startup (distro-aware), plus the workload-interpreter inventory. |
| `scripts/ci/prepare-macos-host.sh` | Per-backend macOS host preparation / prerequisite assertions. |
| `scripts/ci/run_backend_validation_tests.ps1` | Windows dispatcher: backend id → existing backend suite. Also points `TEMP` at the directory CI passes as `-TempDirectory`, so logs get collected. |
| `scripts/ci/run_backend_validation_tests.sh` | Linux/macOS dispatcher: backend id → existing backend suite. |

### Flow

```
Validation.Tests.Scheduled.yml
  └─ dependency-feed-check
      ├─ windows / linux / macos    →  Build.*.Job.yml  (upload artifacts)
      ├─ windows-sdk-bundle         →  Package.WindowsSdk.TestBundle.Job.yml  (upload bundle)
      └─ test-nightly / test-weekly →  Validation.Tests.Matrix.Job.yml
            └─ resolve  →  resolve-validation-test-matrix.mjs --plan <plan>
                 ├─ windows job (matrix) → download artifact (+ SDK bundle for process/isolation-session/wslc) → prepare-windows-host.ps1 → run_backend_validation_tests.ps1
                 ├─ linux   job (matrix) → download artifact → prepare-linux-host.sh   → run_backend_validation_tests.sh
                 └─ macos   job (matrix) → download artifact → prepare-macos-host.sh  → run_backend_validation_tests.sh
```

An entry point **must** build the artifacts before calling the matrix job — the
test jobs only ever `download-artifact`.

## Jobs

### `Validation.Tests.Scheduled.yml` — "Scheduled Validation Tests"

| Job | What it does |
|-----|--------------|
| `dependency-feed-check` | Resolves the locked crate graph through the public `MxcDependencies` feed. Gates the builds. |
| `windows` | `Build.Windows.Job.yml` — x64 + arm64 release build, unit tests, uploads `wxc-binaries-<target>`. The x64 artifact also includes SDK MicroVM tests and the complete signed NVX bundle. |
| `linux` | `Build.Linux.Job.yml` — x64 + arm64 release build, unit tests including Bubblewrap seccomp and argument generation, Bubblewrap SDK streaming/PTY tests, `wxc_e2e_tests`, uploads `lxc-binaries-<target>`. |
| `macos` | `Build.MacOS.Job.yml` — arm64 release build, unit tests, Seatbelt SDK streaming/PTY tests, `wxc_e2e_tests`, uploads `mxc-binaries-aarch64-apple-darwin`. |
| `windows-sdk-bundle` | `Package.WindowsSdk.TestBundle.Job.yml` — uploads `windows-sdk-test-bundle-<target>` for x64 + arm64. |
| `test-nightly` | Calls the matrix job with `plan: nightly`. Runs on every schedule tick and on a `nightly` dispatch. |
| `test-weekly` | Calls the matrix job with `plan: weekly`. Runs only on the Sunday cron and on a `weekly` dispatch. |

Both the standalone bundle builder and the Azure two-branch package template use the shared helper stager. The Azure template loads it from its `self` checkout (`lock-check`), but resolves helper sources against the selected main or feature checkout. Older suites that do not dot-source `LoopbackAnchor.ps1` do not require or package it. Referencing suites must include it, including in the standalone builder's required-file check. Run `scripts/ci/test-isolation-session-test-helpers.ps1` for the offline staging regression checks.

Build artifacts are kept for 1 day — they exist only to feed these jobs. The
test jobs need the three builds; a failed SDK bundle fails the ProcessContainer,
IsolationSession, and WSLC jobs at their bundle download.

### `Validation.Tests.Matrix.Job.yml` — "Create Validation Test Matrix"

| Job | Runner | What it does |
|-----|--------|--------------|
| `resolve` | `ubuntu-latest` | Runs the resolver, emits one matrix per OS family plus `has_<family>` flags so an empty family is skipped rather than failing on an empty matrix. |
| `windows` | `A self-hosted 1ES Pool` | Download artifact (plus the SDK bundle for `process`, `isolation-session`, and `wslc`) → `prepare-windows-host.ps1 -Backend <backend id>` → `run_backend_validation_tests.ps1 -Backend <backend id>`. |
| `linux` | `A self-hosted 1ES Pool` | Download artifact → `prepare-linux-host.sh <backend id>` → `run_backend_validation_tests.sh <backend id>` (under `sudo` for LXC). |
| `macos` | GitHub-hosted `${{ matrix.runner }}` | Download artifact → `prepare-macos-host.sh <backend id>` → `chmod +x` → `run_backend_validation_tests.sh <backend id>`. |

Per-job display name: `<platform id>, <architecture>, <backend>` (macOS omits
the architecture). Job timeout 180 min; host prep 15 min (20 on Windows); the
test step 45 min on Linux and 60 on Windows and macOS, so a hung backend fails
while the log is still useful. Logs are
uploaded either way — see [Log collection](#log-collection).

## The catalog

`scripts/ci/validation-test-matrix.json` has two sections.

### `platforms`

Declares an OS image and, per architecture, the build it consumes, the host pool
it runs on, and **which backends that platform is capable of running in CI**. This is
a capability declaration, not a schedule.

| Field | Meaning |
|-------|---------|
| `id` | Stable key referenced by `triggers`. Also the value shown in job names. |
| `displayName` | Human label (emitted as `os_name`). |
| `family` | `windows` \| `linux` \| `macos` — selects the matrix job and the dispatcher. |
| `architectures.<x64\|arm64>.target` | Rust target triple. |
| `architectures.<…>.artifact` | Build artifact name to download. |
| `architectures.<…>.pool` | 1ES pool name (Windows/Linux). **An empty string means "declared but never scheduled"** — the entry stays documented but dormant. |
| `architectures.<…>.runner` | GitHub-hosted runner label (macOS only; required there). |
| `architectures.<…>.backends` | Backend ids this platform/arch can run. |

Current platforms:

| Platform id | Family | x64 pool | arm64 pool | Declared backends (x64) | Declared backends (arm64) |
|-------------|--------|----------|------------|--------------------------|------------|
| `windows-prerelease-process-container` | windows | `1es-mxc-windows-prerelease-t1-x64` | `1es-mxc-windows-prerelease-t1-arm64` | process, isolation-session, wslc, windows-sandbox, microvm | process, isolation-session |
| `windows-prerelease-isolation-session` | windows | `1es-mxc-e2e-win-prerelease-isolationsesh-x64` | `1es-mxc-e2e-win-prerelease-isolationsesh-arm64` | same as above | same as above |
| `windows-26h2` | windows | `1es-mxc-windows-26h2-pro-x64` | `1es-mxc-windows-26h2-pro-arm64` | process, wslc, windows-sandbox, microvm | process, isolation-session |
| `windows-prerelease-26h1` | windows | `1es-mxc-windows-prerelease-26h1-x64` | `1es-mxc-windows-prerelease-26h1-arm64` | process, isolation-session, wslc, windows-sandbox, microvm | process, isolation-session |
| `windows-25h2` | windows | `1es-mxc-e2e-windows-25h2-pro-x64` | `1es-mxc-e2e-windows-25h2-pro-arm64` | process, wslc, windows-sandbox, microvm | process, isolation-session |
| `windows-24h2` | windows | `1es-mxc-e2e-windows-24h2-pro-x64` | `1es-mxc-e2e-windows-24h2-pro-arm64` | process, wslc, windows-sandbox, microvm | process, isolation-session |
| `windows-23h2` | windows | `1es-mxc-e2e-windows-23h2-enterprise-x64` | *(dormant)* | wslc, windows-sandbox, microvm | — |
| `ubuntu-26.04` | linux | `1es-mxc-e2e-ubuntu-26.04-x64` | *(dormant)* | bubblewrap, lxc | — |
| `ubuntu-24.04` | linux | `1es-mxc-e2e-ubuntu-24.04-x64` | *(dormant)* | bubblewrap, lxc | — |
| `rhel-10` | linux | `1es-mxc-e2e-rhel-10-x64` | *(dormant)* | bubblewrap, lxc | — |
| `debian-13` | linux | `1es-mxc-e2e-debian-13-x64` | *(dormant)* | bubblewrap, lxc | — |
| `macos-27` | macos | — | runner `xcode-27` (public preview) | — | seatbelt |
| `macos-26` | macos | — | runner `macos-26` | — | seatbelt |
| `macos-15` | macos | — | runner `macos-15` | — | seatbelt |

ARM64 is declared throughout but dormant wherever CI cannot run it: no Azure VM SKU offers nested
virtualization on ARM CPUs yet, so only backends that don't require virtualization are supported. macOS is ARM64-only.

### Backend ids

A backend id is passed straight through: the matrix job hands it to the host-prep
script and then to the dispatcher, which has one `switch`/`case` per id. The
`process` case requires `wxc-exec --probe` to report an enabled native PSEC
contract, then runs a filesystem smoke test, public SDK streaming tests, and
the native network and policy suites against the downloaded artifacts.
The network and policy suites delegate their focused loopback and enumeration
checks to standalone native runners. These retain the host controls and
enforcement assertions; enumeration also checks live request-probe agreement
and fixture security on supported and unsupported hosts.

The policy suite also runs the native CLI contract boundary cases, including
the six network-policy rejection shapes and a launched valid control for each
minimum/stable/development contract, and issue #694's DOS/NT final-path
regression. The SDK bundle builder compiles the
final-path fixture into `inproc/mxc-final-path-probe.exe`; validation passes it
explicitly and does not compile it on test hosts. Native UI coverage includes
permissive contained controls and policy permutations for clipboard, input
injection, system parameters, display-settings validation, and desktop control,
alongside the existing handle and atom isolation cases. Inconclusive host
operations are reported as skips, not passing policy assertions.

`tests/scripts/run_processcontainer_workload_tests.ps1` restores the application
workloads for manual native-PSEC use only. It is not included in this matrix or
called by the native policy suite.

`isolation-session` and `wslc` run every suite and report each one. For
`wslc` that is the command-line suite from the build artifact plus the .NET and
Node create-and-run and lifecycle suites from the SDK bundle. The SDK suites skip unless
`MXC_ENABLE_WSLC_TESTS=1`, which the dispatcher sets, and a suite that executed
no tests is reported as a failure, so a WSLC host can never pass on skipped SDK
tests.

An unwired backend fails loudly on purpose: adding it to a trigger produces a
red job ("write the tests or remove it"), never a green no-op. The dispatchers'
accepted-id lists (`ValidateSet` on Windows, the `case` arms on Unix) are what
catch a typo'd id in the catalog.

### `triggers`

Names the OS/backend pairs a plan runs. Entries are architecture-neutral:
expansion emits a job for every architecture of that platform that declares the
backend **and** has a non-empty pool.

| Plan | Wired to | Contents today |
|------|----------|----------------|
| `nightly` | scheduled Mon–Sun | All tests. |
| `weekly` | scheduled Sunday | empty |
| `pr` | *(nothing — `Build.yml` does not call the matrix job)* | empty; reserved for a potential future PR-time subset |
| `enabled` | *(nothing — resolvable locally only)* | reserved for testing this infrastructure and rapid iteration |

### `backendDelayedStart`

Optional. This section staggers the start of jobs
for a named backend instead of letting them all begin at once:

```json
"backendDelayedStart": [
  { "backend": "wslc", "seconds": 30 }
]
```

Every runner in a pool shares one egress address, so a backend whose setup
pulls down a large runtime or several container images concentrates all that
traffic into a burst the moment its jobs start together. Public registries
answer with rate limiting and stalled downloads.

`seconds` is the gap between consecutive jobs of that backend, counted per
backend and following the resolved job order. With the example entry above,
four WSLC jobs would start at 0, 30, 60, and 90 seconds.

Avoid long delays since idle runners might be harvested.

## Backend status

Snapshot of what the matrix actually proves today. Update this table as backends
get fixed or wired.

| Backend | Status | Notes |
|---------|--------|-------|
| ProcessContainer | ✅ Good | Requires native PSEC; verifies public SDK streaming, filesystem policy and aliases, CLI contract boundaries, DOS/NT final paths, egress/loopback/proxy rules, the functional UI matrix, HANDLES, and global atoms. Unsupported host capabilities must reject requests. Privilege removal uses a host-token control. Application workload tests remain manual-only. |
| Bubblewrap | ✅ Good | The scheduled CLI suite checks controlling-terminal isolation with private PTY fixtures, including redirected stdio. The Linux build job also checks SDK pipes under a controlling terminal, cancellation without parent-death protection, and private-PTY input/output and resizing. These checks do not require enabling legacy TIOCSTI. |
| LXC | ✅ Good | Some networking tests fail on distros other than Ubuntu 24.04; seems to be an issue with MXC. The in-process streaming handle is covered at PR time by `lxc-e2e.yml` instead, because this matrix runs prebuilt binaries. |
| WSLC | ✅ Good | Might have to retry hung jobs - this is an issue with overzealous agent reclaiming. |
| IsolationSession | ✅ Good | Runs the one-shot and state-aware suites, the Rust SDK in-process and helper tests, the C# end-to-end tests, the Node SDK suite and the COM apartment probe. Fails when the host cannot run isolation sessions, when a suite executes nothing, or when the run changes the set of local accounts. |
| Windows Sandbox | ⛔ Blocked | Images don't support `Containers-DisposableClientVM` opt. feature |
| MicroVM | Experimental | Windows 25H2 x64 nightly runs the prebuilt `mxc-sdk/tests/nvx_e2e.rs` suite, including executor config scenarios, captured JSON execution, and real console interruption during startup and execution with VM/state cleanup assertions. Host-only and extracted-crate compilation checks remain in normal Windows x64 PR builds. |
| Seatbelt | ✅ Good | Failures are genuine MXC bugs. |

### ProcessContainer SDK streaming

Every scheduled `process` job downloads the architecture-matched Windows SDK
test bundle. The bundle contains native test executables, self-contained .NET
tests, and the Node SDK with its Node 24.21.0 runtime; validation hosts do not
compile or restore SDK dependencies.

The dispatcher explicitly runs the ignored Rust bidirectional-stdio test,
enables `MXC_E2E_PSEC_CAPABLE_HOST` for the .NET `MxcProcessTests`, and runs the
Node public `run` and `spawn` integration cases. The .NET suite checks stdin,
stdout, stderr, large output, cancellation, kill, and timeout behavior.
Required test names and methods must pass; empty selections and skipped
streaming cases fail the job even when the runner exits successfully.

### IsolationSession Rust test concurrency

Tests in `src/mxc-sdk/tests/isolation_session.rs` that create sessions use
`#[serial_test::serial(isolation_session)]` to prevent independent tests from
overlapping, including under ordinary `cargo test`. Apply the same attribute to
new tests that create sessions. Policy-only tests remain parallel.

The lock is local to the test process. Cargo and the validation bundle run test
executables sequentially. The `concurrent_one_shot_runs_stay_isolated` test still
checks concurrent sessions within its own test; the lock keeps other tests out
while it runs.

## Host preparation

Preparation runs before the tests, keyed by the matrix backend id. A backend
with no prerequisites is an explicit no-op, so the step runs unconditionally for
every entry.

`prepare-windows-host.ps1`:

- `process` — no host mutation; the test requires the native probe to report
  PSEC.
- `microvm` — asserts the SDK test executable and signed NVX runtime files are
  in the artifact, adds a Defender exclusion for the binary directory, and
  requires the Windows Hypervisor Platform feature *and* a running hypervisor.
  The dispatcher runs the prebuilt SDK tests without Cargo and fails on missing
  VM completion markers, empty suites, skipped tests, or filtered tests.
- `wslc` — asserts `wslcsdk.dll` shipped, requires the WSL and
  VirtualMachinePlatform optional features to be baked into the image, then
  installs/updates the WSL runtime (including the pre-release ring) up to the
  minimum version parsed from `WSLC_SDK_VERSION` in
  `src/mxc-sdk/build/build_wslc_common.rs`.
- everything else — prints a "no prerequisites yet" line.

Windows optional features are **verified, never enabled**: turning one on needs a
reboot the job cannot take, so a mis-imaged pool fails here with a pointed
message instead of surfacing later as an opaque backend error.

The script does provision two things, for every backend rather than a particular
one: `Repair-Winget` re-registers the App Installer package when `winget` is on
`PATH` but cannot run, and `Install-WorkloadTooling` then installs `pwsh`,
`node`, `python`, `winapp`, and `openssl`
([below](#who-installs-what)).

Every run also opens with the host's Windows caption, release, build, and
edition. The matrix schedules by pool name, so that banner is the only evidence
in the log that a pool really booted the release it advertises. ProcessContainer
jobs require native PSEC and run `run_base_container_network_tests.ps1` after
the checked filesystem write/read smoke. Network cases verify omitted and explicit host-loopback
deny, allow with either ingress default, and successful proxy access paired with
denied direct access to other IPv4/IPv6 loopback endpoints. It retains stdout,
stderr, request JSON, and diagnostic logs under the job's temporary directory.
`run_processcontainer_policy_tests.ps1` also runs allowed and forbidden filesystem
operations, canonical/extended/available-8.3 aliases, unsupported-policy rejection
before workload execution, Win32k on/off controls, bidirectional atom isolation
with a shared-namespace control, and HANDLES access using the published UI probe
with an uncontained host-window control. Forbidden token privileges must be
absent, not merely disabled; that case reports an explicit skip if the host
token has none of the tested privileges. Denied paths, native enumeration, and
denial capture verify enforcement when advertised and fail-closed rejection
otherwise. Deterministic Rust tests also force each unsupported-capability
decision through selection, dispatch, and probing under the shared test lock.

The two native suites use Windows PowerShell 5.1 from
`%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe` for their contained
workloads, always with `-NoProfile -NonInteractive -ExecutionPolicy Bypass`.
They share `tests/scripts/lib/processcontainer_policy_probe.ps1`; Python and
Node are not prerequisites for either suite. The timeout grandchild is a
uniquely named copy of Windows PowerShell with its matching configuration.
Global-atom calls use the shipped `wxc-ui-probe` rather than compiling C# inside
the container. Win32k-disabled cases launch that native probe directly, without
a shell; `WIN32K --win32k-query=true` reads the process mitigation policy instead
of running the potentially blocking GUI-message probe.

The native policy suite snapshots fixture owner/DACL SDDL around every
container run, including rejected requests. It also covers overlapping path
grants with a deny-free sibling control. The main filesystem and
compatibility-consent workloads pause at a ready/release handshake so their
SDDL can also be checked while they are alive. It covers
learning-mode enforcement, explicit capture paths and warnings, multiple
capabilities, environment/cwd/exit propagation, and timeout cleanup of a
ready-signalled grandchild. UI checks cover all four isolation values and use
uncontained positive controls for clipboard, desktop creation, and a no-op
mouse-speed setter. Clipboard tests run only for text-only clipboards; non-text
formats or an unavailable clipboard produce an explicit skip before any change.
Text is saved with `Get-Clipboard -Raw`, restored (or cleared when originally
empty) in `finally`, and read back for equality. Display-mode
changes, input injection, logoff, and IME behavioral controls remain deferred
because they lack safe, reliable runner controls.

Network cases additionally cover all three no-network spellings, the
deny/allow and allow/allow capability rows, proxy environment variables and
external bypass prevention, UDP/53 allow rules, and ICMP denial. External host
controls precede negative cases. Paired direct UDP/53 queries check DNS packet
enforcement without relying on the Windows resolver cache; they first require
a successful query to the same resolver from the host. Curl name resolution
without a UDP/53 rule is not used as a denial oracle or diagnostic gate because
host DNS Client behavior and address rotation cannot be attributed to the
contained process's UDP policy. The successful curl case with TCP/443 and
UDP/53 rules remains required.

`prepare-linux-host.sh`:

- `bubblewrap` — installs `bwrap`, `slirp4netns`, `util-linux`, and `iptables`
  (apt/dnf/yum/microdnf), verifies their required commands, and relaxes
  `kernel.apparmor_restrict_unprivileged_userns` (ephemeral CI hosts only).
- `lxc` — installs the LXC stack, reloads the AppArmor profile, starts and waits
  for `lxcbr0`, and moves the bridge into firewalld's trusted zone on a host
  running firewalld. On RHEL-likes it needs EPEL first, because Red Hat dropped
  LXC after RHEL 7 and ships no replacement. Without the zone assignment the
  default zone rejects the container's IPv4 DHCP, and a container holding only
  an IPv6 address fails every network test.

The historical Linux `microvm` preparation branch is not scheduled. The
Phase 1 NVX runtime supports only Windows x64.

Every install above goes through two shared helpers rather than its own
package-manager chain: `resolve_package_manager` picks the first of `apt-get`,
`dnf`, `yum`, or `microdnf` on the host and caches it, and `install_packages`
holds the single `case` that knows how each one is invoked. Supporting a new
distribution family is therefore one new arm in `install_packages`, not another
branch in every installer. `install_packages` returns the package manager's own
status rather than acting on it, so each caller decides what a failure means.

`prepare-macos-host.sh`:

- `seatbelt` — asserts `mxc-exec-mac` shipped. The sandbox is part of the OS, so
  there is nothing to install; the script exists so macOS has the same shape as
  the other two and a future prerequisite has an obvious home.

Every one of the three scripts also takes the workload-interpreter inventory
([below](#workload-interpreters)) before it dispatches on the backend id.

### Workload interpreters

Some suites do not just exercise MXC's primitives — they run *real programs*
inside the sandbox and assert on what those programs produce. Each preparation
script inventories those programs on the host up front, so a missing one is
reported once, as a preparation result, rather than repeatedly as a confusing
mid-suite failure.

#### The list

| Interpreter | Platforms | Version | Notes |
|-------------|-----------|---------|-------|
| `pwsh` | all | Latest | Installed per job on Windows — see below. The only entry whose absence fails a job, and only on Windows. |
| `git` | all | Latest | |
| `node`, `npm`, `npx` | all | Latest LTS | `npm` and `npx` arrive with Node. Installed per job on Windows. |
| `python`, `pip` | all | Latest stable | Windows tries `python` first, Unix `python3`. Installed per job on Windows. |
| `dotnet` | all | Latest LTS | Currently 10.x, from the `LTS` channel — resolved at image-build time, not pinned. |
| `az` | all | Latest | No ARM64 Windows build exists; ARM64 images get the x64 one under emulation. |
| `gh` | all | Latest | |
| `openssl` | all | Latest | On Windows, installed per job — see below. |
| `nuget` | Windows | Latest | Unix reaches NuGet through `dotnet nuget`, so looking for a binary there would warn forever. |
| `winapp` | Windows | Latest | The Windows App Development CLI. Installed per job — see below. |
| `winget` | Windows | Image | The only entry allowed to resolve inside `WindowsApps`. |
| `scoop`, `choco` | Windows | Latest | |
| `brew` | macOS | Latest | |

Nothing is pinned to an exact version: an image-provided entry is whatever was
current when the image was built, and a per-job install is whatever the source
offers that day — the LTS line for Node, and for Python the newest stable minor,
since Python publishes no LTS line of its own.

The list is **suite-agnostic by design** and is checked for every backend, not
only the ones whose suites need it today: it describes what a validation *host*
provides, not what any one suite consumes.

Each script carries its own copy — `Assert-WorkloadInterpreters` in
`prepare-windows-host.ps1`, `assert_workload_interpreters` in the two `.sh`
scripts — so the platform lists can diverge.

#### Missing means a warning, not a failure

Only `pwsh` on Windows is required; everything else warns, because suites are
expected to report their dependent cases as skipped rather than failing. Nothing
is required on Unix yet.

The cost is that an absent interpreter silently shrinks coverage while the job
still shows green. GitHub's pass/fail icon cannot express "passed, but with less
coverage than yesterday" — a future test-analysis portal is intended to surface
skip counts so that erosion is visible.

On Windows a command resolving under `WindowsApps` does not count. That is
normally a Microsoft Store `AppExecutionAlias` stub: a 0-byte redirect that
opens the Store rather than running. App Installer legitimately ships `winget`
that way, and a working alias is indistinguishable from a stub — both are 0-byte
reparse points — so `winget` alone opts out of the filter.

#### Who installs what

Every pool runs images pre-provisioned with programs installed by
`ubuntu-debian-provision.sh` / `rhel-provision.sh` for Linux and 
`windows-provision.ps1` for Windows. These scripts are located in the
`validation-provision-artifacts` branch in the ADO repo. On Windows that
script covers `dotnet`, `choco`, `scoop`, `az`, `gh` and `nuget`; `git` comes
from a separate image artifact.

During the start of a job, the installed programs are inventoried. On Linux and
macOS no job installs a workload interpreter. Windows installs five of them
through the repaired winget - `pwsh`, `node`, `python`, `openssl`, and `winapp`.

A backend's own prerequisites are separate and are still installed per job by
`prepare-linux-host.sh` — see [Host preparation](#host-preparation).

## Log collection

Every job uploads its logs whether it passed or failed, as
`logs-<plan>-<os>-<arch>-<backend>-<attempt>`, kept 7 days.

The catch is that `$env:TEMP` is not `$RUNNER_TEMP`. The Windows suites write their
scratch trees, transcripts, and results files under the user's temp directory
(`C:\Users\<user>\AppData\Local\Temp`), but `upload-artifact` reads from
`${{ runner.temp }}` (`C:\a\_work\_temp`). Anything left in the former is simply
never collected, which is why the artifact used to arrive nearly empty.

So the Windows run step passes `-TempDirectory $RUNNER_TEMP/mxc-test-temp` to
`run_backend_validation_tests.ps1`, which points `TEMP` and `TMP` there before it
dispatches. Parameter defaults, `[System.IO.Path]::GetTempPath()`, and child
processes all read those variables, so everything temp-rooted lands in the upload
directory without CI having to know a single filename. The upload takes that folder
and `mxc-ci.log`, not all of `$RUNNER_TEMP`, which the runner and the job's actions
also use.

Linux and macOS need none of this — those suites log to stdout, and the run
step tees that into `$RUNNER_TEMP/mxc-ci.log`.

The Windows SDK test bundle downloads under `artifacts/bin`, outside
`$RUNNER_TEMP`, so it is not uploaded again with the logs.

MicroVM validation writes `microvm-nvx.log` and `microvm-perf-results.json`
under the redirected temporary directory, so the normal Windows log upload
collects both. The signed NVX bundle stays under `artifacts/bin` and is not
uploaded again. The former standalone `microvm-e2e.yml` workflow is retired;
real VM execution is scheduled rather than run on each PR.

## Runbook

Always finish with a local resolve, which runs the full catalog validation:

```bash
node scripts/ci/resolve-validation-test-matrix.mjs --plan nightly
```

An invalid catalog fails here and in the `resolve` job — before any specialized
test runner is allocated.

### Schedule an existing backend on an existing OS

1. Add the backend id to that platform/arch's `backends` list in
   `validation-test-matrix.json` if it isn't already declared.
2. Add it to the platform's entry under the plan you want in `triggers`,
   creating the `{ "os": …, "backends": [] }` entry if the platform isn't listed.
3. Confirm the platform/arch has a non-empty `pool` (or `runner` on macOS) —
   otherwise it silently resolves to nothing.
4. Resolve locally and check the new combination appears.

### Stop running something

- **Temporarily, one backend:** remove it from the `triggers` entry. The
  platform keeps declaring the capability.
- **Temporarily, a whole platform/arch:** blank its `pool` (`""`). It stays
  documented but is never scheduled.
- **Permanently:** remove the trigger entry, then the `backends` entries, then
  the platform. If that leaves a backend id declared nowhere, decide whether to
  keep its dispatcher and host-prep branches (harmless) or delete them too.

### Add a new backend

1. **Catalog:** add the id to the `backends` list of every platform/arch that
   can run it. There is no separate registration step — the id *is* the
   dispatcher argument.
2. **Dispatcher:** add a case to `run_backend_validation_tests.ps1` (`ValidateSet` +
   `switch`) or `run_backend_validation_tests.sh` (`usage` + `case`), pointing at the
   suite. Until a suite exists, leave the explicit throw / `exit 2` so
   accidental activation fails loudly.
3. **Host prep:** add a branch to `prepare-windows-host.ps1` (`ValidateSet` +
   `switch`), `prepare-linux-host.sh`, or `prepare-macos-host.sh` (`usage` +
   `case`). Skip only if there is genuinely nothing to install or assert.
4. **Artifact:** make sure everything the suite needs is in the
   `Upload binaries` list of the relevant `Build.*.Job.yml`, and that the build
   enables the backend's cargo feature.
5. **Trigger:** add the OS/backend pair to a plan.

If two ids should run the same suite, give each its own `case` and have both
call a shared function so they can diverge later without workflow changes.

### Add a new OS image

1. Stand up the 1ES pool (Windows/Linux) with the required optional features
   already baked into the image — the jobs verify but never enable them.
2. Add a `platforms` entry: `id`, `displayName`, `family`, and per-architecture
   `target`, `artifact`, `pool`/`runner`, and `backends`.
3. For a new Linux distro, check that `prepare-linux-host.sh` handles its
   package manager and service layout. A new package-manager family needs one
   arm in `install_packages` and one entry in `resolve_package_manager`; a
   family whose package *names* differ also needs its column in the tables in
   `install_lxc` and `install_bubblewrap`.
4. Add it to a plan's `triggers`, then resolve locally.

### Wire an unwired backend to a suite

Replace the explicit failure in the dispatcher with the suite invocation, add
any host prerequisites, then add the OS/backend pair to a trigger. Always verify 
by testing it ahead of time. 

### Stagger a backend's job starts

Add or edit its `backendDelayedStart` entry in the catalog, then resolve
locally to confirm the offsets. Worth reaching for when a backend's setup is
network-heavy enough that concurrent jobs run into rate limits or stalled
downloads — and worth removing again once that pressure is gone.

### Collect a new log file

Have the suite write it under `$env:TEMP`. The dispatcher redirects that to the
upload directory, so nothing in CI needs to change. See
[Log collection](#log-collection).

### Change the schedule

Everything schedule-related lives in `Validation.Tests.Scheduled.yml`: the two
`cron` entries, the `if:` conditions on `test-nightly` / `test-weekly`, and the
`workflow_dispatch` `plan` choices. Keep the three in sync — a new plan needs a
cron *and* a job condition *and* a dispatch choice.

### Add a new plan

1. Add the key to `triggers` in the catalog. That is what defines the plan —
   `resolve-validation-test-matrix.mjs` derives its plan list from these keys,
   so it needs no edit.
2. Copy the `test-weekly` job for it, changing the cron and plan in its `if:`
   and its `plan` input, and add a `workflow_dispatch` choice if it should be
   runnable on demand.

### Enable ARM64

Set the ARM64 `pool` for the platform. That is the whole switch: an
architecture with an empty pool is skipped during expansion, so filling one in
is what puts its jobs in the matrix. Note that the resolver rejects
`microvm` on ARM64 outright (x64-only runtimes), and the WSLC
dispatcher still refuses non-x64.

## Testing Your Changes to the Validation Infrastructure

1. Pick a pre-existing trigger or make a custom trigger with the tests you plan 
   to run in `scripts/ci/validation-test-matrix.json`. 
2. Create a workflow file in your branch with the following code, replacing the 
   branch name and plan name with your branch name and trigger name respectively.
3. Push your changes.

```yml
name: Validation Infrastructure Testing

on:
  push:
    branches:
      - # BRANCH NAME HERE

concurrency:
  group: validation-infra-pr-tests-${{ github.ref }}
  cancel-in-progress: true

permissions:
  actions: read
  contents: read

jobs:
  dependency-feed-check:
    uses: ./.github/workflows/Dependency.Feed.Check.Job.yml

  windows:
    needs: dependency-feed-check
    uses: ./.github/workflows/Build.Windows.Job.yml

  linux:
    needs: dependency-feed-check
    uses: ./.github/workflows/Build.Linux.Job.yml

  macos:
    needs: dependency-feed-check
    uses: ./.github/workflows/Build.MacOS.Job.yml

  windows-sdk-bundle:
    needs: dependency-feed-check
    uses: ./.github/workflows/Package.WindowsSdk.TestBundle.Job.yml

  test:
    needs: [windows, linux, macos, windows-sdk-bundle]
    if: >-
      ${{ !cancelled() && needs.windows.result == 'success' && needs.linux.result == 'success'
      && needs.macos.result == 'success' }}
    uses: ./.github/workflows/Validation.Tests.Matrix.Job.yml
    with:
      plan: # YOUR PLAN HERE
```

## Important to Note

- **A green job does not prove a suite ran.** Several suites print `SKIPPED`
  and exit 0 on an unsupported host. A matrix entry asserts the host *should*
  support the backend, so a silent skip there is a coverage gap — check the
  `SKIPPED` line or the executed count in the log, not just the exit status.
- **Empty pool = invisible.** A trigger entry pointing at a platform whose pool
  is blank resolves to zero jobs and reports nothing. Resolve locally after any
  catalog edit.
- **All OS build jobs must pass** before validation testing happens. 
- **Artifacts live one day.** Re-running a test job long after the build has
  expired fails at download; re-run the whole workflow instead.
