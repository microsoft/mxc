# Validation (E2E) test infrastructure

How MXC runs its backend end-to-end suites across real operating systems, what
each job covers today, and what to change when you need to add, remove, or
retire something.

This document describes the GitHub Actions validation matrix only. PR-time
build/lint/SDK validation is covered by [`pull-requests.md`](pull-requests.md);
the individual local test scripts are documented in
[`tests/scripts/README.md`](../tests/scripts/README.md).

## At a glance

- Validation tests **never build from source**. They download the artifacts
  produced by `Build.Windows.Job.yml` / `Build.Linux.Job.yml` /
  `Build.MacOS.Job.yml` in the same workflow run, so what gets tested is exactly
  what got built.
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
| `scripts/ci/validation-test-matrix.json` | The matrix: OS versions, backends, triggers, job staggering. |
| `scripts/ci/resolve-validation-test-matrix.mjs` | Matrix validator + plan expander. Emits the GitHub Actions matrices. |
| `scripts/ci/prepare-windows-host.ps1` | Per-backend Windows host preparation / prerequisite assertions. |
| `scripts/ci/prepare-linux-host.sh` | Per-backend Linux package install and service startup (distro-aware). |
| `scripts/ci/prepare-macos-host.sh` | Per-backend macOS host preparation / prerequisite assertions. |
| `scripts/ci/assert-workload-interpreters.sh` | Shared Linux/macOS workload-interpreter inventory check. |
| `scripts/ci/run_backend_validation_tests.ps1` | Windows dispatcher: backend id → existing backend suite. Also points `TEMP` at `$RUNNER_TEMP` so logs get collected. |
| `scripts/ci/run_backend_validation_tests.sh` | Linux/macOS dispatcher: backend id → existing backend suite. |

### Flow

```
Validation.Tests.Scheduled.yml
  └─ dependency-feed-check
      ├─ windows / linux / macos    →  Build.*.Job.yml  (upload artifacts)
      └─ test-nightly / test-weekly →  Validation.Tests.Matrix.Job.yml
            └─ resolve  →  resolve-validation-test-matrix.mjs --plan <plan>
                 ├─ windows job (matrix) → download artifact → prepare-windows-host.ps1 → run_backend_validation_tests.ps1
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
| `windows` | `Build.Windows.Job.yml` — x64 + arm64 release build, unit tests, uploads `wxc-binaries-<target>`. |
| `linux` | `Build.Linux.Job.yml` — x64 + arm64 release build, unit tests, `wxc_e2e_tests`, uploads `lxc-binaries-<target>`. |
| `macos` | `Build.MacOS.Job.yml` — arm64 release build, unit + `wxc_e2e_tests`, uploads `mxc-binaries-aarch64-apple-darwin`. |
| `test-nightly` | Calls the matrix job with `plan: nightly`. Runs on every schedule tick and on a `nightly` dispatch. |
| `test-weekly` | Calls the matrix job with `plan: weekly`. Runs only on the Sunday cron and on a `weekly` dispatch. |

Build artifacts are kept for 1 day — they exist only to feed these jobs.

### `Validation.Tests.Matrix.Job.yml` — "Create Validation Test Matrix"

| Job | Runner | What it does |
|-----|--------|--------------|
| `resolve` | `ubuntu-latest` | Runs the resolver, emits one matrix per OS family plus `has_<family>` flags so an empty family is skipped rather than failing on an empty matrix. |
| `windows` | `[self-hosted, 1ES.Pool=<pool>, JobId=mxc-e2e-…]` | Download artifact → `prepare-windows-host.ps1 -Backend <backend id>` → `run_backend_validation_tests.ps1 -Backend <backend id>`. |
| `linux` | `[self-hosted, 1ES.Pool=<pool>, JobId=mxc-e2e-…]` | Download artifact → `prepare-linux-host.sh <backend id>` → `run_backend_validation_tests.sh <backend id>` (under `sudo` for LXC). |
| `macos` | GitHub-hosted `${{ matrix.runner }}` | Download artifact → `prepare-macos-host.sh <backend id>` → `chmod +x` → `run_backend_validation_tests.sh <backend id>`. |

Per-job display name: `<platform id>, <architecture>, <backend>` (macOS omits
the architecture). Job timeout 180 min; host prep 15 min; the test step 45 min
(60 on macOS), so a hung backend fails while the log is still useful. Logs are
uploaded either way — see [Log collection](#log-collection).

## The catalog

`scripts/ci/validation-test-matrix.json` has two sections.

### `platforms`

Declares an OS image and, per architecture, the build it consumes, the host pool
it runs on, and **which backends that platform is capable of running**. This is
a capability declaration, not a schedule.

| Field | Meaning |
|-------|---------|
| `id` | Stable key referenced by `triggers`. Also the value shown in job names. |
| `displayName` | Human label (emitted as `os_name`). |
| `family` | `windows` \| `linux` \| `macos` — selects the matrix job and the dispatcher. |
| `prerelease` | `true` marks an unreleased Windows image. Its `id` must be a neutral alias matching `windows-prerelease-<name>`, because the id is public in job names. |
| `architectures.<x64\|arm64>.target` | Rust target triple. |
| `architectures.<…>.artifact` | Build artifact name to download. |
| `architectures.<…>.pool` | 1ES pool name (Windows/Linux). **An empty string means "declared but never scheduled"** — the entry stays documented but dormant. |
| `architectures.<…>.runner` | GitHub-hosted runner label (macOS only; required there). |
| `architectures.<…>.backends` | Backend ids this platform/arch can run. |

Current platforms:

| Platform id | Family | x64 pool | arm64 pool | Declared backends (x64) |
|-------------|--------|----------|------------|--------------------------|
| `windows-prerelease-process-container` | windows | `1es-mxc-windows-prerelease-t1-x64` | *(dormant)* | process-t1, process-t3, isolation-session, wslc, windows-sandbox, microvm, hyperlight |
| `windows-prerelease-isolation-session` | windows | *(dormant)* | *(dormant)* | same as above |
| `windows-canary` | windows | *(dormant)* | *(dormant)* | same as above |
| `windows-25h2` | windows | `1es-mxc-e2e-windows-25h2-pro-x64` | *(dormant)* | process-t3, wslc, windows-sandbox, microvm, hyperlight |
| `windows-24h2` | windows | `1es-mxc-e2e-windows-24h2-pro-x64` | *(dormant)* | process-t3, wslc, windows-sandbox, microvm, hyperlight |
| `windows-23h2` | windows | `1es-mxc-e2e-windows-23h2-enterprise-x64` | *(dormant)* | process-t3, wslc, windows-sandbox, microvm, hyperlight |
| `ubuntu-26.04` | linux | `1es-mxc-e2e-ubuntu-26.04-x64` | *(dormant)* | bubblewrap, hyperlight, lxc |
| `ubuntu-24.04` | linux | `1es-mxc-e2e-ubuntu-24.04-x64` | *(dormant)* | bubblewrap, microvm, hyperlight, lxc |
| `rhel-10` | linux | `1es-mxc-e2e-rhel-10-x64` | *(dormant)* | bubblewrap, hyperlight, lxc |
| `debian-13` | linux | `1es-mxc-e2e-debian-13-x64` | *(dormant)* | bubblewrap, hyperlight, lxc |
| `macos-26` | macos | — | runner `macos-26` | seatbelt |
| `macos-15` | macos | — | runner `macos-15` | seatbelt |

ARM64 is declared throughout but never emitted: no Azure VM SKU offers nested
virtualization on ARM CPUs yet, so the resolver filters Windows/Linux ARM64 out
after expansion (`suppressNonMacArm64`). macOS is ARM64-only.

### Backend ids

A backend id is passed straight through: the matrix job hands it to the host-prep
script and then to the dispatcher, which has one `switch`/`case` per id. Ids that
share a suite each keep their own case so they can diverge later without a
mapping table — `process-t1` and `process-t3` both run
`WinProcessContainer-Tests.ps1`, and `process-t3` additionally runs
`T3-Workloads.ps1`. Teaching the Process Container test suite to
accept an explicit tier (so a T1 host can also be exercised
at the T3 fallback) is a worthwhile future improvement.

`process-t3` runs its two suites back to back and reports them together: a
failure in the primitives suite does not skip the workloads suite, so one job
run shows both results instead of costing a second run to triage.

The dispatcher passes `T3-Workloads.ps1` its `-GrantDriveRoot` switch. The
pwsh- and git-driven workloads resolve the whole ancestor chain of their working
directory at startup, so granting only the scratch leaf leaves them failing
before they reach the behaviour under test. Granting the drive root covers the
chain, but at T3 a policy path becomes an inheritable ACE, so it rewrites ACLs
across the system drive on every run and again on teardown — acceptable on a
disposable runner, which is why the switch is off by default and only CI opts
in. Temporary until pwsh 7.7 leaves preview.

The suite's git workloads also restamp the ownership of the repo they build.
The 1ES agent runs elevated, and an elevated token's *default owner* is
`BUILTIN\Administrators`, so a fixture created there is Administrators-owned;
git refuses such a repo ("detected dubious ownership") unless the caller is
itself an elevated administrator, which a contained process never is. That is a
property of the agent rather than of containment — the identical fixture is
user-owned on a dev box — so the suite reowns it to the current user and keeps
the two environments testing the same thing.

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
| `nightly` | scheduled Mon–Sun | 4 Windows platforms, 4 Linux platforms |
| `weekly` | scheduled Sunday | empty |
| `pr` | *(nothing — `Build.yml` does not call the matrix job)* | empty; reserved for a potential future PR-time subset |
| `enabled` | *(nothing — resolvable locally only)* | reserved for testing this infrastructure and rapid iteration |

Resolved `nightly` today = **17 jobs**: 9 Windows (prerelease × process-t1,
isolation-session, wslc; 25H2/24H2/23H2 × process-t3 + wslc) and
8 Linux (each of the four distros × bubblewrap + lxc). macOS resolves empty
because Seatbelt has no wired suite.

### `backendDelayedStart`

Optional, and **currently empty** — no backend is staggered today, so every job
starts as soon as its runner is ready. The section staggers the start of jobs
for a named backend instead of letting them all begin at once:

```json
"backendDelayedStart": [
  { "backend": "wslc", "seconds": 300 }
]
```

Every runner in a pool shares one egress address, so a backend whose setup
pulls down a large runtime or several container images concentrates all that
traffic into a burst the moment its jobs start together. Public registries
answer with rate limiting and stalled downloads.

`seconds` is the gap between consecutive jobs of that backend, counted per
backend and following the resolved job order. With the example entry above,
four WSLC jobs would start at 0, 300, 600, and 900 seconds.

The resolver puts the offset on every matrix entry as
`startup_delay_seconds` — `0` where no stagger applies, which is every entry
while the section is empty — and the job sleeps that long before its first
network step. Job timeout is a flat 180 minutes, with plenty of room for any
wait you'd reasonably configure.

Leave the section out (or empty) and every job starts as soon as its runner is
ready. A backend id that no plan schedules is accepted; it just never applies.

Do keep in mind that the runner is held while it sleeps — Actions can't defer
allocating a matrix job, so the wait has to happen inside it. Use no more than
the contention calls for. This spreads simultaneous load and nothing else; a
single download that stalls on its own is unaffected.

Leave the section out (or empty) and every job starts as soon as its runner is
ready. A backend id that no plan schedules is accepted; it just never applies.

Do keep in mind that the runner is held while it sleeps — Actions can't defer
allocating a matrix job, so the wait has to happen inside it. Use no more than
the contention calls for. This spreads simultaneous load and nothing else; a
single download that stalls on its own is unaffected.

## Backend status

Snapshot of what the matrix actually proves today. Update this table as backends
get fixed or wired.

| Backend | Status | Notes |
|---------|--------|-------|
| Process T1 | ✅ Good | Prerelease Windows only. Runs the primitives suite. Remaining failures are genuine MXC bugs or harness limitations. |
| Process T3 | ✅ Good | Non-prerelease Windows builds only. Runs the primitives suite plus `T3-Workloads.ps1` (real programs — pwsh, git, node, python, cmd — on top of the T3 primitives). |
| Bubblewrap | ✅ Good | |
| LXC | ✅ Good | Some networking tests fail on distros other than Ubuntu 24.04; seems to be an issue with MXC. |
| WSLC | ✅ Good | Might have to retry hung jobs - this is an issue with overzealous agent reclaiming. |
| IsolationSession | ✅ Good | |
| Windows Sandbox | ⛔ Blocked | Images don't support `Containers-DisposableClientVM` opt. feature |
| MicroVM | ⛔ Not working | Windows cold and warm starts hang; no Linux suite. The artifact payload is currently commented out in the build jobs. |
| Hyperlight | ⛔ Not implemented | No suite on any platform. |
| Seatbelt | ⛔ Not implemented | The backend itself is healthy; there is no official E2E suite to dispatch to. |

## Host preparation

Preparation runs before the tests, keyed by the matrix backend id. A backend
with no prerequisites is an explicit no-op, so the step runs unconditionally for
every entry.

`prepare-windows-host.ps1`:

- `process-t3` — runs `wxc-host-prep.exe prepare-system-drive` and
  `prepare-null-device --no-sacl`.
- `microvm` — asserts the NanVix payload is in the artifact, adds a Defender
  exclusion for the binary directory, and requires the Windows Hypervisor
  Platform feature *and* a running hypervisor.
- `wslc` — asserts `wslcsdk.dll` shipped, requires the WSL and
  VirtualMachinePlatform optional features to be baked into the image, then
  installs/updates the WSL runtime (including the pre-release ring) up to the
  minimum version parsed from `WSLC_SDK_VERSION` in
  `src/backends/wslc/common/build.rs`.
- everything else — prints a "no prerequisites yet" line.

Windows optional features are **verified, never enabled**: turning one on needs a
reboot the job cannot take, so a mis-imaged pool fails here with a pointed
message instead of surfacing later as an opaque backend error.

`prepare-linux-host.sh`:

- `bubblewrap` — installs `bwrap`, `slirp4netns`, `util-linux`, and `iptables`
  (apt/dnf/yum/microdnf), verifies their required commands, and relaxes
  `kernel.apparmor_restrict_unprivileged_userns` (ephemeral CI hosts only).
- `lxc` — installs the LXC stack, reloads the AppArmor profile, starts and waits
  for `lxcbr0`, enables bridge netfilter, and makes sure the bridge's NAT rule
  is in place. On RHEL-likes it needs EPEL first, because Red Hat dropped LXC
  after RHEL 7 and ships no replacement.
- `microvm` — asserts the NanVix payload exists.
- `hyperlight` — no-op.

`prepare-macos-host.sh`:

- `seatbelt` — asserts `mxc-exec-mac` shipped. The sandbox is part of the OS, so
  there is nothing to install; the script exists so macOS has the same shape as
  the other two and a future prerequisite has an obvious home.

Every one of the three scripts also runs the workload-interpreter check
([below](#workload-interpreters)) before it dispatches on the backend id.

### Workload interpreters

Some suites do not just exercise MXC's primitives — they run *real programs*
(`pwsh`, `git`, `node`, `python`, `cmd`) inside the sandbox and assert on what
those programs produce. Each preparation script verifies that host-side
inventory up front, so a missing tool is reported once as a preparation result
rather than repeatedly as a confusing mid-suite failure.

The check is **suite-agnostic by design**, and runs for *every* backend rather
than only the ones whose suites happen to need it today. It describes what a
validation *host* is expected to provide, not what any one suite consumes, so
any current or future suite that shells out to these programs is served by the
same list. `T3-Workloads.ps1` is simply the first caller; wiring up the next one
needs no change here.

There are two implementations, because the two host families share no shell:
`Assert-WorkloadInterpreters` in `prepare-windows-host.ps1`, and
`assert-workload-interpreters.sh`, which Linux and macOS both invoke. The Unix
script is written to bash 3.2 — no associative arrays — because that is what
macOS still ships.

Each inventory entry carries:

- the command names to try, in order. Resolution mirrors what the suites
  themselves do: on Windows `python` is tried before `python3` and a match under
  `WindowsApps` is ignored (that is a Microsoft Store alias stub, not a real
  interpreter), while on Unix `python3` is tried first.
- whether an absence fails the job or only warns. On Windows only `pwsh` is
  required; its absence means a mis-imaged pool. Everything else warns, because
  suites are expected to report their dependent cases as skipped rather than
  failing. Nothing is required on Unix yet — no Unix suite drives these
  interpreters — so that check currently runs purely as host inventory.
- the image-level fix, quoted in whichever message is emitted. The tools are
  **verified, never installed**, for the same reason the optional features are:
  provisioning a toolchain mid-run would mask the image drift the check exists
  to surface.

Because a warning is deliberately not a failure, an absent optional interpreter
silently shrinks coverage while the job still shows green. GitHub's pass/fail
icon cannot express "passed, but with less coverage than yesterday" — a future
test-analysis portal is intended to surface skip counts so that erosion is
visible.

## Log collection

Every job uploads its logs whether it passed or failed, as
`logs-<plan>-<os>-<arch>-<backend>-<attempt>`, kept 7 days.

The catch is that `$env:TEMP` is not `$RUNNER_TEMP`. The Windows suites write their
scratch trees, transcripts, and results files under the user's temp directory
(`C:\Users\<user>\AppData\Local\Temp`), but `upload-artifact` reads
`${{ runner.temp }}` (`C:\a\_work\_temp`). Anything left in the former is simply
never collected, which is why the artifact used to arrive nearly empty.

So `run_backend_validation_tests.ps1` points `TEMP` and `TMP` at `$RUNNER_TEMP` before
it dispatches. Parameter defaults, `[System.IO.Path]::GetTempPath()`, and child
processes all read those variables, so everything temp-rooted lands in the
upload directory without CI having to know a single filename.

Linux and macOS need none of this — those suites log to stdout, and the run
step tees that into `$RUNNER_TEMP/mxc-ci.log`.

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

If two ids should run the same suite, give each its own `case` and have both call
the shared function — that is how `process-t1` and `process-t3` are wired. Keep
that split in the dispatcher, not in the workflow YAML, so a case can start
passing a distinguishing argument later without touching the matrix.

### Add a new OS image

1. Stand up the 1ES pool (Windows/Linux) with the required optional features
   already baked into the image — the jobs verify but never enable them.
2. Add a `platforms` entry: `id`, `displayName`, `family`, and per-architecture
   `target`, `artifact`, `pool`/`runner`, and `backends`.
3. For a Windows prerelease image set `"prerelease": true` and use a neutral
   `windows-prerelease-<name>` id — the id appears in public job names.
4. For a new Linux distro, check that `prepare-linux-host.sh` handles its
   package manager and service layout.
5. Add it to a plan's `triggers`, then resolve locally.

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
2. Add a job that calls `Validation.Tests.Matrix.Job.yml` with that plan, plus a
   `workflow_dispatch` choice if it should be runnable on demand.

### Enable ARM64

Set the ARM64 `pool` for the platform *and* remove or narrow
`suppressNonMacArm64` in the resolver. Note that the resolver rejects
`hyperlight` and `microvm` on ARM64 outright (x64-only runtimes), and the WSLC
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

  test:
    needs: [windows, linux, macos]
    uses: ./.github/workflows/Validation.Tests.Matrix.Job.yml
    with:
      plan: # YOUR PLAN HERE
```

## Important to Note

- **A green job does not prove a suite ran.** Several suites (notably
  IsolationSession) print `SKIPPED` and exit 0 on an unsupported host, and the
  dispatchers propagate only the exit code. A matrix entry asserts the host
  *should* support the backend, so a silent skip there is a coverage gap — check
  the `SKIPPED` line or the executed count in the log, not just the exit status.
- **Empty pool = invisible.** A trigger entry pointing at a platform whose pool
  is blank resolves to zero jobs and reports nothing. Resolve locally after any
  catalog edit.
- **All OS build jobs must pass** before validation testing happens. 
- **Artifacts live one day.** Re-running a test job long after the build has
  expired fails at download; re-run the whole workflow instead.
