# Test Scripts

> **Audience:** MXC developers

This directory contains convenience scripts for running MXC end-to-end tests
locally and in CI. The primary Rust executor E2E path is
`cargo test -p wxc_e2e_tests`, which invokes the MXC binaries directly instead
of shelling through these scripts.

Arguments and build-profile defaults vary by suite. Use the script's help or
header comment for its supported parameters.

The MicroVM scripts use the packaged fixtures under
`src/mxc-sdk/tests/fixtures/microvm`, not `tests/configs`.

## Prerequisites

Shared:

- Rust toolchain installed (`rustup`, `cargo`)
- Built binaries (`cargo build` from `src/`)

Windows (`.ps1`):

- Windows 11
- PowerShell 7+ (`pwsh`)

Linux / macOS (`.sh`):

- Bash, plus the per-backend prerequisites listed in the backend's doc (for
  example `bwrap` for Bubblewrap, the LXC stack for LXC)

## Scripts

| Script | Description | Extra prerequisites |
|--------|-------------|---------------------|
| `test_loopback_anchor_command.ps1` | Host-only regression checks for direct and shell-wrapped loopback commands, with and without proxy-environment handling; runs in Windows PR builds | `curl.exe`; no sandbox backend |
| `test_native_process_container_capture.ps1` | Host-only capture regression: preserves normal output and rejects inherited output handles within a bounded wait; runs in Windows PR builds | Windows .NET Framework compiler; no sandbox backend |
| `test_native_policy_results.ps1` | Host-only checks that inconclusive UI probes remain skips, both broken allow/deny directions fail, clipboard reads require their round trip, and CLI refusals require the expected error before execution; runs in Windows PR builds | No sandbox backend |
| `test_sdk_suite_results.ps1` | Checks that required Rust, .NET, and Node tests cannot pass CI through an empty selection or skipped streaming cases; runs in Windows PR builds | No sandbox backend |
| `run_basicprocess_test.ps1` | Basic process container test | `wxc-exec.exe` |
| `run_base_container_network_tests.ps1` | Native ProcessContainer egress defaults, host-loopback policy, and IPv4/IPv6 proxy endpoint isolation | Native PSEC support for host loopback and identity-less loopback proxy; IPv6 loopback; Windows PowerShell 5.1; `curl.exe`; outbound access to the egress fixture |
| `run_processcontainer_network_loopback_test.ps1` | Focused default-deny, explicit-deny, and explicit-allow host-loopback checks under both ingress defaults | Native PSEC; `curl.exe`; host loopback; no internet fixture |
| `run_processcontainer_filesystem_enumerate_test.ps1` | Focused request-probe agreement, enumeration-only enforcement, unsupported-host refusal, and unchanged fixture ACLs | Native PSEC; Windows PowerShell 5.1; no UI probe or internet fixture |
| `run_processcontainer_policy_tests.ps1` | Native filesystem policy, CLI contract boundaries, final-path regression #694, functional UI policy matrix, atom isolation, and host-controlled privilege removal | Native PSEC; Windows PowerShell 5.1; `wxc-ui-probe.exe`; no PLM |
| `run_processcontainer_contract_tests.ps1` | Focused minimum/stable/development contract launches, capabilities and registry access, lifecycle/telemetry options, malformed network policies, capture-output path rejection before execution, and unsupported versions | Native PSEC; Windows PowerShell 5.1 |
| `run_processcontainer_workload_tests.ps1` | **Manual only, not wired into CI:** 19 native runtime scenarios covering PowerShell 7, Git, Node, Python, file I/O, child processes, and runtime directory changes | Native PSEC; missing optional interpreters are reported as skips |
| `test_processcontainer_workload_environment.ps1` | **Manual host-only regression:** Git fixture setup preserves absent, empty, and existing caller environment variables, including failure paths | Git and PowerShell 7; no sandbox backend |
| `run_pwsh_test.ps1` | PowerShell Set-Location test | `wxc-exec.exe` |
| `run_test_configs.ps1` | All test configs via wxc-test-driver | `wxc-test-driver.exe` |
| `run_examples.ps1` | All examples via wxc-test-driver | `wxc-test-driver.exe` |
| `run_microvm_basic_test.ps1` | MicroVM smoke test | `wxc-exec.exe`, build with `microvm`, complete signed bundle |
| `run_microvm_tests.ps1` | Windows signed NVX command, output, exit, and timeout E2E suite | WHP enabled, build with `microvm`, complete signed bundle |
| `run_windows_sandbox_one_shot_tests.ps1` | Windows Sandbox one-shot E2E suite (fresh disposable VM per test) | Windows Sandbox enabled |
| `run_windows_sandbox_state_aware_tests.ps1` | Windows Sandbox state-aware lifecycle E2E (single VM held across provision/start/exec*/stop/deprovision) | Windows Sandbox enabled |
| `run_isolation_session_tests.ps1` | IsolationSession one-shot E2E suite | Interactive local session; OS-side IsolationSession service |
| `run_isolation_session_state_aware_tests.ps1` | IsolationSession provision/start/exec/stop/deprovision E2E suite | Interactive local session; OS-side IsolationSession service |
| `run_wslc_all_tests.ps1` | All WSLC create-and-run and container-lifecycle E2E tests; delegates the lifecycle half to `run_wslc_state_aware_tests.ps1` | WSL2, WSLC SDK, staged daemon, and registry access for the image preflight, which warms the create-and-run store and daemon store slots 0 through 2 (`-SkipSetup` needs all stores already warm, because the lifecycle fixtures deny egress) |
| `run_wslc_state_aware_tests.ps1` | WSLC container and session lifecycle E2E suite, including shared sandboxes, identical-session independence, guest CPU/memory sizing, cold-store refusal, warm reuse, exec concurrency and idle teardown; GPU enforcement is not verified | WSL2, WSLC SDK, `wxc-wslc-daemon.exe` staged beside `wxc-exec.exe`, and `alpine:latest` / `python:3.12-alpine` cached in daemon store slots 0 through 2 (warm them with `scripts\setup-wslc.ps1 -DaemonSlots 3`); the fresh cold-store regression requires registry access even with `-SkipSetup` |
| `run_telemetry_consent_smoke_test.ps1` | Consent maintenance, presentation, policy, and exit-code smoke tests | Debug `wxc-exec.exe` built with `test-support` |
| `run_telemetry_etw_smoke_test.ps1` | Isolated consent flow plus public-provider ETW capture | Debug `wxc-exec.exe` built with `test-support`; ETW tooling; Administrator, otherwise the test skips |
| `run_telemetry_consent_release_test.ps1` | Consent path in a **release** executor, where the debug store/policy overrides are compiled out. Mutates the real consent store and HKLM policy, so it requires `-AcceptRealMachineMutation` and an ephemeral machine | Release `wxc-exec.exe`; Administrator for the HKLM policy section, otherwise that section skips unless `-RequirePolicyCeiling` is passed |
| `run_on_repeat.ps1` | Stress test (loops core tests) | `wxc-exec.exe` |

The IsolationSession and native ProcessContainer network suites dot-source
`tests/scripts/lib/LoopbackAnchor.ps1` for their positive network oracle: host
IPv4/IPv6 loopback listeners with known response bodies. Native proxy checks
pair a successful proxied request with denied direct requests to other
loopback endpoints; launch failures do not count as network denials.

The aggregate network and policy suites call the focused loopback and
enumeration runners, respectively. They can also be run independently from
the repository root:

```powershell
.\tests\scripts\run_processcontainer_network_loopback_test.ps1 -BinDir .\src\target\debug
.\tests\scripts\run_processcontainer_filesystem_enumerate_test.ps1 -BinDir .\src\target\debug
```

The enumeration runner probes and executes the same request. Supported hosts
must list the granted directory while denying file reads, writes, and
ungranted-directory enumeration. Unsupported hosts must reject the request
before execution with the enumeration-specific reason. Both paths leave the
owned fixtures' security descriptors unchanged.

Both native ProcessContainer suites run contained workloads through
`%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe` with
`-NoProfile -NonInteractive -ExecutionPolicy Bypass` and the shared
`lib/processcontainer_policy_probe.ps1`. Neither suite requires Python or Node.
The timeout child is a uniquely named copy of Windows PowerShell. Native
Win32k-disabled and global-atom probes use `wxc-ui-probe`; no in-container C#
compilation is needed. Clipboard tests skip non-text formats before changing
anything, and restore and verify the original text in `finally`.

The shared native-process capture helper allows 45 seconds for execution and
five seconds for redirected output to close after executor exit. A descendant
retaining an output handle causes a stream-drain failure rather than an
unbounded wait. Process cleanup also uses a bounded wait.

The UI matrix measures each operation under a fully permissive contained
policy before checking its allow direction. Unavailable operations and input
injection probes that cannot acquire the foreground are explicit skips, not
passes. Clipboard round trips use owned tokens; the host's original clipboard
text and mouse speed are restored and checked. Display-settings probes use
`ChangeDisplaySettingsW` with `CDS_TEST`, which validates a mode without
applying it. The matrix never executes a logoff or mutates IME configuration.

The policy suite also calls the focused CLI contract runner and regression
#694. For each minimum/stable/development contract, network rejection cases
check empty destination/port lists, hostname CIDRs, ranges without a start,
remote ProcessContainer proxies, and retired `defaultPolicy`. Each version
also launches a valid network-policy control; these cases require no external
connectivity. Parser/contract tests remain in the build jobs as well.

Scheduled jobs pass the prebuilt final-path probe from the Windows SDK
test bundle through `-FinalPathProbe`; missing artifacts fail rather than
triggering compilation on validation hosts. Direct local policy runs compile
that small fixture with the inbox .NET Framework compiler when no probe is supplied.

Run the restored application workloads explicitly:

```powershell
.\tests\scripts\run_processcontainer_workload_tests.ps1 -BinDir .\src\target\debug
```

This manual suite uses owned temporary fixtures and native filesystem grants,
not retired host preparation or drive-wide DACL mutation. It is intentionally
not called by the policy aggregate or any CI dispatcher.
Git preparation and contained Git commands use fixture-owned global/system
configuration and XDG files; they do not read the operator's private Git
configuration or require a grant to the operator's profile. Configuration
overrides are assigned only to child processes, never to the invoking shell.

### Unix suites

| Script | Description | Extra prerequisites |
|--------|-------------|---------------------|
| `run_bwrap_all_tests.sh` | All Bubblewrap tests | `lxc-exec`, `bwrap`, Python 3 for terminal isolation |
| `run_lxc_all_tests.sh` | All LXC tests | `lxc-exec`, LXC stack, root |
| `run_seatbelt_all_tests.sh` | All Seatbelt tests; missing prerequisites are failures rather than skips | macOS, `mxc-exec-mac`, unprivileged user, backend prerequisites |

Individual `run_bwrap_*.sh`, `run_lxc_*.sh`, and `run_seatbelt_*.sh` scripts
run focused backend suites; the aggregate scripts above are what CI dispatches to.

Not every script runs in CI: several depend on local OS features such as
Windows Sandbox, WHP, proxy setup, or stress-test duration. The ones CI does
run are reached through the dispatchers below rather than being invoked
directly.

### CI dispatch

The validation matrix (see `scripts/ci/validation-test-matrix.json` and
`.github/workflows/Validation.Tests.Matrix.Job.yml`, documented end to end in
[`CI validation infrastructure`](../../docs/development/build-and-test/ci-validation-infrastructure.md))
never builds from source.
It downloads a build artifact, prepares the host, and then hands off to one of
these dispatchers, which map a matrix backend id to the suites above:

| Dispatcher | Platforms | Backend ids |
|------------|-----------|-------------|
| `scripts/ci/run_backend_validation_tests.ps1` | Windows | `process`, `isolation-session`, `windows-sandbox`, `wslc`, `microvm` |
| `scripts/ci/run_backend_validation_tests.sh` | Linux, macOS | `bubblewrap`, `lxc`, `seatbelt` |

The Unix dispatcher recognizes the catalog's `microvm` entry but exits nonzero
because that suite is not wired. Neither dispatcher accepts `hyperlight`.

Pass the backend id exactly as it appears in the catalog — there is no separate
handler name. The `process` case requires `wxc-exec --probe` to report an
enabled native PSEC contract, then runs a filesystem smoke test and
`run_base_container_network_tests.ps1` plus `run_processcontainer_policy_tests.ps1`.
The filesystem smoke checks a real write/read and its expected stdout marker.
Network coverage includes explicit egress allow-list and deny precedence.
Denied-path, enumerate-only, and Learning Mode cases verify enforcement when
advertised and rejection before execution otherwise. The HANDLES check uses
the published UI probe against a host-owned hidden window, with an uncontained
positive control. Privilege removal is tested only when the host token contains
a tested privilege; otherwise the non-attributable case is explicitly skipped.
Missing required native network
capabilities or listeners fail the job rather than silently skipping cases.

```powershell
scripts\ci\run_backend_validation_tests.ps1 -Backend process `
    -BinaryDirectory <dir> -Architecture x64
```

```bash
scripts/ci/run_backend_validation_tests.sh bubblewrap <binary-directory>
```

A backend with no wired suite exits non-zero on purpose, so accidentally
enabling it in a trigger fails loudly instead of reporting a false success.

To see exactly what a plan would schedule without pushing:

```bash
node scripts/ci/resolve-validation-test-matrix.mjs --plan nightly
```

**Skip semantics.** Several suites degrade gracefully on an unsupported host:
the IsolationSession suites decide availability from a single `wxc-exec --probe`
read of `probes.isolationSessionAvailable`, print `SKIPPED`, and exit 0.

Because a skip exits 0 and the dispatchers propagate only the exit code, **a
green CI job does not by itself prove the suite ran.** Anything treating these
suites as validation evidence must check the `SKIPPED` line or the executed
count, not just the exit status — the matrix entry says the host is expected to
support the backend, so a silent skip there is a gap in coverage rather than a
graceful degradation. Independently, a run that reaches the summary having
executed zero tests always fails, since it substantiates nothing.

`run_lxc_rootless_no_network_test.sh` checks that `lxc-exec` runs a config
with no network section without root.  Neither `run_lxc_all_tests.sh` nor CI
runs it, because it adds a temporary user account to the machine.  Run it
manually with `sudo bash tests/scripts/run_lxc_rootless_no_network_test.sh`.

### Manual smoke tests

Manual smokes are visual-inspection scripts for rendering and event-propagation
behavior that has no automated pass/fail oracle. They must run on a real
`cmd.exe` console on the test host (not via PowerShell, not via PSSession),
and the operator observes the output to confirm healthy behavior.

| Script | Description | Prerequisites |
|--------|-------------|---------------|
| `run_isolation_session_resize_smoke.ps1` | Ruler-line loop inside an isolation session; resize the window and verify `cols=` / `rows=` track the resize and the trailing `|` stays at the actual right edge. Ctrl-C to exit. | `wxc-exec.exe` (built with `--features isolation_session`), real `cmd.exe` console, IsolationSession backend available |

Invoke from `cmd.exe`:

```cmd
powershell -ExecutionPolicy Bypass -File tests\scripts\run_isolation_session_resize_smoke.ps1
```

### Deployment helpers

These scripts copy build artifacts onto a remote test VM. The TShell-based
scripts must be sourced from inside an active TShell session
(`Open-Device -vm <vm>`); the PowerShell Remoting script handles the session
itself and takes a `-ComputerName` / `-VMName` plus `-Credential`.

| Script | Copies | Transport |
|--------|--------|-----------|
| `push_exes_to_vm.ps1` | Native Rust binaries (Debug + Release) | TShell (active `Open-Device` session) |
| `push_batch_and_config_files_to_vm.ps1` | `tests\configs\`, `examples\`, runner batch files, helper scripts | TShell (active `Open-Device` session) |
| `push_sdk_integration_tests_to_vm.ps1` | SDK integration test artifacts (`sdk\bin\x64`, compiled tests, `node_modules`, `package.json`, `run-tests.js`) | PowerShell Remoting (`-ComputerName`/`-VMName` + `-Credential`) |

## Test ownership

Use npm for SDK tests and Cargo for Rust executor tests. Avoid routing npm tests
through Cargo.

```powershell
cd sdk\node
npm test                    # SDK unit tests
npm run test:integration    # SDK integration tests
```

```powershell
cd src
cargo test --workspace       # Rust unit tests
```

### Unix PTY SDK integration tests

The caller-controlled PTY contract is directly runnable on a matching host:

```bash
# Linux with Bubblewrap installed
cd src
cargo test -p mxc-sdk --test streaming_bubblewrap bubblewrap_pty -- --nocapture

# Linux with LXC installed; run as root
sudo --preserve-env=PATH,HOME "$(command -v cargo)" \
  test -p mxc-sdk --test streaming_lxc lxc_pty -- --nocapture

# macOS
cd src
cargo test -p mxc-sdk --test streaming seatbelt_pty -- --nocapture
```

The local Bubblewrap and LXC tests report a prerequisite skip when their backend
is unavailable. Provisioned CI hosts run the same tests in backend-specific
lanes; strict mode turns a missing prerequisite into a failure.

## Running executor E2E via Cargo

The `wxc_e2e_tests` crate runs executor E2E tests directly against
`wxc-exec.exe` and `wxc-test-driver.exe`:

```powershell
cd src
cargo test -p wxc_e2e_tests              # Executor E2E tests (skips if prereqs missing)
cargo test -p wxc_e2e_tests -- --ignored # Include native ProcessContainer, networking, and stress tests
```

### Ignored tests

The following tests are marked `#[ignore]` because they require an enabled
native PSEC contract, and some require additional host capabilities.
Run them explicitly on a capable machine with
`cargo test -p wxc_e2e_tests -- --ignored`:

| Test | Reason |
|------|--------|
| `test_processcontainer_basic` | Requires native PSEC |
| `test_processcontainer_filesystem*` | Requires native PSEC |
| `test_pwsh_setlocation` | Requires native PSEC |
| `test_tests\configs` | Requires the configured native backends |
| `test_examples` | Requires the configured native backends |
| `test_processcontainer_proxy_capture_uses_native_capture` | Requires compatible native proxy and Learning Mode capture support; no PLM elevation |
| `test_processcontainer_capture_denials_output_file` | Requires native Learning Mode capture support |
| `test_processcontainer_capture_denials_timeout_retention` | Requires native Learning Mode capture support and retained-ETL access |
| `test_on_repeat` | Stress test |

## MicroVM E2E

### Build

```powershell
cd src
cargo build --locked -p wxc --features microvm --target x86_64-pc-windows-msvc
```

### Run

```powershell
cd src
cargo test --locked -p mxc-sdk --features microvm --test nvx_e2e --target x86_64-pc-windows-msvc -- --include-ignored --nocapture --test-threads=1
```

The SDK suite runs the seven MicroVM config scenarios plus executor and
captured JSON checks for output, environment, working directory, timeout,
capture limits, and cleanup. VM scenarios require a prepared Windows x64
host and the complete signed bundle. The config scenarios write
`microvm-perf-results.json` under the temporary directory.

The unified Windows 25H2 x64 nightly job runs the prebuilt SDK suite and
collects its logs and performance JSON. `run_microvm_tests.ps1` remains a
local config-only helper; it is not the scheduled CI entry point. See the
[NVX backend guide](../../docs/backends/nvx/nvx.md).
