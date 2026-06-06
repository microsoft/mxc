# Test Scripts

This directory contains PowerShell convenience scripts for running MXC end-to-end
tests locally on Windows. The primary Rust executor E2E path is
`cargo test -p wxc_e2e_tests`, which invokes the MXC binaries directly instead
of shelling through these scripts.

All scripts accept a `-Release` switch to use the release build (default: debug).

## Prerequisites

- Windows 11
- Rust toolchain installed (`rustup`, `cargo`)
- Built binaries (`cargo build` from `src/`)
- PowerShell 7+ (`pwsh`)

## Scripts

| Script | Description | Extra prerequisites |
|--------|-------------|---------------------|
| `run_basicprocess_test.ps1` | Basic process container test | `wxc-exec.exe` |
| `run_lpacac_test.ps1` | LPAC container test | `wxc-exec.exe` |
| `run_pwsh_test.ps1` | PowerShell Set-Location test | `wxc-exec.exe` |
| `run_filesystem_bfs_test.ps1` | BFS filesystem test | `wxc-exec.exe` |
| `run_filesystem_bfsreadonly_test.ps1` | BFS read-only filesystem test | `wxc-exec.exe` |
| `run_filesystem_bfs_spaces_test.ps1` | BFS path-with-spaces test | `wxc-exec.exe` |
| `run_test_configs.ps1` | All test configs via wxc-test-driver | `wxc-test-driver.exe` |
| `run_examples.ps1` | All examples via wxc-test-driver | `wxc-test-driver.exe` |
| `run_microvm_basic_test.ps1` | MicroVM smoke test | `wxc-exec.exe`, NanVix binaries |
| `run_microvm_tests.ps1` | Full MicroVM E2E suite | WHP enabled, NanVix binaries |
| `run_windows_sandbox_one_shot_tests.ps1` | Windows Sandbox one-shot E2E suite (fresh disposable VM per test) | Windows Sandbox enabled |
| `run_windows_sandbox_state_aware_tests.ps1` | Windows Sandbox state-aware lifecycle E2E (single VM held across provision/start/exec*/stop/deprovision) | Windows Sandbox enabled |
| `run_processcontainer_proxy_tests.ps1` | Process container proxy tests | `wxc-exec.exe` |
| `run_on_repeat.ps1` | Stress test (loops core tests) | `wxc-exec.exe` |

These scripts are local helpers. Not every script is run by CI because several
depend on local OS features such as Windows Sandbox, WHP, proxy setup, or stress
test duration.

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

CI currently runs the MicroVM Rust E2E suite when WHP is available. Other
executor E2E tests are local/prerequisite-gated and should be run on machines
with the required Windows features and binaries.

## Test ownership

Use npm for SDK tests and Cargo for Rust executor tests. Avoid routing npm tests
through Cargo.

```powershell
cd sdk
npm test                    # SDK unit tests
npm run test:integration    # SDK integration tests
```

```powershell
cd src
cargo test --workspace       # Rust unit tests
```

## Running executor E2E via Cargo

The `wxc_e2e_tests` crate runs executor E2E tests directly against
`wxc-exec.exe` and `wxc-test-driver.exe`:

```powershell
cd src
cargo test -p wxc_e2e_tests              # Executor E2E tests (skips if prereqs missing)
cargo test -p wxc_e2e_tests -- --ignored # Include BFS, networking, and stress tests
```

### Ignored tests

The following tests are marked `#[ignore]` because they require velocity key
61714527 (BFS deadlock fix) enabled on the machine. AppContainer process
isolation with brokered filesystem or networking depends on this fix.
Run them explicitly on capable machines with
`cargo test -p wxc_e2e_tests -- --ignored`:

| Test | Reason |
|------|--------|
| `test_appcontainer_basic` | Requires velocity key 61714527 (BFS deadlock fix) |
| `test_appcontainer_lpac` | Requires velocity key 61714527 (BFS deadlock fix) |
| `test_filesystem_bfs` | Requires velocity key 61714527 (BFS deadlock fix) |
| `test_filesystem_bfs_readonly` | Requires velocity key 61714527 (BFS deadlock fix) |
| `test_filesystem_bfs_spaces` | Requires velocity key 61714527 (BFS deadlock fix) |
| `test_pwsh_setlocation` | Requires velocity key 61714527 (BFS deadlock fix) |
| `test_tests\configs` | Requires velocity key 61714527 (BFS deadlock fix) |
| `test_examples` | Requires velocity key 61714527 (BFS deadlock fix) |
| `test_processcontainer_proxy` | Requires velocity key 61714527 (BFS deadlock fix) and elevation |
| `test_on_repeat` | Stress test (loops BFS tests) |

## MicroVM E2E

### Build

```powershell
cd src
cargo build --features microvm --target x86_64-pc-windows-msvc
```

### Run

```powershell
cd src
cargo test -p wxc_e2e_tests --target x86_64-pc-windows-msvc test_microvm_suite -- --nocapture
```

The MicroVM suite runs 6 functional tests + 1 timeout behavior test.
It generates `microvm-perf-results.json` with per-test timing and status data (uploaded as CI artifact).
