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
| `run_basicac_test.ps1` | Basic AppContainer test | `wxc-exec.exe` |
| `run_lpacac_test.ps1` | LPAC AppContainer test | `wxc-exec.exe` |
| `run_pwsh_test.ps1` | PowerShell Set-Location test | `wxc-exec.exe` |
| `run_filesystem_bfs_test.ps1` | BFS filesystem test | `wxc-exec.exe` |
| `run_filesystem_bfsreadonly_test.ps1` | BFS read-only filesystem test | `wxc-exec.exe` |
| `run_filesystem_bfs_spaces_test.ps1` | BFS path-with-spaces test | `wxc-exec.exe` |
| `run_test_configs.ps1` | All test configs via wxc-test-driver | `wxc-test-driver.exe` |
| `run_examples.ps1` | All examples via wxc-test-driver | `wxc-test-driver.exe` |
| `run_microvm_basic_test.ps1` | MicroVM smoke test | `wxc-exec.exe`, NanVix binaries |
| `run_microvm_tests.ps1` | Full MicroVM E2E suite | WHP enabled, NanVix binaries |
| `run_windows_sandbox_tests.ps1` | Windows Sandbox E2E suite | Windows Sandbox enabled |
| `run_appcontainer_proxy_tests.ps1` | AppContainer proxy tests | `wxc-exec.exe` |
| `run_on_repeat.ps1` | Stress test (loops core tests) | `wxc-exec.exe` |

These scripts are local helpers. Not every script is run by CI because several
depend on local OS features such as Windows Sandbox, WHP, proxy setup, or stress
test duration.

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
cargo test -p wxc_e2e_tests -- --ignored # Include stress tests
```

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
