# Test Scripts

This directory contains PowerShell scripts for running MXC end-to-end tests locally on Windows.

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

## Running via Cargo

All scripts can also be invoked via the `wxc_e2e_tests` Rust crate:

```powershell
cd src
cargo test -p wxc_e2e_tests                 # All E2E tests (skips if prereqs missing)
cargo test -p wxc_e2e_tests -- test_sdk     # SDK tests only
cargo test -p wxc_e2e_tests -- test_cli     # CLI tests only
cargo test -p wxc_e2e_tests -- --ignored    # Include stress tests
```

## MicroVM E2E

### Build

```powershell
cd src
cargo build --features microvm --target x86_64-pc-windows-msvc
```

### Run

```powershell
cd test_scripts
$repoRoot = Resolve-Path ..
$wxcExe = Join-Path $repoRoot "src\target\x86_64-pc-windows-msvc\debug\wxc-exec.exe"
$configDir = Join-Path $repoRoot "test_configs"
.\run_microvm_tests.ps1 -WxcExePath $wxcExe -ConfigDir $configDir
```

The MicroVM suite runs 6 functional tests + 1 timeout behavior test.
It generates `microvm-perf-results.json` with per-test timing and status data (uploaded as CI artifact).
