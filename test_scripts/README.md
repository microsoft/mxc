# MicroVM E2E Tests

This directory contains scripts for running the MicroVM end-to-end tests locally on Windows.

## Prerequisites

- Windows 11
- Windows Hypervisor Platform (WHP) enabled
- Rust toolchain installed (`rustup`, `cargo`)

## Build

From the repository root:

```powershell
cd src
cargo build --features microvm --target x86_64-pc-windows-msvc
```

## Run the MicroVM E2E script

From the repository root:

```powershell
cd test_scripts
$repoRoot = Resolve-Path ..
$wxcExe = Join-Path $repoRoot "src\target\x86_64-pc-windows-msvc\debug\wxc-exec.exe"
$configDir = Join-Path $repoRoot "test_configs"
.\run_microvm_tests.ps1 -WxcExePath $wxcExe -ConfigDir $configDir
```

## Test coverage

The suite runs:

- 6 functional tests
- 1 timeout behavior test

## Performance output

The test script generates `microvm-perf-results.json` with per-test timing and status data.
In CI, this file is uploaded as a workflow artifact.
