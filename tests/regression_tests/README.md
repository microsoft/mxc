# ProcessContainer regression repros

1. These are per-Issue test cases: each in a .ps1 file.
1. VM-ready (needs no repo or PowerShell test framework)
1. Copy this folder and `wxc-exec.exe` + `host_prep.exe` to a VM
1. Run a case .ps1 directly or use `Run-RegressionTests.ps1`

`TestCases.psd1` is a catalog of each test case, including expected tier support and prerequisites. `ExpectedTierSupport` lists the tiers on which the behavior should work, including tiers beyond the original issue report; it does not select or enforce the executor tier.

## Run
Individual
```powershell
.\test_cases\Invoke-Issue1102-DefaultPath.ps1
```

Full
```powershell
.\Run-RegressionTests.ps1
```

## Harness info
- Harness warns about all missing manifest-listed dependencies and prints their installation commands.
- Missing dependencies stop the run by default; pass `-InstallMissingDependencies` to install supported dependencies with `winget`, or `-RunWithMissingDependencies` to attempt the tests anyway.
- `wxc-exec.exe` is searched for in current directory or `PATH`
- Destructive cases include `DESTRUCTIVE` in the filename, are skipped by default, and refuse direct execution without `-AllowDestructive`.

### Objective output
Use `-PassThru` to emit unformatted result objects for the pipeline:

```powershell
.\Run-RegressionTests.ps1 -PassThru | Where-Object Status -eq "Failed"
```

## Force a ProcessContainer tier

Build a test-only executor from `src`:

```powershell
cargo build -p wxc --features force-tier-testing
```

Set `MXC_FORCE_TIER` before running a case or the harness:

```powershell
$env:MXC_FORCE_TIER = "appcontainer-dacl"
.\Run-RegressionTests.ps1 -WxcExec ..\src\target\debug\wxc-exec.exe
```

Accepted values are `base-container`, `appcontainer-bfs`, and `appcontainer-dacl`. The override is absent from normal builds; never ship an executor built with `force-tier-testing`.

Issue #694 requires `appcontainer-dacl` and fails its precondition when another tier is selected.
