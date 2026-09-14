# ProcessContainer regression repros

1. These are per-Issue test cases: each in a .ps1 file.
1. VM-ready (needs no repo or PowerShell test framework)
1. Copy this folder and `wxc-exec.exe` to a VM
1. Run a case .ps1 directly or use `Run-RegressionTests.ps1`

`TestCases.psd1` is a catalog of each test case, including expected backend
support and prerequisites. ProcessContainer cases require the native PSEC
backend.

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
