# Regenerating Process Security Environment bindings

This crate contains Rust bindings generated from
`external/windows-sdk/ProcessSecurityEnvironment.fbs`.

Install `flatc` 25.12.19 or newer, then run from the repository root:

```powershell
pwsh -File src/core/generated/process_security_environment_specification/regenerate.ps1
```

Pass `-Flatc <path>` when `flatc.exe` is not on `PATH`.
