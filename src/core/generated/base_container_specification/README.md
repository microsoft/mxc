# Regenerating FlatBuffers Bindings

The `sandbox_spec` crate contains the legacy `base_container_layout` bindings and
the newer `process_security_environment_layout` bindings auto-generated from
`external/windows-sdk/base_container/ProcessSecurityEnvironment.fbs`.

## Prerequisites

- `flatc.exe` (FlatBuffers compiler) -- download from https://github.com/google/flatbuffers/releases
- Copy .fbs from Windows SDK to external/windows-sdk/base_container/ProcessSecurityEnvironment.fbs

## Steps

Run the regeneration script in PowerShell from any directory:

```powershell
pwsh -File <repo-path>/src/core/generated/base_container_specification/regenerate.ps1
```

The script runs `flatc`, preserves the legacy bindings, appends the new module to
`lib.rs`, reorganizes the generated files into the crate's module layout, and
formats the result with `cargo fmt`. Pass `-Flatc <path>` if `flatc.exe` is not on
your `PATH`.
