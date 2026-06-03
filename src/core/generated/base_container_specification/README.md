# Regenerating FlatBuffers Bindings

The `base_container_specification` crate contains Rust bindings auto-generated from `external/windows-sdk/BaseContainerSpecification.fbs`.

## Prerequisites

- `flatc.exe` (FlatBuffers compiler) -- download from https://github.com/google/flatbuffers/releases
- Copy .fbs from Windows SDK to external/windows-sdk/BaseContainerSpecification.fbs

## Steps

From the repo root, run the regeneration script in PowerShell:

```powershell
pwsh -File src/core/generated/base_container_specification/regenerate.ps1
```

The script runs `flatc`, reorganizes the output into the crate's module layout,
patches `lib.rs` (module rename + lint suppression), and formats the result with
`cargo fmt`. Pass `-Flatc <path>` if `flatc.exe` is not on your `PATH`.
