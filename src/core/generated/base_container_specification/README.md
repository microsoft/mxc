# Regenerating FlatBuffers Bindings

The `base_container_specification` crate contains Rust bindings auto-generated from `external/windows-sdk/BaseContainerSpecification.fbs`.

## Prerequisites

- `flatc.exe` (FlatBuffers compiler) -- download from https://github.com/google/flatbuffers/releases
- Copy .fbs from Windows SDK to external/windows-sdk/BaseContainerSpecification.fbs

## Steps

From the repo root, run in PowerShell:

```powershell
# Clean old generated output
Remove-Item src\core\generated\base_container_specification\src\ -Recurse

# Run flatc
& "flatc.exe" `
    --rust --gen-object-api --force-empty --no-prefix --rust-module-root-file --gen-all `
    -o src/core/generated/base_container_specification `
    external/windows-sdk/BaseContainerSpecification.fbs

# Move output into the crate's src/ directory and rename to match our module names
mkdir src\core\generated\base_container_specification\src
mv src\core\generated\base_container_specification\mod.rs src\core\generated\base_container_specification\src\lib.rs
mv src\core\generated\base_container_specification\sandbox_tech_spec_layout src\core\generated\base_container_specification\src\base_container_layout

# Patch lib.rs: rename modules and suppress warnings on generated code
(Get-Content src\core\generated\base_container_specification\src\lib.rs) `
    -replace 'pub mod sandbox_tech_spec_layout', 'pub mod base_container_layout' `
    -replace '// @generated', "// @generated`n#![allow(unused_imports, non_snake_case, non_camel_case_types, clippy::all)]" |
    Set-Content src\core\generated\base_container_specification\src\lib.rs

# Format the generated code to pass CI checks
cd src
cargo fmt -p sandbox_spec
```
