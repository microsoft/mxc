# Regenerating FlatBuffers Bindings

The `sandbox_spec` crate contains Rust bindings auto-generated from `external/windows-sdk/BaseContainerSpecification.fbs`.

## Prerequisites

- `flatc.exe` (FlatBuffers compiler) — download from https://github.com/google/flatbuffers/releases

## Steps

From the repo root, run in PowerShell:

```powershell
# Clean old generated output
Remove-Item src\generated\base_container_specification\src\lib.rs
Remove-Item src\generated\base_container_specification\src\ -Recurse

# Run flatc
& "flatc.exe" `
    --rust --gen-object-api --force-empty --no-prefix --rust-module-root-file --gen-all `
    -o src/generated/base_container_specification `
    external/windows-sdk/BaseContainerSpecification.fbs

# Move output into the crate's src/ directory and rename to match our module names
mkdir src\generated\base_container_specification\src
mv src\generated\base_container_specification\mod.rs src\generated\base_container_specification\src\lib.rs
mv src\generated\base_container_specification\sandbox_tech_spec_layout src\generated\base_container_specification\src\base_container_layout
mv src\generated\base_container_specification\src\base_container_layout\sandbox_spec_generated.rs `
   src\generated\base_container_specification\src\base_container_layout\base_container_specification_generated.rs

# Edit lib.rs to use the renamed module names:
#   - Change `pub mod sandbox_tech_spec_layout` to `pub mod base_container_layout`
#   - Change `mod sandbox_spec_generated` to `mod base_container_specification_generated`
#   - Add `#![allow(unused_imports, non_snake_case, clippy::all)]` after the `// @generated` line

# Format the generated code to pass CI checks
cd src
cargo fmt
```
