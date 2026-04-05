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
& "C:\Users\jwhites\Downloads\Windows.flatc.binary\flatc.exe" `
    --rust --gen-object-api --force-empty --no-prefix --rust-module-root-file --gen-all `
    -o src/generated/base_container_specification `
    external/windows-sdk/BaseContainerSpecification.fbs

# Move output into the crate's src/ directory
mkdir src\generated\base_container_specification\src
mv src\generated\base_container_specification\mod.rs src\generated\base_container_specification\src\lib.rs
mv src\generated\base_container_specification\sandbox_tech_spec_layout src\generated\base_container_specification\src\

# Re-add the allow attribute at the top of lib.rs (flatc overwrites it).
# Insert `#![allow(unused_imports, non_snake_case, clippy::all)]` after the
# `// @generated` line, e.g.:
#
#   // @generated
#   #![allow(unused_imports, non_snake_case, clippy::all)]
#   pub mod sandbox_tech_spec_layout { ...

# Format the generated code to pass CI checks
cd src
cargo fmt
```
