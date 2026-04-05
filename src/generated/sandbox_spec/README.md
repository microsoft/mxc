# Regenerating FlatBuffers Bindings

The `sandbox_spec` crate contains Rust bindings auto-generated from `external/windows-sdk/SandboxSpec.fbs`.

## Prerequisites

- `flatc.exe` (FlatBuffers compiler) — download from https://github.com/google/flatbuffers/releases

## Steps

From the repo root, run in PowerShell:

```powershell
# Clean old generated output
Remove-Item src\generated\sandbox_spec\src\lib.rs
Remove-Item src\generated\sandbox_spec\src\ -Recurse

# Run flatc
& "C:\Users\jwhites\Downloads\Windows.flatc.binary\flatc.exe" `
    --rust --gen-object-api --force-empty --no-prefix --rust-module-root-file --gen-all `
    -o src/generated/sandbox_spec `
    external/windows-sdk/SandboxSpec.fbs

# Move output into the crate's src/ directory
mkdir src\generated\sandbox_spec\src
mv src\generated\sandbox_spec\mod.rs src\generated\sandbox_spec\src\lib.rs
mv src\generated\sandbox_spec\sandbox_tech_spec_layout src\generated\sandbox_spec\src\

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
