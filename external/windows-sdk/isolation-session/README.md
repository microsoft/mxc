# Windows.AI.IsolationSession — WinMD Provenance

This directory tracks provenance for the generated Rust bindings in
`src/isolation_session_bindings/`. The WinMD file itself is NOT checked in.

## Source

The WinMD file is produced by an internal Microsoft Windows OS build and is
not publicly redistributable.

## Version Coupling

The generated bindings depend on the `windows` crate at the version specified in
`GENERATION_INFO.toml` (`target_windows_crate`). If the workspace upgrades the
`windows` crate, the bindings crate's `build.rs` will fail with an actionable error
message instructing you to regenerate.
