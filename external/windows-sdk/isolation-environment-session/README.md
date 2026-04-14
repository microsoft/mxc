# IsoEnvBroker Session API — WinMD Provenance

This directory tracks provenance for the generated Rust bindings in
`src/agent_session_bindings/`. The WinMD file itself is NOT checked in.

## Source

The WinMD file is built from the OS repo (`os.2020`):

- **IDL source**: `src/onecoreuap/windows/core/isoenvbroker/src/published/Windows.AI.IsolationEnvironment.idl`
- **Build output**: `obj/<flavor>/onecoreuap/windows/core/isoenvbroker/src/published/objchk/amd64/windows.ai.isolationenvironment.winmd`

## Regenerating Bindings

Requires:
- The WinMD file from an OS build (e.g., amd64chk flavor)
- Rust toolchain (the generation tool builds from source)

```sh
cargo run --manifest-path tools/generate-agent-session-bindings/Cargo.toml -- <path-to-winmd>
```

After regeneration:
1. Review the generated `src/agent_session_bindings/src/bindings.rs`
2. Update `GENERATION_INFO.toml` with the OS commit and WinMD SHA256
3. Build and test: `cd src && cargo test --workspace`

## Version Coupling

The generated bindings depend on the `windows` crate at the version specified in
`GENERATION_INFO.toml` (`target_windows_crate`). If the workspace upgrades the
`windows` crate, the bindings crate's `build.rs` will fail with an actionable error
message instructing you to regenerate.
