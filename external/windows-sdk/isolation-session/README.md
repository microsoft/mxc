# Windows.AI.IsolationSession — SDK NuGet + Build-Time Bindings

This directory pins the OS-produced SDK package that the Rust bindings in
`src/backends/isolation_session/bindings/` are built from. The bindings are
**generated at build time from this package** — there is no committed
`bindings.rs` snapshot.

## What is checked in here

| File | Purpose |
|------|---------|
| `Microsoft.Windows.AI.IsolationSession.SDK.<ver>.nupkg` | The OS-produced SDK package. Contains the WinMD metadata (`metadata/*.winmd`) the bindings are generated from, plus `runtime/IsoSessionApp.dll` for reference. |
| `GENERATION_INFO.toml` | Provenance: bindgen version, source WinMD hash, namespace. |
| `README.md` | This file. |

The `.nupkg` is committed (like `external/wslc-sdk/Microsoft.WSL.Containers.*.nupkg`)
so a clean clone builds fully offline. The WinMD is produced by an internal
Microsoft Windows OS build and is not publicly redistributable outside this
pinned package.

## How the bindings are built (every `cargo build`)

The bindings crate's `build.rs` regenerates the projection on every build:

1. Locates the single `*.nupkg` in this directory.
2. Extracts its **Preview** WinMD (`metadata/windows.ai.isolationsession.preview.winmd`)
   — a `.nupkg` is a zip — into `OUT_DIR`.
3. Runs `windows-bindgen` (pinned `=0.62.1` as a build-dependency) over it with
   the canonical arguments (filter `Windows.AI.IsolationSession.Preview`,
   `--reference windows,skip-root,Windows.Foundation --flat --implement`),
   writing `OUT_DIR/bindings.rs`, which `lib.rs` `include!`s.

This mirrors the OS-side canonical generator
(`onecoreuap/windows/core/isoenvbroker/RustBindingsGenerator/`) exactly, so the
crate is always built **directly against the pinned SDK package**. `build.rs`
re-runs when the `.nupkg` changes (`cargo:rerun-if-changed`).

## Refreshing to a newer OS build

1. Produce a new package with the OS-side
   `nuget/Microsoft.Windows.AI.IsolationSession.SDK/pack.ps1`.
2. From the MXC repository root, run:
   ```powershell
   .\external\windows-sdk\isolation-session\Update-IsoSessionSdk.ps1 `
       -PackagePath C:\path\to\Microsoft.Windows.AI.IsolationSession.SDK.<version>.nupkg
   ```
   The script validates the package payload and runtime identity, removes the
   previously pinned package, copies the new package, and regenerates
   `GENERATION_INFO.toml`.
3. `cargo build` — the new bindings are generated automatically. Review the
   downstream diff (e.g. `cargo check -p wxc --features isolation_session`).

## Version coupling

`windows-bindgen` is pinned to `=0.62.1` in the bindings crate's `Cargo.toml`
and must stay in lockstep with the workspace `windows` crate's major.minor
(`target_windows_crate` in `GENERATION_INFO.toml`). If you bump the `windows`
crate, bump `windows-bindgen` to the matching version in the same change.