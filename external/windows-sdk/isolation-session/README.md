# Windows.AI.IsolationSession — SDK NuGet + Bindings Provenance

This directory pins the OS-produced SDK package that the generated Rust
bindings in `src/backends/isolation_session/bindings/` are built from, plus the
provenance metadata that couples them.

## What is checked in here

| File | Purpose |
|------|---------|
| `Microsoft.Windows.AI.IsolationSession.SDK.<ver>.nupkg` | The OS-produced SDK package. Contains the WinMD metadata (`metadata/*.winmd`) the bindings are generated from, plus `runtime/IsoSessionApp.dll` for reference. |
| `GENERATION_INFO.toml` | Provenance: bindgen version, target `windows` crate version, generated date, and the source winmd hash. Verified by the bindings crate's `build.rs`. |
| `README.md` | This file. |

The `.nupkg` is committed (like `external/wslc-sdk/Microsoft.WSL.Containers.*.nupkg`)
so a clean clone can **regenerate the bindings offline** without fetching
anything. The WinMD is produced by an internal Microsoft Windows OS build and is
not publicly redistributable outside this pinned package.

## Building MXC (no NuGet action required)

A normal MXC build does **not** touch this package. It compiles the
already-checked-in `src/backends/isolation_session/bindings/src/bindings.rs`.
The bindings crate's `build.rs` only reads `GENERATION_INFO.toml`
(`target_windows_crate`) as a version gate against the workspace `windows`
crate — it does not open the `.nupkg` or the WinMD. A fresh clone therefore
builds with zero NuGet/WinMD work.

## Regenerating the bindings (only when the API surface changes)

The bindings are regenerated from the **preview** WinMD inside the pinned
`.nupkg`, using the canonical generator that lives in the OS repo
(`onecoreuap/windows/core/isoenvbroker/RustBindingsGenerator/`).

1. Extract the preview WinMD from the pinned package (a `.nupkg` is a zip):

   ```powershell
   $nupkg = "external/windows-sdk/isolation-session/Microsoft.Windows.AI.IsolationSession.SDK.0.2606.0.nupkg"
   Add-Type -AssemblyName System.IO.Compression.FileSystem
   $out = "$env:TEMP/isosession-winmd"
   [System.IO.Compression.ZipFile]::ExtractToDirectory($nupkg, $out)
   # preview WinMD: $out/metadata/windows.ai.isolationsession.preview.winmd
   ```

2. Run the OS-side one-shot wrapper, pointing it at that WinMD. It regenerates,
   copies `bindings.rs` into this MXC checkout, and runs `cargo check`:

   ```powershell
   # From the OS enlistment:
   .\onecoreuap\windows\core\isoenvbroker\RustBindingsGenerator\Update-IsolationSessionBindings.ps1 `
       -MxcRepoPath C:\mxc `
       -WinMdPath $env:TEMP\isosession-winmd\metadata\windows.ai.isolationsession.preview.winmd `
       -NoPause
   ```

   The generator filters to the `Windows.AI.IsolationSession.Preview` namespace
   (the STABLE surface MXC calls) with windows-bindgen `0.62.1`.

3. Bump `generated_date` (and the source hash, if the WinMD changed) in
   `GENERATION_INFO.toml`, then commit the regenerated `bindings.rs` together
   with the updated provenance.

## Version coupling

The generated bindings depend on the `windows` crate at the version in
`GENERATION_INFO.toml` (`target_windows_crate`). If the workspace upgrades the
`windows` crate past that major.minor, the bindings crate's `build.rs` fails
with an actionable error instructing you to regenerate.

## Refreshing the pinned package

To pick up a newer OS build, produce a new package with the OS-side
`nuget/Microsoft.Windows.AI.IsolationSession.SDK/pack.ps1`, replace the
`.nupkg` here, regenerate the bindings from its preview WinMD (steps above),
and commit both.