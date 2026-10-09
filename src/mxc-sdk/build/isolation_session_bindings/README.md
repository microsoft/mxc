# Windows.AI.IsolationSession SDK selection

MXC supports two explicit IsolationSession build modes:

| Cargo feature | Metadata and runtime |
|---|---|
| `isolation_session` | Uses the committed OS-generated Rust bindings and normal inbox WinRT activation. |
| `isolation_session_lifted` | Restores the pinned SDK package through the configured `MxcDependencies` feed, generates bindings from its Preview WinMD, and stages its lifted activation payload. This feature implies `isolation_session`. |

The repository does not contain the SDK `.nupkg`. Lifted builds run normal
`dotnet restore` using the checked-in `NuGet.Config`, which clears implicit
sources and selects the `MxcDependencies` feed. NuGet restores the exact package
version pinned in `src/mxc-sdk/build/build_mxc_build_common.rs` into the
Cargo target profile's `.mxc-nuget/packages` directory. MXC then independently
verifies the restored `.nupkg` SHA-256 before reading it.

Set `ISOLATION_SESSION_SDK_PACKAGE` to use a local package without restoring.
The local package must still match the pinned version, contents, and SHA-256.
Normal builds never contact NuGet.org directly.

Before updating the pin, seed both the package and locked Cargo dependencies
into the configured feeds by running the `MXC-Update-Feed-Dependencies`
pipeline with this PR number. Builds without the local override fail until the
new package version is available from `MxcDependencies`.

## Runtime prerequisite

Lifted binaries bind the version-pinned runtime installed by the
IsolationSession MSI. Install the matching release with:

```powershell
winget install Microsoft.AI.IsolationSession
```

The build stages `IsoSessionApp.dll` and `IsoSession.manifest` beside
the current MXC native module. MXC never falls back to the inbox runtime
when the payload or MSI is missing; it reports `BackendUnavailable` with this
remediation.

The published package contains one AMD64 `IsoSessionApp.dll`, so lifted mode
currently supports only x64 (`x86_64-pc-windows-msvc` / `win-x64`). Inbox mode
continues to support both Windows architectures. Lifted ARM64 and multi-RID
builds are rejected before compilation or packaging.

## Build commands

From `src`:

```powershell
# Existing inbox OS behavior
cargo build --release -p wxc --features isolation_session

# Lifted SDK NuGet and MSI behavior
cargo build --release -p wxc --features isolation_session_lifted
```

The same features exist on `mxc-sdk` and `mxc_ffi`. From the repository root,
`build.bat --with-isolation-session` builds inbox mode and
`build.bat --with-isolation-session-lifted` builds lifted mode and copies the
payload into the Node and .NET SDK runtimes. The .NET SDK uses
`-p:MxcWithIsolationSession=true` (inbox) or `-p:MxcIsolationSessionLifted=true`
(lifted).

Lifted mode fails the build if package download, integrity validation, metadata
generation, activation-payload staging, or native payload architecture
validation fails. It never silently produces an inbox-mode binary or package a
shim for the wrong target architecture.

## Updating the lifted SDK

1. Run `Update-IsoSessionSdk.ps1 -PackagePath <path-to-package>`. The script
   validates the package, updates `PACKAGE_VERSION` and `PACKAGE_SHA256`, and
   regenerates `LIFTED_SDK_INFO.toml` without copying the package into Git.
2. Run the dependency-feed update pipeline, then build and test both feature
   configurations. Set `ISOLATION_SESSION_SDK_PACKAGE` to the validated local
   package while feed seeding is pending.

`windows-bindgen` is pinned to `=0.62.1` in `src/mxc-sdk/Cargo.toml`
and must stay in lockstep with the workspace `windows` crate's major.minor
(`target_windows_crate` in both provenance files). If you bump the `windows`
crate, bump `windows-bindgen` to the matching version in the same change.

`GENERATION_INFO.toml` describes the committed inbox projection and changes
only when those bindings are regenerated. `LIFTED_SDK_INFO.toml` describes the
pinned lifted package and is updated by `Update-IsoSessionSdk.ps1`.
