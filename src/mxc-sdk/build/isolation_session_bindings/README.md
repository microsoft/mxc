# Windows.AI.IsolationSession SDK selection

MXC supports two explicit IsolationSession build modes:

| Cargo feature | Metadata and runtime |
|---|---|
| `isolation_session` | Uses the committed OS-generated Rust bindings and normal inbox WinRT activation. |
| `isolation_session_lifted` | Restores the pinned SDK package from NuGet.org, generates bindings from its Preview WinMD, and stages its lifted activation payload. This feature implies `isolation_session`. |

The repository does not contain the SDK `.nupkg`. Lifted builds download the
exact package version pinned in
`src/mxc-sdk/build/build_mxc_build_common.rs` from the NuGet.org V3 flat-container
endpoint, verify its SHA-256, and cache it in the standard global NuGet package
directory.

1. `ISOLATION_SESSION_SDK_PACKAGE`, if set, for validating a different local
   copy of the same package.
2. The standard global NuGet package cache, then the NuGet.org V3
   flat-container endpoint (cached after download).

## Runtime prerequisite

Lifted binaries bind the version-pinned runtime installed by the
IsolationSession MSI. Install the matching release with:

```powershell
winget install Microsoft.AI.IsolationSession
```

The build stages `IsoSessionApp.dll` and `IsoSession.manifest` beside
`wxc-exec.exe` and `mxc_ffi.dll`. MXC never falls back to the inbox runtime
when the payload or MSI is missing; it reports `BackendUnavailable` with this
remediation.

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
   regenerates `GENERATION_INFO.toml` without copying the package into Git.
2. Build and test both feature configurations. Set
   `ISOLATION_SESSION_SDK_PACKAGE` to the validated local package until that
   exact version is available from NuGet.org.

`windows-bindgen` is pinned to `=0.62.1` in `src/mxc-sdk/Cargo.toml`
and must stay in lockstep with the workspace `windows` crate's major.minor
(`target_windows_crate` in `GENERATION_INFO.toml`). If you bump the `windows`
crate, bump `windows-bindgen` to the matching version in the same change.
