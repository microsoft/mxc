# Windows.AI.IsolationSession SDK selection

MXC supports two explicit IsolationSession build modes:

| Cargo feature | Metadata and runtime |
|---|---|
| `isolation_session` | Uses the committed OS-generated Rust bindings and normal inbox WinRT activation. |
| `isolation_session_lifted` | Restores the pinned SDK package from NuGet.org, generates bindings from its Preview WinMD, and stages its lifted activation payload. This feature implies `isolation_session`. |

The repository does not contain the SDK `.nupkg`. Lifted builds download the
exact package version pinned in
`src/core/mxc_build_common/src/lib.rs` from the NuGet.org V3 flat-container
endpoint, verify its SHA-256, and cache it in the standard global NuGet package
directory.

For offline builds or validation before a package is public, set
`ISOLATION_SESSION_SDK_PACKAGE` to the exact `.nupkg` path. The same pinned hash
is enforced for this override.

## Build commands

From `src`:

```powershell
# Existing inbox OS behavior
cargo build --release -p wxc --features isolation_session

# Lifted SDK NuGet and MSI behavior
cargo build --release -p wxc --features isolation_session_lifted
```

Lifted mode fails the build if package download, integrity validation, metadata
generation, or activation-payload staging fails. It never silently produces an
inbox-mode binary.

## Updating the lifted SDK

1. Publish the new `Microsoft.Windows.AI.IsolationSession.SDK` package version
   to NuGet.org.
2. Update `PACKAGE_VERSION` and `PACKAGE_SHA256` in
   `src/core/mxc_build_common/src/lib.rs`.
3. Update `GENERATION_INFO.toml` with the package and WinMD provenance.
4. Build and test both feature configurations.

`windows-bindgen` is pinned in the bindings crate and must remain compatible
with the workspace `windows` crate.
