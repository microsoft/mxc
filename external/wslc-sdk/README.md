# WSLC SDK (WSL Container SDK)

**Package:** `Microsoft.WSL.Containers`
**Version:** pinned in `src/backends/wslc/common/build.rs`
(`WSLC_SDK_VERSION`, currently **2.9.3**)
**Source:** the [`MxcDependencies`](https://dev.azure.com/shine-oss/mxc/_artifacts/feed/MxcDependencies)
Azure Artifacts feed — a public, anonymous-read mirror of nuget.org.

## How the SDK is consumed

The `wslc_common` crate's `build.rs` downloads the `Microsoft.WSL.Containers`
`.nupkg` (pinned to `WSLC_SDK_VERSION`) from the MxcDependencies feed at compile
time and extracts it (a nupkg is a zip) into the cargo build output directory.

The feed is used instead of nuget.org because the 1ES build pool does not
allowlist nuget.org; the MxcDependencies feed (which also mirrors the crates.io
dependencies) is reachable and pins the package for reproducible builds.

The SDK is **loaded at runtime via `libloading`** — it is not statically linked
— so `build.rs` only copies `runtimes/win-<arch>/native/wslcsdk.dll` next to the
built binary (`wxc-exec.exe`), where `LoadLibrary` finds it.

### SDK resolution order

`build.rs` resolves the SDK in this order:

1. **`WSLC_SDK_PATH`** — a directory containing `wslcsdk.dll` (or a `native/`
   subdirectory containing it). Set this to a pre-fetched SDK for offline /
   air-gapped builds to bypass the download entirely.
2. **MxcDependencies feed download** — the `.nupkg` for `WSLC_SDK_VERSION` is
   downloaded (via `curl`) and extracted into `OUT_DIR`.
3. **Vendored fallback** — if the feed download fails, the `.nupkg` checked into
   this directory (`Microsoft.WSL.Containers.<version>.nupkg`) is extracted
   instead. This vendored copy is a **transitional safety net** and is expected
   to be removed in a subsequent release once the feed is proven in all official
   build environments.

Override the pinned version at build time with the `WSLC_SDK_VERSION`
environment variable.

## Contents

- `Microsoft.WSL.Containers.2.9.3.nupkg` — vendored fallback copy of the SDK
  (header `wslcsdk.h`, import libs `wslcsdk.lib`, and runtime `wslcsdk.dll` for
  x64 and ARM64). Must match `WSLC_SDK_VERSION` in `build.rs`.

## Updating the SDK version

1. Ensure the new version is available on the MxcDependencies feed (it mirrors
   nuget.org on first restore; contact the feed owner if a version is missing).
2. Update `WSLC_SDK_VERSION` in `src/backends/wslc/common/build.rs`.
3. Replace the vendored `.nupkg` in this directory with the matching version (or
   remove it once the vendored fallback is retired).
4. Re-validate the hand-written FFI bindings in
   `src/backends/wslc/common/src/wslc_bindings.rs` against the new
   `include/wslcsdk.h` (struct sizes, exported symbol names, signatures) — the
   SDK is in preview and its ABI can change between releases.
5. Update the required WSL runtime floor in
   `docs/wsl/wsl-container-getting-started.md` if it changed.

