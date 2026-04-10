# WSLC SDK (WSL Container SDK)

**Version:** 2.8.1
**Source:** Microsoft internal self-host package (`Microsoft.WSL.Containers.2.8.1.nupkg`)

## Contents

- `Microsoft.WSL.Containers.2.8.1.nupkg` — NuGet package containing the SDK
  header (`wslcsdk.h`), import libraries (`wslcsdk.lib`), and runtime DLLs
  (`wslcsdk.dll`) for x64 and ARM64.

## Usage

The `wslc_common` crate's `build.rs` extracts the `.nupkg` (which is a zip
file) into the cargo build output directory at compile time, then links
against `wslcsdk.lib`.

At runtime, `wslcsdk.dll` must be available on the system — it is installed
by the WSLC SDK MSI and is **not** bundled with MXC.

### SDK resolution order

`build.rs` resolves the SDK lib path in this order:

1. **`WSLC_SDK_PATH` environment variable** — set this to a directory
   containing `wslcsdk.lib` (e.g., from a CI/CD pipeline or local NuGet
   cache) to skip nupkg extraction.
2. **`external/wslc-sdk/*.nupkg`** — extracted to `OUT_DIR/wslc-sdk/` at
   build time.

Once the `Microsoft.WSL.Containers` NuGet package is available on a public
feed, `build.rs` can be updated to download it directly, and the checked-in
`.nupkg` can be removed from the repo.

## Updating

When a new version is available:
1. Replace the `.nupkg` file in this directory
2. Update the version number above
