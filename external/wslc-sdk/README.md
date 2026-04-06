# WSLC SDK (WSL Container SDK)

**Version:** 2.8.1
**Source:** Microsoft internal self-host package (`Microsoft.WSL.Containers.2.8.1.nupkg`)

## Contents

- `include/wslcsdk.h` — C API header
- `runtimes/win-x64/wslcsdk.lib` — Static import library (x64)
- `runtimes/win-x64/wslcsdk.dll` — Runtime DLL (x64)
- `runtimes/win-arm64/wslcsdk.lib` — Static import library (ARM64)
- `runtimes/win-arm64/wslcsdk.dll` — Runtime DLL (ARM64)

## Usage

The `wslc_common` crate links against `wslcsdk.lib` at build time via `build.rs`.
At runtime, `wslcsdk.dll` must be available on the system — it is installed by the
WSLC SDK MSI and is **not** bundled with MXC. The `.dll` files checked into this
directory are for development convenience only (e.g., local builds without the MSI
installed) and should not be deployed to production.

### SDK resolution order

`build.rs` resolves the SDK lib path in this order:

1. **`WSLC_SDK_PATH` environment variable** — set this to the NuGet package extract
   path (e.g., from a CI/CD pipeline or local NuGet cache) to avoid relying on the
   checked-in copy.
2. **`external/wslc-sdk/runtimes/win-{arch}/`** — fallback while the NuGet package
   is not yet available in the build pipeline.

Once the `Microsoft.WSL.Containers` NuGet package is integrated into the build
pipeline, this `external/wslc-sdk/` directory can be removed from the repo.

## Updating

When a new version is available:
1. Extract the updated `.nupkg`
2. Replace files in this directory
3. Update the version number above
