# WSLC gateway image

> **Audience:** MXC developers

The WSLC gateway (`mxc-wslc-gateway`) is the built-in proxy for WSLC
 networking: a static Linux musl binary that runs in its own container. It ships as a single-layer image tar, one
per architecture, committed under `src/mxc-sdk/assets/`:

| File | Container architecture |
|---|---|
| `mxc-wslc-gateway-x86_64.tar` | amd64 |
| `mxc-wslc-gateway-aarch64.tar` | arm64 |

A Windows `--features wslc` build reads the tar for the target architecture,
checks that its image ID and layer match its config, compiles the ID into
`mxc-sdk` as `MXC_WSLC_GATEWAY_IMAGE_ID`, and stages the tar as
`mxc-wslc-gateway.tar` beside `wslcsdk.dll`. Every package that ships
`wslcsdk.dll` also ships the tar.

## Sources

| Path | Role |
|---|---|
| `src/tools/wslc_gateway/` | The gateway binary. Linux only. An unpublished workspace crate, so `mxc-sdk`'s dependencies never reach the image build. |
| `src/mxc-sdk/src/backends/wslc/gateway_policy.rs` | The policy the backend passes to the gateway and the egress rule check. The gateway compiles this file in directly and doesn't link `mxc-sdk`. |
| `[profile.wslc-gateway]` in `src/Cargo.toml` | Size-optimized release profile used for the image. |
| `scripts/build-wslc-gateway-image.ps1` | Builds both binaries and writes the image tars. |
| `src/mxc-sdk/build/build_wslc_gateway_image.rs` | Verifies and stages the committed tar. |

## Regenerating the images

Regenerate both tars after changing any of the sources above, a dependency in
`Cargo.lock` that the gateway uses, or `$gatewayToolchain` in the script.
Commit the tars in the same change. When the channel in
`src/rust-toolchain.toml` changes, move `$gatewayToolchain` to a release on it.

On Windows, from the repository root:

```powershell
.\scripts\build-wslc-gateway-image.ps1
```

The script installs the x64 Windows host toolchain for `$gatewayToolchain`, an
exact Rust release, with the musl targets and `rust-src`, and links with the
bundled `rust-lld`. It prints each image ID.

The same source and toolchain always give the same image IDs. To keep them
stable, the script:

- **Runs on Windows.** Panic messages embed source paths, and Windows and Linux
  paths differ.

- **Pins the exact compiler.** A new patch release of the workspace channel
  would change the binary.

- **Uses the x64 host toolchain, even on ARM64.** Cargo hashes the host into
  build script units and so into dependent crates' symbols. ARM64 Windows runs
  the toolchain under emulation, which is slower.

- **Remaps machine-specific paths.** The Cargo home, the registry source
  directory, the `src` directory and the `rust-src` component map to fixed
  prefixes.

- **Writes the tar deterministically.** Timestamps, owners and JSON formatting
  are fixed.

## Validation

- `scripts/build-wslc-gateway-image.ps1 -Check` builds into a temporary
  directory and fails if a committed tar differs. The `wslc-gateway-image-check`
  pull request job runs it on Windows x64.

- The Linux build job runs the gateway and policy unit tests, for both the gnu
  and the shipped musl target, and the image integrity checks against the
  committed tars:

  ```text
  cargo test -p mxc-wslc-gateway
  cargo test -p mxc-sdk --test wslc_gateway_image
  ```

- A Windows `--features wslc` build fails if the committed tar is missing, or
  its config or layer doesn't match its digests.
