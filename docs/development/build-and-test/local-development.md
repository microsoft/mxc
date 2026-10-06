# Local development

> **Audience:** MXC developers

Use the repository build scripts for complete platform builds. The commands
below target individual components or validation steps during development.
Run Rust commands from `src/`.

## Component builds

```text
# Windows x64
cargo build --release --target x86_64-pc-windows-msvc

# Windows ARM64
cargo build --release --target aarch64-pc-windows-msvc

# Linux executor for the LXC and Bubblewrap backends
cargo build --release -p lxc

# macOS executor
cargo build --release -p mxc_darwin --target aarch64-apple-darwin
```

Build the Node SDK from `sdk/node/`:

```text
npm install
npm run build
```

## Format and lint

```text
# From src/
cargo fmt --all -- --check

# Windows
cargo clippy --workspace --all-targets -- -D warnings

# Linux
cargo clippy -p lxc -p mxc-sdk -p unix_test_proxy --all-targets -- -D warnings

# macOS
cargo clippy -p mxc_darwin -p seatbelt_common --all-targets -- -D warnings
```

## Tests

```text
# From src/
cargo test --workspace
cargo test -p mxc-sdk --lib
cargo test -p mxc-sdk --lib -- config_parser
cargo test -p wxc_e2e_tests

# From sdk/node/
npm test
npm run test:integration

# From sdk/dotnet/
dotnet test --solution Microsoft.Mxc.Sdk.slnx
```

Host-dependent backend suites and their prerequisites are documented in
[`tests/scripts/README.md`](../../../tests/scripts/README.md).
