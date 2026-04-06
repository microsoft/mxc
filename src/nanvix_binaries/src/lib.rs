/// Path to the directory containing downloaded NanVix binaries.
///
/// Set by build.rs via `cargo:rustc-env`. This points to the build-time
/// OUT_DIR and is used by wxc/build.rs to copy binaries next to the final
/// executable. At runtime, the NanVix runner discovers binaries via
/// `std::env::current_exe()` — it does NOT use this constant.
pub const NANVIX_BIN_DIR: &str = env!("NANVIX_BIN_DIR");

/// List of required NanVix binary filenames.
pub const REQUIRED_BINARIES: &[&str] = &[
    "nanvixd.exe",
    "kernel.elf",
    "python.elf",
    "cpython-ramfs.img",
];
