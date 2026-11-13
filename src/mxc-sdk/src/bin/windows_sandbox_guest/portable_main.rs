#[cfg(all(target_os = "windows", not(test)))]
#[path = "../../lib.rs"]
#[allow(
    dead_code,
    unused_imports,
    reason = "Sidecars compile the implementation privately"
)]
mod implementation;
#[cfg(all(target_os = "windows", not(test)))]
pub(crate) use implementation::*;
#[cfg(all(target_os = "windows", test))]
pub(crate) use mxc_internal::*;

#[cfg(target_os = "windows")]
include!("main.rs");

#[cfg(not(target_os = "windows"))]
fn main() {
    eprintln!("wxc-windows-sandbox-guest is Windows-only.");
    std::process::exit(64);
}
