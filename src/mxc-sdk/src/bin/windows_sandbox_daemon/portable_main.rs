#[cfg(target_os = "windows")]
include!("main.rs");

#[cfg(not(target_os = "windows"))]
fn main() {}
