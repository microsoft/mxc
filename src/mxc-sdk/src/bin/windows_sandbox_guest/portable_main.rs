#[cfg(target_os = "windows")]
include!("main.rs");

#[cfg(not(target_os = "windows"))]
fn main() {
    eprintln!("wxc-windows-sandbox-guest is Windows-only.");
    std::process::exit(64);
}
