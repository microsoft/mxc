//! Library surface for the permissive learning mode (PLM) crate.
//! Pure-data modules compile cross-platform; Windows-only items are
//! gated per-module. The `plm` binary in `main.rs` is Windows-only.

pub mod access_event;
pub mod config;
pub mod coordination;
pub mod event_parser;
pub mod extract_caps;
pub mod profile_gen;
pub mod ui_limits;

#[cfg(target_os = "windows")]
pub mod log;

#[cfg(target_os = "windows")]
pub mod start;

#[cfg(target_os = "windows")]
pub mod stop;

#[cfg(target_os = "windows")]
pub mod wpr_path;
