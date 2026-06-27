//! Library surface for the permissive learning mode (PLM) crate.
//! Pure-data modules compile cross-platform; Windows-only items are
//! gated per-module. The `plm` binary in `main.rs` is Windows-only.
//!
//! This PR introduces the trace-lifecycle skeleton only: WPR start/stop,
//! the host-wide singleton mutex, the embedded `plm.wprp` materializer,
//! and the `wxc-exec --audit` plumbing. Event parsing, capability
//! extraction, filesystem/UI merging, and the adjusted-config writer
//! arrive in later PRs.

pub mod coordination;
pub mod profile_gen;

#[cfg(target_os = "windows")]
pub mod log;

#[cfg(target_os = "windows")]
pub mod start;

#[cfg(target_os = "windows")]
pub mod stop;

#[cfg(target_os = "windows")]
pub mod wpr_path;
