//! Library surface for the permissive learning mode (PLM) crate.
//!
//! All modules now compile cross-platform: Windows-only items inside
//! each module are gated with `#[cfg(target_os = "windows")]`, while
//! pure-data parsers (XML, hex, ACE bytes, normalization,
//! `CapabilityIndex`, `ParseAccumulator`) compile on every target so
//! their unit tests run in Linux/macOS CI. Round-3 testability fix.
//!
//! The thin `plm` binary lives in `main.rs` and is itself Windows-only.

pub mod access_event;
pub mod config;
pub mod event_parser;
pub mod extract_caps;
pub mod ui_limits;

#[cfg(target_os = "windows")]
pub mod log;

#[cfg(target_os = "windows")]
pub mod start;

#[cfg(target_os = "windows")]
pub mod stop;

#[cfg(target_os = "windows")]
pub mod wpr_path;
