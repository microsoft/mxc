//! Library surface for the permissive learning mode (PLM) crate.
//!
//! Split into:
//! * **portable modules** (`access_event`, `config`, `ui_limits`) that
//!   compile on every target so their tests can run in Linux/macOS CI.
//! * **Windows-only modules** (`event_parser`, `extract_caps`, `log`,
//!   `start`, `stop`) gated by `#[cfg(target_os = "windows")]`; they
//!   wrap WPR / ETW / EventLog / capability-SID APIs that have no
//!   cross-platform equivalent.
//!
//! The thin `plm` binary lives in `main.rs` and is itself Windows-only.

pub mod access_event;
pub mod config;
pub mod ui_limits;

#[cfg(target_os = "windows")]
pub mod event_parser;

#[cfg(target_os = "windows")]
pub mod extract_caps;

#[cfg(target_os = "windows")]
pub mod log;

#[cfg(target_os = "windows")]
pub mod start;

#[cfg(target_os = "windows")]
pub mod stop;
