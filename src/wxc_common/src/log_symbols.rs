// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Shared Unicode symbols used in structured log output.
//!
//! Centralised here so that multiple crates (e.g. `base_container_runner`,
//! `mxc_diagnostic_console`) can reference a single source of truth.

/// ⚪ White circle — neutral / default state.
pub const EMOJI_NEUTRAL: &str = "\u{26AA}";

/// ⚠ Warning sign — non-default or noteworthy state.
pub const EMOJI_WARNING: &str = "\u{26A0}";

/// ❌ Cross mark — blocked / denied.
pub const EMOJI_BLOCKED: &str = "\u{274C}";

/// ✅ Check mark — allowed / permitted.
pub const EMOJI_ALLOWED: &str = "\u{2705}";

/// ▶ Play / section marker — delimits logical sections in log output.
pub const EMOJI_SECTION: &str = "\u{25B6}";
