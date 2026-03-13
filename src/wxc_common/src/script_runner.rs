// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::logger::Logger;
use crate::models::{CodexRequest, ScriptResponse};

/// Trait for executing scripts within a containment backend.
///
/// Each backend (AppContainer, Windows Sandbox, etc.) implements this trait
/// to provide a uniform interface for `wxc-exec`.
pub trait ScriptRunner {
    /// Execute the script inside this backend's containment and return the response.
    fn run(&mut self, request: &CodexRequest, logger: &mut Logger) -> ScriptResponse;
}

/// Convert a timeout value to milliseconds, treating 0 as infinite (INFINITE = `u32::MAX`).
pub fn get_timeout_milliseconds(timeout: u32) -> u32 {
    if timeout == 0 {
        u32::MAX
    } else {
        timeout
    }
}

#[cfg(test)]
mod tests {
    use super::get_timeout_milliseconds;
    #[test]
    fn timeout_zero_returns_u32_max() {
        let result = get_timeout_milliseconds(0);
        assert_eq!(result, u32::MAX);
    }
    #[test]
    fn timeout_non_zero_returns_same_value() {
        let value = 1500u32;
        let result = get_timeout_milliseconds(value);
        assert_eq!(result, value);
    }
}
