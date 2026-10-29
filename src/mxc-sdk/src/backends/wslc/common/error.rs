// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Typed failure modes for the WSLc backend.
//!
//! WSLc previously built every failure as a free-text [`ScriptResponse`], which
//! left `failure_phase` at its `None` default. Because
//! `crate::mxc_engine::dispatch::map_spawn_error` discriminates on exactly that field,
//! every WSLc failure reached the Rust SDK as an opaque `backend_error` — so a
//! caller could only tell a missing-WSL host from a rejected policy by parsing
//! the message. Each variant here attributes the failure to a lifecycle phase
//! instead.
//!
//! `Display` reproduces the pre-existing message verbatim, so the text a user
//! sees is unchanged.

use std::fmt;

use crate::mxc_common::models::{FailurePhase, ScriptResponse};

use crate::wslc_common::wslc_bindings::HRESULT;

/// A WSLc backend failure, tagged with the phase it is attributable to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum WslcError {
    /// A WSLc SDK call returned a failing `HRESULT`.
    Sdk {
        context: String,
        hr: HRESULT,
        sdk_msg: String,
    },
    /// The SDK, or a WSL component it depends on, is missing on this host.
    Unavailable(String),
    /// The request cannot be honored as written — a policy or config rejection
    /// that the same input will not get past on a retry.
    Rejected(String),
    /// Host-side bring-up failed before the container process started.
    Host(String),
    /// The container started, but the run could not be carried to a clean exit.
    Runtime(String),
}

impl WslcError {
    /// A failing SDK call. Mirrors the message the former `sdk_error` helper
    /// built, including the `HRESULT` rendering.
    pub(crate) fn sdk(context: impl Into<String>, hr: HRESULT, sdk_msg: impl Into<String>) -> Self {
        WslcError::Sdk {
            context: context.into(),
            hr,
            sdk_msg: sdk_msg.into(),
        }
    }

    /// Lifecycle phase this failure is attributed to, so a caller can tell a
    /// retryable launch failure from a rejection or an unusable host.
    pub(crate) fn failure_phase(&self) -> FailurePhase {
        match self {
            // Host cannot run WSLc at all — callers may fall back to another tier.
            WslcError::Unavailable(_) => FailurePhase::BackendUnavailable,
            // Non-retryable preflight: the input itself has to change.
            WslcError::Rejected(_) => FailurePhase::Rejected,
            // The SDK call or host bring-up failed; generally worth retrying.
            WslcError::Sdk { .. } | WslcError::Host(_) => FailurePhase::LaunchFailed,
            // The container was up but the run broke.
            WslcError::Runtime(_) => FailurePhase::PostLaunchFailed,
        }
    }

    /// Render as a [`ScriptResponse`] carrying the message verbatim.
    pub(crate) fn into_response(self) -> ScriptResponse {
        ScriptResponse::failed(self.failure_phase(), &self.to_string())
    }
}

impl fmt::Display for WslcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WslcError::Sdk {
                context,
                hr,
                sdk_msg,
            } if sdk_msg.is_empty() => {
                write!(f, "{}: HRESULT 0x{:08X}", context, *hr as u32)
            }
            WslcError::Sdk {
                context,
                hr,
                sdk_msg,
            } => write!(f, "{}: {} (HRESULT 0x{:08X})", context, sdk_msg, *hr as u32),
            WslcError::Unavailable(m)
            | WslcError::Rejected(m)
            | WslcError::Host(m)
            | WslcError::Runtime(m) => f.write_str(m),
        }
    }
}

impl From<WslcError> for ScriptResponse {
    fn from(err: WslcError) -> Self {
        err.into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The former helper, kept verbatim so the typed path can be proven to
    /// produce byte-identical text.
    fn legacy_sdk_message(context: &str, hr: HRESULT, sdk_msg: &str) -> String {
        if sdk_msg.is_empty() {
            format!("{}: HRESULT 0x{:08X}", context, hr as u32)
        } else {
            format!("{}: {} (HRESULT 0x{:08X})", context, sdk_msg, hr as u32)
        }
    }

    #[test]
    fn sdk_message_is_unchanged_from_the_untyped_helper() {
        // 0x8007_0490 as a c_long is negative; the `as u32` cast in both the old
        // and new renderings must agree on the printed form.
        for (ctx, hr, sdk_msg) in [
            ("WslcCreateContainer failed", 0x8007_0490_u32 as HRESULT, ""),
            (
                "WslcCreateContainerProcess failed",
                0x8007_0490_u32 as HRESULT,
                "no such image",
            ),
            ("WslcGetMissingComponents failed", -1, ""),
        ] {
            assert_eq!(
                WslcError::sdk(ctx, hr, sdk_msg).to_string(),
                legacy_sdk_message(ctx, hr, sdk_msg),
                "typed rendering must match the legacy message exactly"
            );
        }
    }

    #[test]
    fn message_carrying_variants_render_verbatim() {
        let msg = "WSLc: network.allowLocalNetwork=true is not supported.";
        for err in [
            WslcError::Unavailable(msg.to_string()),
            WslcError::Rejected(msg.to_string()),
            WslcError::Host(msg.to_string()),
            WslcError::Runtime(msg.to_string()),
        ] {
            assert_eq!(err.to_string(), msg, "message must not be reworded");
        }
    }

    #[test]
    fn response_carries_the_message_and_the_phase() {
        let typed = WslcError::Host("bring-up failed".to_string()).into_response();

        assert_eq!(typed.exit_code, -1);
        assert_eq!(typed.error_message, "bring-up failed");
        assert_eq!(typed.failure_phase, FailurePhase::LaunchFailed);
    }

    /// A WSLc rejection has to cost the caller the same exit code a rejection
    /// from any other backend does.
    #[test]
    fn exit_codes_follow_the_shared_phase_contract() {
        let s = || "x".to_string();
        assert_eq!(
            WslcError::Rejected(s()).into_response().exit_code,
            ScriptResponse::rejected("x").exit_code
        );
        assert_eq!(
            WslcError::Unavailable(s()).into_response().exit_code,
            ScriptResponse::unavailable("x").exit_code
        );
        for err in [
            WslcError::Host(s()),
            WslcError::Runtime(s()),
            WslcError::sdk("op", -1, ""),
        ] {
            assert_eq!(err.into_response().exit_code, -1);
        }
    }

    #[test]
    fn each_variant_maps_to_its_lifecycle_phase() {
        let s = || "x".to_string();
        assert_eq!(
            WslcError::Unavailable(s()).failure_phase(),
            FailurePhase::BackendUnavailable
        );
        assert_eq!(
            WslcError::Rejected(s()).failure_phase(),
            FailurePhase::Rejected
        );
        assert_eq!(
            WslcError::sdk("op", -1, "").failure_phase(),
            FailurePhase::LaunchFailed
        );
        assert_eq!(
            WslcError::Host(s()).failure_phase(),
            FailurePhase::LaunchFailed
        );
        assert_eq!(
            WslcError::Runtime(s()).failure_phase(),
            FailurePhase::PostLaunchFailed
        );
    }
}
