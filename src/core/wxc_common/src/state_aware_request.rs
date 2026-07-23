// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! State-aware request types — public domain output of the parser.
//!
//! `MxcRequest` is the bridge between parser and dispatcher: a one-shot call
//! produces `MxcRequest::OneShot(ExecutionRequest)`, a state-aware call produces
//! `MxcRequest::StateAware(ParsedStateAwareRequest)`. The parser narrows the
//! discriminator by presence of the wire-format `phase` field.
//!
//! `ParsedStateAwareRequest` bundles the inner `ExecutionRequest` (populated by
//! the same parser path one-shot uses for cross-cutting fields) with the
//! state-aware-only fields: `phase`, optional `containment`, optional
//! `sandbox_id`, and the raw JSON `experimental` block. The dispatcher
//! resolves the backend, deserialises the per-backend per-phase config from
//! `experimental_raw` via `deserialize_config<C>`, and asserts
//! `sandbox_id_required` for non-provision phases.

use std::collections::HashMap;

use serde::de::DeserializeOwned;
use serde_json::value::RawValue;
use serde_json::Value;

use crate::config_deserialize;
use crate::models::{ContainmentBackend, ExecutionRequest};
use crate::mxc_error::MxcError;

/// Lifecycle phase in a state-aware request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Phase {
    Provision,
    Start,
    Exec,
    Stop,
    Deprovision,
}

impl Phase {
    /// Wire-format string for the phase, matching the SDK's `Phase` union.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Provision => "provision",
            Self::Start => "start",
            Self::Exec => "exec",
            Self::Stop => "stop",
            Self::Deprovision => "deprovision",
        }
    }
}

impl std::fmt::Display for Phase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl From<crate::wire::Phase> for Phase {
    fn from(p: crate::wire::Phase) -> Self {
        match p {
            crate::wire::Phase::Provision => Self::Provision,
            crate::wire::Phase::Start => Self::Start,
            crate::wire::Phase::Exec => Self::Exec,
            crate::wire::Phase::Stop => Self::Stop,
            crate::wire::Phase::Deprovision => Self::Deprovision,
        }
    }
}

/// Parsed state-aware request. Pairs the inner `ExecutionRequest` with the
/// state-aware-only wire fields the dispatcher consumes.
#[derive(Debug, Clone)]
pub struct ParsedStateAwareRequest {
    /// Domain model populated from the request's cross-cutting wire fields
    /// (`process`, `filesystem`, `network`, `ui`) — same path one-shot calls use.
    /// For non-exec phases the process-related fields (`script_code`,
    /// `working_directory`, `script_timeout`, `env`) are left at their default
    /// values; only exec carries process info on the wire.
    pub request: ExecutionRequest,
    pub phase: Phase,
    /// Present iff the request carried a `containment` field. Required for
    /// `provision`; for non-provision phases the dispatcher resolves the
    /// backend from the `sandbox_id` prefix instead.
    pub containment: Option<ContainmentBackend>,
    /// Present iff the request carried a `sandboxId` field. Required for all
    /// non-provision phases; absent for `provision`.
    pub sandbox_id: Option<String>,
    /// Present iff the request carried a `correlationVector` field — the MS-CV
    /// seeded at `provision` and relayed by the client into every later phase so
    /// all phases of one lifecycle share a telemetry base prefix. Absent for
    /// `provision` (which seeds its own) and when telemetry is not in use.
    pub correlation_vector: Option<String>,
    /// Raw `experimental` JSON object (un-narrowed). Shape:
    /// `{ <backend_key>: { <phase_name>: <typed-config>, ... }, ... }`.
    /// `deserialize_config<C>` navigates the two layers.
    pub experimental_raw: Option<Value>,
    /// Full DECODED request text, retained so `deserialize_config<C>` can
    /// deserialize the `experimental.<backend>.<phase>` sub-slice positionally
    /// and report typed errors with whole-file (line, column) coordinates —
    /// parity with base-config errors. `None` disables the positional path and
    /// falls back to the value-based `experimental_raw` deserialize.
    pub source_text: Option<Box<str>>,
}

impl ParsedStateAwareRequest {
    /// Returns the typed per-phase config for the given backend, or `None` if
    /// the wire request does not carry one. Surfaces shape mismatches as
    /// `MxcError::MalformedRequest`.
    ///
    /// `backend_key` is the wire-format backend name (the `containment`
    /// string, e.g. "isolation_session") — typically pulled from a trait const
    /// at the dispatcher.
    pub fn deserialize_config<C: DeserializeOwned>(
        &self,
        backend_key: &str,
        phase_name: &str,
    ) -> Result<Option<C>, MxcError> {
        // Presence gate over the parsed value tree. Cheap, and preserves the
        // established "backend key or phase key absent => None" behavior
        // regardless of whether the positional path below is available.
        let Some(exp) = self.experimental_raw.as_ref() else {
            return Ok(None);
        };
        let Some(backend_obj) = exp.get(backend_key) else {
            return Ok(None);
        };
        let Some(phase_value) = backend_obj.get(phase_name) else {
            return Ok(None);
        };

        let prefix = format!("experimental.{backend_key}.{phase_name}");

        // Preferred path: deserialize the phase config directly from its
        // sub-slice of the retained source text so typed errors carry
        // whole-file line/column, matching base-config diagnostics. Any failure
        // to locate the sub-slice falls through to the value-based path so a
        // would-be typed error is never turned into a navigation panic.
        if let Some(source_text) = self.source_text.as_deref() {
            if let Some((fragment, fragment_offset)) =
                locate_phase_fragment(source_text, backend_key, phase_name)
            {
                return match config_deserialize::from_str::<C>(fragment) {
                    Ok(config) => Ok(Some(config)),
                    Err(error) => {
                        let error = config_deserialize::remap_error_to_source(
                            error,
                            fragment,
                            fragment_offset,
                            source_text,
                        );
                        Err(MxcError::malformed_request(
                            error.with_prefix(&prefix).to_string(),
                        ))
                    }
                };
            }
        }

        // Fallback: value-based deserialize. A `serde_json::Value` carries no
        // source offsets, so these errors keep only the JSON-path prefix (the
        // prior behavior) — no regression.
        config_deserialize::from_value_ref(phase_value)
            .map(Some)
            .map_err(|error| MxcError::malformed_request(error.with_prefix(&prefix).to_string()))
    }

    /// Returns the `sandbox_id` for non-provision phases. Surfaces a missing
    /// id as `MxcError::MalformedRequest` — the caller typically only invokes
    /// this on phases where the wire format requires it.
    pub fn sandbox_id_required(&self) -> Result<&str, MxcError> {
        self.sandbox_id.as_deref().ok_or_else(|| {
            MxcError::malformed_request(format!("phase {} requires a sandboxId", self.phase))
        })
    }
}

/// Navigate the retained request text to the `experimental.<backend>.<phase>`
/// sub-slice, returning the fragment (borrowed from `source_text`) and its byte
/// offset within `source_text`.
///
/// Each layer is re-parsed as a map of owned-key → borrowed [`RawValue`], so the
/// returned fragment is a genuine sub-slice of `source_text` whose byte offset is
/// the pointer delta. Returns `None` when any navigation step fails or the
/// located fragment is not contained within `source_text` (mirroring the
/// fail-closed containment check used by the base-config source-span logic), so
/// the caller falls back to the value-based path rather than fabricating an
/// offset.
///
/// Map keys are deserialized as owned `String` (not borrowed `&str`): the
/// permissive `experimental` object may carry sibling keys containing JSON
/// escapes (e.g. `"is\u006Flation_session"`), which cannot be borrowed as
/// `&str` and would otherwise fail the whole-map parse and silently drop the
/// positional (line/column) diagnostics. Only the values are borrowed, so the
/// returned fragment still points into `source_text`.
fn locate_phase_fragment<'a>(
    source_text: &'a str,
    backend_key: &str,
    phase_name: &str,
) -> Option<(&'a str, usize)> {
    let top: HashMap<String, &RawValue> = serde_json::from_str(source_text).ok()?;
    let experimental = top.get("experimental")?;
    let backends: HashMap<String, &RawValue> = serde_json::from_str(experimental.get()).ok()?;
    let backend = backends.get(backend_key)?;
    let phases: HashMap<String, &RawValue> = serde_json::from_str(backend.get()).ok()?;
    let fragment = phases.get(phase_name)?.get();

    let offset = (fragment.as_ptr() as usize).checked_sub(source_text.as_ptr() as usize)?;
    (offset.checked_add(fragment.len())? <= source_text.len()).then_some((fragment, offset))
}

/// Public bridge between parser and dispatcher.
#[derive(Debug, Clone)]
pub enum MxcRequest {
    OneShot(ExecutionRequest),
    StateAware(ParsedStateAwareRequest),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::IsolationSessionConfig;
    use crate::mxc_error::MxcErrorCode;
    use serde::Deserialize;
    use serde_json::json;

    #[derive(Debug, Deserialize, PartialEq, Eq)]
    struct DummyStartConfig {
        configuration_id: String,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    #[allow(dead_code)]
    struct ArrayStartConfig {
        port_mappings: Vec<ArrayPortMapping>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    #[allow(dead_code)]
    struct ArrayPortMapping {
        windows_port: u16,
        container_port: u16,
    }

    fn parsed_with_experimental(exp: Option<Value>, phase: Phase) -> ParsedStateAwareRequest {
        ParsedStateAwareRequest {
            request: ExecutionRequest::default(),
            phase,
            containment: None,
            sandbox_id: None,
            correlation_vector: None,
            experimental_raw: exp,
            source_text: None,
        }
    }

    /// Build a request from full request text, populating both `experimental_raw`
    /// (the presence gate) and `source_text` (the positional path) the way the
    /// real parser does — so `deserialize_config` exercises the whole-file
    /// coordinate translation.
    fn parsed_with_source(source_text: &str, phase: Phase) -> ParsedStateAwareRequest {
        let full: Value = serde_json::from_str(source_text).expect("valid JSON");
        let experimental_raw = full.get("experimental").cloned();
        ParsedStateAwareRequest {
            request: ExecutionRequest::default(),
            phase,
            containment: None,
            sandbox_id: None,
            correlation_vector: None,
            experimental_raw,
            source_text: Some(source_text.to_owned().into_boxed_str()),
        }
    }

    #[test]
    fn deserialize_config_returns_none_when_no_experimental_block() {
        let p = parsed_with_experimental(None, Phase::Start);
        let r = p
            .deserialize_config::<DummyStartConfig>("isolation_session", "start")
            .unwrap();
        assert!(r.is_none());
    }

    #[test]
    fn deserialize_config_returns_none_when_backend_key_absent() {
        let p = parsed_with_experimental(Some(json!({})), Phase::Start);
        let r = p
            .deserialize_config::<DummyStartConfig>("isolation_session", "start")
            .unwrap();
        assert!(r.is_none());
    }

    #[test]
    fn deserialize_config_returns_none_when_phase_absent() {
        let exp = json!({"isolation_session": {}});
        let p = parsed_with_experimental(Some(exp), Phase::Start);
        let r = p
            .deserialize_config::<DummyStartConfig>("isolation_session", "start")
            .unwrap();
        assert!(r.is_none());
    }

    #[test]
    fn deserialize_config_round_trips_typed_config() {
        let exp = json!({
            "isolation_session": {
                "start": { "configuration_id": "small" }
            }
        });
        let p = parsed_with_experimental(Some(exp), Phase::Start);
        let r = p
            .deserialize_config::<DummyStartConfig>("isolation_session", "start")
            .unwrap()
            .expect("config should be present");
        assert_eq!(
            r,
            DummyStartConfig {
                configuration_id: "small".into(),
            }
        );
    }

    #[test]
    fn deserialize_config_rejects_shape_mismatch_as_malformed_request() {
        // Missing `configuration_id` — DummyStartConfig requires it.
        let exp = json!({
            "isolation_session": { "start": { "wrong_field": 42 } }
        });
        let p = parsed_with_experimental(Some(exp), Phase::Start);
        let err = p
            .deserialize_config::<DummyStartConfig>("isolation_session", "start")
            .unwrap_err();
        assert_eq!(err.code, MxcErrorCode::MalformedRequest);
        assert!(
            err.message.contains("experimental.isolation_session.start"),
            "expected the complete subtree path, got: {}",
            err.message
        );
        assert!(
            err.message.contains("missing field `configuration_id`"),
            "expected the missing field, got: {}",
            err.message
        );
    }

    #[test]
    fn deserialize_config_reports_whole_file_line_for_typed_error() {
        // The offending `configuration_id` value sits on whole-file line 5.
        let source_text = "\
{
  \"experimental\": {
    \"isolation_session\": {
      \"start\": {
        \"configuration_id\": 42
      }
    }
  }
}";
        let parsed = parsed_with_source(source_text, Phase::Start);

        let err = parsed
            .deserialize_config::<DummyStartConfig>("isolation_session", "start")
            .unwrap_err();

        assert_eq!(err.code, MxcErrorCode::MalformedRequest);
        assert!(
            err.message
                .contains("experimental.isolation_session.start.configuration_id"),
            "expected the full subtree path, got: {}",
            err.message
        );
        assert!(
            err.message.contains("line 5"),
            "expected whole-file line 5, got: {}",
            err.message
        );
    }

    #[test]
    fn deserialize_config_whole_file_line_is_computed_not_hardcoded() {
        // Same shape as above, shifted down by two leading fields so the
        // offending value lands on whole-file line 7 instead of line 5.
        let source_text = "\
{
  \"sandboxId\": \"iso:wxc-abcd1234\",
  \"correlationVector\": \"cv.1\",
  \"experimental\": {
    \"isolation_session\": {
      \"start\": {
        \"configuration_id\": 42
      }
    }
  }
}";
        let parsed = parsed_with_source(source_text, Phase::Start);

        let err = parsed
            .deserialize_config::<DummyStartConfig>("isolation_session", "start")
            .unwrap_err();

        assert!(
            err.message
                .contains("experimental.isolation_session.start.configuration_id"),
            "expected the full subtree path, got: {}",
            err.message
        );
        assert!(
            err.message.contains("line 7"),
            "expected whole-file line 7, got: {}",
            err.message
        );
        assert!(
            !err.message.contains("line 5"),
            "location must be computed, not hardcoded, got: {}",
            err.message
        );
    }

    #[test]
    fn deserialize_config_falls_back_to_path_only_without_source_text() {
        // With no retained source text the value-based path is used: the typed
        // error still carries the full path prefix (prior behavior), no panic.
        let exp = json!({
            "isolation_session": { "start": { "wrong_field": 42 } }
        });
        let parsed = parsed_with_experimental(Some(exp), Phase::Start);

        let err = parsed
            .deserialize_config::<DummyStartConfig>("isolation_session", "start")
            .unwrap_err();

        assert_eq!(err.code, MxcErrorCode::MalformedRequest);
        assert!(
            err.message.contains("experimental.isolation_session.start"),
            "expected the subtree path in the fallback path, got: {}",
            err.message
        );
        assert!(
            err.message.contains("missing field `configuration_id`"),
            "expected the missing field, got: {}",
            err.message
        );
    }

    #[test]
    fn deserialize_config_reports_complete_array_element_path() {
        let exp = json!({
            "wslc": {
                "start": {
                    "portMappings": [
                        {
                            "windowsPort": "8080",
                            "containerPort": 80
                        }
                    ]
                }
            }
        });
        let parsed = parsed_with_experimental(Some(exp), Phase::Start);

        let error = parsed
            .deserialize_config::<ArrayStartConfig>("wslc", "start")
            .unwrap_err();

        assert_eq!(error.code, MxcErrorCode::MalformedRequest);
        assert!(
            error
                .message
                .contains("experimental.wslc.start.portMappings[0].windowsPort"),
            "expected complete array element path, got: {}",
            error.message
        );
        assert!(error.message.contains("expected u16"));
    }

    #[test]
    fn deserialize_config_redacts_secret_values() {
        let exp = json!({
            "isolation_session": {
                "start": {
                    "user": {
                        "upn": "alice@contoso.com",
                        "wamToken": 123456789
                    }
                }
            }
        });
        let parsed = parsed_with_experimental(Some(exp), Phase::Start);

        let error = parsed
            .deserialize_config::<IsolationSessionConfig>("isolation_session", "start")
            .unwrap_err();

        assert!(error
            .message
            .contains("experimental.isolation_session.start.user.wamToken"));
        assert!(error.message.contains("invalid secret value"));
        assert!(!error.message.contains("123456789"));
    }

    #[test]
    fn deserialize_config_preserves_location_with_escaped_sibling_key() {
        // A sibling key in the permissive `experimental` object carries a JSON
        // escape (`\u005F` decodes to `_`). A borrowed-`&str`-keyed map parse
        // cannot borrow such a key and would fail the whole-map parse, silently
        // dropping the positional path; owned `String` keys keep the whole-file
        // line/column intact. The offending value sits on whole-file line 6
        // (fragment-local line 2), proving the positional path still ran.
        let source_text = "\
{
  \"experimental\": {
    \"sib\\u005Fling\": {},
    \"isolation_session\": {
      \"start\": {
        \"configuration_id\": 42
      }
    }
  }
}";
        let parsed = parsed_with_source(source_text, Phase::Start);

        let err = parsed
            .deserialize_config::<DummyStartConfig>("isolation_session", "start")
            .unwrap_err();

        assert_eq!(err.code, MxcErrorCode::MalformedRequest);
        assert!(
            err.message
                .contains("experimental.isolation_session.start.configuration_id"),
            "expected the full subtree path, got: {}",
            err.message
        );
        assert!(
            err.message.contains("line 6"),
            "escaped sibling key must not drop positional path (want line 6), got: {}",
            err.message
        );
        assert!(
            !err.message.contains("line 2"),
            "location must be whole-file, not fragment-local, got: {}",
            err.message
        );
    }

    #[test]
    fn deserialize_config_reports_exact_whole_file_column() {
        // The offending value is not at column 1, so an exact column assertion
        // proves the column is computed and remapped, not ignored or hardcoded.
        let source_text = "\
{
  \"experimental\": {
    \"isolation_session\": {
      \"start\": { \"configuration_id\": 42 }
    }
  }
}";
        let parsed = parsed_with_source(source_text, Phase::Start);

        let err = parsed
            .deserialize_config::<DummyStartConfig>("isolation_session", "start")
            .unwrap_err();

        // `42` sits on whole-file line 4; serde reports the column at the end of
        // the integer token. The exact coordinate is asserted so a regression in
        // the fragment→whole-file offset math is caught.
        assert!(
            err.message.contains("line 4 column 39"),
            "expected exact whole-file coordinate 'line 4 column 39', got: {}",
            err.message
        );
    }

    #[test]
    fn deserialize_config_preserves_line_across_crlf_source() {
        // Line counting keys on `\n`, so CRLF endings must not shift the
        // whole-file line. (Column arithmetic is ASCII-by-design per
        // `byte_offset_of_line_col`; only the line is asserted here.)
        let source_text =
            "{\r\n  \"experimental\": {\r\n    \"isolation_session\": {\r\n      \"start\": {\r\n        \"configuration_id\": 42\r\n      }\r\n    }\r\n  }\r\n}";
        let parsed = parsed_with_source(source_text, Phase::Start);

        let err = parsed
            .deserialize_config::<DummyStartConfig>("isolation_session", "start")
            .unwrap_err();

        assert!(
            err.message.contains("line 5"),
            "CRLF endings must not shift the whole-file line (want line 5), got: {}",
            err.message
        );
    }

    #[test]
    fn deserialize_config_positional_path_redacts_secret_with_whole_file_location() {
        // Positional (source_text) path AND secret redaction together: the
        // wamToken secret value is malformed; the message must redact the value,
        // carry the full path, and report the whole-file line (7), not the
        // fragment-local one.
        let source_text = "\
{
  \"experimental\": {
    \"isolation_session\": {
      \"start\": {
        \"user\": {
          \"upn\": \"alice@contoso.com\",
          \"wamToken\": 123456789
        }
      }
    }
  }
}";
        let parsed = parsed_with_source(source_text, Phase::Start);

        let err = parsed
            .deserialize_config::<IsolationSessionConfig>("isolation_session", "start")
            .unwrap_err();

        assert!(
            err.message
                .contains("experimental.isolation_session.start.user.wamToken"),
            "expected the full secret path, got: {}",
            err.message
        );
        assert!(err.message.contains("invalid secret value"));
        assert!(
            !err.message.contains("123456789"),
            "secret leaked: {}",
            err.message
        );
        assert!(
            err.message.contains("line 7"),
            "expected whole-file secret location line 7, got: {}",
            err.message
        );
    }

    #[test]
    fn deserialize_config_falls_back_when_source_text_present_but_locator_fails() {
        // `source_text` is present and the presence gate passes, but the
        // retained text shapes `experimental.isolation_session` as a scalar, so
        // `locate_phase_fragment` cannot navigate to the phase fragment. The
        // code must fall back to the value-based path (path prefix, no source
        // coordinates) rather than panic or fabricate a location.
        let parsed = ParsedStateAwareRequest {
            request: ExecutionRequest::default(),
            phase: Phase::Start,
            containment: None,
            sandbox_id: None,
            correlation_vector: None,
            experimental_raw: Some(json!({
                "isolation_session": { "start": { "wrong_field": 42 } }
            })),
            source_text: Some(
                r#"{"experimental":{"isolation_session":5}}"#
                    .to_owned()
                    .into_boxed_str(),
            ),
        };

        let err = parsed
            .deserialize_config::<DummyStartConfig>("isolation_session", "start")
            .unwrap_err();

        assert_eq!(err.code, MxcErrorCode::MalformedRequest);
        assert!(
            err.message.contains("experimental.isolation_session.start"),
            "expected the subtree path from the fallback path, got: {}",
            err.message
        );
        assert!(
            err.message.contains("missing field `configuration_id`"),
            "expected the missing field, got: {}",
            err.message
        );
        assert!(
            !err.message.contains("line "),
            "fallback path carries no source coordinates, got: {}",
            err.message
        );
    }

    #[test]
    fn sandbox_id_required_returns_id_when_present() {
        let mut p = parsed_with_experimental(None, Phase::Start);
        p.sandbox_id = Some("iso:abcd1234".into());
        assert_eq!(p.sandbox_id_required().unwrap(), "iso:abcd1234");
    }

    #[test]
    fn sandbox_id_required_errors_when_absent() {
        let p = parsed_with_experimental(None, Phase::Start);
        let err = p.sandbox_id_required().unwrap_err();
        assert_eq!(err.code, MxcErrorCode::MalformedRequest);
    }
}
