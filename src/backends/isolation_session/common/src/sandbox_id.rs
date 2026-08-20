// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! The IsolationSession `sandboxId` codec.
//!
//! # Format
//!
//! ```text
//! iso:<base64url-nopad( JSON object, UTF-8 )>
//! ```
//!
//! The prefix and the first `:` are the cross-backend routing contract (the
//! dispatcher reads only that much). Everything after it is this backend's
//! private payload — each backend defines its own tail format.
//!
//! # Why an encoded payload rather than delimited segments
//!
//! The payload must say exactly which fields are present without relying on any
//! assumption about separator characters. The `agentUserName` is OS-assigned
//! and its format is explicitly not guaranteed stable across builds, so no
//! charset assumption about it is safe. The base64url alphabet
//! (`A-Z a-z 0-9 - _`) provably contains no `:`, no path separator, no shell
//! metacharacter, no whitespace and no NUL, which makes the entire class of
//! separator and path-traversal bugs *unrepresentable* rather than merely
//! prevented by careful parsing.
//!
//! # The envelope is frozen
//!
//! The tail is **always** base64url-nopad of a JSON object. The envelope itself
//! is not versioned and will not change; all future evolution happens as keys
//! inside the JSON. If it ever genuinely had to change, that is a hard break
//! handled by a new prefix or a coordinated rollout — not by carrying an outer
//! version segment indefinitely against a remote contingency.
//!
//! # Versioning
//!
//! `version` gates readers in one direction only:
//!
//! * newer than this build understands → rejected, with a message saying so
//!   (the remediation is "upgrade MXC", not "this id is corrupt")
//! * older → the reader decides (not reachable at v1)
//!
//! Bump `version` **only** for a change an old reader must not silently
//! mishandle. Adding an optional key does *not* bump it — a version that moved
//! on every additive change would reject ids old readers could have handled,
//! which is worse than having no version at all. Unknown keys are ignored on
//! decode (no `deny_unknown_fields`) so additive evolution is transparent.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};

use wxc_common::mxc_error::MxcError;

/// Routing prefix for every IsolationSession `sandboxId`. The single source of
/// truth: the `StatefulSandboxBackend::ID_PREFIX` associated const reads from
/// here so the codec and the dispatcher cannot drift.
pub(super) const ID_PREFIX: &str = "iso";

/// Payload schema version understood by this build.
pub(super) const CURRENT_VERSION: u32 = 1;

/// Maximum accepted `appId` length, in characters.
///
/// A sanity bound, not a security boundary — nothing downstream breaks at any
/// particular length. It comfortably clears a Package Family Name and a full
/// AUMID, and stops an absurd value from producing an id that makes the
/// caller's own later phases fail confusingly.
pub(super) const APP_ID_MAX_CHARS: usize = 256;

/// The decoded `sandboxId` payload.
///
/// `agent_user_name` is the OS-assigned account name and the addressing key for
/// every post-provision phase. `app_id` is the caller-supplied value forwarded
/// to the provisioning call and retained here so later phases can recover it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct SandboxIdPayload {
    pub version: u32,
    pub agent_user_name: String,
    /// Absent key means absent. An explicitly-supplied empty string is a
    /// *distinct* value from absent and round-trips as such — a future OS API
    /// may assign meaning to the empty string, so MXC does not collapse the
    /// two, and never synthesizes an empty string the caller did not send.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_id: Option<String>,
}

impl SandboxIdPayload {
    pub(super) fn new(agent_user_name: impl Into<String>, app_id: Option<String>) -> Self {
        Self {
            version: CURRENT_VERSION,
            agent_user_name: agent_user_name.into(),
            app_id,
        }
    }
}

/// Structural validation for a caller-supplied `appId`.
///
/// Structural only, deliberately: MXC is a pass-through carrier here and the OS
/// is the real consumer, so enforcing a Package Family Name grammar would risk
/// rejecting identity forms a future OS API accepts. For unpackaged
/// applications the value can legitimately be anything.
///
/// The two rejections are concrete hazards rather than judgements about
/// meaning:
///
/// * control characters — JSON can legally carry `\u0000`, and such a value
///   would later cross a `String` → `HSTRING` boundary where many Windows APIs
///   treat an embedded NUL as a terminator, silently truncating it
/// * length — see [`APP_ID_MAX_CHARS`]
///
/// The value is otherwise preserved verbatim: no trimming, no case folding, no
/// normalisation. An empty string is accepted.
pub(super) fn validate_app_id(app_id: &str) -> Result<(), MxcError> {
    if let Some(c) = app_id.chars().find(|c| c.is_control()) {
        return Err(MxcError::policy_validation(format!(
            "appId must not contain control characters (found U+{:04X})",
            c as u32
        )));
    }
    let len = app_id.chars().count();
    if len > APP_ID_MAX_CHARS {
        return Err(MxcError::policy_validation(format!(
            "appId must be at most {APP_ID_MAX_CHARS} characters (got {len})"
        )));
    }
    Ok(())
}

/// Encodes a payload into the full `iso:<base64url>` sandbox id.
///
/// Serialised from the struct rather than a map, so key order is deterministic
/// and the same content always produces the same id string.
pub(super) fn encode(payload: &SandboxIdPayload) -> Result<String, MxcError> {
    let json = serde_json::to_vec(payload).map_err(|e| {
        MxcError::backend_error(format!("failed to serialize sandbox id payload: {e}"))
    })?;
    Ok(format!("{ID_PREFIX}:{}", URL_SAFE_NO_PAD.encode(json)))
}

/// Decodes a full `iso:<base64url>` sandbox id.
///
/// Every structural failure surfaces as `malformed_id`. A payload minted by a
/// newer MXC uses the same code but says so explicitly, because the remediation
/// differs completely from a corrupt string.
pub(super) fn decode(sandbox_id: &str) -> Result<SandboxIdPayload, MxcError> {
    let (prefix, tail) = sandbox_id.split_once(':').ok_or_else(|| {
        MxcError::malformed_id(format!(
            "expected {ID_PREFIX}:<encoded payload>, got {sandbox_id:?}"
        ))
    })?;
    if prefix != ID_PREFIX {
        return Err(MxcError::malformed_id(format!(
            "expected the {ID_PREFIX:?} prefix, got {prefix:?}"
        )));
    }
    if tail.is_empty() {
        return Err(MxcError::malformed_id(format!(
            "sandbox_id {sandbox_id:?} has an empty payload"
        )));
    }

    let bytes = URL_SAFE_NO_PAD.decode(tail).map_err(|_| {
        MxcError::malformed_id(format!(
            "sandbox_id payload is not valid base64url: {sandbox_id:?}"
        ))
    })?;

    // Parse to a Value first so a non-object payload (array, string, number,
    // null) reports what it actually is rather than a serde field error.
    let value: serde_json::Value = serde_json::from_slice(&bytes).map_err(|_| {
        MxcError::malformed_id(format!(
            "sandbox_id payload is not valid JSON: {sandbox_id:?}"
        ))
    })?;
    if !value.is_object() {
        return Err(MxcError::malformed_id(format!(
            "sandbox_id payload must be a JSON object: {sandbox_id:?}"
        )));
    }

    // Read the version before the full shape so an id from a newer MXC is
    // reported as such even if its other fields do not fit this build's struct.
    match value.get("version").and_then(serde_json::Value::as_u64) {
        Some(v) if v > CURRENT_VERSION as u64 => {
            return Err(MxcError::malformed_id(format!(
                "sandbox_id was minted by a newer MXC (payload version {v}, this build \
                 understands up to {CURRENT_VERSION}); upgrade MXC to use this sandbox"
            )));
        }
        Some(_) => {}
        None => {
            return Err(MxcError::malformed_id(format!(
                "sandbox_id payload is missing a numeric `version`: {sandbox_id:?}"
            )));
        }
    }

    let payload: SandboxIdPayload = serde_json::from_value(value).map_err(|e| {
        MxcError::malformed_id(format!("sandbox_id payload has the wrong shape: {e}"))
    })?;

    // Post-shape invariants. Both hold by construction at mint time, so an id
    // violating either was hand-crafted or corrupted. Both surface as
    // `malformed_id`, never `policy_validation`: a caller-supplied id being
    // wrong is an id problem, and the phases that consume an id accept no
    // policy for a policy error to belong to.
    if payload.agent_user_name.is_empty() {
        return Err(MxcError::malformed_id(format!(
            "sandbox_id payload has an empty `agentUserName`: {sandbox_id:?}"
        )));
    }
    // `appId` is validated at provision, but `sandboxId` is caller-supplied on
    // every later phase, so provision is not the only way a value can arrive.
    // Re-checking here makes the guarantee hold by *value* rather than by
    // provenance — without it, a future consumer reading `app_id` off a decoded
    // id could see something `validate_app_id` never approved, including the
    // embedded NUL that check exists to keep away from a `String` -> `HSTRING`
    // boundary.
    if let Some(app_id) = payload.app_id.as_deref() {
        validate_app_id(app_id).map_err(|e| {
            MxcError::malformed_id(format!(
                "sandbox_id payload carries an invalid `appId`: {}",
                e.message
            ))
        })?;
    }

    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use wxc_common::mxc_error::MxcErrorCode;

    fn round_trip(agent: &str, app: Option<&str>) -> SandboxIdPayload {
        let payload = SandboxIdPayload::new(agent, app.map(str::to_string));
        let id = encode(&payload).unwrap();
        decode(&id).unwrap()
    }

    // ====== round-tripping ======

    #[test]
    fn round_trips_with_an_app_id() {
        let got = round_trip("_iso_abc_123", Some("PFN:Contoso.App_8wekyb3d8bbwe"));
        assert_eq!(got.agent_user_name, "_iso_abc_123");
        assert_eq!(got.app_id.as_deref(), Some("PFN:Contoso.App_8wekyb3d8bbwe"));
        assert_eq!(got.version, CURRENT_VERSION);
    }

    #[test]
    fn round_trips_without_an_app_id() {
        let got = round_trip("_iso_abc_123", None);
        assert_eq!(got.agent_user_name, "_iso_abc_123");
        assert_eq!(got.app_id, None);
    }

    #[test]
    fn empty_app_id_is_distinct_from_absent() {
        // The central property: a future OS API may assign meaning to the empty
        // string, so MXC must not collapse it into "absent".
        let with_empty = encode(&SandboxIdPayload::new("agent", Some(String::new()))).unwrap();
        let without = encode(&SandboxIdPayload::new("agent", None)).unwrap();
        assert_ne!(
            with_empty, without,
            "empty and absent appId must not encode identically"
        );
        assert_eq!(decode(&with_empty).unwrap().app_id.as_deref(), Some(""));
        assert_eq!(decode(&without).unwrap().app_id, None);
    }

    #[test]
    fn absent_app_id_omits_the_key_entirely() {
        let id = encode(&SandboxIdPayload::new("agent", None)).unwrap();
        let tail = id.split_once(':').unwrap().1;
        let json = String::from_utf8(URL_SAFE_NO_PAD.decode(tail).unwrap()).unwrap();
        assert!(
            !json.contains("appId"),
            "absent appId must omit the key: {json}"
        );
    }

    #[test]
    fn app_id_is_preserved_verbatim() {
        // No trimming, no case folding, no normalisation.
        for app in [
            "  leading and trailing  ",
            "MiXeD.CaSe_App",
            "spaces in the middle",
            "punctuation:\\/?#[]@!$&'()*+,;=",
            "unicode-\u{00e9}\u{4e2d}\u{6587}-\u{1F600}",
            " ",
        ] {
            let got = round_trip("agent", Some(app));
            assert_eq!(
                got.app_id.as_deref(),
                Some(app),
                "appId {app:?} not verbatim"
            );
        }
    }

    #[test]
    fn agent_user_name_with_hostile_characters_round_trips() {
        // The whole reason for encoding rather than delimiting: the OS-assigned
        // name carries no charset guarantee, so a colon or a path separator in
        // it must be harmless.
        for agent in [
            "has:a:colon",
            "has\\a\\backslash",
            "has/a/slash",
            "..",
            "../../etc/passwd",
            "C:\\Windows\\System32",
            "has a space",
            "unicode-\u{00e9}\u{4e2d}\u{6587}",
            "\"quoted\"",
        ] {
            let got = round_trip(agent, None);
            assert_eq!(
                got.agent_user_name, agent,
                "agent {agent:?} did not round-trip"
            );
        }
    }

    #[test]
    fn encoding_is_deterministic() {
        let payload = SandboxIdPayload::new("agent", Some("app".into()));
        assert_eq!(encode(&payload).unwrap(), encode(&payload).unwrap());
    }

    #[test]
    fn encoded_tail_contains_no_colon_or_path_separator() {
        // The alphabet property that makes the format safe by construction.
        for agent in ["has:a:colon", "..\\..\\x", "/etc/passwd", "plain"] {
            let id = encode(&SandboxIdPayload::new(agent, Some("a:b/c\\d".into()))).unwrap();
            let tail = id.split_once(':').unwrap().1;
            assert!(
                !tail.contains([':', '/', '\\', '.', ' ']),
                "tail {tail:?} escaped the base64url alphabet"
            );
        }
    }

    // ====== appId validation ======

    #[test]
    fn app_id_accepts_the_maximum_length_and_rejects_one_more() {
        let at_max = "a".repeat(APP_ID_MAX_CHARS);
        validate_app_id(&at_max).expect("exactly the cap must be accepted");
        let over = "a".repeat(APP_ID_MAX_CHARS + 1);
        let err = validate_app_id(&over).unwrap_err();
        assert_eq!(err.code, MxcErrorCode::PolicyValidation);
    }

    #[test]
    fn app_id_length_is_counted_in_characters_not_bytes() {
        // A multi-byte character must not consume several units of the budget.
        let at_max = "\u{4e2d}".repeat(APP_ID_MAX_CHARS);
        validate_app_id(&at_max).expect("cap is in characters, not bytes");
    }

    #[test]
    fn app_id_rejects_control_characters_including_nul() {
        for bad in [
            "has\u{0}nul",
            "has\nnewline",
            "has\ttab",
            "has\rcr",
            "\u{7}",
        ] {
            let err = validate_app_id(bad).unwrap_err();
            assert_eq!(
                err.code,
                MxcErrorCode::PolicyValidation,
                "expected rejection for {bad:?}"
            );
        }
    }

    #[test]
    fn app_id_accepts_empty_and_whitespace() {
        validate_app_id("").expect("empty is a legal, distinct value");
        validate_app_id("   ").expect("whitespace is preserved verbatim, not trimmed away");
    }

    // ====== decode failures ======

    #[test]
    fn decode_rejects_a_foreign_prefix() {
        let err = decode("wsb:deadbeef").unwrap_err();
        assert_eq!(err.code, MxcErrorCode::MalformedId);
    }

    #[test]
    fn decode_rejects_a_missing_colon_and_an_empty_tail() {
        assert_eq!(
            decode("no-colon-here").unwrap_err().code,
            MxcErrorCode::MalformedId
        );
        assert_eq!(decode("iso:").unwrap_err().code, MxcErrorCode::MalformedId);
        assert_eq!(decode("").unwrap_err().code, MxcErrorCode::MalformedId);
    }

    #[test]
    fn decode_rejects_invalid_base64() {
        let err = decode("iso:not valid base64!!").unwrap_err();
        assert_eq!(err.code, MxcErrorCode::MalformedId);
    }

    #[test]
    fn decode_rejects_valid_base64_that_is_not_json() {
        let id = format!("iso:{}", URL_SAFE_NO_PAD.encode(b"not json at all"));
        assert_eq!(decode(&id).unwrap_err().code, MxcErrorCode::MalformedId);
    }

    #[test]
    fn decode_rejects_json_that_is_not_an_object() {
        for json in ["[1,2,3]", "\"a string\"", "42", "null", "true"] {
            let id = format!("iso:{}", URL_SAFE_NO_PAD.encode(json.as_bytes()));
            let err = decode(&id).unwrap_err();
            assert_eq!(
                err.code,
                MxcErrorCode::MalformedId,
                "expected rejection for payload {json}"
            );
        }
    }

    #[test]
    fn decode_rejects_a_missing_or_non_numeric_version() {
        for json in [
            r#"{"agentUserName":"a"}"#,
            r#"{"version":"1","agentUserName":"a"}"#,
            r#"{"version":null,"agentUserName":"a"}"#,
        ] {
            let id = format!("iso:{}", URL_SAFE_NO_PAD.encode(json.as_bytes()));
            let err = decode(&id).unwrap_err();
            assert_eq!(err.code, MxcErrorCode::MalformedId, "payload {json}");
        }
    }

    #[test]
    fn decode_rejects_a_missing_or_wrongly_typed_agent_user_name() {
        for json in [r#"{"version":1}"#, r#"{"version":1,"agentUserName":42}"#] {
            let id = format!("iso:{}", URL_SAFE_NO_PAD.encode(json.as_bytes()));
            let err = decode(&id).unwrap_err();
            assert_eq!(err.code, MxcErrorCode::MalformedId, "payload {json}");
        }
    }

    #[test]
    fn decode_rejects_an_empty_agent_user_name() {
        // The name is the addressing key for every post-provision phase. An
        // empty one is structurally malformed, and letting it through would
        // hand `""` to the OS lifecycle calls — which answers "not found",
        // surfacing as `stale_id` ("re-provision") for a request that was never
        // well-formed in the first place.
        let json = r#"{"version":1,"agentUserName":""}"#;
        let id = format!("iso:{}", URL_SAFE_NO_PAD.encode(json.as_bytes()));
        let err = decode(&id).unwrap_err();
        assert_eq!(err.code, MxcErrorCode::MalformedId);
        assert!(
            err.message.contains("agentUserName"),
            "error must name the offending field, got: {}",
            err.message
        );
    }

    #[test]
    fn decode_rejects_an_app_id_that_provision_would_have_refused() {
        // `sandboxId` is caller-supplied on every post-provision phase, so a
        // crafted id can carry an `appId` that never passed provision-time
        // validation. Re-check on decode so the guarantee holds by value, not
        // by provenance.
        let oversized = "a".repeat(APP_ID_MAX_CHARS + 1);
        for app in [oversized.as_str(), "has\u{0}nul", "has\u{7}bell"] {
            let json = serde_json::json!({
                "version": CURRENT_VERSION,
                "agentUserName": "agent",
                "appId": app,
            })
            .to_string();
            let id = format!("iso:{}", URL_SAFE_NO_PAD.encode(json.as_bytes()));
            let err = decode(&id).unwrap_err();
            // `malformed_id`, NOT `policy_validation`: this is a bad id, and
            // the phases that consume one accept no policy.
            assert_eq!(
                err.code,
                MxcErrorCode::MalformedId,
                "expected MalformedId for appId {app:?}"
            );
            assert!(
                err.message.contains("appId"),
                "error must name the offending field, got: {}",
                err.message
            );
        }
    }

    #[test]
    fn decode_still_accepts_an_app_id_at_exactly_the_cap() {
        // The decode-side check must be the same check, not a stricter one.
        let json = serde_json::json!({
            "version": CURRENT_VERSION,
            "agentUserName": "agent",
            "appId": "a".repeat(APP_ID_MAX_CHARS),
        })
        .to_string();
        let id = format!("iso:{}", URL_SAFE_NO_PAD.encode(json.as_bytes()));
        let got = decode(&id).expect("exactly the cap must round-trip");
        assert_eq!(got.app_id.map(|a| a.len()), Some(APP_ID_MAX_CHARS));
    }

    #[test]
    fn decode_rejects_a_wrongly_typed_app_id() {
        let json = r#"{"version":1,"agentUserName":"a","appId":42}"#;
        let id = format!("iso:{}", URL_SAFE_NO_PAD.encode(json.as_bytes()));
        assert_eq!(decode(&id).unwrap_err().code, MxcErrorCode::MalformedId);
    }

    // ====== version gate ======

    #[test]
    fn decode_ignores_unknown_keys() {
        // Forward compatibility within a version depends on this.
        let json = format!(
            r#"{{"version":{CURRENT_VERSION},"agentUserName":"a","appId":"x","futureField":true}}"#
        );
        let id = format!("iso:{}", URL_SAFE_NO_PAD.encode(json.as_bytes()));
        let got = decode(&id).expect("unknown keys must be ignored, not rejected");
        assert_eq!(got.agent_user_name, "a");
        assert_eq!(got.app_id.as_deref(), Some("x"));
    }

    #[test]
    fn decode_rejects_a_newer_version_with_an_actionable_message() {
        let json = format!(
            r#"{{"version":{},"agentUserName":"a"}}"#,
            CURRENT_VERSION + 1
        );
        let id = format!("iso:{}", URL_SAFE_NO_PAD.encode(json.as_bytes()));
        let err = decode(&id).unwrap_err();
        assert_eq!(err.code, MxcErrorCode::MalformedId);
        assert!(
            err.message.contains("newer MXC"),
            "a newer-version id must say so rather than read as corrupt, got: {}",
            err.message
        );
    }

    #[test]
    fn decode_reports_a_newer_version_even_when_the_rest_does_not_fit() {
        // The version is read before the full shape, so an id whose other
        // fields this build cannot parse still gets the actionable message.
        let json = format!(
            r#"{{"version":{},"agentUserName":{{"nested":"shape"}}}}"#,
            CURRENT_VERSION + 1
        );
        let id = format!("iso:{}", URL_SAFE_NO_PAD.encode(json.as_bytes()));
        let err = decode(&id).unwrap_err();
        assert!(err.message.contains("newer MXC"), "got: {}", err.message);
    }

    #[test]
    fn decode_accepts_the_current_version() {
        let id = encode(&SandboxIdPayload::new("a", None)).unwrap();
        assert_eq!(decode(&id).unwrap().version, CURRENT_VERSION);
    }
}
