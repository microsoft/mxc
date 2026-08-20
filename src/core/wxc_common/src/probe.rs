// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::id::parse_sandbox_id_prefix;
use crate::models::ContainmentBackend;
use crate::mxc_error::MxcError;
use crate::wire;
use std::borrow::Cow;

#[derive(serde::Deserialize)]
struct ContainmentProbe {
    #[serde(default)]
    containment: Option<wire::Containment>,
}

pub(crate) fn probe_one_shot_backend(json: &str) -> Option<ContainmentBackend> {
    let probe: ContainmentProbe = serde_json::from_str(json).ok()?;

    Some(
        probe
            .containment
            .unwrap_or(wire::Containment::Process)
            .into(),
    )
}

/// Just the `sandboxId` declaration.
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct SandboxIdProbe<'a> {
    #[serde(borrow, default)]
    sandbox_id: Option<Cow<'a, str>>,
}

pub(crate) fn probe_state_aware_backend(json: &str) -> Result<ContainmentBackend, MxcError> {
    let probe: SandboxIdProbe =
        serde_json::from_str(json).map_err(|e| MxcError::malformed_request(e.to_string()))?;

    let sandbox_id = probe
        .sandbox_id
        .ok_or_else(|| MxcError::malformed_request("state-aware requests require 'sandboxId'"))?;

    crate::state_aware_dispatch::backend_from_prefix(parse_sandbox_id_prefix(&sandbox_id)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mxc_error::MxcErrorCode;

    /// The phase probe is reused from `mxc_config_contract::dev` rather than
    /// reimplemented here.
    #[test]
    fn reused_phase_probe_classifies_one_shot_and_exec() {
        use mxc_config_contract::dev::{probe_phase, Phase};

        // Absent phase selects the one-shot path.
        assert_eq!(
            probe_phase(r#"{"process":{"commandLine":"echo hi"}}"#).unwrap(),
            None
        );

        // Exec is the only phase the CLI command override is valid for.
        assert_eq!(
            probe_phase(r#"{"phase":"exec","sandboxId":"iso:abcd1234"}"#).unwrap(),
            Some(Phase::Exec),
        );

        for (phase, expected) in [
            ("provision", Phase::Provision),
            ("start", Phase::Start),
            ("stop", Phase::Stop),
            ("deprovision", Phase::Deprovision),
        ] {
            assert_eq!(
                probe_phase(&format!(r#"{{"phase":"{phase}"}}"#)).unwrap(),
                Some(expected),
            );
        }
    }

    /// The contract probe is stricter than the rolling parser: it rejects
    /// declarations the parser accepts and reports differently.
    #[test]
    fn reused_phase_probe_is_stricter_than_the_rolling_parser() {
        use mxc_config_contract::dev::probe_phase;

        assert!(probe_phase(r#"{"phase":null}"#).is_err());
        assert!(probe_phase(r#"{"phase":42}"#).is_err());
        assert!(probe_phase(r#"{"phase":"start","phase":"exec"}"#).is_err());
        assert!(probe_phase(r#"{"phase":"nope"}"#).is_err());
    }

    #[test]
    fn one_shot_probe_agrees_with_the_parser_for_every_spelling() {
        for spelling in [
            "process",
            "processcontainer",
            "appcontainer",
            "vm",
            "windows_sandbox",
            "lxc",
            "microvm",
            "hyperlight",
            "wslc",
            "seatbelt",
            "macos_sandbox",
            "isolation_session",
        ] {
            let wire: wire::Containment =
                serde_json::from_str(&format!(r#""{spelling}""#)).unwrap();
            assert_eq!(
                probe_one_shot_backend(&format!(r#"{{"containment":"{spelling}"}}"#)),
                Some(crate::config_parser::map_wire_containment(Some(&wire))),
                "probe and parser disagree on {spelling}",
            );
        }
        assert_eq!(
            probe_one_shot_backend("{}"),
            Some(crate::config_parser::map_wire_containment(None)),
        );
    }

    #[test]
    fn state_aware_probe_resolves_every_registered_prefix() {
        for (id, expected) in [
            ("iso:abcd1234", ContainmentBackend::IsolationSession),
            ("wsb:abcd1234", ContainmentBackend::WindowsSandbox),
            ("wslc:abcd1234", ContainmentBackend::Wslc),
        ] {
            let json = format!(r#"{{"phase":"exec","sandboxId":"{id}"}}"#);
            assert_eq!(probe_state_aware_backend(&json).unwrap(), expected);
        }
    }

    #[test]
    fn state_aware_probe_rejects_missing_malformed_and_unregistered_ids() {
        // Missing sandboxId.
        assert!(probe_state_aware_backend(r#"{"phase":"exec"}"#).is_err());
        // No `<prefix>:` form.
        assert!(probe_state_aware_backend(r#"{"sandboxId":"no-colon"}"#).is_err());
        // Empty prefix.
        assert!(probe_state_aware_backend(r#"{"sandboxId":":abcd"}"#).is_err());
        // Syntactically valid, but no backend registers it.
        let err = probe_state_aware_backend(r#"{"sandboxId":"zzz:abcd"}"#).unwrap_err();
        assert_eq!(err.code, MxcErrorCode::UnsupportedContainment);
    }

    #[test]
    fn one_shot_probe_returns_none_for_malformed_input() {
        assert!(probe_one_shot_backend(r#"{"containment":"nope"}"#).is_none());
        assert!(probe_one_shot_backend(r#"{"containment":42}"#).is_none());
        assert!(probe_one_shot_backend(r#"{ "process": "#).is_none());
        // Explicit null is absent, and resolves to the host default — same as the parser.
        assert_eq!(
            probe_one_shot_backend(r#"{"containment":null}"#),
            Some(crate::config_parser::map_wire_containment(None)),
        );
    }
}
