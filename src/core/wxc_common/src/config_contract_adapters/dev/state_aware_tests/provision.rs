// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::common::{adapt, assert_clean_common, assert_common_matches_legacy};
use crate::config_parser::legacy_payload_reference::extract;
use crate::models::{IsolationSessionProvisionConfig, WslcProvisionConfig};
use crate::state_aware_operation::{StateAwareOperation, StateAwareProvision};
use crate::wire;
use mxc_config_contract::dev as contract;

fn source(backend: &str, fields: &str) -> String {
    let network = if backend == "isolation_session" {
        r#","network":{"defaultPolicy":"allow","allowLocalNetwork":true}"#
    } else {
        ""
    };
    format!(
        r#"{{"version":"0.9.0-alpha","phase":"provision","containment":"{backend}"{network}{fields}}}"#
    )
}

#[test]
fn isolation_session_configuration_presence_matches_explicit_values_and_legacy() {
    for (fields, expected) in [
        ("", None),
        (r#","experimental":{}"#, None),
        (r#","experimental":{"isolation_session":{}}"#, None),
        (
            r#","experimental":{"isolation_session":{"provision":{}}}"#,
            Some(None),
        ),
        (
            r#","experimental":{"isolation_session":{"provision":{"appId":""}}}"#,
            Some(Some("")),
        ),
        (
            r#","experimental":{"isolation_session":{"provision":{"appId":"example"}}}"#,
            Some(Some("example")),
        ),
    ] {
        let json = source("isolation_session", fields);
        let (common, operation) = adapt(&json);
        assert_clean_common(&common);
        assert_common_matches_legacy(&json, &common);
        assert!(common.filesystem.is_none());
        assert!(common.process.is_none());
        let network = common.network.unwrap();
        assert_eq!(network.allow_local_network, Some(true));
        assert!(matches!(
            network.default_policy,
            Some(wire::NetworkPolicy::Allow)
        ));
        let StateAwareOperation::Provision(StateAwareProvision::IsolationSession(config)) =
            operation
        else {
            panic!("wrong operation");
        };
        assert_eq!(
            config.as_ref().map(|config| config.app_id.as_deref()),
            expected
        );
        assert_eq!(
            config,
            extract::<IsolationSessionProvisionConfig>(&json, "isolation_session", "provision")
                .unwrap()
        );
    }
}

#[test]
fn isolation_session_acknowledgment_forms_map_without_synthesizing_network() {
    // Legacy-only, acknowledgment-only, and both-consistent are all valid
    // during the additive phase. The acknowledgment-only form must reach the
    // runtime with NO network section at all: synthesizing a legacy `allow`
    // would assert a grant the caller never wrote.
    let acknowledgment = r#","experimental":{"isolation_session":{"provision":{"acknowledgeUnrestrictedNetwork":true}}}"#;
    let legacy = r#""network":{"defaultPolicy":"allow","allowLocalNetwork":true}"#;
    let request = |fields: &str| {
        format!(
            r#"{{"version":"0.9.0-alpha","phase":"provision","containment":"isolation_session"{fields}}}"#
        )
    };

    for (fields, network_present, expected_config) in [
        (format!(",{legacy}"), true, None),
        (acknowledgment.to_owned(), false, Some((true, None))),
        (format!(",{legacy}{acknowledgment}"), true, Some((true, None))),
        (
            r#","experimental":{"isolation_session":{"provision":{"appId":"Contoso.App","acknowledgeUnrestrictedNetwork":true}}}"#.to_owned(),
            false,
            Some((true, Some("Contoso.App"))),
        ),
        (
            format!(
                r#",{legacy},"experimental":{{"isolation_session":{{"provision":{{"appId":"Contoso.App"}}}}}}"#
            ),
            true,
            Some((false, Some("Contoso.App"))),
        ),
    ] {
        let json = request(&fields);
        let (common, operation) = adapt(&json);
        assert_clean_common(&common);
        // The rolling parser is the independent check that the exact adapter
        // neither invents nor drops the common network section.
        assert_common_matches_legacy(&json, &common);
        assert_eq!(common.network.is_some(), network_present, "{json}");
        let StateAwareOperation::Provision(StateAwareProvision::IsolationSession(config)) =
            operation
        else {
            panic!("wrong operation");
        };
        assert_eq!(
            config.map(|config| (
                config.acknowledge_unrestricted_network.is_some(),
                config.app_id
            )),
            expected_config
                .map(|(acknowledged, app_id): (bool, Option<&str>)| (
                    acknowledged,
                    app_id.map(str::to_owned)
                )),
            "{json}"
        );
    }
}

#[test]
fn isolation_session_provision_requires_one_acknowledgment_form() {
    // Structural: the contract refuses the document, so the adapter is never
    // reached and no backend policy check is involved.
    for fields in [
        "",
        r#","experimental":{}"#,
        r#","experimental":{"isolation_session":{"provision":{"appId":"Contoso.App"}}}"#,
        r#","network":{}"#,
        r#","network":{"defaultPolicy":"block","allowLocalNetwork":true}"#,
    ] {
        let json = format!(
            r#"{{"version":"0.9.0-alpha","phase":"provision","containment":"isolation_session"{fields}}}"#
        );
        assert!(contract::parse_request(&json).is_err(), "{json}");
    }
}

#[test]
fn the_acknowledgment_is_provision_only_and_backend_scoped() {
    // Later phases carry no per-phase config, and another backend's provision
    // section is closed, so a misplaced acknowledgment is refused rather than
    // silently ignored.
    for phase in ["start", "stop", "deprovision"] {
        let json = format!(
            r#"{{"version":"0.9.0-alpha","phase":"{phase}","sandboxId":"iso:example","experimental":{{"isolation_session":{{"provision":{{"acknowledgeUnrestrictedNetwork":true}}}}}}}}"#
        );
        assert!(contract::parse_request(&json).is_err(), "{json}");
    }
    let exec = r#"{"version":"0.9.0-alpha","phase":"exec","sandboxId":"iso:example","process":{"commandLine":"echo hi"},"experimental":{"isolation_session":{"provision":{"acknowledgeUnrestrictedNetwork":true}}}}"#;
    assert!(contract::parse_request(exec).is_err());

    for backend in ["windows_sandbox", "wslc"] {
        let json = format!(
            r#"{{"version":"0.9.0-alpha","phase":"provision","containment":"{backend}","experimental":{{"{backend}":{{"provision":{{"acknowledgeUnrestrictedNetwork":true}}}}}}}}"#
        );
        assert!(contract::parse_request(&json).is_err(), "{json}");
    }
}

#[test]
fn wslc_configuration_matches_explicit_values_without_wire_conversion() {
    for (fields, expected) in [
        ("", None),
        (r#","experimental":{}"#, None),
        (r#","experimental":{"wslc":{}}"#, None),
        (
            r#","experimental":{"wslc":{"provision":{}}}"#,
            Some((None, None)),
        ),
        (
            r#","experimental":{"wslc":{"provision":{"image":"image"}}}"#,
            Some((Some("image"), None)),
        ),
        (
            r#","experimental":{"wslc":{"provision":{"imageTarPath":"archive.tar"}}}"#,
            Some((None, Some("archive.tar"))),
        ),
        (
            r#","experimental":{"wslc":{"provision":{"image":"image","imageTarPath":"archive.tar"}}}"#,
            Some((Some("image"), Some("archive.tar"))),
        ),
        (
            r#","experimental":{"wslc":{"provision":{"image":"","imageTarPath":""}}}"#,
            Some((Some(""), Some(""))),
        ),
        (
            r#","experimental":{"wslc":{"provision":{"image":""}}}"#,
            Some((Some(""), None)),
        ),
        (
            r#","experimental":{"wslc":{"provision":{"imageTarPath":""}}}"#,
            Some((None, Some(""))),
        ),
    ] {
        let json = source("wslc", fields);
        let (common, operation) = adapt(&json);
        assert_clean_common(&common);
        assert_common_matches_legacy(&json, &common);
        assert!(common.network.is_none());
        let StateAwareOperation::Provision(StateAwareProvision::Wslc(config)) = operation else {
            panic!("wrong operation");
        };
        let observed = config
            .as_ref()
            .map(|config| (config.image.as_deref(), config.image_tar_path.as_deref()));
        assert_eq!(observed, expected);
        let legacy = extract::<wire::WslcProvisionPhase>(&json, "wslc", "provision").unwrap();
        assert_eq!(
            observed,
            legacy
                .as_ref()
                .map(|config| (config.image.as_deref(), config.image_tar_path.as_deref()))
        );
    }
}

#[test]
fn rolling_wslc_conversion_has_independent_expected_fields() {
    for (image, image_tar_path) in [
        (None, None),
        (Some(""), None),
        (None, Some("archive.tar")),
        (Some("image"), Some("archive.tar")),
    ] {
        let wire = wire::WslcProvisionPhase {
            image: image.map(str::to_owned),
            image_tar_path: image_tar_path.map(str::to_owned),
        };
        let runtime = WslcProvisionConfig::from(wire);
        assert_eq!(runtime.image.as_deref(), image);
        assert_eq!(runtime.image_tar_path.as_deref(), image_tar_path);
    }
}

#[test]
fn provision_common_fields_are_independent_of_backend_payload() {
    for backend in ["isolation_session", "windows_sandbox", "wslc"] {
        for fields in [
            "",
            r#","_comment":null"#,
            r#","experimental":{}"#,
            r#","telemetry":{}"#,
            r#","$schema":"https://example.com/schema","_comment":"comment","telemetry":{"enabled":false}"#,
        ] {
            let json = source(backend, fields);
            let (common, operation) = adapt(&json);
            assert_clean_common(&common);
            assert_common_matches_legacy(&json, &common);
            assert_eq!(common.version.as_deref(), Some("0.9.0-alpha"));
            assert_eq!(operation.phase().as_str(), "provision");
            assert!(operation.sandbox_id().is_none());
            if backend == "windows_sandbox" {
                assert_eq!(
                    operation,
                    StateAwareOperation::Provision(StateAwareProvision::WindowsSandbox)
                );
            }
            if fields.contains("\"enabled\"") {
                assert_eq!(common.telemetry.unwrap().enabled, Some(false));
            }
        }
    }
    for backend in ["windows_sandbox", "wslc"] {
        let json = source(backend, r#","filesystem":{}"#);
        let (common, _) = adapt(&json);
        assert_common_matches_legacy(&json, &common);
        let filesystem = common.filesystem.unwrap();
        assert!(filesystem.readonly_paths.is_none());
        assert!(filesystem.readwrite_paths.is_none());
        assert!(filesystem.denied_paths.is_none());

        let json = source(
            backend,
            r#","filesystem":{"readonlyPaths":["/read"],"readwritePaths":["/write"],"deniedPaths":["/deny"]}"#,
        );
        let (common, _) = adapt(&json);
        assert_common_matches_legacy(&json, &common);
        let filesystem = common.filesystem.unwrap();
        assert_eq!(filesystem.readonly_paths.unwrap(), ["/read"]);
        assert_eq!(filesystem.readwrite_paths.unwrap(), ["/write"]);
        assert_eq!(filesystem.denied_paths.unwrap(), ["/deny"]);
    }
    let (common, _) = adapt(&source("wslc", r#","network":{}"#));
    let network = common.network.unwrap();
    assert!(network.default_policy.is_none());
    assert!(network.allowed_hosts.is_none());
    assert!(network.blocked_hosts.is_none());
    assert!(network.proxy.is_none());
    let json = source(
        "wslc",
        r#","network":{"defaultPolicy":"block","enforcementMode":"firewall","allowLocalNetwork":false,"allowedHosts":["allowed"],"blockedHosts":["blocked"],"proxy":{"url":"http://proxy.example"}}"#,
    );
    let (common, _) = adapt(&json);
    assert_common_matches_legacy(&json, &common);
    let network = common.network.unwrap();
    assert!(matches!(
        network.default_policy,
        Some(wire::NetworkPolicy::Block)
    ));
    assert!(matches!(
        network.enforcement_mode,
        Some(wire::NetworkEnforcement::Firewall)
    ));
    assert_eq!(network.allow_local_network, Some(false));
    assert_eq!(network.allowed_hosts.unwrap(), ["allowed"]);
    assert_eq!(network.blocked_hosts.unwrap(), ["blocked"]);
    assert_eq!(
        network.proxy.unwrap().url.as_deref(),
        Some("http://proxy.example")
    );
}

#[test]
fn exact_rejections_do_not_inherit_legacy_null_or_unknown_field_acceptance() {
    for (backend, field) in [
        ("isolation_session", "appId"),
        ("wslc", "image"),
        ("wslc", "imageTarPath"),
    ] {
        for invalid in ["null", "42", "true", "[]", "{}"] {
            let fields = format!(
                r#","experimental":{{"{backend}":{{"provision":{{"{field}":{invalid}}}}}}}"#
            );
            let json = source(backend, &fields);
            assert!(contract::parse_request(&json).is_err(), "{json}");
            if invalid == "null" {
                if backend == "isolation_session" {
                    assert_eq!(
                        extract::<IsolationSessionProvisionConfig>(&json, backend, "provision")
                            .unwrap()
                            .unwrap()
                            .app_id,
                        None
                    );
                } else {
                    let legacy = extract::<wire::WslcProvisionPhase>(&json, backend, "provision")
                        .unwrap()
                        .unwrap();
                    assert_eq!(legacy.image, None);
                    assert_eq!(legacy.image_tar_path, None);
                }
            }
        }
        for payload in [
            format!(r#"{{"{field}":"a","{field}":"b"}}"#),
            r#"{"unknown":true}"#.to_owned(),
        ] {
            let json = source(
                backend,
                &format!(r#","experimental":{{"{backend}":{{"provision":{payload}}}}}"#),
            );
            assert!(contract::parse_request(&json).is_err(), "{json}");
            if payload.contains("unknown") {
                if backend == "isolation_session" {
                    assert_eq!(
                        extract::<IsolationSessionProvisionConfig>(&json, backend, "provision")
                            .unwrap()
                            .unwrap()
                            .app_id,
                        None,
                    );
                } else {
                    let legacy = extract::<wire::WslcProvisionPhase>(&json, backend, "provision")
                        .unwrap()
                        .unwrap();
                    assert!(legacy.image.is_none());
                    assert!(legacy.image_tar_path.is_none());
                }
            }
        }
    }
    for fields in [
        r#","experimental":{"windows_sandbox":{"provision":{}}}"#,
        r#","experimental":{"provision":{}}"#,
    ] {
        assert!(contract::parse_request(&source("windows_sandbox", fields)).is_err());
    }
}

#[test]
fn non_provision_phases_reject_backend_payloads_and_invalid_wrappers() {
    for phase in ["start", "exec", "stop", "deprovision"] {
        let process = if phase == "exec" {
            r#","process":{"commandLine":"echo"}"#
        } else {
            ""
        };
        for backend in ["isolation_session", "windows_sandbox", "wslc"] {
            let experimental = serde_json::json!({backend: {phase: {}}});
            let json = format!(
                r#"{{"version":"0.9.0-alpha","phase":"{phase}","sandboxId":"id"{process},"experimental":{experimental}}}"#
            );
            assert!(contract::parse_request(&json).is_err(), "{json}");
        }
        for invalid in ["null", "42", "[42]", "true", r#""text""#] {
            let json = format!(
                r#"{{"version":"0.9.0-alpha","phase":"{phase}","sandboxId":"id"{process},"experimental":{invalid}}}"#
            );
            assert!(contract::parse_request(&json).is_err(), "{json}");
        }

        let json = format!(
            r#"{{"version":"0.9.0-alpha","phase":"{phase}","sandboxId":"id"{process},"experimental":{{}},"experimental":{{}}}}"#
        );
        assert!(contract::parse_request(&json).is_err(), "{json}");
    }
}

#[test]
fn empty_experimental_sequence_retains_existing_exact_contract_acceptance() {
    // The existing empty contract structs deserialize [] as well as {}.
    // This internal migration must not tighten that contract incidentally.
    for phase in ["start", "exec", "stop", "deprovision"] {
        let process = if phase == "exec" {
            r#","process":{"commandLine":"echo"}"#
        } else {
            ""
        };
        let json = format!(
            r#"{{"version":"0.9.0-alpha","phase":"{phase}","sandboxId":"id"{process},"experimental":[]}}"#
        );
        let (common, operation) = adapt(&json);
        assert_eq!(operation.phase().as_str(), phase);
        assert_eq!(operation.sandbox_id(), Some("id"));
        assert!(common.experimental.is_none());
    }
}
