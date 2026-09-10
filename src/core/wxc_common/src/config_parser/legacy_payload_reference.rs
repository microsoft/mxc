// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Independent reference for the pre-typed-operation payload extraction.

use serde::de::DeserializeOwned;
use serde_json::Value;

pub(crate) fn extract<C: DeserializeOwned>(
    source: &str,
    backend: &str,
    phase: &str,
) -> Result<Option<C>, serde_json::Error> {
    let document: Value = serde_json::from_str(source)?;
    document
        .get("experimental")
        .and_then(|experimental| experimental.get(backend))
        .and_then(|configuration| configuration.get(phase))
        .map(|configuration| serde_json::from_value(configuration.clone()))
        .transpose()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config_parser::legacy_state_aware_request::LegacyStateAwareRequest as ParsedStateAwareRequest;
    use crate::state_aware_request::Phase;
    use crate::wire;

    /// Frozen mirror of the runtime IsolationSession provision config as it
    /// stood before the Phase 10a acknowledgment was added.
    ///
    /// This module is an *independent reference* for the pre-typed extraction,
    /// so it must characterize the old shape rather than track the live runtime
    /// type. Deserializing into the runtime type would make the reference learn
    /// each field added to that type later, which would quietly turn the
    /// baseline into a copy of current behavior.
    #[derive(Debug, Default, PartialEq, Eq, serde::Deserialize)]
    #[serde(default, rename_all = "camelCase")]
    struct FrozenIsolationSessionProvisionConfig {
        app_id: Option<String>,
    }

    #[test]
    fn legacy_sensitive_field_matching_remains_case_insensitive() {
        for field in [
            "apiToken",
            "CLIENT_SECRET",
            "USER",
            "password",
            "connectionString",
        ] {
            assert!(
                crate::config_deserialize::is_secret_path_field_ci(field),
                "{field}"
            );
        }
        for field in ["appId", "image", "imageTarPath", "username"] {
            assert!(
                !crate::config_deserialize::is_secret_path_field_ci(field),
                "{field}"
            );
        }
    }

    fn source(backend: &str, payload: Option<&str>) -> String {
        match payload {
            None => "{}".to_owned(),
            Some(payload) => format!(r#"{{"experimental":{{"{backend}":{payload}}}}}"#),
        }
    }

    fn old_request(source: &str) -> ParsedStateAwareRequest {
        let document: Value = serde_json::from_str(source).unwrap();
        ParsedStateAwareRequest {
            request: Default::default(),
            phase: Phase::Provision,
            containment: None,
            sandbox_id: None,
            experimental_raw: document.get("experimental").cloned(),
            source_text: Some(source.into()),
        }
    }

    #[test]
    fn isolation_session_reference_preserves_presence_and_values() {
        for (payload, expected) in [
            (None, None),
            (Some("{}"), None),
            (Some(r#"{"provision":{}}"#), Some(None)),
            (Some(r#"{"provision":{"appId":""}}"#), Some(Some(""))),
            (
                Some(r#"{"provision":{"appId":"example"}}"#),
                Some(Some("example")),
            ),
            // Legacy acceptance is deliberately broader than the exact contract.
            (Some(r#"{"provision":{"appId":null}}"#), Some(None)),
        ] {
            let json = source("isolation_session", payload);
            let observed = extract::<FrozenIsolationSessionProvisionConfig>(
                &json,
                "isolation_session",
                "provision",
            )
            .unwrap();
            assert_eq!(
                observed.as_ref().map(|config| config.app_id.as_deref()),
                expected
            );
            assert_eq!(
                old_request(&json)
                    .deserialize_config::<FrozenIsolationSessionProvisionConfig>(
                        "isolation_session",
                        "provision",
                    )
                    .unwrap(),
                observed,
            );
        }
        assert!(extract::<FrozenIsolationSessionProvisionConfig>(
            &source("isolation_session", Some(r#"{"provision":{"appId":7}}"#)),
            "isolation_session",
            "provision",
        )
        .is_err());
    }

    #[test]
    fn wslc_reference_checks_wire_fields_without_runtime_conversion() {
        for (payload, expected) in [
            (None, None),
            (Some("{}"), None),
            (Some(r#"{"provision":{}}"#), Some((None, None))),
            (
                Some(r#"{"provision":{"image":"image"}}"#),
                Some((Some("image"), None)),
            ),
            (
                Some(r#"{"provision":{"imageTarPath":"archive.tar"}}"#),
                Some((None, Some("archive.tar"))),
            ),
            (
                Some(r#"{"provision":{"image":"image","imageTarPath":"archive.tar"}}"#),
                Some((Some("image"), Some("archive.tar"))),
            ),
            (
                Some(r#"{"provision":{"image":"","imageTarPath":""}}"#),
                Some((Some(""), Some(""))),
            ),
            (
                Some(r#"{"provision":{"image":null,"imageTarPath":null}}"#),
                Some((None, None)),
            ),
        ] {
            let json = source("wslc", payload);
            let observed = extract::<wire::WslcProvisionPhase>(&json, "wslc", "provision").unwrap();
            let fields = |config: &wire::WslcProvisionPhase| {
                (config.image.clone(), config.image_tar_path.clone())
            };
            assert_eq!(
                observed.as_ref().map(fields),
                expected.map(|(image, tar)| (image.map(str::to_owned), tar.map(str::to_owned))),
            );
            let old = old_request(&json)
                .deserialize_config::<wire::WslcProvisionPhase>("wslc", "provision")
                .unwrap();
            assert_eq!(old.as_ref().map(fields), observed.as_ref().map(fields));
        }
        for field in ["image", "imageTarPath"] {
            let payload = format!(r#"{{"provision":{{"{field}":7}}}}"#);
            assert!(extract::<wire::WslcProvisionPhase>(
                &source("wslc", Some(&payload)),
                "wslc",
                "provision",
            )
            .is_err());
        }
    }

    #[test]
    fn absent_and_empty_outer_wrappers_have_no_configuration() {
        for json in ["{}", r#"{"experimental":{}}"#] {
            for backend in ["isolation_session", "windows_sandbox", "wslc"] {
                for phase in ["provision", "start", "exec", "stop", "deprovision"] {
                    assert!(extract::<Value>(json, backend, phase).unwrap().is_none());
                }
            }
        }
    }
}
