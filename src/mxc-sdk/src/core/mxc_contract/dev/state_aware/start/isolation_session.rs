// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::mxc_contract::dev::state_aware::provision::IsolationSessionUser;
use crate::mxc_contract::dev::OptionalField;
use serde::Deserialize;

/// IsolationSession settings accepted at start.
#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "schema-gen", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IsolationSessionStart {
    /// Optional Entra credentials for a sandbox provisioned with `user`.
    #[serde(default)]
    pub user: OptionalField<IsolationSessionUser>,
}

/// IsolationSession settings accepted by a start request.
#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "schema-gen", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StartIsolationSession {
    /// Optional start-phase settings.
    #[serde(default)]
    pub start: OptionalField<IsolationSessionStart>,
}

#[cfg(test)]
mod tests {
    use crate::mxc_contract::dev::{parse_request, Request, StartRequest};

    fn start(fields: &str) -> String {
        format!(r#"{{"version":"1.1.0-alpha","phase":"start","sandboxId":"iso:example"{fields}}}"#)
    }

    fn parse(fields: &str) -> Result<StartRequest, String> {
        match parse_request(&start(fields)) {
            Ok(Request::Start(request)) => Ok(request),
            Ok(other) => panic!("expected a start request: {other:?}"),
            Err(error) => Err(error.to_string()),
        }
    }

    #[test]
    fn user_is_accepted_under_the_start_section() {
        let request = parse(
            r#","isolationSession":{"start":{"user":{"upn":"alice@contoso.com","wamToken":"tok"}}}"#,
        )
        .unwrap();
        let user = request
            .isolation_session
            .as_ref()
            .and_then(|isolation_session| isolation_session.start.as_ref())
            .and_then(|start| start.user.as_ref())
            .expect("user bundle");
        assert_eq!(user.upn, "alice@contoso.com");
        assert_eq!(user.wam_token, "tok");
    }

    #[test]
    fn empty_sections_are_accepted() {
        parse(r#","isolationSession":{}"#).unwrap();
        parse(r#","isolationSession":{"start":{}}"#).unwrap();
    }

    #[test]
    fn other_phases_and_members_are_rejected() {
        for fields in [
            r#","isolationSession":{"provision":{}}"#,
            r#","isolationSession":{"start":{"appId":"Contoso.App"}}"#,
            r#","isolationSession":{"start":{"user":{"upn":"alice@contoso.com"}}}"#,
            r#","isolationSession":{"user":{"upn":"alice@contoso.com","wamToken":"tok"}}"#,
            r#","isolationSession":null"#,
            r#","isolationSession":{"start":null}"#,
        ] {
            assert!(parse(fields).is_err(), "{fields}");
        }
    }
}
