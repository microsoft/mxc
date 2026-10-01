// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::common::adapt;
use crate::mxc_common::state_aware_operation::{StateAwareOperation, StateAwareStart};

#[test]
fn start_preserves_common_fields_and_unvalidated_identifier() {
    super::common::assert_no_config_phase("start");
}

#[test]
fn isolation_session_start_presence_and_user_map_verbatim() {
    for (fields, expected) in [
        ("", None),
        (r#","isolationSession":{}"#, None),
        (r#","isolationSession":{"start":{}}"#, Some(None)),
        (
            r#","isolationSession":{"start":{"user":{"upn":"alice@contoso.com","wamToken":"tok"}}}"#,
            Some(Some(("alice@contoso.com", "tok"))),
        ),
    ] {
        let source = format!(
            r#"{{"version":"1.1.0-alpha","phase":"start","sandboxId":"iso:example"{fields}}}"#
        );
        let (_, operation) = adapt(&source);
        let StateAwareOperation::Start { config, .. } = operation else {
            panic!("wrong operation: {fields}");
        };
        let observed = match &config {
            StateAwareStart::Absent => None,
            StateAwareStart::IsolationSession(config) => Some(
                config
                    .user
                    .as_ref()
                    .map(|user| (user.upn.as_str(), user.wam_token.as_str())),
            ),
        };
        assert_eq!(observed, expected, "{fields}");
    }
}
