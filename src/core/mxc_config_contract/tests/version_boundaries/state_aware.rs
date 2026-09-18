// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use mxc_config_contract::published::v0_8_0_alpha::Request as V08Request;
use mxc_config_contract::published::v0_9_0_alpha::{parse_request, ProvisionRequest, Request};

#[derive(Clone, Copy)]
enum ExpectedRoot {
    IsolationSessionProvision,
    WslcProvision,
    Start,
    Exec,
    Stop,
    Deprovision,
}

impl ExpectedRoot {
    fn matches(self, request: &Request) -> bool {
        matches!(
            (self, request),
            (
                Self::IsolationSessionProvision,
                Request::Provision(ProvisionRequest::IsolationSession(_)),
            ) | (Self::Start, Request::Start(_))
                | (
                    Self::WslcProvision,
                    Request::Provision(ProvisionRequest::Wslc(_)),
                )
                | (Self::Exec, Request::Exec(_))
                | (Self::Stop, Request::Stop(_))
                | (Self::Deprovision, Request::Deprovision(_))
        )
    }
}

struct StateAwareCase {
    name: &'static str,
    json: &'static str,
    expected: ExpectedRoot,
}

const CASES: &[StateAwareCase] = &[
    StateAwareCase {
        name: "WSLC provision",
        json: r#"{
            "version": "0.9.0-alpha",
            "phase": "provision",
            "containment": "wslc",
            "filesystem": {"readonlyPaths": ["/workspace"]},
            "wslc": {
                "provision": {
                    "image": "alpine:latest"
                }
            }
        }"#,
        expected: ExpectedRoot::WslcProvision,
    },
    StateAwareCase {
        name: "IsolationSession provision",
        json: r#"{
            "version": "0.9.0-alpha",
            "phase": "provision",
            "containment": "isolation_session",
            "telemetry": {"enabled": false},
            "network": {
                "egress": {"default": "allow"},
                "ingress": {"default": "allow", "hostLoopback": "allow"}
            },
            "isolationSession": {
                "provision": {
                    "appId": "Contoso.Sample_1234567890abc"
                }
            }
        }"#,
        expected: ExpectedRoot::IsolationSessionProvision,
    },
    StateAwareCase {
        name: "start",
        json: r#"{
            "_comment": "Start the provisioned sandbox.",
            "version": "0.9.0-alpha",
            "phase": "start",
            "sandboxId": "iso:1234abcd",
            "telemetry": {"enabled": true}
        }"#,
        expected: ExpectedRoot::Start,
    },
    StateAwareCase {
        name: "exec",
        json: r#"{
            "version": "0.9.0-alpha",
            "phase": "exec",
            "sandboxId": "wslc:1234abcd",
            "process": {
                "commandLine": "curl -sS https://example.com",
                "cwd": "/workspace",
                "env": ["MODE=test"],
                "timeout": 30000
            },
            "runtimeConfig": {"networkProxy": "http://proxy.example:8080"},
            "telemetry": {"enabled": false}
        }"#,
        expected: ExpectedRoot::Exec,
    },
    StateAwareCase {
        name: "stop",
        json: r#"{
            "version": "0.9.0-alpha",
            "phase": "stop",
            "sandboxId": "iso:1234abcd",
            "telemetry": {"enabled": true}
        }"#,
        expected: ExpectedRoot::Stop,
    },
    StateAwareCase {
        name: "deprovision",
        json: r#"{
            "version": "0.9.0-alpha",
            "phase": "deprovision",
            "sandboxId": "iso:1234abcd",
            "telemetry": {"enabled": false}
        }"#,
        expected: ExpectedRoot::Deprovision,
    },
];

#[test]
fn state_aware_roots_are_introduced_in_v09() {
    for case in CASES {
        serde_json::from_str::<serde_json::Value>(case.json)
            .unwrap_or_else(|error| panic!("{} used malformed JSON: {error}", case.name));

        let v08_json = case.json.replace("0.9.0-alpha", "0.8.0-alpha");
        assert!(
            serde_json::from_str::<V08Request>(&v08_json).is_err(),
            "published 0.8 accepted the {} request",
            case.name
        );

        let request = parse_request(case.json)
            .unwrap_or_else(|error| panic!("published 0.9 rejected {}: {error}", case.name));
        assert!(
            case.expected.matches(&request),
            "published 0.9 selected the wrong root for {}",
            case.name
        );
    }
}
