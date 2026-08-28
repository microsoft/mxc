// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use mxc_config_contract::dev::{parse_request, ProvisionRequest, Request};
use mxc_config_contract::published::v0_8_0_alpha::Request as V08Request;

#[derive(Clone, Copy)]
enum ExpectedRoot {
    WindowsSandboxProvision,
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
                Self::WindowsSandboxProvision,
                Request::Provision(ProvisionRequest::WindowsSandbox(_)),
            ) | (
                Self::IsolationSessionProvision,
                Request::Provision(ProvisionRequest::IsolationSession(_)),
            ) | (
                Self::WslcProvision,
                Request::Provision(ProvisionRequest::Wslc(_))
            ) | (Self::Start, Request::Start(_))
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
        name: "Windows Sandbox provision",
        json: r#"{
            "$schema": "https://github.com/microsoft/mxc/schemas/dev/mxc-config.schema.0.9.0-alpha.json",
            "_comment": "Provision a Windows Sandbox with fixed filesystem policy.",
            "version": "0.9.0-alpha",
            "phase": "provision",
            "containment": "windows_sandbox",
            "filesystem": {
                "readwritePaths": ["C:\\work"],
                "readonlyPaths": ["C:\\inputs"],
                "deniedPaths": ["C:\\secrets"]
            },
            "experimental": {
                "telemetry": {"enabled": true}
            }
        }"#,
        expected: ExpectedRoot::WindowsSandboxProvision,
    },
    StateAwareCase {
        name: "IsolationSession provision",
        json: r#"{
            "version": "0.9.0-alpha",
            "phase": "provision",
            "containment": "isolation_session",
            "network": {
                "defaultPolicy": "allow",
                "allowLocalNetwork": true
            },
            "experimental": {
                "isolation_session": {
                    "provision": {
                        "appId": "Contoso.Sample_1234567890abc"
                    }
                },
                "telemetry": {"enabled": false}
            }
        }"#,
        expected: ExpectedRoot::IsolationSessionProvision,
    },
    StateAwareCase {
        name: "WSLC provision",
        json: r#"{
            "version": "0.9.0-alpha",
            "phase": "provision",
            "containment": "wslc",
            "filesystem": {
                "readwritePaths": ["/workspace"],
                "readonlyPaths": ["/inputs"],
                "deniedPaths": ["/secrets"]
            },
            "network": {
                "defaultPolicy": "block",
                "enforcementMode": "firewall",
                "allowedHosts": ["packages.example"],
                "allowLocalNetwork": false
            },
            "wslc": {
                "provision": {
                    "image": "ubuntu:24.04",
                    "imageTarPath": "C:\\images\\ubuntu.tar"
                }
            },
            "experimental": {
                "telemetry": {"enabled": true}
            }
        }"#,
        expected: ExpectedRoot::WslcProvision,
    },
    StateAwareCase {
        name: "start",
        json: r#"{
            "_comment": "Start the provisioned sandbox.",
            "version": "0.9.0-alpha",
            "phase": "start",
            "sandboxId": "wsb:1234abcd",
            "correlationVector": "test.0",
            "experimental": {
                "telemetry": {"enabled": true}
            }
        }"#,
        expected: ExpectedRoot::Start,
    },
    StateAwareCase {
        name: "exec",
        json: r#"{
            "version": "0.9.0-alpha",
            "phase": "exec",
            "sandboxId": "wslc:1234abcd",
            "correlationVector": "test.1",
            "process": {
                "commandLine": "curl -sS https://example.com",
                "cwd": "/workspace",
                "env": ["MODE=test"],
                "timeout": 30000
            },
            "network": {
                "proxy": {"url": "http://proxy.example:8080"}
            },
            "experimental": {
                "telemetry": {"enabled": false}
            }
        }"#,
        expected: ExpectedRoot::Exec,
    },
    StateAwareCase {
        name: "stop",
        json: r#"{
            "version": "0.9.0-alpha",
            "phase": "stop",
            "sandboxId": "wsb:1234abcd",
            "correlationVector": "test.2",
            "experimental": {
                "telemetry": {"enabled": true}
            }
        }"#,
        expected: ExpectedRoot::Stop,
    },
    StateAwareCase {
        name: "deprovision",
        json: r#"{
            "version": "0.9.0-alpha",
            "phase": "deprovision",
            "sandboxId": "wsb:1234abcd",
            "correlationVector": "test.3",
            "experimental": {
                "telemetry": {"enabled": false}
            }
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
            .unwrap_or_else(|error| panic!("development 0.9 rejected {}: {error}", case.name));
        assert!(
            case.expected.matches(&request),
            "development 0.9 selected the wrong root for {}",
            case.name
        );
    }
}
