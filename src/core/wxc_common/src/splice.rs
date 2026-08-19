// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use serde_json::{json, Value};

pub(crate) struct Spliced {
    pub json: String,
    /// True when the document already carried a non-empty `process.commandLine`.
    /// Drives the "Overriding policy process.commandLine" log, which today fires
    /// only when `apply_command_override` finds a non-empty `script_code`.
    pub replaced_existing: bool,
}

pub(crate) fn splice_command(json: &str, command: &str) -> Option<Spliced> {
    let mut doc: Value = serde_json::from_str(json).ok()?;
    let obj = doc.as_object_mut()?;
    let process = obj.entry("process").or_insert_with(|| json!({}));
    let process = process.as_object_mut()?;
    let replaced = matches!(process.get("commandLine"), Some(Value::String(s)) if !s.is_empty());
    process.insert("commandLine".into(), Value::String(command.to_string()));

    Some(Spliced {
        json: serde_json::to_string(&doc).ok()?,
        replaced_existing: replaced,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config_parser::load_mxc_request_from_json;
    use crate::logger::{Logger, Mode};
    use crate::state_aware_request::MxcRequest;

    #[test]
    fn splice_overwrites_an_existing_command_line() {
        let original = r#"{"process":{"commandLine":"echo hi"}}"#;
        let spliced = splice_command(original, "echo bye").unwrap();
        assert_eq!(spliced.json, r#"{"process":{"commandLine":"echo bye"}}"#);
        assert!(spliced.replaced_existing);
    }

    #[test]
    fn splice_creates_an_absent_process_object() {
        let original = r#"{}"#;
        let spliced = splice_command(original, "echo bye").unwrap();
        assert_eq!(spliced.json, r#"{"process":{"commandLine":"echo bye"}}"#);
        assert!(!spliced.replaced_existing);
    }

    #[test]
    fn splice_reports_an_empty_command_line_as_not_replaced() {
        let original = r#"{"process":{"commandLine":""}}"#;
        let spliced = splice_command(original, "echo bye").unwrap();
        assert_eq!(spliced.json, r#"{"process":{"commandLine":"echo bye"}}"#);
        assert!(!spliced.replaced_existing);
    }

    const RICH_POLICY: &str = r#"{
        "$schema": "https://example.com/mxc-config.schema.json",
        "_comment": null,
        "version": "0.6.0-alpha",
        "containerId": "test-container",
        "containment": "processcontainer",
        "lifecycle": { "destroyOnExit": false, "preservePolicy": true },
        "process": {
            "commandLine": "policy-app.exe --from-policy",
            "cwd": "C:\\work space\\proj",
            "env": ["PATH=C:\\bin", "GREETING=héllo \"world\"", "EMPTY="],
            "timeout": 4294967295
        },
        "filesystem": {
            "readwritePaths": ["C:\\rw"],
            "readonlyPaths": [],
            "deniedPaths": ["C:\\secrets"]
        },
        "network": {
            "defaultPolicy": "allow",
            "allowLocalNetwork": false,
            "allowedHosts": ["example.com", "*.contoso.com"],
            "proxy": { "localhost": 8080 }
        },
        "processContainer": {
            "leastPrivilege": true,
            "capabilities": []
        }
    }"#;

    #[test]
    fn splice_preserves_every_other_field() {
        let over = "cli-app.exe --from-cli";
        let spliced = splice_command(RICH_POLICY, over).unwrap();

        let actual = serde_json::from_str::<Value>(&spliced.json).unwrap();
        let mut expected: Value = serde_json::from_str(RICH_POLICY).unwrap();
        expected["process"]["commandLine"] = Value::String(over.to_string());

        assert_eq!(actual, expected);
        assert!(spliced.replaced_existing);
    }

    #[test]
    fn splice_rejects_a_non_object_process() {
        let original = r#"{"process":42}"#;
        assert!(splice_command(original, "echo bye").is_none());
    }

    #[test]
    fn splice_rejects_a_non_object_root() {
        for original in [r#"42"#, r#""a string""#, r#"[]"#, r#"[{"process":{}}]"#] {
            assert!(
                splice_command(original, "echo bye").is_none(),
                "non-object root should not splice: {original}"
            );
        }
    }

    #[test]
    fn splice_output_reparses_into_the_same_request() {
        let over = "cli-app.exe --from-cli";
        let original = r#"{
            "process": { "cwd": "C:\\workspace" },
            "filesystem": { "readwritePaths": ["C:\\workspace"] }
        }"#;

        let spliced = splice_command(original, over).unwrap();

        let mut logger = Logger::new(Mode::Buffer);
        let request = match load_mxc_request_from_json(&spliced.json, &mut logger).unwrap() {
            MxcRequest::OneShot(request) => request,
            MxcRequest::StateAware(_) => panic!("expected a one-shot request"),
        };

        // The spliced document is a complete request in its own right: it needs
        // no `allow_missing_command` relaxation to load.
        assert_eq!(request.script_code, over);
        assert_eq!(request.working_directory, "C:\\workspace");
    }
}
