// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::id::parse_sandbox_id_prefix;
use crate::models::ContainmentBackend;
use crate::mxc_error::MxcError;
use crate::wire;
use serde::de::{MapAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::value::RawValue;
use std::fmt;
use std::ops::Range;

pub(crate) struct Spliced {
    pub json: String,
    /// True when the document already carried a non-empty `process.commandLine`.
    /// Drives the "Overriding policy process.commandLine" log.
    pub replaced_existing: bool,
}

struct RawMember<'a> {
    key: String,
    value: &'a RawValue,
}

// Keep members in source order rather than a map so duplicate keys survive
// this structural probe for the typed parser to reject later.
struct RawObject<'a> {
    members: Vec<RawMember<'a>>,
}

impl<'de> Deserialize<'de> for RawObject<'de> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct RawObjectVisitor;

        impl<'de> Visitor<'de> for RawObjectVisitor {
            type Value = RawObject<'de>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a JSON object")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut members = Vec::new();
                while let Some((key, value)) = map.next_entry::<String, &'de RawValue>()? {
                    members.push(RawMember { key, value });
                }
                Ok(RawObject { members })
            }
        }

        deserializer.deserialize_map(RawObjectVisitor)
    }
}

pub(crate) struct CommandSource<'a> {
    json: &'a str,
    root: RawObject<'a>,
}

impl<'a> CommandSource<'a> {
    pub(crate) fn parse(json: &'a str) -> Option<Self> {
        let root = serde_json::from_str(json).ok()?;
        Some(Self { json, root })
    }

    pub(crate) fn one_shot_backend(&self) -> Option<ContainmentBackend> {
        let containment = match find_member(&self.root, "containment") {
            MemberMatch::Missing => None,
            MemberMatch::Duplicate => return None,
            MemberMatch::Unique(value) => {
                serde_json::from_str::<Option<wire::Containment>>(value.get()).ok()?
            }
        };

        Some(containment.unwrap_or(wire::Containment::Process).into())
    }

    pub(crate) fn state_aware_backend(&self) -> Result<ContainmentBackend, MxcError> {
        let sandbox_id = match find_member(&self.root, "sandboxId") {
            MemberMatch::Missing => None,
            MemberMatch::Duplicate => {
                return Err(MxcError::malformed_request("duplicate field `sandboxId`"))
            }
            MemberMatch::Unique(value) => serde_json::from_str::<Option<String>>(value.get())
                .map_err(|_| MxcError::malformed_request("'sandboxId' must be a string"))?,
        }
        .ok_or_else(|| MxcError::malformed_request("state-aware requests require 'sandboxId'"))?;

        crate::state_aware_dispatch::backend_from_prefix(parse_sandbox_id_prefix(&sandbox_id)?)
    }
}

enum MemberMatch<'a> {
    Missing,
    Unique(&'a RawValue),
    Duplicate,
}

fn find_member<'a>(object: &'a RawObject<'a>, key: &str) -> MemberMatch<'a> {
    let mut matches = object
        .members
        .iter()
        .filter(|member| member.key == key)
        .map(|member| member.value);
    let Some(value) = matches.next() else {
        return MemberMatch::Missing;
    };
    if matches.next().is_some() {
        MemberMatch::Duplicate
    } else {
        MemberMatch::Unique(value)
    }
}

fn raw_value_range(source: &str, value: &RawValue) -> Option<Range<usize>> {
    // Borrowed RawValues point into `source`; convert that subslice into the
    // byte range replaced by the localized edit.
    let start = (value.get().as_ptr() as usize).checked_sub(source.as_ptr() as usize)?;
    let end = start.checked_add(value.get().len())?;
    (end <= source.len()).then_some(start..end)
}

fn replace_range(source: &str, range: Range<usize>, replacement: &str) -> String {
    let mut output = String::with_capacity(source.len() - range.len() + replacement.len());
    output.push_str(&source[..range.start]);
    output.push_str(replacement);
    output.push_str(&source[range.end..]);
    output
}

fn object_opening_brace(source: &str) -> Option<usize> {
    source
        .char_indices()
        .find(|(_, character)| !character.is_whitespace())
        .and_then(|(index, character)| (character == '{').then_some(index))
}

fn insert_member(source: &str, object: &RawObject<'_>, member: &str) -> Option<String> {
    let (offset, separator) = match object.members.last() {
        Some(last) => (raw_value_range(source, last.value)?.end, ","),
        None => (object_opening_brace(source)? + 1, ""),
    };
    Some(replace_range(
        source,
        offset..offset,
        &format!("{separator}{member}"),
    ))
}

impl CommandSource<'_> {
    pub(crate) fn splice_command(&self, command: &str) -> Option<Spliced> {
        let command = serde_json::to_string(command).ok()?;

        match find_member(&self.root, "process") {
            MemberMatch::Missing => {
                let process = format!(r#""process":{{"commandLine":{command}}}"#);
                Some(Spliced {
                    json: insert_member(self.json, &self.root, &process)?,
                    replaced_existing: false,
                })
            }
            MemberMatch::Duplicate => None,
            MemberMatch::Unique(process_raw) => {
                let process_source = process_raw.get();
                let process: RawObject<'_> = serde_json::from_str(process_source).ok()?;

                let (process_json, replaced_existing) = match find_member(&process, "commandLine") {
                    MemberMatch::Missing => {
                        let member = format!(r#""commandLine":{command}"#);
                        (insert_member(process_source, &process, &member)?, false)
                    }
                    MemberMatch::Duplicate => return None,
                    MemberMatch::Unique(command_line_raw) => {
                        let replaced_existing = if command_line_raw.get().trim() == "null" {
                            false
                        } else {
                            let existing: String =
                                serde_json::from_str(command_line_raw.get()).ok()?;
                            !existing.is_empty()
                        };
                        let range = raw_value_range(process_source, command_line_raw)?;
                        (
                            replace_range(process_source, range, &command),
                            replaced_existing,
                        )
                    }
                };

                let process_range = raw_value_range(self.json, process_raw)?;
                Some(Spliced {
                    json: replace_range(self.json, process_range, &process_json),
                    replaced_existing,
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config_parser::load_mxc_request_from_json;
    use crate::logger::{Logger, Mode};
    use crate::mxc_error::MxcErrorCode;
    use crate::state_aware_request::MxcRequest;
    use serde_json::Value;

    fn splice_command(json: &str, command: &str) -> Option<Spliced> {
        CommandSource::parse(json)?.splice_command(command)
    }

    #[test]
    fn one_shot_backend_agrees_with_the_parser_for_every_spelling() {
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
            let json = format!(r#"{{"containment":"{spelling}"}}"#);
            let source = CommandSource::parse(&json).unwrap();
            assert_eq!(
                source.one_shot_backend(),
                Some(crate::config_parser::map_wire_containment(Some(&wire))),
                "raw command source and parser disagree on {spelling}",
            );
        }

        let source = CommandSource::parse("{}").unwrap();
        assert_eq!(
            source.one_shot_backend(),
            Some(crate::config_parser::map_wire_containment(None)),
        );
    }

    #[test]
    fn state_aware_backend_resolves_every_registered_prefix() {
        for (id, expected) in [
            ("iso:abcd1234", ContainmentBackend::IsolationSession),
            ("wsb:abcd1234", ContainmentBackend::WindowsSandbox),
            ("wslc:abcd1234", ContainmentBackend::Wslc),
        ] {
            let json = format!(r#"{{"phase":"exec","sandboxId":"{id}"}}"#);
            let source = CommandSource::parse(&json).unwrap();
            assert_eq!(source.state_aware_backend().unwrap(), expected);
        }
    }

    #[test]
    fn state_aware_backend_rejects_missing_malformed_and_unregistered_ids() {
        for json in [
            r#"{"phase":"exec"}"#,
            r#"{"sandboxId":"no-colon"}"#,
            r#"{"sandboxId":":abcd"}"#,
        ] {
            let source = CommandSource::parse(json).unwrap();
            assert!(source.state_aware_backend().is_err(), "{json}");
        }

        let source = CommandSource::parse(r#"{"sandboxId":"zzz:abcd"}"#).unwrap();
        let error = source.state_aware_backend().unwrap_err();
        assert_eq!(error.code, MxcErrorCode::UnsupportedContainment);
    }

    #[test]
    fn one_shot_backend_returns_none_for_malformed_declarations() {
        for json in [
            r#"{"containment":"nope"}"#,
            r#"{"containment":42}"#,
            r#"{"containment":"process","containment":"lxc"}"#,
        ] {
            let source = CommandSource::parse(json).unwrap();
            assert!(source.one_shot_backend().is_none(), "{json}");
        }

        assert!(CommandSource::parse(r#"{ "process": "#).is_none());

        let source = CommandSource::parse(r#"{"containment":null}"#).unwrap();
        assert_eq!(
            source.one_shot_backend(),
            Some(crate::config_parser::map_wire_containment(None)),
        );
    }

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

    #[test]
    fn splice_reports_a_null_command_line_as_not_replaced() {
        let original = r#"{"process":{"commandLine":null}}"#;
        let spliced = splice_command(original, "echo bye").unwrap();
        assert_eq!(spliced.json, r#"{"process":{"commandLine":"echo bye"}}"#);
        assert!(!spliced.replaced_existing);
    }

    #[test]
    fn splice_rejects_invalid_existing_command_line_types() {
        for value in ["42", "true", "[]", "{}"] {
            let original = format!(r#"{{"process":{{"commandLine":{value}}}}}"#);
            assert!(
                splice_command(&original, "echo bye").is_none(),
                "invalid commandLine value should be left for the parser: {value}"
            );
        }
    }

    #[test]
    fn splice_rejects_duplicate_process_members() {
        let original = r#"{"process":{},"process":{}}"#;
        assert!(splice_command(original, "echo bye").is_none());
    }

    #[test]
    fn splice_rejects_duplicate_command_line_members() {
        let original = r#"{"process":{"commandLine":"first.exe","commandLine":"second.exe"}}"#;
        assert!(splice_command(original, "echo bye").is_none());
    }

    #[test]
    fn splice_preserves_unrelated_duplicate_members_for_typed_validation() {
        let original = r#"{
            "process": {"commandLine": "policy.exe"},
            "filesystem": {"readwritePaths": ["first"]},
            "filesystem": {"readwritePaths": ["second"]}
        }"#;

        let spliced = splice_command(original, "cli.exe").unwrap();

        assert_eq!(spliced.json.matches("\"filesystem\"").count(), 2);
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

        let expected =
            RICH_POLICY.replacen("policy-app.exe --from-policy", "cli-app.exe --from-cli", 1);
        assert_eq!(spliced.json, expected);

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
            "version": "0.9.0-alpha",
            "process": { "cwd": "C:\\workspace" },
            "filesystem": { "readwritePaths": ["C:\\workspace"] }
        }"#;

        let spliced = splice_command(original, over).unwrap();

        let mut logger = Logger::new(Mode::Buffer);
        let request = match load_mxc_request_from_json(&spliced.json, &mut logger).unwrap() {
            MxcRequest::OneShot(request) => request,
            MxcRequest::StateAware(_) => panic!("expected a one-shot request"),
        };

        // The spliced document is a complete request in its own right.
        assert_eq!(request.script_code, over);
        assert_eq!(request.working_directory, "C:\\workspace");
    }
}
