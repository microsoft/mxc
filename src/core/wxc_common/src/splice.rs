// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use serde::de::{MapAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::value::RawValue;
use std::fmt;
use std::ops::Range;

#[derive(Debug, Clone)]
pub(crate) struct SourceEdit {
    pub original_range: Range<usize>,
    pub replacement_range: Range<usize>,
}

impl SourceEdit {
    fn shifted(self, offset: usize) -> Option<Self> {
        Some(Self {
            original_range: self.original_range.start.checked_add(offset)?
                ..self.original_range.end.checked_add(offset)?,
            replacement_range: self.replacement_range.start.checked_add(offset)?
                ..self.replacement_range.end.checked_add(offset)?,
        })
    }
}

fn source_edit(original_range: Range<usize>, replacement_len: usize) -> Option<SourceEdit> {
    let replacement_start = original_range.start;
    let replacement_end = replacement_start.checked_add(replacement_len)?;

    Some(SourceEdit {
        original_range,
        replacement_range: replacement_start..replacement_end,
    })
}

pub(crate) struct Spliced {
    pub json: String,
    /// True when the document already carried a non-empty `process.commandLine`.
    /// Drives the "Overriding policy process.commandLine" log.
    pub replaced_existing: bool,
    pub edit: SourceEdit,
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

fn insert_member(
    source: &str,
    object: &RawObject<'_>,
    member: &str,
) -> Option<(String, SourceEdit)> {
    let (offset, separator) = match object.members.last() {
        Some(last) => (raw_value_range(source, last.value)?.end, ","),
        None => (object_opening_brace(source)? + 1, ""),
    };

    let replacement = format!("{separator}{member}");
    let original_range = offset..offset;
    let edit = source_edit(original_range.clone(), replacement.len())?;

    Some((replace_range(source, original_range, &replacement), edit))
}

pub(crate) fn splice_command(json: &str, command: &str) -> Option<Spliced> {
    let root: RawObject<'_> = serde_json::from_str(json).ok()?;
    let command = serde_json::to_string(command).ok()?;

    match find_member(&root, "process") {
        MemberMatch::Missing => {
            let process = format!(r#""process":{{"commandLine":{command}}}"#);
            let (json, edit) = insert_member(json, &root, &process)?;

            Some(Spliced {
                json,
                replaced_existing: false,
                edit,
            })
        }
        MemberMatch::Duplicate => None,
        MemberMatch::Unique(process_raw) => {
            let process_source = process_raw.get();

            if process_source.trim() == "null" {
                let process_json = format!(r#"{{"commandLine":{command}}}"#);
                let process_range = raw_value_range(json, process_raw)?;
                let edit = source_edit(process_range.clone(), process_json.len())?;

                return Some(Spliced {
                    json: replace_range(json, process_range, &process_json),
                    replaced_existing: false,
                    edit,
                });
            }

            let process: RawObject<'_> = serde_json::from_str(process_source).ok()?;

            let (process_json, replaced_existing, local_edit) =
                match find_member(&process, "commandLine") {
                    MemberMatch::Missing => {
                        let member = format!(r#""commandLine":{command}"#);
                        let (process_json, edit) =
                            insert_member(process_source, &process, &member)?;
                        (process_json, false, edit)
                    }
                    MemberMatch::Duplicate => return None,
                    MemberMatch::Unique(command_line_raw) => {
                        let replaced_existing = if command_line_raw.get().trim() == "null" {
                            false
                        } else {
                            let existing: String =
                                serde_json::from_str(command_line_raw.get()).ok()?;
                            if existing.contains('\0') {
                                return None;
                            }
                            !existing.is_empty()
                        };
                        let range = raw_value_range(process_source, command_line_raw)?;
                        let edit = source_edit(range.clone(), command.len())?;

                        (
                            replace_range(process_source, range, &command),
                            replaced_existing,
                            edit,
                        )
                    }
                };

            let process_range = raw_value_range(json, process_raw)?;
            let edit = local_edit.shifted(process_range.start)?;

            Some(Spliced {
                json: replace_range(json, process_range, &process_json),
                replaced_existing,
                edit,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config_parser::load_mxc_request_from_json;
    use crate::logger::{Logger, Mode};
    use crate::state_aware_request::MxcRequest;
    use serde_json::Value;

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
    fn splice_treats_a_null_process_as_missing() {
        let original = r#"{"process":null}"#;
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
    fn splice_rejects_a_positional_process_sequence() {
        assert!(splice_command(
            r#"{"process":["policy.exe",null,null,null]}"#,
            "cli.exe --flag",
        )
        .is_none());
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

        // The spliced document is a complete request in its own right.
        assert_eq!(request.script_code, over);
        assert_eq!(request.working_directory, "C:\\workspace");
    }
}
