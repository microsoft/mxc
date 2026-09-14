// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::fmt;

#[cfg(test)]
use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer};
use serde_json::error::Category;
#[cfg(test)]
use serde_json::Value;
use unicode_general_category::{get_general_category, GeneralCategory};

/// Field-name substrings that mark a value as secret-bearing. Matched anywhere
/// within a single path segment, so `token` catches `apiToken`, `secret`
/// catches `clientSecret`, and so on.
const SECRET_PATH_MARKERS: &[&str] = &[
    "token",
    "password",
    "secret",
    "credential",
    "apikey",
    "accesskey",
    "privatekey",
    "passphrase",
    "pwd",
    "bearer",
    "saskey",
    "connectionstring",
];

/// Whole path segments that mark a value as secret-bearing. Matched as a
/// complete field name (not a substring) so they never collide with unrelated
/// fields such as `username`. `user` marks a credential bundle: a shape error
/// where the object itself is expected is pathed at `user` rather than at the
/// secret-bearing leaf inside it, so the whole subtree must be marked.
/// Over-redaction fails safe — it only replaces an error value with a location,
/// never leaks one.
const SECRET_PATH_SEGMENTS: &[&str] = &["user"];

/// Whether a single lower-cased JSON object key is secret-bearing, per
/// [`SECRET_PATH_SEGMENTS`] (whole-field match) and [`SECRET_PATH_MARKERS`]
/// (substring match). Shared by error-path redaction (this module) and raw
/// config redaction (`diagnostic::redact_raw_config_json`) so both use one
/// definition of "secret-bearing".
pub(crate) fn is_secret_path_field(field: &str) -> bool {
    SECRET_PATH_SEGMENTS.contains(&field)
        || SECRET_PATH_MARKERS
            .iter()
            .any(|marker| field.contains(marker))
}

/// A JSON deserialization failure with the path at which typed policy parsing
/// failed. Syntax errors have no meaningful policy path.
#[derive(Debug)]
pub(crate) struct ConfigDeserializeError {
    path: Option<String>,
    source: serde_json::Error,
}

impl ConfigDeserializeError {
    /// The exact source field that failed structural deserialization.
    pub(crate) fn path(&self) -> Option<&str> {
        self.path.as_deref()
    }

    fn from_path_error(error: serde_path_to_error::Error<serde_json::Error>) -> Self {
        let path = error.path().to_string();
        let path = (path != ".").then_some(path);
        Self {
            path,
            source: error.into_inner(),
        }
    }

    fn path_contains_secret(&self) -> bool {
        self.path.as_deref().is_some_and(|path| {
            path.to_ascii_lowercase().split('.').any(|segment| {
                // Match on the field name only, dropping any array-index suffix
                // so `field[0]` matches on `field`.
                let field = segment.split('[').next().unwrap_or(segment);
                is_secret_path_field(field)
            })
        })
    }
}

impl fmt::Display for ConfigDeserializeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let source = if self.path_contains_secret() {
            redact_secret_value(&self.source)
        } else {
            self.source.to_string()
        };
        let source = escape_control_characters(&source);
        match self.source.classify() {
            Category::Syntax | Category::Eof => {
                write!(formatter, "Invalid JSON syntax: {source}")
            }
            Category::Data => match self.path.as_deref() {
                Some(path) => write!(
                    formatter,
                    "Invalid configuration at `{}`: {source}",
                    escape_control_characters(path)
                ),
                None => write!(formatter, "Invalid configuration: {source}"),
            },
            // Current constructors cannot produce reader I/O failures. Keep a
            // defensive message in case a reader-backed constructor is added.
            Category::Io => write!(formatter, "Unable to read JSON configuration: {source}"),
        }
    }
}

fn redact_secret_value(source: &serde_json::Error) -> String {
    let line = source.line();
    let column = source.column();
    if line > 0 {
        return format!("invalid secret value at line {line} column {column}");
    }
    "invalid secret value".to_string()
}

fn escape_control_characters(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        if character.is_control() {
            escaped.extend(character.escape_default());
        } else if is_diagnostic_format_character(character) {
            escaped.extend(character.escape_unicode());
        } else {
            escaped.push(character);
        }
    }
    escaped
}

/// Escape control and invisible-format characters in free-form, user-controlled
/// text before it reaches a diagnostic sink.
pub(crate) fn escape_diagnostic_text(value: &str) -> String {
    escape_control_characters(value)
}

fn is_diagnostic_format_character(character: char) -> bool {
    matches!(
        get_general_category(character),
        GeneralCategory::Format
            | GeneralCategory::LineSeparator
            | GeneralCategory::ParagraphSeparator
    )
}

impl std::error::Error for ConfigDeserializeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

fn deserialize_with_path<'de, T, D>(deserializer: D) -> Result<T, ConfigDeserializeError>
where
    T: Deserialize<'de>,
    D: Deserializer<'de, Error = serde_json::Error>,
{
    serde_path_to_error::deserialize(deserializer).map_err(ConfigDeserializeError::from_path_error)
}

pub(crate) fn from_str<'de, T>(json: &'de str) -> Result<T, ConfigDeserializeError>
where
    T: Deserialize<'de>,
{
    let mut deserializer = serde_json::Deserializer::from_str(json);
    let value = deserialize_with_path(&mut deserializer)?;
    deserializer
        .end()
        .map_err(|source| ConfigDeserializeError { path: None, source })?;
    Ok(value)
}

#[cfg(test)]
pub(crate) fn from_value<T>(value: Value) -> Result<T, ConfigDeserializeError>
where
    T: DeserializeOwned,
{
    deserialize_with_path(value)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    #[allow(dead_code)]
    struct Outer {
        inner: Inner,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    #[allow(dead_code)]
    struct Inner {
        count: u16,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    #[allow(dead_code)]
    struct Secret {
        api_token: String,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    #[allow(dead_code)]
    struct NumericSecret {
        api_token: u32,
    }

    #[derive(Debug, Deserialize)]
    #[allow(dead_code)]
    struct MapOuter {
        items: HashMap<String, Inner>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    #[allow(dead_code)]
    struct UserHolder {
        user: Secret,
    }

    #[test]
    fn redacts_scalar_supplied_where_credential_subtree_is_expected() {
        // A token supplied where the `user` object is expected pathes the error
        // at `user`, not at the secret leaf inside it; the whole subtree must still
        // redact so the scalar is never echoed into diagnostics or the envelope.
        let error = from_str::<UserHolder>(r#"{"user": "super-secret-bearer-token"}"#).unwrap_err();
        let message = error.to_string();

        assert!(
            message.contains("Invalid configuration at `user`"),
            "got: {message}"
        );
        assert!(message.contains("invalid secret value"), "got: {message}");
        assert!(
            !message.contains("super-secret-bearer-token"),
            "got: {message}"
        );
    }

    #[test]
    fn data_errors_include_the_nested_path_and_source_location() {
        let error = from_str::<Outer>(
            r#"{
                "inner": {
                    "count": 70000
                }
            }"#,
        )
        .unwrap_err();

        assert_eq!(error.path.as_deref(), Some("inner.count"));
        let message = error.to_string();
        assert!(message.contains("Invalid configuration at `inner.count`"));
        assert!(message.contains("expected u16"));
        assert!(message.contains("line 3"));
    }

    #[test]
    fn syntax_errors_are_distinguished_from_typed_config_errors() {
        let error = from_str::<Outer>(r#"{"inner": {"count": 1}"#).unwrap_err();
        let message = error.to_string();
        assert!(message.starts_with("Invalid JSON syntax:"));
        assert!(message.contains("line 1"));
    }

    #[test]
    fn trailing_json_data_is_rejected() {
        let error = from_str::<Outer>(r#"{"inner": {"count": 1}} {"second": true}"#).unwrap_err();
        assert!(error.to_string().starts_with("Invalid JSON syntax:"));
    }

    #[test]
    fn from_value_reports_the_typed_error_path() {
        let value = serde_json::json!({"inner": {"count": "many"}});
        let error = from_value::<Outer>(value).unwrap_err();

        assert_eq!(error.path.as_deref(), Some("inner.count"));
        assert!(error.to_string().contains("expected u16"));
    }

    #[test]
    fn display_escapes_control_characters_from_paths_and_sources() {
        let json = "{\"items\":{\"forged\\n\\u001b[31mline\":{\"count\":\"value\\n\\u001b[32m\"}}}";
        let error = from_str::<MapOuter>(json).unwrap_err();
        let message = error.to_string();

        assert!(!message.contains('\n'));
        assert!(!message.contains('\u{1b}'));
        assert!(message.contains("\\n"), "got: {message}");
        assert!(message.contains("\\u{1b}"), "got: {message}");
    }

    #[test]
    fn display_escapes_unicode_format_characters_from_paths_and_sources() {
        let json = "{\"items\":{\"forged\u{202e}line\":{\"count\":\"value\u{200b}hidden\"}}}";
        let error = from_str::<MapOuter>(json).unwrap_err();
        let message = error.to_string();

        assert!(!message.contains('\u{202e}'));
        assert!(!message.contains('\u{200b}'));
        assert!(message.contains("\\u{202e}"), "got: {message}");
        assert!(message.contains("\\u{200b}"), "got: {message}");
    }

    #[test]
    fn display_redacts_values_at_secret_bearing_paths() {
        let error = from_str::<Secret>(r#"{"apiToken": 123456789}"#).unwrap_err();
        let message = error.to_string();

        assert!(message.contains("Invalid configuration at `apiToken`"));
        assert!(message.contains("invalid secret value"));
        assert!(message.contains("line 1"));
        assert!(!message.contains("123456789"));
    }

    #[test]
    fn secret_redaction_never_parses_attacker_controlled_error_text() {
        let error = from_str::<NumericSecret>(
            r#"{"apiToken": "expected leak-of-secret-data", "other": true}"#,
        )
        .unwrap_err();
        let message = error.to_string();

        assert!(message.contains("Invalid configuration at `apiToken`"));
        assert!(message.contains("invalid secret value at line 1 column"));
        assert!(!message.contains("expected leak-of-secret-data"));
        assert!(!message.contains("leak-of-secret-data"));
    }

    #[test]
    fn secret_markers_are_detected_case_insensitively() {
        for path in [
            "apiToken",
            "adminPassword",
            "clientSecret",
            "serviceCredential",
            "apiKey",
            "accessKey",
            "privateKey",
            "passphrase",
            "pwd",
            "bearer",
            "sasKey",
            "connectionString",
        ] {
            let error = ConfigDeserializeError {
                path: Some(path.to_string()),
                source: serde_json::from_str::<Secret>(r#"{"apiToken": 123456789}"#).unwrap_err(),
            };

            assert!(
                error.to_string().contains("invalid secret value"),
                "path {path} was not treated as sensitive"
            );
        }
    }

    #[test]
    fn ordinary_key_suffixes_are_not_treated_as_secrets() {
        let error = ConfigDeserializeError {
            path: Some("monkey".to_string()),
            source: serde_json::from_str::<Secret>(r#"{"apiToken": 123456789}"#).unwrap_err(),
        };

        assert!(!error.to_string().contains("invalid secret value"));
    }

    #[test]
    fn user_segment_is_secret_but_similar_field_names_are_not() {
        // `user` marks the credential bundle when matched as a whole path
        // segment. It must redact at the segment itself, nested under a parent,
        // with an array index, and at any descendant — but must NOT collide with
        // unrelated fields that merely contain the substring `user`.
        let redacted = [
            "user",
            "experimental.someBackend.user",
            "experimental.someBackend.user.name",
            "users[0].user",
        ];
        for path in redacted {
            let error = ConfigDeserializeError {
                path: Some(path.to_string()),
                source: serde_json::from_str::<Secret>(r#"{"apiToken": 123456789}"#).unwrap_err(),
            };
            assert!(
                error.to_string().contains("invalid secret value"),
                "path {path} should be treated as sensitive"
            );
        }

        let not_redacted = ["username", "userProfile", "userName", "superuser"];
        for path in not_redacted {
            let error = ConfigDeserializeError {
                path: Some(path.to_string()),
                source: serde_json::from_str::<Secret>(r#"{"apiToken": 123456789}"#).unwrap_err(),
            };
            assert!(
                !error.to_string().contains("invalid secret value"),
                "path {path} should NOT be treated as sensitive"
            );
        }
    }

    #[test]
    fn escapes_line_and_paragraph_separators() {
        // U+2028 (LINE SEPARATOR) and U+2029 (PARAGRAPH SEPARATOR) render as
        // hard line breaks in some terminals/log viewers, so they must be
        // escaped to prevent forged multi-line diagnostics.
        let escaped = escape_diagnostic_text("a\u{2028}b\u{2029}c");

        assert!(!escaped.contains('\u{2028}'));
        assert!(!escaped.contains('\u{2029}'));
        assert!(escaped.contains("\\u{2028}"), "got: {escaped}");
        assert!(escaped.contains("\\u{2029}"), "got: {escaped}");
    }

    #[test]
    fn leaves_plain_text_unchanged() {
        let plain = "plain diagnostic text 123";
        assert_eq!(escape_diagnostic_text(plain), plain);
    }
}
