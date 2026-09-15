// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use unicode_general_category::{get_general_category, GeneralCategory};

/// Escape control and invisible-format characters in free-form,
/// user-controlled text before it reaches a diagnostic sink.
pub fn escape(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        if character.is_control() {
            escaped.extend(character.escape_default());
        } else if is_format_character(character) {
            escaped.extend(character.escape_unicode());
        } else {
            escaped.push(character);
        }
    }
    escaped
}

/// Invisible Unicode formatting characters and line/paragraph separators that
/// `char::is_control()` does not cover.
fn is_format_character(character: char) -> bool {
    matches!(
        get_general_category(character),
        GeneralCategory::Format
            | GeneralCategory::LineSeparator
            | GeneralCategory::ParagraphSeparator
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_control_and_format_characters() {
        let escaped = escape("a\n\u{1b}\u{2028}\u{2029}b");

        assert_eq!(escaped, "a\\n\\u{1b}\\u{2028}\\u{2029}b");
    }

    #[test]
    fn leaves_plain_text_unchanged() {
        let plain = "plain diagnostic text 123";
        assert_eq!(escape(plain), plain);
    }
}
