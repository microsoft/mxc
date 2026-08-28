// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Canonical, versioned telemetry consent resources.
//!
//! The versioned JSON resource is embedded at build time. Presenters must
//! render every field verbatim.

/// One independently localizable consent message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConsentMessage {
    /// Stable localization identifier.
    pub id: &'static str,
    /// Complete localized text.
    pub text: &'static str,
}

/// Canonical telemetry consent resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConsentPrompt {
    /// Version stored with a grant.
    pub resource_version: u32,
    /// BCP 47 locale.
    pub locale: &'static str,
    /// Title.
    pub title: ConsentMessage,
    /// Disclosure body.
    pub body: ConsentMessage,
    /// Affirmative action.
    pub affirmative_label: ConsentMessage,
    /// Negative action.
    pub negative_label: ConsentMessage,
    /// Learn-more label.
    pub learn_more_label: ConsentMessage,
    /// Learn-more URL.
    pub learn_more_url: &'static str,
}

include!(concat!(env!("OUT_DIR"), "/telemetry_consent_resource.rs"));

/// Resolve the resource for a locale, falling back to `en-US`.
pub fn prompt_for_locale(locale: Option<&str>) -> &'static ConsentPrompt {
    locale
        .and_then(find_prompt)
        .unwrap_or(&EN_US_CONSENT_PROMPT)
}

fn find_prompt(locale: &str) -> Option<&'static ConsentPrompt> {
    is_english_locale(locale).then_some(&EN_US_CONSENT_PROMPT)
}

fn is_english_locale(locale: &str) -> bool {
    locale
        .trim()
        .split(['-', '_'])
        .next()
        .is_some_and(|language| language.eq_ignore_ascii_case("en"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_resource_is_complete_and_versioned() {
        let prompt = prompt_for_locale(Some("en-US"));
        assert_eq!(prompt.resource_version, CONSENT_RESOURCE_VERSION);
        assert_eq!(prompt.locale, "en-US");
        assert_eq!(
            prompt.title.text,
            "Help improve Microsoft eXecution Container (MXC)"
        );
        assert_eq!(
            prompt.body.text,
            "Help improve MXC by sharing optional diagnostic data with Microsoft.\n\
             If enabled, MXC sends diagnostic information about product usage, performance, \
             and reliability. When Learning Mode capture is used, this can include sanitized \
             technical details about resource-access events, such as provider and event \
             identifiers, process IDs, access classifications, and bounded redacted properties. \
             MXC does not send your commands, credentials, complete file paths, usernames, or \
             sandbox output.\n\
             You can change your choice at any time."
        );
        assert_eq!(prompt.affirmative_label.text, "Yes");
        assert_eq!(prompt.negative_label.text, "No");
        assert_eq!(prompt.learn_more_label.text, "Privacy Statement");
        assert_eq!(
            prompt.learn_more_url,
            "https://go.microsoft.com/fwlink/?linkid=521839"
        );
    }

    #[test]
    fn locale_lookup_normalizes_english_and_falls_back_to_en_us() {
        for locale in [
            None,
            Some("en"),
            Some("EN_us"),
            Some("en-GB"),
            Some("fr-FR"),
        ] {
            assert_eq!(prompt_for_locale(locale), &EN_US_CONSENT_PROMPT);
        }
    }

    #[test]
    fn message_ids_are_stable_and_unique() {
        let prompt = &EN_US_CONSENT_PROMPT;
        let ids = [
            prompt.title.id,
            prompt.body.id,
            prompt.affirmative_label.id,
            prompt.negative_label.id,
            prompt.learn_more_label.id,
        ];
        for (index, id) in ids.iter().enumerate() {
            assert!(!id.is_empty());
            assert!(!ids[..index].contains(id), "duplicate message id: {id}");
        }
    }
}
