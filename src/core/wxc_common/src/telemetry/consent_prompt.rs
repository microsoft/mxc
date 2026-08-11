// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Canonical, versioned telemetry consent resources.
//!
//! Rust owns the complete resource so the executor and every SDK binding
//! present identical language. Hosts may control layout and accessibility, but
//! must render every field verbatim before returning an affirmative decision.

/// The current telemetry consent resource version.
///
/// A grant is valid only for this exact version. Increment it when the meaning
/// of consent or the disclosed data categories change.
pub const CONSENT_RESOURCE_VERSION: u32 = 1;

/// The mandatory fallback locale.
pub const FALLBACK_LOCALE: &str = "en-US";

/// One independently localizable consent message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConsentMessage {
    /// Stable identifier used by future generated localization resources.
    pub id: &'static str,
    /// Complete localized text. Sentence fragments are never concatenated.
    pub text: &'static str,
}

/// The complete canonical telemetry consent resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConsentPrompt {
    /// Version bound to a persisted affirmative decision.
    pub resource_version: u32,
    /// BCP 47 locale of every message in this resource.
    pub locale: &'static str,
    /// Prompt title.
    pub title: ConsentMessage,
    /// Full disclosure body.
    pub body: ConsentMessage,
    /// Affirmative action label.
    pub affirmative_label: ConsentMessage,
    /// Negative action label.
    pub negative_label: ConsentMessage,
    /// Learn-more link label.
    pub learn_more_label: ConsentMessage,
    /// Learn-more URL.
    pub learn_more_url: &'static str,
}

/// Canonical US English consent resource, version 1.
pub const EN_US_CONSENT_PROMPT: ConsentPrompt = ConsentPrompt {
    resource_version: CONSENT_RESOURCE_VERSION,
    locale: FALLBACK_LOCALE,
    title: ConsentMessage {
        id: "telemetry-consent-title",
        text: "Help improve Microsoft eXecution Container (MXC)",
    },
    body: ConsentMessage {
        id: "telemetry-consent-body",
        text: r#"Would you like to send optional diagnostic data to Microsoft to help us understand how MXC is used, diagnose problems, and improve the product?

If you choose Yes, MXC will send the MXC version and channel, containment backend, run outcome and exit code, run duration, bounded failure category, lifecycle phase, and random identifiers used to correlate events from the same app session or sandbox lifecycle.

MXC does not send your command text, file paths, environment variables, standard input or output, usernames, credentials, or free-form error messages.

Choosing No, closing this prompt, or not responding will keep telemetry off. If this consent request is never shown, telemetry also remains off. You can change or withdraw your choice later using MXC telemetry consent controls."#,
    },
    affirmative_label: ConsentMessage {
        id: "telemetry-consent-affirmative-label",
        text: "Yes, send optional diagnostic data",
    },
    negative_label: ConsentMessage {
        id: "telemetry-consent-negative-label",
        text: "No, do not send",
    },
    learn_more_label: ConsentMessage {
        id: "telemetry-consent-learn-more-label",
        text: "Microsoft Privacy Statement",
    },
    learn_more_url: "https://privacy.microsoft.com/privacystatement",
};

/// Resolve the best available resource for a requested BCP 47 locale.
///
/// Only `en-US` is currently shipped. The lookup still accepts normalized
/// English tags and always falls back to `en-US`, leaving room for a generated
/// resource provider without changing the public consent API.
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
        assert_eq!(prompt.resource_version, 1);
        assert_eq!(prompt.locale, "en-US");
        assert!(!prompt.title.text.is_empty());
        assert!(!prompt.body.text.is_empty());
        assert!(!prompt.affirmative_label.text.is_empty());
        assert!(!prompt.negative_label.text.is_empty());
        assert!(!prompt.learn_more_label.text.is_empty());
        assert_eq!(
            prompt.learn_more_url,
            "https://privacy.microsoft.com/privacystatement"
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
