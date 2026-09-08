// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use serde::Deserialize;
use std::collections::HashSet;
use std::env;
use std::fs;
use std::io;
use std::path::PathBuf;

#[derive(Debug, Deserialize)]
struct ConsentResource {
    #[serde(rename = "resourceVersion")]
    resource_version: u32,
    locale: String,
    messages: ConsentMessages,
    #[serde(rename = "learnMoreUrl")]
    learn_more_url: String,
}

#[derive(Debug, Deserialize)]
struct ConsentMessages {
    title: ConsentMessage,
    body: ConsentMessage,
    #[serde(rename = "affirmativeLabel")]
    affirmative_label: ConsentMessage,
    #[serde(rename = "negativeLabel")]
    negative_label: ConsentMessage,
    #[serde(rename = "learnMoreLabel")]
    learn_more_label: ConsentMessage,
}

#[derive(Debug, Deserialize)]
struct ConsentMessage {
    id: String,
    text: String,
}

fn invalid_resource(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn rust_string(value: &str) -> String {
    format!("{value:?}")
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?);
    let resource_path = manifest_dir.join("resources/telemetry/consent/en-US.json");
    println!("cargo:rerun-if-changed={}", resource_path.display());

    let resource: ConsentResource = serde_json::from_str(&fs::read_to_string(&resource_path)?)?;
    if resource.locale != "en-US" {
        return Err(invalid_resource(format!(
            "the fallback consent resource must use locale en-US, got {}",
            resource.locale
        ))
        .into());
    }
    if resource.resource_version == 0 {
        return Err(invalid_resource("the consent resource version must be nonzero").into());
    }
    if resource.learn_more_url.is_empty() {
        return Err(invalid_resource("the consent resource must include a learn-more URL").into());
    }

    let messages = [
        &resource.messages.title,
        &resource.messages.body,
        &resource.messages.affirmative_label,
        &resource.messages.negative_label,
        &resource.messages.learn_more_label,
    ];
    if messages
        .iter()
        .any(|message| message.id.is_empty() || message.text.is_empty())
    {
        return Err(invalid_resource("consent message IDs and text must be nonempty").into());
    }
    let ids: HashSet<&str> = messages.iter().map(|message| message.id.as_str()).collect();
    if ids.len() != messages.len() {
        return Err(invalid_resource("consent message IDs must be unique").into());
    }

    let generated = format!(
        r#"        pub const CONSENT_RESOURCE_VERSION: u32 = {};
        pub const FALLBACK_LOCALE: &str = {};

        pub static EN_US_CONSENT_PROMPT: ConsentPrompt = ConsentPrompt {{
    resource_version: CONSENT_RESOURCE_VERSION,
    locale: FALLBACK_LOCALE,
    title: ConsentMessage {{
        id: {},
        text: {},
    }},
    body: ConsentMessage {{
        id: {},
        text: {},
    }},
    affirmative_label: ConsentMessage {{
        id: {},
        text: {},
    }},
    negative_label: ConsentMessage {{
        id: {},
        text: {},
    }},
    learn_more_label: ConsentMessage {{
        id: {},
        text: {},
    }},
    learn_more_url: {},
}};
"#,
        resource.resource_version,
        rust_string(&resource.locale),
        rust_string(&resource.messages.title.id),
        rust_string(&resource.messages.title.text),
        rust_string(&resource.messages.body.id),
        rust_string(&resource.messages.body.text),
        rust_string(&resource.messages.affirmative_label.id),
        rust_string(&resource.messages.affirmative_label.text),
        rust_string(&resource.messages.negative_label.id),
        rust_string(&resource.messages.negative_label.text),
        rust_string(&resource.messages.learn_more_label.id),
        rust_string(&resource.messages.learn_more_label.text),
        rust_string(&resource.learn_more_url),
    );

    let out_dir = PathBuf::from(env::var("OUT_DIR")?);
    fs::write(out_dir.join("telemetry_consent_resource.rs"), generated)?;
    Ok(())
}
