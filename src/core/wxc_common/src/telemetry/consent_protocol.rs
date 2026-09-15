// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Private JSON messages exchanged by the executor consent command.
//!
//! These types are not part of the MXC execution configuration contract and
//! intentionally have no JSON Schema or generated SDK wire surface.

use serde::{Deserialize, Serialize};

use super::consent_cli::ConsentAction;

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) enum ConsentResult {
    Status,
    PresentationRequired,
    Granted,
    Denied,
    Dismissed,
    Withdrawn,
    AlreadyGranted,
    PolicyBlocked,
    PresentationUnavailable,
    NotApplicable,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) enum ConsentDecision {
    Yes,
    No,
    Dismissed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct PresenterResponse {
    pub challenge: String,
    pub resource_version: u32,
    pub decision: ConsentDecision,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(super) enum ConsentState {
    Granted,
    Denied,
    Undetermined,
    NotApplicable,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(super) enum PolicyState {
    Unrestricted,
    Allowed,
    Blocked,
    NotApplicable,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(super) enum StatusReason {
    NoRecord,
    StoreUnreadable,
    StoreMalformed,
    ConsentSchemaUnsupported,
    PromptVersionMissing,
    PromptVersionUnsupported,
    PolicyBlocked,
    PresentationUnavailable,
    NotApplicable,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ConsentMessage {
    pub id: String,
    pub text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ConsentPrompt {
    pub resource_version: u32,
    pub locale: String,
    pub title: ConsentMessage,
    pub body: ConsentMessage,
    pub affirmative_label: ConsentMessage,
    pub negative_label: ConsentMessage,
    pub learn_more_label: ConsentMessage,
    pub learn_more_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ConsentResponse {
    pub action: ConsentAction,
    pub result: ConsentResult,
    pub stored_state: ConsentState,
    pub effective_state: ConsentState,
    pub reason: Option<StatusReason>,
    pub policy: PolicyState,
    pub needs_prompt: bool,
    pub prompt: Option<ConsentPrompt>,
    pub challenge: Option<String>,
}
