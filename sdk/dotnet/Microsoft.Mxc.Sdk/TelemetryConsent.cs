// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace Microsoft.Mxc.Sdk;

/// <summary>An independently localizable canonical consent message.</summary>
public sealed record TelemetryConsentMessage(string Id, string Text);

/// <summary>The complete Rust-owned consent resource a host must render verbatim.</summary>
public sealed record TelemetryConsentPrompt(
    uint ResourceVersion,
    string Locale,
    TelemetryConsentMessage Title,
    TelemetryConsentMessage Body,
    TelemetryConsentMessage AffirmativeLabel,
    TelemetryConsentMessage NegativeLabel,
    TelemetryConsentMessage LearnMoreLabel,
    string LearnMoreUrl);

/// <summary>The explicit result returned by a host consent presenter.</summary>
public enum TelemetryConsentDecision
{
    No,
    Yes,
    Dismissed,
}

/// <summary>Why persisted consent does not currently authorize collection.</summary>
public enum TelemetryConsentStatusReason
{
    NoRecord,
    StoreUnreadable,
    StoreMalformed,
    ConsentSchemaUnsupported,
    PromptVersionMissing,
    PromptVersionUnsupported,
    NotApplicable,
}

/// <summary>Result of a consent request or withdrawal.</summary>
public enum TelemetryConsentActionResult
{
    Granted,
    Denied,
    Dismissed,
    Withdrawn,
    AlreadyGranted,
    PolicyBlocked,
    NotApplicable,
}

/// <summary>Persisted and effective consent together with the policy ceiling.</summary>
public sealed record TelemetryConsentStatus(
    TelemetryConsentState StoredState,
    TelemetryConsentState EffectiveState,
    TelemetryConsentStatusReason? Reason,
    TelemetryPolicyState Policy);

/// <summary>Result and resulting status of a consent-changing operation.</summary>
public sealed record TelemetryConsentOutcome(
    TelemetryConsentActionResult Result,
    TelemetryConsentState StoredState,
    TelemetryConsentState EffectiveState,
    TelemetryConsentStatusReason? Reason,
    TelemetryPolicyState Policy);
