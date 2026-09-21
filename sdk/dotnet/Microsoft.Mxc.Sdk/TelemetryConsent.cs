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

/// <summary>Result of a consent request or withdrawal.</summary>
public enum TelemetryConsentActionResult
{
    Unknown = 0,
    Granted = 1,
    Denied = 2,
    Dismissed = 3,
    Withdrawn = 4,
    AlreadyGranted = 5,
    PolicyBlocked = 6,
    NotApplicable = 7,
}

/// <summary>Persisted and effective consent together with the policy ceiling.</summary>
public sealed record TelemetryConsentStatus(
    TelemetryConsentState StoredState,
    TelemetryConsentState EffectiveState,
    TelemetryPolicyState Policy);

/// <summary>Result and resulting status of a consent-changing operation.</summary>
public sealed record TelemetryConsentOutcome(
    TelemetryConsentActionResult Result,
    TelemetryConsentState StoredState,
    TelemetryConsentState EffectiveState,
    TelemetryPolicyState Policy);
