// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace Microsoft.Mxc.Sdk;

/// <summary>
/// Telemetry consent state used for both persisted and effective values.
/// Telemetry is collected only when the effective state is <see cref="Granted"/>.
/// </summary>
public enum TelemetryConsentState
{
    /// <summary>Consent is granted.</summary>
    Granted,

    /// <summary>Consent is denied.</summary>
    Denied,

    /// <summary>
    /// Consent is unavailable or cannot currently authorize telemetry. Treated
    /// as <see cref="Denied"/> for gating; use <c>MxcTelemetry.NeedsConsentPrompt()</c>
    /// to determine whether to present consent.
    /// </summary>
    Undetermined,

    /// <summary>
    /// Not a Windows host. MXC does not collect telemetry here, so consent is not
    /// a meaningful concept — hosts must not offer a consent prompt at all on
    /// these platforms.
    /// </summary>
    NotApplicable,
}
