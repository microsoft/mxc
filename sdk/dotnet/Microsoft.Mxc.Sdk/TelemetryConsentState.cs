// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace Microsoft.Mxc.Sdk;

/// <summary>
/// The user's persisted telemetry consent decision. See
/// docs/telemetry/telemetry-consent-design.md for the full design: MXC only
/// ever collects telemetry on Windows, and only when this flag is
/// <see cref="Granted"/>. It is stored per-user by MXC itself
/// (%LOCALAPPDATA%\mxc\telemetry-consent.json) and is never derived from, or
/// synchronized with, any Windows-level diagnostics/consent setting.
/// </summary>
public enum TelemetryConsentState
{
    /// <summary>The user has explicitly agreed to telemetry collection.</summary>
    Granted,

    /// <summary>The user has explicitly declined telemetry collection.</summary>
    Denied,

    /// <summary>
    /// No decision has been recorded yet (fresh install, or an unreadable/corrupt
    /// store). Treated identically to <see cref="Denied"/> for gating purposes —
    /// callers should use this state to decide whether to show a first-run
    /// consent prompt.
    /// </summary>
    Undetermined,

    /// <summary>
    /// Not a Windows host. MXC does not collect telemetry here, so consent is not
    /// a meaningful concept — hosts must not offer a consent prompt at all on
    /// these platforms.
    /// </summary>
    NotApplicable,
}
