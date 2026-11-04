// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace Microsoft.Mxc.Sdk.V1;

/// <summary>
/// The telemetry policy state for this machine.
///
/// MXC has no administrative telemetry policy; user consent alone governs
/// collection. <see cref="MxcTelemetry.GetPolicy"/> currently reports
/// <see cref="Unrestricted"/> on Windows and <see cref="NotApplicable"/>
/// elsewhere. <see cref="Allowed"/> and <see cref="Blocked"/> are retained for
/// compatibility and are not currently reported by a successful call. Policy
/// is never a grant: an explicit <see cref="TelemetryConsentState.Granted"/> is
/// required before anything is collected.
/// </summary>
public enum TelemetryPolicyState
{
    /// <summary>
    /// Retained for compatibility; not currently reported by a successful
    /// call. Also the fail-closed value when the policy state could not be
    /// determined (for example, the native library is unavailable). Nothing is
    /// collected in this state.
    /// </summary>
    Blocked = 0,

    /// <summary>
    /// No policy applies. Telemetry is governed solely by the user's own
    /// consent decision. This is not a grant. Reported on Windows.
    /// </summary>
    Unrestricted = 1,

    /// <summary>
    /// Retained for compatibility; not currently reported. Still requires user
    /// consent before anything is collected.
    /// </summary>
    Allowed = 2,

    /// <summary>
    /// Not a Windows host. MXC collects no telemetry here.
    /// </summary>
    NotApplicable = 3,
}
