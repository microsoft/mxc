// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace Microsoft.Mxc.Sdk;

/// <summary>
/// The administrative (MDM / Group Policy) telemetry decision for this machine.
/// See docs/telemetry/telemetry-administrative-policy.md for the admin-facing reference.
///
/// An administrator can disable MXC telemetry machine-wide via Intune, another
/// MDM, or Group Policy. The policy is a <em>ceiling, never a grant</em>: an
/// administrator who permits telemetry has not consented on the user's behalf,
/// so an explicit <see cref="TelemetryConsentState.Granted"/> is still
/// required before anything is collected.
///
/// MXC deliberately does not read the Windows-wide diagnostic data setting:
/// Microsoft's Policy CSP documentation scopes that policy to Windows itself
/// and states it does not apply to additional installed apps, and the Windows
/// privacy guidance for app-classified components requires them to own their
/// own notice and consent experience.
/// </summary>
public enum TelemetryPolicyState
{
    /// <summary>
    /// No administrative policy is configured. Telemetry is governed solely by
    /// the user's own consent decision. This is not a grant.
    /// </summary>
    Unrestricted,

    /// <summary>
    /// An administrator has permitted the optional (usage) telemetry category
    /// MXC emits. Still requires user consent before anything is collected.
    /// </summary>
    Allowed,

    /// <summary>
    /// An administrator has denied MXC telemetry, the configured policy value
    /// could not be understood, or the policy could not be determined at all.
    /// Nothing is collected regardless of user consent, and hosts must not
    /// offer a consent prompt.
    ///
    /// Because this state also covers "could not be determined", a host should
    /// word its UI as "telemetry is unavailable on this device" rather than
    /// asserting that an administrator is responsible.
    /// </summary>
    Blocked,

    /// <summary>
    /// Not a Windows host. MXC collects no telemetry here, so administrative
    /// policy is not a meaningful concept.
    /// </summary>
    NotApplicable,
}
