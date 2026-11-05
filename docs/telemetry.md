# MXC diagnostic data and administrative policy

> **Audience:** Developers integrating the MXC SDK into products that ship to Windows devices.

MXC collects Required diagnostic data on supported Windows builds to help keep the component secure, reliable, up to date, and functioning as expected. Administrators can restrict collection through an MXC-specific, machine-wide policy.

Existing published contracts retain their current behavior, as described under [Availability and compatibility](#availability-and-compatibility).

## Required diagnostic data

Required diagnostic data describes execution and container lifecycle progress, categorized operational failures, and observed process exits. It includes diagnostic fields and random invocation or lifecycle identifiers used to correlate related events.

The following events are Required:

| Event | Purpose |
|---|---|
| `MXC.ExecutionStart` | Beginning of an execution or container lifecycle operation. |
| `MXC.ExecutionEnd` | Completion of an execution or container lifecycle operation. |
| `MXC.Error` | A categorized operational failure associated with a container run. |
| `MXC.ProcessExited` | A process exit reported through the diagnostics telemetry helper. |

Required collection does not require user consent or per-request opt-in. Collection remains subject to administrative policy, supported builds, and collection availability.

## Administrative policy

Administrators can permit or block Required diagnostic-data collection using the following machine-wide registry setting:

| Setting | Value |
|---|---|
| Key | `HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Mxc` |
| Value name | `AllowTelemetry` |
| Type | `REG_DWORD` |
| Scope | Machine: all users on the device |

This is an administrator-controlled registry location. MXC does not honor a per-user (`HKCU`) equivalent.

### Values

| Value | Effect on MXC |
|---|---|
| Value absent | No administrative restriction. Required collection is permitted. |
| `0` | Block Required collection. |
| `1` or `3` | Permit Required collection. |
| Unsupported value, incorrect registry type, or read failure | Block Required collection. |

Value `2` is unsupported and blocks collection.

Permitting collection does not enable it on unsupported builds or where collection is unavailable. The administrative policy is a restriction on collection, not a way to enable telemetry outside its supported configuration.

MXC treats unreadable or invalid settings as blocked. It reports each distinct policy-read or validation failure once per process so operators can distinguish a deployment problem from an intentional block without weakening this fail-closed behavior.

## Deploying the policy

Use an administrative script, installer, or configuration-management package that writes the registry setting directly.

For example, this PowerShell script blocks collection:

```powershell
$key = 'HKLM:\SOFTWARE\Policies\Mxc'
New-Item -Path $key -Force | Out-Null
Set-ItemProperty -Path $key -Name 'AllowTelemetry' -Value 0 -Type DWord
```

### Verifying the setting

Read the configured value from an elevated PowerShell session:

```powershell
Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Mxc' -Name 'AllowTelemetry'
```

A value of `0` blocks collection. A value of `1` or `3` permits Required collection, subject to build support and collection availability. An absent value imposes no administrative restriction.

Registry inspection confirms the configured policy; it does not establish that telemetry is available or being collected.

## Privacy information for products embedding MXC

MXC documents its diagnostic-data collection and privacy controls in this documentation. Products integrating the MXC SDK should inform their users that MXC collects Required diagnostic data to help keep the component secure, reliable, and functioning as expected.

Products should cover this collection within their existing privacy disclosures and settings, linking to this documentation and the [Microsoft Privacy Statement](https://privacy.microsoft.com/privacystatement).

The Required diagnostic-data notification explains the collection; it does not ask users to opt in.

## Relationship to Windows diagnostic-data settings

The MXC policy is stored in the Windows registry, but it belongs to MXC, not Windows diagnostic-data collection:

- **MXC:** `HKLM\SOFTWARE\Policies\Mxc\AllowTelemetry`
- **Windows:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection\AllowTelemetry`

MXC uses similar numeric values, but reads only its own administrative policy key. It does not read or derive its collection behavior from:

- `HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection\AllowTelemetry`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection\AllowTelemetry`
- The Windows Settings **Diagnostics & feedback** choice
- The `System/AllowTelemetry` Policy CSP node

Windows diagnostic-data settings do not substitute for the MXC-specific administrative policy. Administrators who want to restrict MXC collection must configure `HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Mxc\AllowTelemetry`.

## Availability and compatibility

Automatic Required collection applies only to supported Windows builds configured and approved for Microsoft telemetry routing. Local and open-source builds do not acquire automatic Required collection. MXC telemetry remains unavailable on macOS and Linux.

Required collection is introduced through a versioned contract. Existing published contracts retain their current explicit opt-in, consent, and administrative-policy behavior. In particular, those contracts continue to block collection at policy value `1`; an absent value or value `3` does not bypass their consent or per-request opt-in requirements.

## See also

- [Telemetry architecture](development/architecture/telemetry.md)
- [Lifecycle correlation](development/architecture/telemetry.md#correlating-a-lifecycle)
- [Telemetry consent design for existing contracts](development/architecture/telemetry-consent-design.md)
