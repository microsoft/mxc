# MXC diagnostic data

> **Audience:** Developers integrating the MXC SDK into products that ship to Windows devices.

MXC collects Required diagnostic data on supported Windows builds to help keep the component secure, reliable, up to date, and functioning as expected.

Required collection applies to all supported request contracts, as described under [Availability and compatibility](#availability-and-compatibility).

## Required diagnostic data

Required diagnostic data describes execution and container lifecycle progress, categorized operational failures, and observed process exits. It includes diagnostic fields and random invocation or lifecycle identifiers used to correlate related events.

The following events are Required:

| Event | Purpose |
|---|---|
| `MXC.ExecutionStart` | Beginning of an execution or container lifecycle operation. |
| `MXC.ExecutionEnd` | Completion of an execution or container lifecycle operation. |
| `MXC.Error` | A categorized operational failure associated with a container run. |
| `MXC.ProcessExited` | A process exit reported through the diagnostics telemetry helper. |

Required collection does not require user consent or per-request opt-in. It is not controlled by an MXC setting or registry key. Collection applies only on supported builds where collection is available.

## Privacy information for products embedding MXC

MXC documents its diagnostic-data collection and privacy controls in this documentation. Products integrating the MXC SDK should inform their users that MXC collects Required diagnostic data to help keep the component secure, reliable, and functioning as expected.

Products should cover this collection within their existing privacy disclosures and settings, linking to this documentation and the [Microsoft Privacy Statement](https://privacy.microsoft.com/privacystatement).

The Required diagnostic-data notification explains the collection; it does not ask users to opt in.

## Availability and compatibility

Automatic Required collection applies only to supported Windows builds configured and approved for Microsoft telemetry routing. Windows release builds from source use the signed telemetry component bundled in the repository and are routed; debug builds are not. To build a release without routing, set `MXC_TELEMETRY_COMPONENT_PATH` to an empty value. MXC telemetry remains unavailable on macOS and Linux.

Requests using `0.9.0-alpha`, `1.0.0`, or `1.1.0-alpha` collect only the four Required events. This includes V1 SDK requests targeting `1.0.0`. Omitting `telemetry`, setting `telemetry.enabled` to `false`, withdrawing consent, or configuring administrative policy does not disable these events.

This changes the earlier optional-collection behavior of `0.9.0-alpha` and `1.0.0`. Their JSON fields remain accepted, but no longer control Required collection. Local denial reports, audit artifacts, and diagnostic logs are unchanged; verbose denial data is not sent as telemetry for these contracts.

## Consent-management compatibility

The existing consent-management APIs and CLI remain available and continue to read and persist consent and report the MXC administrative policy. These results describe consent state, not whether Required events are collected. MXC does not change existing consent records or infer grants.

Internal requests without source-contract attribution retain their existing optional behavior: collection requires request opt-in, current MXC consent, provider availability, and a permitting `REG_DWORD` value `AllowTelemetry` under `HKLM\SOFTWARE\Policies\Mxc`. An absent value imposes no restriction; only value `3` explicitly permits collection. Other values, wrong types, and read failures block that optional path. None of these settings controls Required events. JSON version validation is unchanged.

## See also

- [Telemetry architecture](development/architecture/telemetry.md)
- [Lifecycle correlation](development/architecture/telemetry.md#correlating-a-lifecycle)
- [Telemetry consent-management design](development/architecture/telemetry-consent-design.md)
