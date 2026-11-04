# MXC diagnostic data

> **Audience:** Developers integrating the MXC SDK into products that ship to Windows devices.

MXC collects Required diagnostic data on supported Windows builds to help keep the component secure, reliable, up to date, and functioning as expected.

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

Required collection does not require user consent or per-request opt-in. It is not controlled by an MXC setting or registry key. Collection applies only on supported builds where collection is available.

## Privacy information for products embedding MXC

MXC documents its diagnostic-data collection and privacy controls in this documentation. Products integrating the MXC SDK should inform their users that MXC collects Required diagnostic data to help keep the component secure, reliable, and functioning as expected.

Products should cover this collection within their existing privacy disclosures and settings, linking to this documentation and the [Microsoft Privacy Statement](https://privacy.microsoft.com/privacystatement).

The Required diagnostic-data notification explains the collection; it does not ask users to opt in.

## Availability and compatibility

Automatic Required collection applies only to supported Windows builds configured and approved for Microsoft telemetry routing. Local and open-source builds do not acquire automatic Required collection. MXC telemetry remains unavailable on macOS and Linux.

Required collection is introduced through a versioned contract. Existing published contracts retain their current explicit opt-in and consent behavior, which is unchanged.

## See also

- [Telemetry architecture](development/architecture/telemetry.md)
- [Lifecycle correlation](development/architecture/telemetry.md#correlating-a-lifecycle)
- [Telemetry consent design for existing contracts](development/architecture/telemetry-consent-design.md)
