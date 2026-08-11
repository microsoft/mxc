# MXC administrative telemetry policy

Audience: IT administrators, and developers embedding MXC in a product that
ships to managed devices.

MXC supports a single administrative policy that lets an organization prevent
MXC from collecting diagnostic data on a device, regardless of what the user
chooses. It is a **ceiling, never a grant** — see
[Why policy cannot substitute for consent](#why-policy-cannot-substitute-for-consent).

The policy is **Windows-only**, because [MXC only ever collects telemetry on
Windows](telemetry.md). On Linux and macOS there is nothing to restrict.

## The setting

| | |
|---|---|
| Key | `HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Mxc` |
| Value name | `AllowTelemetry` |
| Type | `REG_DWORD` |
| Scope | Machine (all users on the device) |

`HKLM\SOFTWARE\Policies\...` is the standard managed-policy hive: it is
writable only by administrators and is the location Group Policy, Intune, and
other MDM services write to. MXC deliberately does not honor a per-user
(`HKCU`) equivalent — a policy a user can edit is not a policy.

### Values

The values mirror the Windows diagnostic-data scale so administrators do not
have to learn a second one:

| Value | Windows name | Effect on MXC |
|-------|--------------|---------------|
| *(value absent)* | — | **Unrestricted.** MXC is unmanaged; the user's own choice decides. |
| `0` | Security / Off | **Blocked.** MXC collects nothing. |
| `1` | Required (Basic) | **Blocked.** MXC collects nothing. |
| `3` | Optional (Full) | **Allowed.** MXC may collect *if the user has also consented.* |
| anything else | — | **Blocked** (fail closed). |

`1` blocks MXC because everything MXC emits is classified as
*product-and-service-usage* data — optional diagnostic data in Windows'
taxonomy. MXC emits no required diagnostic data, so there is nothing left to
send at level `1`. Value `2` is not a defined level on modern Windows and is
therefore treated as unrecognized.

Any value MXC cannot read or cannot parse — a wrong type, a corrupt value, a
registry error — is treated as `Blocked`. Telemetry collection is never the
outcome of a failure.

## Deploying it

### Group Policy (native, works today)

There is no inbox ADMX for MXC yet. Either use Group Policy Preferences to
write the registry value, or import the ADMX below.

<details>
<summary><code>Mxc.admx</code></summary>

```xml
<?xml version="1.0" encoding="utf-8"?>
<policyDefinitions revision="1.0" schemaVersion="1.0">
  <policyNamespaces>
    <target prefix="mxc" namespace="Microsoft.Policies.Mxc" />
    <using prefix="windows" namespace="Microsoft.Policies.Windows" />
  </policyNamespaces>
  <resources minRequiredRevision="1.0" />
  <categories>
    <category name="MXC" displayName="$(string.MXC)" />
  </categories>
  <policies>
    <policy name="AllowTelemetry"
            class="Machine"
            displayName="$(string.AllowTelemetry)"
            explainText="$(string.AllowTelemetry_Help)"
            key="SOFTWARE\Policies\Mxc"
            presentation="$(presentation.AllowTelemetry)">
      <parentCategory ref="MXC" />
      <supportedOn ref="windows:SUPPORTED_Windows10" />
      <elements>
        <enum id="AllowTelemetry_Enum" valueName="AllowTelemetry" required="true">
          <item displayName="$(string.Off)">
            <value><decimal value="0" /></value>
          </item>
          <item displayName="$(string.Required)">
            <value><decimal value="1" /></value>
          </item>
          <item displayName="$(string.Optional)">
            <value><decimal value="3" /></value>
          </item>
        </enum>
      </elements>
    </policy>
  </policies>
</policyDefinitions>
```

The matching `Mxc.adml` needs `MXC`, `AllowTelemetry`, `AllowTelemetry_Help`,
`Off`, `Required` and `Optional` strings plus a `dropdownList` presentation for
`AllowTelemetry_Enum`.

</details>

### Microsoft Intune

Import `Mxc.admx` (above) via **Devices → Configuration → Import ADMX**, then
create a Configuration profile from the imported template and set
**AllowTelemetry**.

MXC's policy key lives at `SOFTWARE\Policies\Mxc` — deliberately *not* under
`Policies\Microsoft` — specifically so that this works. Windows forbids
ADMX-ingested policies from writing under `System`, `Software\Microsoft`, or
`Software\Policies\Microsoft`, except for a hardcoded allowlist (Office, Edge,
OneDrive, VisualStudio, …). An ADMX targeting a key under those prefixes is
rejected. See [Win32 and Desktop Bridge app ADMX policy
ingestion](https://learn.microsoft.com/windows/client-management/win32-and-centennial-app-policy-configuration).

Equivalent alternatives, if you would rather not ingest an ADMX:

- **A PowerShell script** (Devices → Scripts and remediations), running in the
  system context:

  ```powershell
  $key = 'HKLM:\SOFTWARE\Policies\Mxc'
  New-Item -Path $key -Force | Out-Null
  Set-ItemProperty -Path $key -Name 'AllowTelemetry' -Value 0 -Type DWord
  ```

- **A Win32 app or configuration package** that writes the same value.
- **On-premises Group Policy**, for hybrid-joined devices.

### Verifying

Any MXC surface will report the effective policy. From the command line:

```
wxc-exec.exe --telemetry-consent-status
```

```json
{"action":"status","result":"status","storedState":"granted","effectiveState":"granted","reason":null,"policy":"blocked","needsPrompt":false,"prompt":null,"challenge":null}
```

The `policy` field is one of `unrestricted`, `allowed`, `blocked`, or
`not-applicable` (returned on non-Windows platforms). The same value is
available programmatically as `mxc_sdk::telemetry::get_policy()` (Rust),
`MxcTelemetry.GetPolicy()` (C#), and `getTelemetryPolicy()` (Node).

## How the policy interacts with user consent

MXC collects diagnostic data only when **every** gate is open:

```
collect = policy_permits AND user_consented AND build_has_telemetry_enabled
```

Concretely:

| Policy | User consent | Result |
|--------|--------------|--------|
| unrestricted | granted | collects |
| unrestricted | denied / undetermined | **no collection** |
| allowed (`3`) | granted | collects |
| allowed (`3`) | denied / undetermined | **no collection** |
| blocked (`0`/`1`/other) | *anything* | **no collection** |

Two consequences worth calling out:

1. **A blocking policy suppresses the first-run consent prompt.** Asking a user
   to permit something the administrator has already refused is a question with
   no meaning. `needsPrompt` reports `false` while the policy blocks.
2. **A blocking policy does not erase the user's recorded choice.** If a user
   had already consented and an administrator later blocks telemetry,
   collection stops immediately but the recorded consent is preserved. If the
   policy is later relaxed, the user's own prior decision takes effect again
   rather than the user being re-prompted.

### Why policy cannot substitute for consent

An administrator setting `AllowTelemetry=3` does **not** cause MXC to start
collecting. It only removes MXC's administrative restriction; the user is still
asked, and still decides.

In particular, **if the user has opted out and the policy permits collection,
the result is opt-out.** A policy can only ever subtract. There is no policy
value, and no combination of policy and configuration, that causes MXC to
collect from a user who has not explicitly granted consent — including a user
who has never been asked.

This is a product rule MXC holds itself to, not merely a reading of external
guidance. It is also consistent with that guidance: Microsoft's privacy
direction for components classified as *apps* (rather than as parts of the
operating system) requires them to build their own notice-and-consent
experience and not to rely on the Windows diagnostic-data consent. An
administrative policy is an availability control, not an expression of a
user's informed choice, and no Microsoft guidance treats an admin "allow" as
consent on the user's behalf.

The rule is enforced in one place — the conjunction in
`wxc_common::telemetry::is_enabled` — and is locked in by tests that assert a
denied or undetermined consent wins under *every* policy value, including `3`.

## Relationship to the Windows `AllowTelemetry` policy

MXC reads **only** its own key. It does not read, and is not affected by:

- `HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection\AllowTelemetry`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection\AllowTelemetry`
- the Windows Settings → Diagnostics & feedback choice
- the `System/AllowTelemetry` Policy CSP node

Two reasons:

1. **Microsoft documents that it doesn't apply.** The Policy CSP documentation
   for `System/AllowTelemetry` states that it "impacts the operating system and
   apps that are considered part of Windows and doesn't apply to any additional
   apps installed by your organization." MXC is such an app.
2. **Reading it would leak the user's Windows choice into MXC.** The supported
   OS APIs for evaluating that policy deliberately combine the administrative
   setting with the user's own Settings-app selection. Consuming them would
   make MXC's behaviour depend on Windows consent state, which MXC's design
   forbids.

The dominant pattern among Microsoft first-party applications — Office,
Visual Studio, Visual Studio Code, WinGet, PowerToys — is likewise an
application-specific policy under `SOFTWARE\Policies\Microsoft\<app>`.

## See also

- [Telemetry overview](telemetry.md)
- [Telemetry consent design](telemetry-consent-design.md)
