# MXC administrative telemetry policy

Audience: developers embedding MXC in a product that ships to Windows devices.

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

`HKLM\SOFTWARE\Policies\...` is an administrator-controlled machine-level registry location. MXC deliberately does not honor a per-user (`HKCU`) equivalent.

### Values

The values mirror the Windows diagnostic-data scale so administrators do not
have to learn a second one:

| Value | Windows name | Effect on MXC |
|-------|--------------|---------------|
| *(value absent)* | — | **Unrestricted.** The user's own choice decides. |
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

### Registry deployment

Use any deployment mechanism that writes
HKLM\SOFTWARE\Policies\Mxc\AllowTelemetry directly. For example:

- A startup/admin script:

  ```powershell
  $key = 'HKLM:\SOFTWARE\Policies\Mxc'
  New-Item -Path $key -Force | Out-Null
  Set-ItemProperty -Path $key -Name 'AllowTelemetry' -Value 0 -Type DWord
  ```

- Any installer or configuration package that writes the same value.

### Verifying

The consent status surface reports the user's recorded choice separately from
the administrative ceiling. The consent APIs expose the stored and effective
states, the policy state, and whether a prompt is needed.

For example, if a user previously granted consent and an administrator later
sets `AllowTelemetry=0`, the status must still make both facts visible:

- the stored user choice remains **granted**
- the administrative policy is **blocked**
- effective collection is therefore **off**
- no prompt is needed while the policy blocks

Keeping those states separate lets hosts explain why telemetry is currently
disabled without losing the user's prior choice.

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

The implementation stack enforces this rule in one place rather than
re-deriving it in each host surface. The telemetry gate combines the per-run
request with the consent and administrative-policy states before each event.

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
