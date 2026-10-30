# MXC administrative telemetry policy

> **Audience:** MXC consumers

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

MXC reports each distinct unreadable or unrecognized policy failure once per
process so operators can distinguish a broken deployment from an intentional
block without weakening the fail-closed result.

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

## Execution start and end

`MXC.ExecutionStart` and `MXC.ExecutionEnd` replace `MXC.Execution`, which is
no longer emitted. Update collector filters and queries to the new names.
Both events retain the previous execution payload fields and types, including
backend, containment kind, lifecycle phase, and correlation vector. Both now
also include the lifecycle session ID.

Both also include `mxc.capture_denials`, a bounded string:

| Value | Selected configuration |
|---|---|
| `enforce` | Normal ProcessContainer policy enforcement without learning-mode denial recording |
| `deny-and-record` | Enforce policy denials and record them |
| `allow-and-record` | Allow accesses that would otherwise be denied and record them |
| `not_applicable` | Learning modes do not apply to this backend or no applicable invocation context is available |

The value comes from the normalized policy, including `learningMode` and
`captureDenials`. For `wxc-exec`, it also accounts for `--audit` and the
diagnostic-console learning override before setup starts. Permissive mode takes
precedence over deny-and-record. This reports the selected configuration, not
proof that sandbox setup succeeded or that the OS applied every restriction.
Streaming handles and best-effort executor crash/cancellation reporting retain
the invocation's original mode on End.

Start is emitted after telemetry authorization but before execution or lifecycle
dispatch. Its result fields are placeholders: `mxc.outcome` is `started`,
`mxc.exit_code` and `mxc.duration_ms` are `0`, and `mxc.failure_reason` is empty.
This does not mean a child process launched or exited successfully.

End reports the terminal result, retaining existing handled-failure and
best-effort executor panic/cancellation reporting. Streaming SDK calls emit End
when the handle observes a terminal result, is successfully killed, or is
disposed, not merely when spawn returns.

Each event independently checks consent and policy. An unmatched Start means
no End was observed, not proof of a crash: withdrawal, hard termination, native
crashes, and collection/delivery loss can all leave a gap. Requests rejected
before telemetry initialization do not have a guaranteed pair.
`mxc.session_id` groups the lifecycle; lifecycle operations also use `__TlgCV__`
to distinguish dispatches. No per-invocation ID is added.
See the [event contract](development/architecture/telemetry.md#mxcexecutionstart-and-mxcexecutionend).

## Lifecycle session correlation

All 11 event types include `mxc.session_id`, a lowercase hyphenated UUID
such as `7c54602b-e604-45ca-9a7a-e59bc86a6167` (illustrative only). One container
lifecycle shares the ID across provision, start, repeated exec calls, stop, and
deprovision, including separate executor processes. Each create-and-run execution
gets its own fresh ID. SDK consumers do not provide or forward it.

MXC reuses the random root in its existing per-user lifecycle correlation store;
the session ID is not derived from the caller, user, device, or sandbox ID.
Streaming handles retain their own ID across threads and restore it while backend
operations and cleanup run, without sharing another invocation's attribution.
Existing opt-in, consent, administrative policy and emission checks still apply.

Successful deprovision removes the stored root. If telemetry starts after
provision, or the record was lost or corrupted, the next authorized phase
establishes a new stable segment; earlier events cannot be joined to that segment.
Unavailable storage can break cross-process continuity and reports a diagnostic.
Exceptional attribution failures use `unknown` rather than a user-derived fallback.
See the [architecture details](development/architecture/telemetry.md#correlating-a-lifecycle)
for persistence, retention and random-generation limits.

The version `4` notice discloses random lifecycle correlation. Earlier grants
require explicit re-consent before collection resumes; no existing consent
record or policy is automatically upgraded. This notice is unreleased and
still requires privacy and release-owner review before shipping.

## See also

- [Telemetry architecture](development/architecture/telemetry.md)
- [Lifecycle correlation](development/architecture/telemetry.md#correlating-a-lifecycle)
- [Telemetry consent design](development/architecture/telemetry-consent-design.md)
