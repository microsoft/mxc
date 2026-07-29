# Telemetry Consent — Feature Spec

> Status: **Implemented** — this document describes the consent and policy
> contract as shipped, and is maintained alongside the code. It began as a
> feature spec per the "Write a Feature Spec" step in
> [`docs/authoring-a-new-feature.md`](../authoring-a-new-feature.md); the
> section-by-section implementation status is tracked in §9.

## 1. Problem statement

MXC already has a fully-built ETW TraceLogging pipeline
(`mxc_telemetry` + `wxc_common::telemetry`, see
[`telemetry.md`](telemetry.md)), gated behind `--experimental` and a
per-request JSON field, `experimental.telemetry.enabled`. Today that field is
the *entire* consent model, and the code says so explicitly
(`wxc_common/src/telemetry/mod.rs`):

> "Note: Consent is the SDK consumer's responsibility. MXC does not
> implement consent prompts or persistent consent storage."

That is insufficient for a real end-user consent experience:

- There is no **persistent** record of a user's choice — every SDK consumer
  would have to build (and get right) their own storage, first-run prompt,
  and toggle UI, redundantly and inconsistently, or (worse) hardcode
  `enabled: true` and never ask anyone.
- Nothing stops a config author from setting `enabled: true` regardless of
  whether the person running the sandbox ever agreed to anything.
- There is no cross-platform story: `mxc_telemetry` is already a Windows-only
  ETW provider (no-op elsewhere), but the *consent surface* doesn't
  explicitly reflect that — a consumer could plausibly wire up an opt-in UI
  on Linux/macOS for a pipe that will never collect anything, which is
  actively misleading to end users.

This spec defines a **persistent, per-user, Windows-only telemetry consent
flag**, owned by MXC itself, that:

1. Gates all telemetry emission — no consent, no data, full stop.
2. Is the single source of truth shared by every SDK surface (Node, C#,
   direct `wxc-exec.exe` callers), instead of being reimplemented per consumer.
3. Is offered to end users on first sandbox run, and can be changed at any
   time by whatever agent/app is hosting MXC.
4. Does not exist at all — no flag, no prompt, no storage, no API surface
   claiming to do anything — on Linux/macOS, because MXC does not and must
   not collect telemetry on those platforms.

## 2. Grounding in Microsoft's privacy principles

Microsoft's public privacy commitments (Microsoft Privacy Promise /
Trust Center: <https://www.microsoft.com/trust-center/privacy>) center on
**control, transparency, consent, and security**. Microsoft's public
guidance is also clear that the Windows diagnostic-data setting governs
Windows itself, not separately installed applications: the `AllowTelemetry`
policy "doesn't apply to any additional apps installed by your
organization"
([Microsoft Learn](https://learn.microsoft.com/windows/privacy/configure-windows-diagnostic-data-in-your-organization)).
Consent for an application's own diagnostic data is therefore that
application's responsibility, not something it inherits from the OS.

MXC is not a Windows inbox component and cannot piggyback on the OS-level
Diagnostic Data setting (`Settings > Privacy > Diagnostics & feedback`); it
must implement and honor its own consent, exactly as any third-party
Windows app or SDK must. This design applies the same pillars end-to-end:

| Privacy Promise pillar | How this design honors it |
|---|---|
| **Consent** | Telemetry is **off by default** (`Undetermined` ⇒ treated as denied). Nothing is ever collected before an explicit, affirmative "granted". |
| **Control** | The user (or the agent acting on their behalf) can flip the flag at any time, as many times as they like — no re-install, no support ticket. |
| **Transparency** | A `status` query is always available and cheap (local file read, no network call) so any consumer can show the current state and link to [`telemetry.md`](telemetry.md) describing exactly what is collected. |
| **No dark patterns** | Denying is exactly as easy as granting; MXC does not nag on every run once a choice has been made; the consent primitives never bias the wording or defaults toward "on". |
| **Least privilege / data minimization** | Reuses the existing bounded, PII-scrubbed event schema (`MXC.Execution` / `MXC.Error`, see `telemetry.md`) — this spec changes *whether* those events fire, never *what* they contain. |
| **Fail closed** | Any ambiguous state — missing file, corrupt file, unreadable file, unknown platform — resolves to **not collecting**, never to collecting. |
| **Platform honesty** | Non-Windows builds do not merely default the flag to "off" — the consent module does not compile in on non-Windows targets, so there is no code path, storage file, or API pretending consent is meaningful where MXC cannot and does not collect anything. |

### 2.1 Provider-group classification and why it doesn't change this design

MXC's ETW provider may be registered under a UTC provider group. Provider
groups affect how already-emitted events are *classified and routed* by the
backend — for example, keeping an application's data separated from Windows
diagnostic data. They say nothing about whose consent gates emission in the
first place.

Because MXC is an application rather than a Windows system component, it is
responsible for its own notice and consent experience and must not rely on
the Windows diagnostic consent. That responsibility is unaffected by
provider-group choice.

Regardless of which UTC provider group MXC's ETW provider is registered
under (see `telemetry.md`'s *Private GUID Substitution* section), **the sole
gate for emission is the persisted
`%LOCALAPPDATA%\mxc\telemetry-consent.json` flag described in this document
— never the Windows Diagnostics & feedback setting, never an implicit
UTC-level opt-in.**

## 3. Design overview

```
┌────────────────────────────────────────────────────────────┐
│ Host application ("agent") using MXC                       │
│  - First run: sees needsConsentPrompt == true, shows its   │
│    own UI, calls setTelemetryConsent(...)                  │
│  - Any later time: settings page calls get/setTelemetry     │
│    Consent(...) again to flip the choice                   │
└───────────────┬──────────────────────────────────────────────┘
                │ SDK call (Node / C#)
                ▼
┌────────────────────────────────────────────────────────────┐
│ SDK thin wrapper (sdk/node, sdk/dotnet)                     │
│  getTelemetryConsent() / setTelemetryConsent(state)         │
└───────────────┬──────────────────────────────────────────────┘
                │ shells out to wxc-exec.exe --telemetry-consent-*
                │ (Node)  OR  P/Invoke into mxc_ffi (C#)
                ▼
┌────────────────────────────────────────────────────────────┐
│ wxc_common::telemetry::consent   (Windows-only module)     │
│  - reads/writes the persisted consent file                 │
│  - single source of truth for every surface                │
└───────────────┬──────────────────────────────────────────────┘
                │
                ▼
   %LOCALAPPDATA%\mxc\telemetry-consent.json   (per Windows user)

┌────────────────────────────────────────────────────────────┐
│ wxc_common::telemetry::policy    (Windows-only module)     │
│  - reads the administrative (MDM / Group Policy) ceiling   │
│  - deny-only; never a substitute for consent               │
└───────────────┬──────────────────────────────────────────────┘
                │
                ▼
   HKLM\SOFTWARE\Policies\Mxc\AllowTelemetry  (per device)
```

Telemetry emission (`wxc_common::telemetry::is_enabled`) becomes:

```
effective = platform_is_windows
         && admin_policy_permits
         && persisted_consent == Granted
         && request.experimental.telemetry.enabled != Some(false)
```

- Persisted consent is the **gate**. Without `Granted`, nothing fires,
  regardless of what a config author put in the per-request JSON.
- The administrative policy is a **ceiling**. It can only ever subtract: an
  administrator can stop MXC collecting on a device, but an administrator
  permitting collection does not stand in for the user's own decision. See
  [`telemetry-policy.md`](telemetry-policy.md) for the full specification.
- The existing `experimental.telemetry.enabled` field becomes an
  **explicit opt-in that can only subtract**: collection requires
  `true`, while omitting the field or setting `false` always disables it (a
  caller can always force telemetry off for one run, e.g. CI, a support
  repro, or a policy override); explicit `true` can no longer *bypass*
  consent — it is simply ignored if consent isn't `Granted`. This closes the
  "hardcode `true` and never ask anyone" loophole described in §1 while
  preserving today's emergency-off behavior.
- On non-Windows, `persisted_consent` is not merely "false" — the consent
  module is `#[cfg(target_os = "windows")]`-gated out entirely, so the
  expression above compiles to the existing Linux/macOS no-op path
  unchanged. The policy module is gated the same way and reports
  `NotApplicable`, which does not itself deny (there is nothing to deny —
  the consent gate has already stopped collection, and reporting a denial
  would wrongly imply an administrator had acted).

No JSON config **schema** change is required: consent is out-of-band,
per-user host state, not a per-run parameter, so `wire.rs` /
`schemas/dev/*.json` are untouched. This also avoids any stable/dev schema
promotion churn.

## 4. Persisted consent store

- **Location**: `%LOCALAPPDATA%\mxc\telemetry-consent.json` — per-user, not
  `%ProgramData%`. Consent is a personal choice tied to the signed-in
  Windows user (mirrors how Windows Diagnostic Data settings and most app
  privacy toggles are scoped), and per-user storage means multiple people
  sharing one machine each control their own choice independently, with no
  admin/elevation requirement to change it (`wxc-exec.exe` does not
  self-elevate — see `docs/host-prep.md`).
- **Format** (schema-versioned, forward-compatible, mirrors the
  `null-device-acl.log` JSON-lines style already used by `wxc-host-prep`):

  ```json
  {
    "schemaVersion": 1,
    "consent": "granted",
    "source": "prompt",
    "promptedMxcVersion": "0.9.2",
    "updatedAtEpoch": 1785169735
  }
  ```

  - `consent`: `"granted" | "denied" | "undetermined"`.
  - `source`: `"prompt" | "settings-toggle" | "cli" | "sdk"` — free-form
    provenance for support/debugging, never transmitted anywhere.
  - `updatedAtEpoch`: Unix epoch seconds — internal provenance only, never
    surfaced through the CLI/FFI/SDK surfaces (those only ever expose
    `consent`).
  - File is written atomically (write to a temp file in the same directory,
    then rename) to avoid a torn read if a crash happens mid-write.
- **Fail-closed reads**: missing file, unreadable file, unparseable JSON, or
  an unrecognized `schemaVersion` all resolve to `Undetermined` (⇒ not
  collecting) — never to `Granted`. A corrupt file is logged as a
  diagnostic (same `Logger` used elsewhere) but never treated as consent.
- **No telemetry about consent itself**: flipping the flag never emits an
  ETW event. At the moment of a transition we may be entering *or leaving*
  a consented state, so the only safe behavior is silence — this also
  avoids a "one last ping on the way out the door" problem when a user
  revokes.

## 5. Surface: `wxc-exec.exe` flags

Following the existing flag style in `src/core/wxc/src/main.rs` (`--probe`,
`--delete`, `--setup-hyperlight`, …) rather than introducing a clap
subcommand tree:

| Flag | Behavior |
|---|---|
| `--telemetry-consent-status` | Prints current state as one-line JSON (`{"consent":"granted","needsPrompt":false,"policy":"allowed"}`) and exits. Available on every platform; on non-Windows always prints `{"consent":"not-applicable","needsPrompt":false,"policy":"not-applicable"}` and never touches disk. The payload carries exactly the three things a host needs to act — the user's own decision, whether it should prompt, and the administrative ceiling. `needsPrompt` is emitted rather than left for each SDK to derive from `consent`, so the prompt policy has exactly one implementation (`ConsentState::needs_prompt`, combined with the policy read) shared by every language; in particular a `blocked` policy suppresses the prompt, so `needsPrompt` is never `true` alongside `"policy":"blocked"`. `policy` is one of `unrestricted` (no MDM/Group Policy value configured), `allowed` (configured and permits collection), `blocked` (configured to deny, *or* unreadable — see [`telemetry-policy.md`](telemetry-policy.md)), or `not-applicable` (non-Windows). `source` and the on-disk timestamp are internal provenance never surfaced through this CLI. |
| `--telemetry-consent-grant` | Persists `Granted` (source `"cli"` unless `--telemetry-consent-source <value>` is passed, e.g. by an SDK wrapper), then prints the same status JSON as above. Windows-only; on non-Windows, exits non-zero (`1`) with `Error: telemetry is Windows-only; consent is not applicable on this platform` — MXC must not pretend to accept consent it can never act on. `--telemetry-consent-grant` and `--telemetry-consent-revoke` are mutually exclusive (exits with code `64` if both are passed). |
| `--telemetry-consent-revoke` | Persists `Denied`, then prints the same status JSON. Same platform behavior as above. |

All three flags are handled by one shared implementation,
`wxc_common::telemetry::consent_cli::handle_consent_flags`, that each
executor's `main.rs` delegates to — this is a fast path evaluated before any
other startup work, so the flags behave identically across `wxc-exec`,
`lxc-exec`, and `mxc-exec-mac` even though only `wxc-exec` can actually
persist a decision.

These are detection/administration fast paths, mirroring `--probe`: they run
before COM/runner initialization, do not execute any sandbox, and exit
immediately. This is the "engaging with the agent that is using
`wxc-exec.exe`" toggle mechanism the SDKs call into — the host application's
own settings UI shells out to one of these flags (or calls the SDK wrapper,
which does the same thing under the hood).

## 6. Surface: Node SDK (`sdk/node`)

New module `sdk/node/src/telemetry.ts`, re-exported from `index.ts`:

```ts
export type TelemetryConsentState = 'granted' | 'denied' | 'undetermined' | 'not-applicable';
export type TelemetryConsentSource = 'prompt' | 'settings-toggle' | 'cli' | 'sdk' | (string & {});
export type TelemetryPolicyState = 'unrestricted' | 'allowed' | 'blocked' | 'not-applicable';

/** Always 'not-applicable' on non-Windows — MXC does not collect telemetry there. Never throws. */
export function getTelemetryConsent(): TelemetryConsentState;

/**
 * Same as getTelemetryConsent(), but also reports *why* the state is what it is,
 * so a host can distinguish "the user genuinely has not decided" (prompt) from
 * "we could not reach wxc-exec" (broken install — prompting will not help).
 * `needsPrompt` and `policy` come straight from the native layer; the SDK does
 * not derive either. This is the single-spawn snapshot the other three read
 * functions are thin wrappers over — prefer it when you need more than one
 * answer, so all three are consistent with each other. Never throws.
 */
export function queryTelemetryConsent(): TelemetryConsentQuery;

export interface TelemetryConsentQuery {
  state: TelemetryConsentState;
  needsPrompt: boolean;
  policy: TelemetryPolicyState;
  error?: string;
}

/** The administrative (MDM / Group Policy) ceiling. Fails closed to 'blocked'. Never throws. */
export function getTelemetryPolicy(): TelemetryPolicyState;

/** Throws if the decision could not be persisted — always the case on non-Windows. */
export function setTelemetryConsent(granted: boolean, source?: TelemetryConsentSource): void;

/**
 * Convenience for first-run flows: the native layer's `needsPrompt` answer.
 * Always `false` when the policy is `'blocked'` — asking for permission an
 * administrator has already refused is a meaningless question.
 */
export function needsTelemetryConsentPrompt(): boolean;
```

Both read paths short-circuit on `process.platform !== 'win32'` *before* any
attempt to spawn `wxc-exec`, so a spawn failure on macOS/Linux can never be
reported as `'undetermined'` and can never drive a host into showing a consent
prompt on a platform where MXC collects nothing. The C# SDK's
`MxcTelemetry.GetConsent()`/`SetConsent()` apply the same
`OperatingSystem.IsWindows()` guard before touching the native library.

Implementation shells out to `wxc-exec.exe --telemetry-consent-*` (the SDK
already resolves the native binary path via `platform.ts`), keeping the
actual persistence logic in exactly one place (Rust). The SDK is
deliberately **UI-agnostic**: it does not render a prompt itself. A hosting
agent calls `needsTelemetryConsentPrompt()` once at first sandbox run, shows
its own UI if `true`, then calls `setTelemetryConsent(...)`; a settings page
can call `get`/`setTelemetryConsent` at any later time.

None of the read functions throw. On Windows, a missing `wxc-exec` is a broken
install rather than an unsupported platform, so it fails closed to
`'undetermined'` / `'blocked'` and reports why in
`TelemetryConsentQuery.error` — it must not be reported as `'not-applicable'`,
which would tell the host this machine never collects telemetry and hide the
failure. Because the three convenience getters discard `error`, every
fail-closed read is also warned to the console once per distinct failure per
process (deduplicated: a host may poll these to render a settings toggle).

## 7. Surface: C# SDK (`sdk/dotnet`)

New `MxcTelemetry` static class wrapping four new `mxc_ffi` exports:

```rust
// ffi/mxc_ffi
pub unsafe extern "C" fn mxc_telemetry_get_consent(out_utf8: *mut *mut c_char) -> i32;
pub unsafe extern "C" fn mxc_telemetry_set_consent(granted: i32, source_utf8: *const c_char) -> i32;
pub unsafe extern "C" fn mxc_telemetry_needs_consent_prompt(out_needs_prompt: *mut i32) -> i32;
pub unsafe extern "C" fn mxc_telemetry_get_policy(out_utf8: *mut *mut c_char) -> i32;
```

All are `catch_unwind`-wrapped like every other `mxc_ffi` entry point — a panic
must never unwind into a foreign frame, which would be undefined behaviour.
Because `catch_unwind` otherwise discards the payload and leaves the host with
a bare `MXC_STATUS_PANIC` and no way to diagnose it, the boundary writes the
panic message to stderr before returning. The same applies to the write-failure
reason in `mxc_telemetry_set_consent`, which the status code alone cannot
convey (missing profile directory, denied ACL, read-only volume).
`mxc_telemetry_get_consent` always succeeds and reports `"not-applicable"`
on non-Windows (it never fails because of platform). `mxc_telemetry_set_consent`
returns `MXC_STATUS_CONSENT_WRITE_FAILED` when the decision can't be
persisted — always the case on non-Windows, since MXC must not collect (and
therefore must not offer consent for) telemetry there.
`mxc_telemetry_needs_consent_prompt` exists so C# does not re-derive the
prompt policy from the state string; it writes `0` on non-Windows.
`mxc_telemetry_get_policy` reports the administrative ceiling and likewise
always succeeds, reporting `"not-applicable"` on non-Windows. All compile on
every platform so `NativeMethods.g.cs` stays uniform across OSes.

```csharp
public static class MxcTelemetry
{
    public static TelemetryConsentState GetConsent();
    public static void SetConsent(bool granted, string? source = null);
    public static bool NeedsConsentPrompt();
    public static TelemetryPolicyState GetPolicy();
}
```

`NeedsConsentPrompt()` and `GetPolicy()` **never throw at all** — they fail
closed to `false` / `Blocked` on any failure, including a non-`Success` status
from the native layer (which covers a caught panic). A read-only query on a
privacy gate must not be able to take down a host that calls it on its startup
path.

`GetConsent()` also fails closed to `Undetermined` for a missing, mismatched, or
unloadable native library, but still surfaces a genuine native-layer failure as
`MxcException` — its caller has to be able to tell "the user has not decided"
apart from "we could not read the decision", or it would prompt on a broken
install. `SetConsent()` likewise throws, since the caller asked to persist a
decision and silence would be a lie.

Both throwing paths only ever raise `MxcException`: an unexpected exception
from the marshalling layer is wrapped (preserving the original as
`InnerException`) rather than escaping raw, so a host catching the documented
type is not taken down by a surprise one.

Every swallowed failure is reported once per distinct failure per process on
stderr — otherwise a broken install is completely silent, since the fail-closed
return values are indistinguishable from legitimate ones. The reporter cannot
itself throw.

## 7a. Surface: Rust SDK (`src/core/mxc-sdk`)

`mxc-sdk` — the public Rust SDK — re-exports the consent and policy API
verbatim from `wxc_common::telemetry`, so a Rust consumer gets the same
operations as a Node or C# consumer:

```rust
pub mod telemetry {
    pub use wxc_common::telemetry::consent::{
        get_consent, needs_consent_prompt, set_consent, ConsentState,
    };
    pub use wxc_common::telemetry::policy::{get_policy, is_blocked_by_policy, PolicyState};
}
```

This is a **pure re-export** — there is deliberately no Rust-SDK-specific
consent logic to keep in sync. A Rust host calls `needs_consent_prompt()`
at first sandbox run, shows its own UI, then calls `set_consent(..)`, and
can call `get_consent()`/`set_consent(..)` from a settings surface later —
exactly the flow described in §8.

## 8. First-run flow (end to end)

1. Host application calls `needsTelemetryConsentPrompt()` (or the C#/CLI
   equivalent) once, e.g. right before its first `spawnSandbox` call.
2. If `true` (Windows + `Undetermined`), the host shows **its own** consent
   UI — MXC does not ship a UI, since it is a library used by arbitrary
   host apps/agents with their own look and feel and localization needs.
   The UI copy should point at `docs/telemetry/telemetry.md` (or the host's
   own equivalent) so the "transparency" pillar is satisfied with concrete,
   specific information, not a vague "help us improve" prompt.
3. The host calls `setTelemetryConsent(true|false)` with the user's answer.
   This persists to `%LOCALAPPDATA%\mxc\telemetry-consent.json` for that
   Windows user and is immediately effective for every subsequent
   `wxc-exec.exe` invocation (one-shot and state-aware) run by that user —
   no restart, no cache to invalidate, since `is_enabled()` re-reads the
   file at each process's `telemetry::init()`.
4. On Linux/macOS, `needsTelemetryConsentPrompt()` always resolves `false`
   — hosts never see a prompt opportunity, satisfying the hard requirement
   that consent must not even be *offered* off Windows.
5. At any later time — a settings/preferences screen, a CLI flag, an admin
   tool — the host calls `setTelemetryConsent` again to flip the choice.
   There is no limit on how often this can change; every call is a plain,
   idempotent, atomic file write.

## 9. Files touched (implementation checklist)

| File | Change | Status |
|---|---|---|
| `src/core/wxc_common/src/telemetry/consent.rs` (new) | `ConsentState` enum, `read_consent()`/`write_consent()`, atomic-write helper, fail-closed parsing. `#[cfg(target_os = "windows")]` real impl + stub for other targets that always returns `NotApplicable` and never touches disk. | ✅ Done |
| `src/core/wxc_common/src/telemetry/mod.rs` | `is_enabled()` updated to the new resolution order in §3; doc comment correction (remove the "MXC does not implement consent" note, replace with a pointer to this design). | ✅ Done |
| `src/core/wxc/src/main.rs` | Add `--telemetry-consent-status` / `--telemetry-consent-grant` / `--telemetry-consent-revoke` (+ `--telemetry-consent-source`) flags, handled as an early fast path like `--probe`. | ✅ Done |
| `src/core/lxc/src/main.rs`, `src/core/mxc_darwin/src/main.rs` | Add the same flags for CLI symmetry; always report/act `not-applicable` (never write a file, never accept "grant"). | ✅ Done |
| `src/core/mxc-sdk/src/lib.rs` | `pub mod telemetry` re-exporting `get_consent` / `set_consent` / `needs_consent_prompt` / `ConsentState` from `wxc_common`, so the public **Rust** SDK offers the same consent surface as the Node and C# SDKs. Pure re-export — no Rust-SDK-specific logic. | ✅ Done |
| `src/core/wxc_common/src/telemetry/consent.rs` | `ConsentState::needs_prompt()` + free fn `needs_consent_prompt()` — the single definition of the prompt policy for every consumer surface. | ✅ Done |
| `ffi/mxc_ffi/src/lib.rs` | `mxc_telemetry_get_consent` / `mxc_telemetry_set_consent` / `mxc_telemetry_needs_consent_prompt` exports; new `MXC_STATUS_CONSENT_WRITE_FAILED` status code. | ✅ Done |
| `sdk/node/src/telemetry.ts` (new) | `getTelemetryConsent`, `queryTelemetryConsent`, `setTelemetryConsent`, `needsTelemetryConsentPrompt`, `TelemetryConsentState`/`TelemetryConsentSource`/`TelemetryConsentQuery` types, all behind a `process.platform === 'win32'` guard. | ✅ Done |
| `sdk/node/src/index.ts` | Re-export the above. | ✅ Done |
| `sdk/node/README.md` | Document the consent API and the first-run flow. | ✅ Done |
| `sdk/dotnet/Microsoft.Mxc.Sdk/MxcTelemetry.cs`, `TelemetryConsentState.cs` (new) | `GetConsent()` / `SetConsent(bool, string?)` / `NeedsConsentPrompt()` wrapping the new FFI exports. | ✅ Done |
| `sdk/dotnet/README.md` | Same documentation as the Node README. | ✅ Done |
| `docs/telemetry/telemetry.md` | New "## Consent" section describing the persisted flag, replacing the old "consent is the SDK consumer's responsibility" note; also documents why provider-group classification does not affect the consent gate. | ✅ Done |
| `scripts/check-dotnet-errorcode-parity.js` | No code change needed — it already diffs `MXC_STATUS_*` against `ErrorCode.cs` generically. | ✅ Verified passing |
| `scripts/check-dotnet-bindings-codegen.js` | Extended `REQUIRED_ENTRY_POINTS` with the three new FFI exports. | ✅ Done |
| Tests (`wxc_common`, `mxc_ffi`, `sdk/node/tests`, `sdk/dotnet` tests) | See §10. | ✅ Done |
| `tests/scripts/run_telemetry_consent_smoke_test.ps1` (new) | Standalone CLI smoke test: grant/status/revoke/status round-trip + mutual-exclusion rejection, against a consent store isolated via `MXC_TEST_LOCALAPPDATA_OVERRIDE`. Debug builds only (release compiles the override out); the script asserts the redirect took effect before trusting any result. | ✅ Done |

## 10. Test plan

- **Unit (`wxc_common`, Windows-only `#[cfg(target_os = "windows")]` tests,
  run in the existing Windows CI job)**:
  - Fresh machine (no file) ⇒ `Undetermined`, `is_enabled() == false`.
  - Grant ⇒ persists, re-read returns `Granted`, `is_enabled() == true`
    (with `experimental.telemetry.enabled` set to `true`).
  - Grant + request omits `enabled` or sets it to `false` ⇒ `is_enabled()
    == false` (collection requires an explicit opt-in).
  - Deny ⇒ persists, `is_enabled() == false` even if request sets
    `enabled: true` (consent gates; config can't bypass it).
  - Corrupt file / unknown `schemaVersion` / unreadable file ⇒ fail closed
    to `Undetermined`.
  - Atomic write: simulate a crash between temp-write and rename (best
    effort — assert the original file is untouched if rename never
    happens).
  - **Status: implemented in `consent.rs` and `telemetry/mod.rs`; 464/464
    `wxc_common` tests pass, including the full matrix above.**
- **Unit (non-Windows, run in Linux/macOS CI jobs)**:
  - `consent::read()` compiles to the stub and returns `NotApplicable`
    without creating any file or directory.
  - `is_enabled()` remains `false` unconditionally, matching today's
    behavior.
  - **Status: covered by the same cross-platform test module (the stub path
    compiles and is exercised via `cfg`-gated assertions); full behavioral
    verification on non-Windows hosts is deferred to the Linux/macOS CI
    matrix, which already runs `cargo test --workspace`.**
- **CLI smoke test** (`tests/scripts/run_telemetry_consent_smoke_test.ps1`,
  Windows): round-trip `--telemetry-consent-grant` →
  `--telemetry-consent-status` → `--telemetry-consent-revoke` →
  `--telemetry-consent-status`, asserting the JSON output at each step;
  verify the file lands under the isolated store directory.
  - Isolation uses the debug-only `MXC_TEST_LOCALAPPDATA_OVERRIDE` env var,
    not `LOCALAPPDATA` (production never reads `LOCALAPPDATA` — it resolves
    the known folder directly, so that an attacker who can set an env var
    cannot redirect the consent store). The script therefore refuses to run
    against a release binary, and fails loudly if the first write does not
    land under the temp directory.
  - **Status: implemented and passing** (also verified the mutual-exclusion
    rejection of `--telemetry-consent-grant` + `--telemetry-consent-revoke`).
- **SDK unit tests**: `sdk/node/tests/unit/telemetry.test.ts` mocking the
  child-process call; assert `needsTelemetryConsentPrompt()` is always
  `false` when `platform.ts` reports non-Windows, without invoking the
  binary at all.
  - Also asserts, per non-Windows platform, that `getTelemetryConsent()`
    returns `not-applicable`, `needsTelemetryConsentPrompt()` is `false`, and
    `setTelemetryConsent()` throws — all *without* the injected runner ever
    being called, so a runner failure can never be mistaken for
    `undetermined` off Windows.
  - **Status: implemented (21 tests), wired into `npm run test:unit`; full
    213-test Node suite passes.**
- **C# tests**: round-trip Get/SetConsent against the real `mxc_ffi`
  build, matching the existing `Microsoft.Mxc.Sdk.Tests` pattern.
  - The fixture redirects the store via `MXC_TEST_LOCALAPPDATA_OVERRIDE` and
    then *verifies* the redirect took effect with two read-only probes
    (write `granted` to the temp store, expect `Granted`; write `denied`,
    expect `Denied` — the real store cannot be both), failing loudly rather
    than silently mutating the real per-user consent file when the native
    library under test is a release build.
  - **Status: implemented in `MxcTelemetryTests.cs` (9 tests, including the
    native-load-failure classification matrix); full 14-test C# suite passes.**
- **Regression**: existing `28_telemetry_enabled.json` example continues to
  document the config field; add a note (or a second example) showing that
  the field alone, without persisted consent, produces no telemetry.
  - **Status: not yet done — tracked as a follow-up.**

### Test isolation conventions

Two process-global resources back the Windows tests — the consent store
directory (`MXC_TEST_LOCALAPPDATA_OVERRIDE`) and the policy key
(`MXC_TEST_POLICY_KEY_OVERRIDE`). Each is guarded by its own mutex, so a
test that needs both can deadlock against a test that takes them in the
opposite order.

- **`telemetry::test_support::TelemetryTestEnv`** is the only sanctioned way
  to hold both. It acquires the policy guard first and the consent guard
  second, and its fields are declared so that Rust's declaration-order drop
  releases them in exactly the reverse order. Never construct
  `PolicyKeyGuard` and `LocalAppDataGuard` directly in the same test.
- Any test that reads consent or policy state must hold the corresponding
  guard, even if it "only reads" — otherwise it reads the real machine's
  state and is non-deterministic on a managed device.
- The `wxc_common` **`test-support`** cargo feature re-exports
  `telemetry::policy::test_support` outside the crate's own `cfg(test)`
  build, so downstream crates (`mxc_ffi`) can drive the policy override from
  their integration tests. It is a dev-dependency-only feature; nothing in a
  shipping build enables it, and the override itself remains
  `cfg(any(test, debug_assertions))`-gated regardless.
- Both overrides are gated on `cfg(any(test, debug_assertions))`, not
  `cfg(debug_assertions)` alone. `cfg(test)` is what keeps them present under
  `cargo test --release`, which is the only way CI runs tests — a
  `debug_assertions`-only gate would silently drop every consent and policy
  test from CI *and* leave them reading and overwriting the developer's real
  consent store and the real machine policy. Neither condition holds for a
  binary MXC ships (not compiled with `--test`, `debug_assertions` off), so
  a release `wxc-exec.exe` still resolves only the real known-folder store
  and the real `HKLM` policy key.

## 11. Explicitly out of scope for this spec

- Any UI/prompt widget shipped by MXC itself — the SDKs stay UI-agnostic;
  hosting agents own presentation.
- Any administrative policy that could *grant* consent on a user's behalf.
  MXC now honors a machine-wide administrative policy, but strictly as a
  deny-only ceiling (see §12.1 and [`telemetry-policy.md`](telemetry-policy.md));
  no policy value causes collection to begin without the user's own decision.
- Reading Windows' own diagnostic-data consent or the Windows
  `AllowTelemetry` policy. Permanently out of scope: Microsoft documents that
  the Windows policy "doesn't apply to any additional apps installed by your
  organization", and the supported OS evaluation APIs deliberately fold in the
  user's Settings-app choice, which MXC must not consume.
- Any change to the *content* of `MXC.Execution` / `MXC.Error` events —
  this spec only changes the gate in front of the existing, already
  PII-reviewed schema.
- Linux/macOS telemetry of any kind — explicitly and permanently not a goal.

## 12. Resolved decisions

All questions raised for review have been decided. Recorded here so the
rationale survives, and so a future change knows what it would be
reversing.

### Governing rule: policy may restrict, never substitute for, consent

Stated first because it governs every numbered decision below. This is a
ratified product rule, not an inference from external guidance.

An administrative policy is a deny-only ceiling: it can subtract from what a
user permitted, never add to it. An administrator cannot opt a user in.
Concretely, **if the user has opted out and the policy permits collection, the
result is opt-out.**

The full consent × policy matrix, all of which is enforced by the single
conjunction in `wxc_common::telemetry::is_enabled` and locked in by
`is_enabled_false_when_consent_denied_under_every_policy` and
`is_enabled_false_when_consent_undetermined_under_every_policy`:

| Consent \ Policy | absent (unrestricted) | `0` / `1` (blocked) | `3` (allowed) |
|---|---|---|---|
| Granted | **collect** | no | **collect** |
| Denied | no | no | **no** ← policy cannot opt the user back in |
| Undetermined | no | no | **no** ← policy is not a substitute for a decision |

Every cell that collects requires an explicit user grant. There is no policy
value, and no combination of policy and config, that produces collection
without one.

1. **Consent scope is per-user, permanently.** The store stays at
   `%LOCALAPPDATA%\mxc\telemetry-consent.json`. Consent is a property of the
   person whose data it is, not of the machine or the tenant, so there is no
   machine-wide way to record or override a *decision*, and each user of a
   shared machine decides independently.

   **Revised (superseding the original "no machine-wide override at all"):**
   an enterprise administrator *can* now prevent MXC from collecting on a
   device, via the `HKLM\SOFTWARE\Policies\Mxc\AllowTelemetry`
   policy. This does not weaken the guarantee the original decision was
   protecting, because the policy is **deny-only**: it can subtract from what
   a user permitted, never add to it. An administrator still cannot force
   telemetry on, and on an unmanaged/BYOD machine (no policy present) the
   behaviour is exactly as originally specified. See
   [`telemetry-policy.md`](telemetry-policy.md) for the full design and the
   reasoning for why an administrative "allow" is not consent.
2. **The policy key omits the `Microsoft` segment, on purpose.** The key is
   `HKLM\SOFTWARE\Policies\Mxc`, not `HKLM\SOFTWARE\Policies\Microsoft\Mxc`,
   even though MXC is a Microsoft product. Windows refuses to let an
   ADMX-ingested policy write under `System`, `Software\Microsoft`, or
   `Software\Policies\Microsoft`, except for a hardcoded allowlist (Office,
   Edge, OneDrive, VisualStudio, …). MXC is not on that list and cannot join
   it without a Windows servicing change, so a key under `Policies\Microsoft`
   would make `Mxc.admx` un-ingestible by Intune and every other MDM —
   leaving administrators with only scripts and Win32 packages.

   `SOFTWARE\Policies\<Vendor>` is the shape Microsoft's own ingestion
   documentation uses for third-party apps. Security is unaffected:
   `HKLM\SOFTWARE\Policies` is administrator/SYSTEM-write and user-read by
   default, and subkeys inherit that, so a standard user still cannot forge a
   permit. Note that `Software\Policies\Microsoft\VisualStudio` *is* on the
   allowlist — sibling Microsoft developer tools under `Policies\Microsoft`
   are there by explicit exemption, which is not a precedent MXC can inherit.

   This was settled before the first release precisely so that no deployed
   policy would ever have to be migrated. Moving the key now would be a
   breaking change to the administrator-facing contract.
3. **The CLI flags require neither elevation nor `--experimental`.**
   `--telemetry-consent-status` is read-only and informational;
   `--telemetry-consent-grant`/`-revoke` write only inside the invoking
   user's own `%LOCALAPPDATA%`. Withdrawing consent must never be harder
   than granting it, so neither may be gated behind relaunching elevated
   or passing an experimental flag.
4. **Flag naming is `--telemetry-consent-*`.** Ratified as shipped; it
   reads unambiguously alongside the existing `MXC_TELEMETRY` env var.
5. **`--telemetry-consent-status` carries `needsPrompt` and `policy`
   alongside `consent`.** The payload is not "just the state" — it is "the
   state, whether to prompt, and the administrative ceiling". Emitting the
   extra fields is what lets the prompt policy and the policy evaluation each
   have exactly one implementation (`ConsentState::needs_prompt`,
   `telemetry::policy::get_policy`) across Rust, C#, Node, and the CLI,
   rather than one copy per language. See §5.
6. **A blocking policy suppresses the consent prompt but preserves the
   recorded consent.** Asking a user to permit what an administrator has
   already refused is a meaningless question, so `needsPrompt` reports
   `false`. But the stored decision is left untouched, so relaxing the policy
   later restores the user's real choice instead of re-prompting them.

### Known gaps (tracked, deliberately not fixed here)

- `mxc_ffi` still duplicates `wxc_common`'s *consent* test harness:
  `wxc_common::telemetry::consent::test_support` remains `#[cfg(test)]
  pub(crate)` and so is not compiled into dependent crates. The *policy*
  harness is no longer duplicated — `telemetry::policy::test_support` is
  shared through the `test-support` cargo feature — and extending the same
  feature to cover the consent harness is the remaining work. Tracked as
  [#690](https://github.com/microsoft/mxc/issues/690).
- The consent CLI smoke test depends on `MXC_TEST_LOCALAPPDATA_OVERRIDE`
  and `MXC_TEST_POLICY_KEY_OVERRIDE`, which are compiled out of shipping
  builds. `wxc_common`'s own unit tests keep them via `cfg(test)` and so run
  under `cargo test --release`, but cross-crate consumers (`mxc_ffi`'s Rust
  tests, the C# and Node suites driving a native binary) only get them from a
  debug build, so their consent/policy coverage is debug-only. Tracked as
  [#691](https://github.com/microsoft/mxc/issues/691).


