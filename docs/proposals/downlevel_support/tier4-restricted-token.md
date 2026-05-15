# Tier 4 — `RestrictedTokenRunner`

**Status:** Proposed.
**Companion docs:** [`basecontainer-fallback-plan.md`][v1] (v1),
[`basecontainer-fallback-plan-v2.md`][v2] (v2),
[`basecontainer-fallback-plan-divergence.md`][divergence] (post-phase5
divergence analysis).

[v1]: ./basecontainer-fallback-plan.md
[v2]: ./basecontainer-fallback-plan-v2.md
[divergence]: ./basecontainer-fallback-plan-divergence.md

## TL;DR

A fourth tier under `ContainmentBackend::ProcessContainer`, used only as
the last-resort fallback when Tiers 1–3 are unavailable or unable to
honor the policy. The core primitive is a Win32 **restricted primary
token** (`CreateRestrictedToken`) plus **Low integrity** plus the
existing host-DACL plumbing (`DaclManager`) plus the existing UI Job
Object plus Win32k mitigation plus an optional builtin proxy. There is
no AppContainer SID, no capability scoping, no kernel-managed namespace
isolation, and no firewall-based network enforcement.

The single most important reason for adding Tier 4 is that **Tier 3
cannot enumerate or traverse a workspace** without ACLing every
ancestor up to the drive root — see [Motivation](#motivation). Tier 4
inherits ancestor traversal naturally because `Users` /
`Authenticated Users` remain in the restricting SID set.

## Motivation — the Tier 3 traversal problem

Real-world testing of Tier 3 (AppContainer + host DACL fallback)
exposed a fundamental gap that Tier 4 directly solves:

> ACLing a target path like `C:\workspace\proj` to grant the
> AppContainer SID `FILE_GENERIC_READ` works for code that *already
> holds the full path*, but breaks for any code that needs to walk
> into it.

Operations that fail under Tier 3 against a workspace at
`C:\workspace\proj`:

- `Get-ChildItem C:\workspace`
- `Set-Location C:\workspace\proj`
- `python -c "import os; os.listdir('C:\\workspace')"`
- `git status` from any cwd that requires walking up to find `.git`
- Resolving any relative path against an inherited cwd

All of these require **`FILE_TRAVERSE`** on every ancestor directory up
to the drive root. The default DACLs on `C:\` and `C:\workspace` grant
traverse to `Users` / `Authenticated Users` — **not** to AppContainer
SIDs. Honoring traversal under Tier 3 would require adding an ACE on
every parent up to the drive root, on every run, for every readwrite
and readonly path. That is not a sane production fallback. It changes
host security state in a way that's hard to clean up, races with other
processes that read DACLs on `C:\`, and is unsupported on enterprise
images where the caller does not have `WRITE_DAC` on `C:\`.

A restricted token does not have this problem **because the restricting
SID list still includes `Users` (or `Authenticated Users`)**. When the
kernel performs an access check on `C:\` for a restricted process, it
intersects the normal-token decision (allowed via `Users:RX`) with the
restricting-SID decision (also allowed via `Users:RX`, because `Users`
is in the restricting set). Traversal of system paths *just works*
with no manual ACL fixup. MXC then only needs to ACL the **leaf** paths
named in the policy (`readwritePaths` / `readonlyPaths` /
`deniedPaths`), exactly as before — and only those ACEs need to grant
access to the restricting principal.

This reframes the v1-vs-v2 question. v2's argument was "AppContainer is
universal on the floor, so falling below it gains nothing." The Tier 3
traversal failure shows that **AppContainer alone is not sufficient to
honor `readwritePaths` / `readonlyPaths` semantics on real codebases**
without either BFS (Tier 2, not always present) or kernel-managed paths
(Tier 1, not always available). Tier 4 is the answer for anything
below the cohorts where BFS or BaseContainer are present.

## Relationship to v1 and v2

- [**v1**][v1] places Tier 4 (`RestrictedToken`) at the bottom of a
  four-tier graceful-degradation ladder under `ProcessContainer`:

  ```
  Tier 1  BaseContainer            (Cohort B — GE/BR, experimental allowed)
  Tier 2  AppContainer + BFS       (Cohort C — GE/BR, experimental blocked)
  Tier 3  AppContainer + DACL      (Cohort A — pre-GE Win11)
  Tier 4  RestrictedToken          (anything below cohort A — no AppContainer)
  ```

  v1 itself flagged the open question: "Unclear whether Tier 4 is
  necessary at all."

- [**v2**][v2] explicitly removed Tier 4, citing "AppContainer is
  universally available on the supported floor [Win11 21H2]; falling
  below it provides little real isolation." v2 reframes the ladder as a
  three-tier cohort model and hard-fails below Tier 3.

- The [divergence analysis][divergence] records Tier 4 as dropped on
  **OS-version grounds**.

This proposal reopens Tier 4 on **functional grounds** that neither v1
nor v2 had data for at the time: the Tier 3 enumeration failure
documented above. The reopening is not a rejection of v2's security
analysis (which remains correct — Tier 4 buys little additional
isolation when AppContainer is available); it is a recognition that the
v2 cohort model leaves enumeration-heavy workloads with no working
fallback.

## When Tier 4 is selected

Per v1's detection logic (`fallback_detector.rs`):

```
1. BaseContainer API present?                       → Tier 1
2. bfscfg.exe present?                              → Tier 2
3. WRITE_DAC on policy paths AND allowDaclFallback? → Tier 3
4. (anything else)                                  → Tier 4
```

In addition to the bottom-of-ladder case, Tier 4 is the right choice
whenever any of:

- The workload is known to enumerate or traverse (the primary
  motivator). Today this is signalled implicitly: Tier 3 would refuse
  the run because ancestor paths require traversal that the
  AppContainer SID cannot satisfy without ancestor ACE injection.
- The caller does not own all parent directories (no `WRITE_DAC` on
  `C:\`), so even adding traverse ACEs is not an option.
- The caller sets `allowDaclFallback: false` but still wants to run.
- A SKU or future Windows variant where AppContainer profile creation
  is blocked or unavailable but `CreateRestrictedToken` still works.

## Architectural placement

**Tier 4 is not a peer top-level `ContainmentBackend` variant.** It is
a fallback *within* `ProcessContainer`, alongside the existing
AppContainer and BaseContainer paths. This matches v1 and v2's framing
and lets the existing `FallbackDetector` own tier selection rather than
pushing it up to the user's config.

Dispatch wiring in `src/wxc/src/main.rs` (using the phase5
`dispatch_with_fallback` surface):

```rust
ContainmentBackend::ProcessContainer => {
    match FallbackDetector::detect(&request.policy).0 {
        IsolationTier::BaseContainer    => /* phase5 — BaseContainer path */,
        IsolationTier::AppContainerBfs  => /* Tier 2 — TBD */,
        IsolationTier::AppContainerDacl => /* phase5 — AppContainer + DaclManager */,
        IsolationTier::RestrictedToken  => /* new — RestrictedTokenRunner + DaclManager */,
    }
}
```

If a deliberate, user-visible override is desired (e.g., for testing or
for callers who want to force Tier 4), expose it under
`experimental.restrictedTokenForced: bool` rather than as a top-level
backend value. This avoids polluting the public `containment` enum
with an internal fallback rung. The `MXC_FORCE_TIER` env-var seam
already exists in phase5; extending it to accept `restricted_token`
(or `t4`) suffices for tests.

## How Tier 4 differs from the existing runners

| Aspect | AppContainer | BaseContainer | RestrictedToken (Tier 4) |
|---|---|---|---|
| Core primitive | AppContainer SID + capability SIDs | OS sandbox spec (FlatBuffer) | Restricted token (`CreateRestrictedToken`) |
| Process API | `CreateProcessW` + `STARTUPINFOEXW` w/ `PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES` | `Experimental_CreateProcessInSandbox` (`processmodel.dll`) | `CreateProcessAsUserW` with restricted primary token |
| Filesystem isolation | BFS keyed on AppContainer name/SID | Spec field `fs_read_write` / `fs_read_only` | DACLs on **leaf paths only**, scoped to the restricting SID. Traversal works naturally because `Users` is in the restricting set — **no ancestor ACL fixup required**. Shared with Tier 3 via SID-parameterized `DaclManager`. |
| Network isolation | WFP firewall keyed on AppContainer SID; capability `internetClient` | Spec field `network_policy.proxy.url` | **Proxy only.** Firewall COM keyed to a non-AppContainer principal is not workable (per v1's matrix). |
| UI restrictions | `UiJobObject::set_ui_limits` | Spec `ui_restrictions` bitmask | `UiJobObject::set_ui_limits` (reused) |
| Win32k mitigation | `PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY` | Spec `disallow_win32k_system_calls` | `PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY` (reused) |
| Integrity level | Implicit (AppContainer is below Low) | Spec `integrity` field | Explicit: drop to **Low** via `SetTokenInformation(TokenIntegrityLevel, …)` |
| Availability gating | Win11 21H2+ | OS export probe | Universal — always callable on supported Windows |
| LPAC / least-privilege | Yes | Yes | **Rejected** — AppContainer-only construct |

## Token construction

The only genuinely new Win32 code in this runner is the construction
of the restricted primary token:

```text
OpenProcessToken(current_process, TOKEN_DUPLICATE | TOKEN_QUERY) → base
DuplicateTokenEx(base, …, TokenPrimary) → primary
CreateRestrictedToken(
    primary,
    DISABLE_MAX_PRIVILEGE,   // drops all privileges except SeChangeNotify
    sids_to_disable,         // empty initially; can grow if needed
    privileges = none,       // already covered by DISABLE_MAX_PRIVILEGE
    restricting_sids,        // see below — must include a Users-equivalent
    &restricted_token
)
SetTokenInformation(restricted_token, TokenIntegrityLevel, &low_il_tml, …)
```

### Restricting SID set — load-bearing for traversal

The restricting set must include a SID that the default DACLs on
system directories (`C:\`, `C:\Users`, `C:\Program Files`, etc.)
already grant `FILE_TRAVERSE` and `FILE_LIST_DIRECTORY` to. The
canonical set:

| SID | Role |
|---|---|
| `S-1-5-32-545` *Users* (Builtin\Users) | Grants traversal / listing of system dirs via default DACLs — **the fix for the Tier 3 problem** |
| `S-1-5-11` *Authenticated Users* | Same; additionally needed on some file shares and user-profile paths |
| `S-1-5-12` *Restricted Code* | Identifies this process as restricted; the SID we hand to `DaclManager` for leaf-path ACEs |
| `<LogonSid>` from `GetTokenInformation(TokenLogonSid)` | Per-session scoping; lets per-session resources (window stations, etc.) still resolve |

Dropping `Users` / `Authenticated Users` from this set reintroduces the
Tier 3 enumeration problem. Any change to the set must be guarded by
the named regression test `restricted_token_can_enumerate_workspace`.

### Integrity level

Default integrity level: **Low** (Chromium / IE Protected-Mode
precedent). Low IL must be paired with the broader restricting set
above — if we drop to Low *and* exclude `Users` / `Authenticated
Users`, mandatory-integrity checks on system directories will deny
traversal regardless of DACLs. The combination "Low IL +
`Users` in restricting set" is the one that delivers traversal without
granting write access.

A future `experimental.restrictedToken.integrity` knob could expose
`Medium` / `Untrusted`. Out of scope for this proposal.

## Policy enforcement matrix

Tier 4's `validate_runner` enforces:

| Policy field | Tier 4 behavior |
|---|---|
| `readwritePaths` / `readonlyPaths` | Honored via `DaclManager` ACEs on **leaf paths only**, granting the Restricted Code SID (`S-1-5-12`) the corresponding access. No ancestor ACEs. |
| `deniedPaths` | Honored via `DaclManager::add_deny_aces` against the Restricted Code SID. |
| `network.defaultPolicy` / `allowedHosts` / `blockedHosts` | **Proxy only.** Built-in test proxy supported via `ProxyCoordinator`. Firewall-based modes are rejected. |
| `network_enforcement_mode = Capabilities` or `Both` | **Accepted** but only the proxy honors the policy. The presence of capability-keyed enforcement is detected via `policy.capabilities` (see below); without capability SIDs there is nothing to key firewall rules to, so the mode field alone carries no enforcement intent. |
| `policy.ui.*` (clipboard, injection, desktop) | Honored via `UiJobObject::set_ui_limits` (same module as Tiers 1–3). |
| `policy.ui.disable` (Win32k lockdown) | Honored via `PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY` on `CreateProcessAsUserW`. |
| `policy.least_privilege_mode` (LPAC) | **Rejected** in `validate_runner`. LPAC is an AppContainer-only construct. |
| `policy.capabilities` (non-empty) | **Rejected** in `validate_runner`. Capability SIDs require an AppContainer principal. |

Rejections are surfaced as actionable errors that name Tier 4
explicitly, e.g. "Tier 4 rejects `leastPrivilegeMode = true`: LPAC is
an AppContainer-only construct."

## Caller privilege requirements (operational)

Tier 4 spawns the child via `CreateProcessAsUserW`, which requires
the **calling** process to hold `SeIncreaseQuotaPrivilege` (the
"Adjust memory quotas for a process" privilege; `0x80070522` /
`ERROR_PRIVILEGE_NOT_HELD` is raised when missing). On Windows
this privilege is granted by default to:

- Members of the Administrators group (elevated processes).
- Service identities: `LocalSystem`, `LocalService`, `NetworkService`.
- Users explicitly assigned the privilege via Local Security Policy.

Standard interactive users running an unelevated shell **do not**
have this privilege and Tier 4 spawn will fail at
`CreateProcessAsUserW`. This is the same elevation requirement as
Tier 1 (BaseContainer) and the path-augmentation half of Tier 3
(`DaclManager` write-DAC). Only Tier 2 (AppContainer + BFS) is
fully usable from a non-privileged shell.

`maybe_enable_quota_privilege()` in the runner attempts to enable
the privilege if it is present-but-disabled in the calling token
(a common case for elevated processes whose privileges are inactive
until `AdjustTokenPrivileges` is called). It is best-effort: if the
privilege is not present at all, the spawn fails with a clear error
message that names the missing privilege.

Switching to `CreateProcessWithTokenW` would relax the requirement
to `SeImpersonatePrivilege`, which standard interactive users also
do not have by default — so it is not a meaningful improvement
without a broker. A future iteration may introduce a small
elevated/service-context broker that fronts Tier 4 spawns for
unelevated callers; that is out of scope for this proposal.

## Threat model

### What Tier 4 enforces

- **Privilege drop.** `DISABLE_MAX_PRIVILEGE` strips all privileges
  except `SeChangeNotify` from the primary token.
- **Object access restriction.** The restricting SID set means access
  checks against any object (file, registry key, named pipe, etc.) are
  the intersection of the normal-token check and the restricting-SID
  check. Anything the user could access but `Users` / `Authenticated
  Users` / `Restricted Code` / `<LogonSid>` cannot is denied.
- **Mandatory integrity.** Low IL blocks writes to objects of Medium
  IL or higher, which covers most user-profile and system locations
  by default.
- **Filesystem policy.** `DaclManager` grants the Restricted Code SID
  exactly the access named in `readwritePaths` / `readonlyPaths` and
  applies deny ACEs for `deniedPaths`. Leaf-only — no ancestor
  mutation.
- **UI surface.** `UiJobObject` limits clipboard, window-handle access,
  desktop switching, etc.
- **Win32k surface.** `PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY` with
  `ProcessSystemCallDisablePolicy` blocks Win32k system calls when
  `policy.ui.disable` is set.
- **Network.** Optional builtin proxy via `ProxyCoordinator`. Outbound
  HTTP(S) traffic is forced through the proxy via env injection.

### What Tier 4 does **not** enforce

- **No kernel-managed namespace isolation.** Unlike BaseContainer, Tier
  4 shares the host's object namespace. Anything the restricting SID
  set can name and the host DACL grants, the process can reach.
- **No LPAC.** No capability-scoped access. No least-privilege user
  account.
- **No firewall-based network policy.** A non-AppContainer principal
  cannot cleanly key WFP rules; only the proxy path is supported.
- **No AppContainer profile per execution.** No automatic per-execution
  cleanup beyond the `DaclManager`'s crash-safe state file.
- **No write-protection on host trust boundaries beyond DACLs and
  integrity.** The standard "restricted token escape" caveats apply
  (registry, COM, mark-of-the-web, etc.). Tier 4 is a defense-in-depth
  fallback, not a substitute for AppContainer or kernel containment.

### Comparison with the v2 trade-off

v2's argument — that AppContainer is universal on the floor and Tier 4
buys little additional isolation when AppContainer is available — is
correct and remains the design's stance. Tier 4 is selected **only**
when AppContainer (Tier 2/3) is either unavailable or unable to honor
the policy. The motivation here is functional coverage of policy
fields, not stronger isolation than AppContainer.

## Reuse map

Almost everything Tier 4 needs already exists in the phase5 branch
(`origin/user/gudge/downlevel_phase5`).

| Component | Source | How Tier 4 uses it |
|---|---|---|
| `ScriptRunner` trait | `script_runner.rs` | Implement directly |
| `OwnedHandle`, `SidAndAttributes` | `process_util.rs` | RAII for `HANDLE`s; layout for `CreateRestrictedToken` argument arrays |
| `UiJobObject` + `ui_policy::resolve_ui_restrictions` | `job_object.rs` + `ui_policy.rs` | Same job-assignment pattern as `appcontainer_runner.rs` |
| `process_mitigation::win32k_disable_value` | `process_mitigation.rs` | Same `PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY` site |
| `string_util::{to_wide, sid_to_string}` | existing | Wide-string + SID formatting |
| `proxy_coordinator::ProxyCoordinator` | existing | Builtin test proxy |
| `validator::validate_common` | existing | Via the `ScriptRunner::run` default |
| `build_proxy_env_block` | currently inside `appcontainer_runner.rs`, **needs lift** | Move to shared module; both AppContainer and Tier 4 use it |
| Attribute-list scaffolding | pattern in `appcontainer_runner.rs` | Reuse pattern; drop SECURITY_CAPABILITIES and LPAC entries |
| `CREATE_SUSPENDED` → assign job → `ResumeThread` ordering | pattern in `appcontainer_runner.rs` | Reuse verbatim |
| `DaclManager` (phase5 `filesystem_dacl.rs`) | phase5 | Reuse with the Restricted Code SID. Rename `grant_appcontainer_access` → `grant_principal_access`. |
| `FallbackDetector` (phase5) | phase5 | Selects Tier 4 once the new variant is added |
| `dispatcher::dispatch_with_fallback` (phase5) | phase5 | Add a `RestrictedToken` arm |
| `OwnedSid` | phase5 `filesystem_dacl.rs` | Reuse for the restricting / principal SIDs |

### What does **not** apply

- `CreateAppContainerProfile` / `DeriveAppContainerSidFromAppContainerName`
- Capability SIDs (`get_capability_sid_from_name`)
- `PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES`
- `PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY` (LPAC)
- `FileSystemBfsManager` (BFS is AppContainer-keyed)
- `NetworkManager`'s firewall path (no AppContainer principal)
- `processmodel.dll` / FlatBuffer `SandboxSpec`

## Implementation plan

Base branch: `origin/user/gudge/downlevel_phase5`. That branch provides
the Tier 2/3 infrastructure this work depends on:
`filesystem_dacl::DaclManager` (SID-parameterized in practice,
crash-safe side-file + orphan recovery + per-path mutex),
`fallback_detector` (3-tier enum + `MXC_FORCE_TIER` debug seam),
`dispatcher::dispatch_with_fallback` (already wired into
`wxc/main.rs`, with documented Drop ordering),
`appcontainer_runner::FilesystemMode` (opt-out for in-runner filesystem
so the dispatcher can own DACLs), `probe.rs`, and an `OwnedSid` RAII
wrapper.

Six phases, ordered to deliver a working, testable runner as early as
possible (Phase 1 spawns under a real restricted token), then layer
policy enforcement on top. Each phase is independently mergeable.

### Phase 0 — Prep on top of phase5

- Lift `build_proxy_env_block` from `appcontainer_runner.rs` into a
  shared module (`process_util.rs` or new `child_env.rs`). Update
  `AppContainerScriptRunner` to call the shared copy.
- Rename `DaclManager::grant_appcontainer_access` →
  `grant_principal_access`; rename the `appcontainer_sid_str`
  parameter to `principal_sid_str`. The parameter is already a SID
  string (tests already exercise it with `S-1-1-0`). Update doc
  comments to state the **leaf-only** contract.
- Optional: move `OwnedSid` out of `filesystem_dacl.rs` into
  `process_util.rs` so the token-construction code can use it without
  pulling in the DACL module.

Exit criteria: phase5 tests still pass; no behavior change.

### Phase 1 — Skeleton + token construction + happy-path spawn

- New module `src/wxc_common/src/restricted_token_runner.rs`, declared
  in `lib.rs` behind `#[cfg(target_os = "windows")]`.
- Implement `build_restricted_token` (see [Token
  construction](#token-construction)).
- Implement `RestrictedTokenRunner::execute` with `CreateProcessAsUserW`
  + `CREATE_SUSPENDED` + `ResumeThread` + `WaitForSingleObject` +
  `GetExitCodeProcess`. No UI/Win32k/proxy yet.
- Implement `ScriptRunner::validate_runner` with all rejections from
  the policy enforcement matrix.
- Extend the `MXC_FORCE_TIER` seam to accept `restricted_token` /
  `t4`.
- Unit tests:
  - `build_restricted_token_drops_privileges`
  - `build_restricted_token_sets_low_integrity`
- Smoke test config: `test_configs/restricted_token_hello.json`.

Exit criteria: with `MXC_FORCE_TIER=t4`, the smoke config exits 42
with `"hello"` on stdout.

### Phase 2 — UI Job Object + Win32k mitigation

- Add attribute-list scaffolding for
  `PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY` when `policy.ui.disable`.
- Adapt the `CREATE_SUSPENDED` → assign `UiJobObject` →
  `ResumeThread` sequence from `AppContainerScriptRunner`.
- Reuse `ui_policy::resolve_ui_restrictions` and
  `process_mitigation::win32k_disable_value`.
- Unit tests:
  - `restricted_token_blocks_win32k_when_ui_disabled`
  - `restricted_token_is_in_ui_job_object` (`IsProcessInJob`)
- Test config: `test_configs/restricted_token_ui_blocked.json`.

### Phase 3 — Proxy + environment injection

- Add `ProxyCoordinator` field to `RestrictedTokenRunner`.
- On `execute`: optional `launch_test_proxy` (mirrors
  `BaseContainerRunner`); on success, inject `HTTP_PROXY` /
  `HTTPS_PROXY` via the lifted `build_proxy_env_block`; pass
  `CREATE_UNICODE_ENVIRONMENT` and the env block to
  `CreateProcessAsUserW`.
- On exit, `proxy_coordinator.stop`.
- Test config: `test_configs/restricted_token_proxy.json`.

### Phase 4 — Wire into the dispatcher + DACLs

- `fallback_detector.rs`:
  - Add `IsolationTier::RestrictedToken` variant.
  - Extend `detect` to select Tier 4 when (a) the existing detector
    would refuse the run because of `WriteDacUnavailable` on ancestor
    paths (the Tier 3 enumeration failure), or (b) the
    `MXC_FORCE_TIER` seam picks it.
  - Extend `TierDecision` warnings to explain why Tier 4 was chosen
    over Tier 3.
- `dispatcher.rs`:
  - Add a `RestrictedToken` arm:
    - Construct `RestrictedTokenRunner::new()`.
    - Construct `DaclManager::new()`; call `grant_principal_access`
      with the **Restricted Code SID** (`S-1-5-12`) — the SID baked
      into the token by `CreateRestrictedToken` — over the policy's
      readwrite / readonly leaves. `add_deny_aces` for `deniedPaths`.
    - Return `Dispatched { runner, dacl_manager: Some(_), tier:
      RestrictedToken, warnings }`.
  - Existing Drop-ordering contract handles cleanup.
- Tests:
  - `restricted_token_can_read_dacl_scoped_path`
  - `restricted_token_cannot_read_unscoped_path`
  - `restricted_token_can_write_readwrite_path`
  - `restricted_token_cannot_write_readonly_path`
  - **`restricted_token_can_enumerate_workspace`** — the named
    regression for Tier 3's failure mode. Create
    `C:\<tempws>\sub\file.txt`, ACL *only* `C:\<tempws>` for the
    Restricted Code SID (no ACEs on `C:\`), spawn `cmd /c dir
    C:\<tempws>` under Tier 4, assert exit 0 and `sub` in stdout.
  - `dispatch_t4_with_denied_paths_has_dacl`
- Test configs:
  - `test_configs/restricted_token_filesystem.json`
  - `test_configs/restricted_token_enumeration.json`

Exit criteria: enumeration regression passes; Tier 4 selectable via
`MXC_FORCE_TIER` and via natural fallback when Tier 3 would fail.

### Phase 5 — Schema, docs, telemetry, polish

- Schema: no `containment` enum addition. Optional config knob under
  `experimental.*` for a user-visible forcing override.
- Update v2 and the divergence-analysis doc with a "Reopened — see
  `tier4-restricted-token.md`" note.
- `.github/copilot-instructions.md`: row added to the containment
  backends table.
- Telemetry: emit `tier_selected = RestrictedToken` event from the
  dispatcher's Tier 4 arm.
- E2E coverage in `wxc_e2e_tests` driving Tier 4 via `MXC_FORCE_TIER`.

### Phase dependency graph

```
phase5 (base) ─► Phase 0 (prep) ─► Phase 1 (skeleton + token) ─┬─► Phase 2 (UI/Win32k)
                                                               ├─► Phase 3 (proxy)
                                                               └─► Phase 4 (DACL + dispatcher) ─► Phase 5 (docs/E2E)
```

Phases 2, 3, 4 are independent after Phase 1 lands.

### Rebase risk on phase5

Low. The surface this plan depends on is small and additive:

- `IsolationTier` enum: adding a variant.
- `DaclManager` API: relying on the existing string-SID parameter
  (already public contract via tests) and existing
  `grant_*` / `add_deny_aces` / `restore` methods.
- `dispatcher.rs`: adding a match arm.
- `appcontainer_runner::FilesystemMode`: read-only consumer.

Main downside: phase5 hasn't merged to `main` yet. Tier 4 will land
either as a stacked PR after phase5 merges, or as a branch off phase5
that the same author keeps rebased while the phase5 PR is reviewed.

## Open design questions

1. **User-visible override knob, or detector-only?** Recommended:
   detector-only for end users; expose a forcing knob under
   `experimental.*` for tests and downlevel validation.
2. **Reject vs warn-and-ignore for non-applicable policy fields**
   (`leastPrivilegeMode`, `capabilities`, firewall network modes)?
   Recommended: reject in `validate_runner`, with a clear error that
   names the tier. Silent degradation hides security gaps from callers.
3. **Default integrity level**: Low (recommended) vs Medium. Low
   matches Chromium / IE Protected-Mode precedent. Medium reduces
   compat surprises but weakens the isolation story noticeably. Pick
   Low for v1; add a knob later.
4. **Restricting-SID set composition.** Must include a SID that
   ancestor system DACLs already grant traversal to (`Users` and/or
   `Authenticated Users`) — otherwise we reintroduce the Tier 3
   enumeration problem. Recommendation: `[Users, AuthenticatedUsers,
   RestrictedCode, LogonSid]`. Guard with the
   `restricted_token_can_enumerate_workspace` regression test.
5. **Logon-SID lifetime.** The per-session logon SID changes across
   sign-outs. Acceptable for a single-execution runner; document so a
   future state-aware variant does not get tripped up.
