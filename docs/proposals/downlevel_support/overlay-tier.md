# `filesystem_overlay` — ProjFS-based filesystem-policy enforcer for MXC

Status: **Phase D-1 landed; D-2 (runner wiring) pending.**
Branch: `user/gudge/downlevel_projfs_and_bindflt`.

This is the design + empirical-findings doc for the `filesystem_overlay`
sub-module under `src/wxc_common/src/filesystem_overlay/`. It captures
the reasoning behind a series of pivots the design went through during
implementation — not just the final shape — so future readers can see
why the obvious-sounding earlier designs were rejected.

For the empirical foundation that motivated this work, see:

- [`projfs-t3-spike-step1.md`](./projfs-t3-spike-step1.md) — proves the
  ProjFS plumbing works (provider callbacks fire from an AC).
- [`projfs-t3-spike-step2.md`](./projfs-t3-spike-step2.md) — proves the
  semantics (8/8 matrix cells green, host ACLs unchanged,
  reparse-point refusal, Deny-ACE-for-AC-SID empirical matrix).
- [`projfs-t3-spike-step3.md`](./projfs-t3-spike-step3.md) — the
  recommendation that turned into the work tracked here, plus the
  placeholder-DACL fix that closed the RO-create regression cell.

## 0. Terminology — three independent OS mechanisms

These get conflated easily and I conflated them at least once early in
the design. They are *not* the same thing:

| Mechanism | Driver / API | Role in MXC |
|---|---|---|
| **DACL** | Win32 security APIs (`SetNamedSecurityInfoW`, `SetEntriesInAclW`) | `filesystem_dacl.rs` — grants the AC SID rights on host paths; adds deny ACEs. Mutates host filesystem state. |
| **BFS** (Brokered File System) | `bfs.sys` + the `bfscfg.exe` broker | `filesystem_bfs.rs` — per-AC allow-list of paths via the brokered tool. **Unrelated to BindFlt** (different driver, different broker). |
| **BindFlt** (Bind Filter) | `bindflt.sys` + `bindfltapi.dll` (`BfSetupFilter` / `CreateBindLink`) | Used by Windows containers for namespace bind-mounts. Not in MXC today. |
| **UnionFS** | `UnionFS.sys` + `UnionFSApi.dll` (`CreateFileSystemUnion`) | Layered filesystem for containers; supports first-class tombstones. Not in MXC today. |
| **WCIFS** | `wcifs.sys` + `wci.dll` | Windows Container Isolation File System; reparse-point-based layered FS. Not in MXC today. |
| **ProjFS** (Projected File System) | `prjflt.sys` + `ProjectedFSLib.dll` (`Prj*`) | User-mode-driven filesystem virtualization. Was a `mxc.green` spike (`user/gudge/projfs_t3_spike`); now production via `filesystem_overlay`. |

## 1. Goal and scope

**Goal.** Add an enforcer that satisfies the existing `ContainerPolicy`
(`readwrite_paths`, `readonly_paths`, `denied_paths`) **without
mutating host DACLs**, as an additive choice alongside the existing
`filesystem_dacl`.

**Scope constraints:**

- **AppContainer is the container.** No Silo / no AppSilo.
- **`filesystem_dacl.rs` is not replaced.** It stays as the canonical
  T3 DACL enforcer and the T1 `denied_paths` augmentor. The overlay
  tier is **additive**, selected only when the user opts in.
- The dispatcher's existing AppContainerBfs and AppContainerDacl tiers
  remain selectable.

**What problems the new tier solves vs DACL-T3:**

- The `microsoft/mxc#304` ancestor-traverse pain — `FindFirstFile`
  blocked inside an AC, requiring admin priming of `ALL APPLICATION
  PACKAGES:(X)` on `C:\` and `C:\Users\`. The overlay tier sidesteps
  this entirely because the projection root lives inside the AC
  profile.
- Host ACL flicker — DACL-T3 mutates host paths transiently. The
  overlay tier never touches host DACLs.
- `WRITE_DAC` prerequisite — DACL-T3 fails when the launching user
  doesn't hold `WRITE_DAC` on policy paths. The overlay tier doesn't
  need it.
- TOCTOU between ACL apply and process-create — eliminated, because
  there is no apply step on host paths.
- `SetNamedSecurityInfoW` walk perf cost — ~800 ms cold on a 332k-file
  tree per spike measurements; eliminated.
- AAP-grant gap in `add_deny_aces` — Deny ACEs for an AC SID do *not*
  override an inherited `ALL APPLICATION PACKAGES` grant on a regular
  AC (spike step 2 (7/N)). The overlay tier's structural denies don't
  inherit anything, so the gap doesn't apply.

## 2. The architectural pivots — why the design landed where it did

The design went through three significant pivots during implementation.
Documenting them here so the surprises don't have to be relearned.

### 2.1 Pivot 1 — "ProjFS + BindFlt" → "BindFlt is admin-only"

**Initial design.** Two primitives, layered per policy entry: ProjFS
for broad-RO roots (where the AC's LowBox token has no implicit read
on the host path), BindFlt for narrow RW paths and tombstones (where
path identity matters and the AC has natural access).

**Empirical finding (Phase B-1, commit `369b797`).** Both the public
`CreateBindLink` API (gated `NTDDI_WIN10_CU+`) and the internal
`BfSetupFilter` / `BfSetupFilterEx` family return
`HRESULT 0x80070005 (E_ACCESSDENIED)` for non-admin users on Win11
25H2 (build 26200), regardless of whether a `JobHandle` is supplied.
The BindFlt kernel filter enforces an admin check at the filter-
manager layer before honoring any namespace-mapping call.

**Generalisation.** Subsequent probing of `UnionFSApi.dll::CreateFileSystemUnion`
returned the same `E_ACCESSDENIED` for non-admin. WCIFS is in the same
container-infrastructure family; not separately probed but it sits on
the same gate. The pattern is:

> Any Windows kernel-filter-based filesystem namespace remapping
> requires admin. ProjFS escapes this only because its projection root
> must live in a directory the calling user already owns — which is
> also why ProjFS doesn't preserve host path identity.

**Consequence.** BindFlt remains in tree as FFI scaffolding
(`filesystem_overlay::bindflt`) but the production path is **ProjFS-only**.
The FFI surface is a starting point for any future broker-mediated
elevation work, but no current selection path emits BindFlt primitives.

### 2.2 Pivot 2 — "ProjFS RO-only" → "ProjFS RO + RW with writeback"

**Brief intermediate position.** When pivot 1 happened, I briefly
adopted "ProjFS handles RO, BindFlt handles RW" with the idea that RW
through BindFlt would later become admin-required. That was incoherent
once BindFlt was off the menu entirely.

**Current rule.** ProjFS RO branches enforce read-only via
`PRJ_NOTIFY_FILE_PRE_CONVERT_TO_FULL` veto + placeholder DACL
(blocks new-file creation in RO). ProjFS RW branches let writes
through to the hydrated full file, and sync the modified file back to
the host backing on close via `PRJ_NOTIFY_FILE_HANDLE_CLOSED_FILE_MODIFIED`
(Phase A.5, commit `433a404`).

### 2.3 Pivot 3 — accepting path-identity loss

**The constraint.** ProjFS projects content but does **not** preserve
host path identity. `c:\etc\src\git\myrepo` on the host appears inside
the AC at `%LOCALAPPDATA%\Packages\<ac-profile>\AC\<projection-root>\myrepo`
— content visible, path remapped. BindFlt would preserve identity but
requires admin.

**Decision.** Accept the remapping. The runner injects
`MXC_POLICY_ROOT` into the AC's environment so agent scripts can
discover the projection root. Most agent workloads (`git`, `cargo`,
`cmake`) work from cwd via relative paths and tolerate this; tools
that hardcode absolute host paths don't, and that is a documented
limitation of the non-admin path.

## 3. Per-policy-entry rules (current)

For each entry in the policy, the classifier (`policy::classify`)
emits:

| Policy entry | Primitive | Why |
|---|---|---|
| `readonly_paths` entry | `OverlayPrimitive::ProjFsBranch { mode: ReadOnly, … }` | AC's LowBox token has no implicit read on arbitrary host paths. ProjFS placeholder DACL evaluates against the AC SID directly. |
| `readwrite_paths` entry | `OverlayPrimitive::ProjFsBranch { mode: ReadWrite, … }` | Same LowBox-sidestep rationale. Writes hydrate the placeholder and sync to host backing on close. |
| `denied_paths` entry inside a projected branch | Branch's `deny_subpaths` field | Structural deny: enumeration filters the entry out; `cb_get_placeholder_info` returns `ERROR_FILE_NOT_FOUND`. Zero cost beyond a path-prefix check per callback. |
| `denied_paths` entry outside any projected branch | (no primitive) | The projection root has only the policy's projected entries — anything not in policy is structurally invisible. |

**Composition limitation (Phase C-2 follow-up).** Nested rw/ro pairs
(e.g. `readonly: C:\Users\u` + `readwrite: C:\Users\u\scratch`) are
**rejected** by the classifier with a clear `OverlayError::Classify`
message. The composition requires multi-branch path resolution in the
provider state which hasn't been built yet.

**The dominant policy shape** (broad RO of `C:` + narrow RW under
`%USERPROFILE%` + narrow deny inside `%USERPROFILE%`) currently runs
into this limitation because broad-RO `C:\` overlaps with narrow-RW
`%USERPROFILE%\*`. The Phase C-2 follow-up is required before this
shape works.

## 4. Module structure (current — as committed)

```
src/wxc_common/src/
    filesystem_dacl.rs              ← unchanged (DACL)
    filesystem_bfs.rs               ← unchanged (BFS, bfscfg.exe — a separate mechanism)
    fallback_detector.rs            ← extended: AppContainerOverlay tier
    filesystem_overlay/
        mod.rs                      ← OverlayManager (mirrors DaclManager shape)
        policy.rs                   ← classify(): ContainerPolicy → OverlayPlan
        plan.rs                     ← OverlayPlan / OverlayPrimitive / BranchMode
        error.rs                    ← OverlayError + MxcErrorCode mapping
        handle.rs                   ← OverlayHandle returned to the runner
        state.rs                    ← StateFile / AppliedRecord / write+read+process-liveness
        recovery.rs                 ← recover_orphaned_state at startup
        test_support.rs             ← env_lock() mutex + ScopedStateDir for parallel test safety
        projfs/
            mod.rs                  ← apply_branches / restore lifecycle
            virt.rs                 ← five callbacks + notification + writeback (promoted from spike)
            feature_detect.rs       ← Client-ProjFS state probe
        bindflt/
            mod.rs                  ← apply_mapping / restore_mapping (deferred; admin-required)
            api.rs                  ← bindfltapi.dll FFI via LoadLibraryExW
            mapping.rs              ← apply_ro_overlay / apply_rw_overlay / restore
            feature_detect.rs       ← bindfltapi.dll availability probe
```

`OverlayManager` parallels `DaclManager`:

```rust
pub struct OverlayManager { /* run_id, state_path, … */ }

impl OverlayManager {
    pub fn new() -> Result<Self, OverlayError>;
    pub fn apply_policy(
        &mut self,
        appcontainer_sid_str: &str,
        policy: &ContainerPolicy,
    ) -> Result<OverlayHandle, OverlayError>;
    pub fn restore(&mut self) -> Result<(), OverlayError>;
    pub fn warnings(&self) -> &[String];
}
impl Drop for OverlayManager { /* best-effort restore */ }

pub fn recover_orphaned_state() -> Result<RecoveryReport, OverlayError>;

pub struct OverlayHandle {
    pub effective_cwd: Option<PathBuf>,
    pub env_injections: Vec<(String, OsString)>,
    pub plan_summary: OverlayPlanSummary,
}
```

### Crash safety

Mirrors `DaclManager`:

1. **Persist before apply.** Each primitive's intent lands on disk in
   `<state_dir>/<run-id>.json` *before* the underlying ProjFS call.
   Atomic write via staged `.tmp` + `MoveFileExW(MOVEFILE_REPLACE_EXISTING)`.
2. **PID + FILETIME orphan check.** The state file records the
   owning process's PID and creation FILETIME. Recovery considers a
   state file orphaned only when the PID is dead OR the live PID's
   FILETIME differs (defeats PID reuse).
3. **Quarantine.** Unparseable state files are renamed to
   `<file>.json.corrupt` so they don't trip the same parse error on
   every startup.
4. **Best-effort `Drop`.** Errors swallowed and logged; entries that
   fail to restore stay on disk for the next startup's recovery pass.

State directory: `%LOCALAPPDATA%\Microsoft\MXC\overlay-state\`
(overridable via `MXC_OVERLAY_STATE_DIR`).

## 5. Selection: `fallback_detector` extension

### 5.1 New tier

```rust
pub enum IsolationTier {
    BaseContainer,
    AppContainerBfs,        // existing (BFS via bfscfg.exe — unrelated to BindFlt)
    AppContainerOverlay,    // NEW (Phase D-1)
    AppContainerDacl,       // existing
}
```

### 5.2 Selection logic

After the existing `BaseContainer` probe, before falling through to
BFS / DACL:

```text
overlay_mode = experimental.filesystem_overlay.mode (default Off)
match overlay_mode:
    Off  -> skip overlay entirely; fall through to BFS/DACL
    On   -> require Client-ProjFS enabled AND policy has rw/ro paths;
            on failure, return FallbackError::OverlayUnavailable
    Auto -> select overlay if Client-ProjFS enabled AND policy has rw/ro;
            otherwise log a warning and fall through to BFS/DACL
```

Overlay decisions set `needs_dacl_augmentation = false` — overlay
never mutates host DACLs, even with `denied_paths` (handled structurally).

### 5.3 Config surface

`experimental.filesystem_overlay` in `schemas/dev/mxc-config.schema.0.6.0-dev.json`:

```jsonc
{
  "experimental": {
    "filesystem_overlay": {
      "mode": "off" | "auto" | "on",            // default "off"
      "writeIsolation": "passthrough" | "private"  // default "passthrough"
    }
  }
}
```

- `mode = "off"` (default): preserve existing behaviour; overlay never selected.
- `mode = "auto"`: detector decides per §5.2.
- `mode = "on"`: force overlay; typed error if unavailable.
- `writeIsolation`: currently advisory — `"passthrough"` is the only
  implemented behaviour (writes propagate to host backing on close).
  `"private"` requires the BindFlt RW overlay path, which is deferred
  until admin elevation is solved.

## 6. Key empirical findings (the receipts)

These are the discoveries that drove the pivots above. Documented here
because they're easy to forget and re-discover.

### 6.1 ProjFS into AC: 8/8 spike-matrix cells reproduce

Phase 0.1 (commit `ea3aaa4`) reproduced the spike's matrix on the
current `mxc.yellow` tree. Win11 25H2 (build 26200), non-admin user,
host ACLs byte-identical before vs after. Confirms nothing
bit-rotted in the spike code during the port.

### 6.2 BindFlt requires admin — confirmed on all entry points

Win11 25H2 (build 26200), non-admin user shell:

| Call | Result |
|---|---|
| `CreateBindLink(virt, host, flags=NONE, 0, NULL)` | `HRESULT 0x80070005` |
| `CreateBindLink(virt, host, flags=READ_ONLY, 0, NULL)` | `HRESULT 0x80070005` |
| `BfSetupFilter(NULL_jobhandle, flags=0, virt, host, NULL, 0)` | `HRESULT 0x80070005` |
| `BfSetupFilter(non_admin_created_jobhandle, …)` | `HRESULT 0x80070005` |

The DLL loads and all exports resolve; the kernel filter rejects the
mapping call at the filter-manager layer.

### 6.3 UnionFS requires admin — confirmed on `CreateFileSystemUnion`

Same probe shape as BindFlt. `CreateFileSystemUnion(union_id, layers, 2, 0, NULL, NULL)`
returns `HRESULT 0x80070005` from a non-admin shell.

### 6.4 ProjFS suppresses notification callbacks for the provider's own process

Discovered while writing the Phase A.5 writeback e2e test. The test
process IS the provider (it owns the virt session created by
`PrjStartVirtualizing`). Writes from the test process via
`std::fs::write` do NOT trigger `cb_notification` —
`FILE_HANDLE_CLOSED_FILE_MODIFIED` is silent for the provider's own
writes. Re-implementing the writer to spawn a `powershell.exe` child
process (which is a different process from the provider) makes the
notification fire correctly.

**Implication for production:** the AC is necessarily a child process
of the provider (`wxc-exec`), so this suppression doesn't affect
production behaviour — but it does affect how tests exercise the
writeback path.

### 6.5 ProjFS does not preserve host path identity

The projection root must live in a directory the calling user owns
(per ProjFS's design). For an AppContainer, that means inside the AC
profile folder. So `c:\etc\src\git\myrepo` on the host appears at
something like `%LOCALAPPDATA%\Packages\<ac>\AC\<projection-id>\myrepo`
inside the AC — content visible, path remapped.

This is what makes ProjFS work without admin, but it also means
absolute-path-aware agent code (`cd c:\etc\src\git\myrepo` inside the
AC) doesn't work. The runner injects `MXC_POLICY_ROOT` so scripts can
discover the projection root at startup.

## 7. Implementation status (current)

| Phase | Status | Commit | Notes |
|---|---|---|---|
| 0 — spike import baseline | ✅ done | `ea3aaa4` | 8/8 cells green; +3,827 LOC scaffolding |
| A.1 — module skeleton | ✅ done | `cc09513` | 8 files, 880 LOC, 15 unit tests |
| A.2 — promote ProjFS spike | ✅ done | `00bae68` | `apply_branches`/`restore` lifecycle; e2e smoke passes in 0.11 s |
| A.3 — state file + orphan recovery | ✅ done | `185f624` | Persist-before-apply; PID+FILETIME check; 12 new tests |
| A.4 — placeholder DACL | ✅ done in A.2 | — | DWORD-pad + AU-grant promoted from spike step 3 |
| A.5 — ProjFS writeback | ✅ done | `433a404` | `PRJ_NOTIFY_FILE_HANDLE_CLOSED_FILE_MODIFIED` |
| A.6 — cwd + `MXC_POLICY_ROOT` | ✅ done in A.2 | — | `OverlayHandle.effective_cwd` |
| A.7 — recovery wired into wxc-exec | ✅ done | `12c3634` | Best-effort call after the DACL recovery |
| A.8 — schema field | ✅ done | `12c3634` | `experimental.filesystem_overlay`; 6 parser tests |
| B-1 — BindFlt FFI | ✅ scaffolding only | `369b797` | Deferred to elevated future; FFI stays in tree |
| C — `policy::classify` real | ✅ done | `7ab52f8` | Per-entry selection + structural deny; 10 new tests |
| D-1 — detector tier + projfs feature_detect | ✅ done | `a52bd1e` | 7 new tests; 404 unit total |
| **D-2 — `appcontainer_runner` wiring** | ⏳ **pending** | — | Runner doesn't call `detect()` at all today |
| A.x — retire spike scaffolding crates | ⏳ pending | — | `wxc_projfs_probe[_child]` once D-2 lands |
| C-2 — nested rw/ro composition | ⏳ pending | — | Required for the broad-RO + narrow-RW shape |
| Phase E — perf / probe / docs | ⏳ pending | — | This doc is part of E.4 |

**Tests at HEAD (`a52bd1e`):** 404 unit tests pass + 2 `#[ignore]`-gated
e2e smokes (ProjFS+writeback+deny, BindFlt with elevation handling).
`cargo fmt --all -- --check`, `cargo clippy -p wxc_common --all-targets -- -D warnings`,
and `cargo check --workspace --all-targets` all clean.

## 8. Pending work — what's required to ship this

1. **D-2 — wire `appcontainer_runner` to the new tier.** The runner
   currently doesn't call `fallback_detector::detect()` at all. Phase
   D-2 must thread the detector decision through the runner so a
   real `wxc-exec` invocation with `experimental.filesystem_overlay.mode
   = "auto"` actually constructs an `OverlayManager` and sets the
   AC's cwd / env from the returned `OverlayHandle`.

2. **C-2 — nested rw/ro composition.** Required before the dominant
   policy shape (broad RO of `C:` + narrow RW dirs) can be served.

3. **A.x — retire spike scaffolding.** `wxc_projfs_probe` and
   `wxc_projfs_probe_child` were imported at Phase 0 as the baseline;
   their valuable bits have been promoted into `filesystem_overlay`.
   They can be deleted along with the `Cargo.toml` workspace member
   entries and the `Win32_Storage_ProjectedFileSystem` feature gate
   on the windows crate (which can remain — it's now consumed by
   `filesystem_overlay::projfs::virt`).

4. **E — hardening.**
   - Performance characterization vs DACL-T3 baseline (the spike
     measured ~800 ms cold for DACL apply on a 332k-file tree).
   - `wxc-exec --probe` JSON gains the new tier + Client-ProjFS
     enablement state.
   - SDK `getPlatformSupport()` mirrors that.
   - Diagnostic-logging hooks for the callbacks and the selection
     decision.
   - SDK README updates documenting the one-time
     `Enable-WindowsOptionalFeature -Online -FeatureName Client-ProjFS`
     enable.
   - `.github/copilot-instructions.md` backend table updated.

## 9. Decisions and their rationale

| # | Decision | Recommendation taken |
|---|---|---|
| 1 | Module name | `filesystem_overlay` — covers ProjFS + BindFlt + minimal placeholder ACL; survives future primitives without rename |
| 2 | Default for `experimental.filesystem_overlay.mode` | `"off"` until the e2e matrix has soaked one release; then flip to `"auto"` |
| 3 | Default for `writeIsolation` | `"passthrough"` (matches DACL-T3 observable semantics: writes immediately visible to host) |
| 4 | BindFlt admin requirement | **Empirically confirmed** (see §6.2). Path forward: ProjFS-only non-admin tier; BindFlt FFI stays as scaffolding for a future elevated-broker design |
| 5 | Pre-25H2 ProjFS coverage | ProjFS shipped in Win10 1809 (Oct 2018 Update); broad availability is not the blocker. VM matrix for spot-checking pre-25H2 cohorts is being set up separately. |
| 6 | State directory | `%LOCALAPPDATA%\Microsoft\MXC\overlay-state\`; override via `MXC_OVERLAY_STATE_DIR`. Parallels the DACL one. |
| 7 | `filesystem_bfs.rs` future | Unrelated to this work; coexists. Whether BFS retires eventually is a separate decision. |

## 10. Test plan (current shape)

### 10.1 Unit tests (`cargo test -p wxc_common --lib filesystem_overlay`)

56 tests at HEAD covering: `policy::classify` (empty / RO-only / RW+RO
disjoint / nested-rejected / denied-inside / denied-outside /
denied-nonexistent / ambiguous-names / nonexistent-rw / canonical-path
helpers), state-file round-trip + atomic write, process-liveness
checks (self / zero PID / bogus FILETIME), recovery flows (no state
dir / live owner / dead PID reaping / corrupt-file quarantine /
BindFlt-record retention), `OverlayPrimitive` summarisation,
`OverlayError` ↔ `MxcErrorCode` mapping, and the BindFlt FFI's
either-success-or-clean-unavailable contract.

### 10.2 Detector tests (`cargo test -p wxc_common --lib fallback_detector`)

22 tests at HEAD including the new overlay-tier selection cases:
mode=Off never selects, mode=On + empty policy errors,
mode=On + rw path either selects or surfaces `OverlayUnavailable`,
mode=Auto + rw path either selects or falls through, forced overlay
via `MXC_FORCE_TIER` succeeds without DACL.

### 10.3 End-to-end (`#[ignore]`-gated; run explicitly)

```
cargo test -p wxc_common --lib filesystem_overlay -- --ignored
```

1. **ProjFS apply / read / writeback / structural-deny / restore.**
   Creates host scratch with rw + ro branches and a "secret" subdir
   under RO added to `deny_subpaths`. Asserts:
   - Both branches enumerate at the projection root.
   - RW branch's `readme.txt` content readable through the projection.
   - PowerShell-child-process write to `rw/readme.txt` propagates to
     the host backing within 2 s.
   - RO branch write attempt does NOT modify the host backing.
   - The denied `secret` subdir does NOT appear in the RO enumeration
     and `stat` on it returns not-found.
   - `restore()` cleanly stops the virt session and removes the
     projection root (with retry against transient error 369).

2. **BindFlt FFI smoke.** Either succeeds (admin shell) or surfaces a
   clean `E_ACCESSDENIED` (non-admin) — both are acceptable test
   outcomes documenting the empirical constraint.

### 10.4 Pre-merge gates (already in CI for the workspace)

- `cargo fmt --all -- --check`
- `cargo clippy -p wxc_common --all-targets -- -D warnings`
- `cargo check --workspace --all-targets`
- `cargo test -p wxc_common --lib`

### 10.5 OS-version matrix (deferred to Phase E)

ProjFS shipped Win10 1809; full per-build matrix (21H2 / 22H2 / 23H2 /
24H2 / 25H2) for the e2e flow is part of Phase E hardening, blocked
on VM testbed availability.

## 11. Related work

- The DACL-T3 implementation in `src/wxc_common/src/filesystem_dacl.rs`
  and the `add_deny_aces` AAP-grant gap finding (spike step 2 (7/N))
  remain relevant for the DACL fallback path.
- The existing BFS path in `src/wxc_common/src/filesystem_bfs.rs` is
  unaffected by this work.
- The `agentic-sandbox-v1.md` proposal in
  `docs/proposals/agent-isolation/` is broader (Silo + BindFlt +
  restricted token); explicitly **out of scope** for this work per
  user direction.
