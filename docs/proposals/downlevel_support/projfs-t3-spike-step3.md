# ProjFS-T3 spike — step 3 findings and recommendation

Spike branch: `user/gudge/projfs_t3_spike` @ `54e5cc3`
Worktree: `mxc.yellow`

## What this document is

Consolidates the architectural answer the spike was asked to deliver,
and proposes a concrete next step. Step 1 (`projfs-t3-spike-step1.md`)
proved the plumbing. Step 2 (`projfs-t3-spike-step2.md`) proved the
semantics. Step 3 — this doc — proposes what to do about it.

## Recommendation

**Replace `filesystem_dacl.rs` with `filesystem_projfs.rs` as the T3
implementation on the supported floor (Windows 11 21H2+).**

The architectural premise that motivated the spike held up at every
measurable cell:

- The known T3-DACL pain — `FindFirstFile` blocked from inside an AC,
  requiring admin-only priming of `ALL APPLICATION PACKAGES:(X)` on
  `C:\` and `C:\Users\` (microsoft/mxc#304) — does not exist with
  ProjFS-into-AC. Receipt: AC child enumerated rw/ro branches cleanly
  in step 1d and step 2 (1/N).
- Host-side ACL flicker (threat-model item #5) does not exist with
  ProjFS-into-AC. Receipt: `Get-Acl` SDDL on the four scratch dirs
  byte-identical before and after a full matrix run, AC SID not
  present in any host DACL.
- `WRITE_DAC`-on-policy-paths prerequisite (the
  `WriteDacUnavailable` error path in `fallback_detector`) is gone.
  Receipt: spike runs as non-admin on this user's account, no DACL
  modification.
- TOCTOU between ACL apply and process create (threat-model item #6)
  is gone. Receipt: no apply step at all.
- Reparse-point follow-out (threat-model item #7) is closed at the
  provider level. Receipt: junction created inside `rw` host dir,
  invisible to both the AC and the launching user through the
  projection.
- `SetNamedSecurityInfoW` walk perf cost (~800 ms cold on 332k-file
  tree, from mxc.green's `Measure-AclIdempotence.ps1`) is gone.
  Receipt: by inspection — no `SetNamedSecurityInfo` calls in the
  ProjFS provider path. Quantitative comparison deferred to a perf
  follow-on PR.

One cell genuinely regresses vs DACL-T3, with a documented and bounded
fix: see "Known open work" below.

## Migration plan

This is the cleanest possible shape, given the spike's findings:

1. **Land a `filesystem_projfs` module in `wxc_common`.** Promotion of
   `wxc_projfs_probe::virt` and `ac_launch` into production code. The
   policy resolution and callback set carry over almost verbatim. The
   five callbacks are unchanged; the notification callback is unchanged;
   the AC launcher merges with existing
   `wxc_common::appcontainer_runner`.
2. **Wire it into the dispatcher.** `IsolationTier::AppContainerDacl`
   becomes `IsolationTier::AppContainerProjFs` (or both, with the
   detector preferring ProjFS when the optional feature is enabled).
   Existing `fallback_detector` shape mostly stands; the
   `has_write_dac` probe is no longer load-bearing for T3 — instead
   we probe `Client-ProjFS` enablement using the technique from step
   1a (`feature_detect::detect`).
3. **Update `--probe` JSON + SDK `getPlatformSupport()`** to report
   the ProjFS-T3 tier and its prereqs (optional feature enabled
   yes/no) instead of WRITE_DAC.
4. **Retire `filesystem_dacl.rs`** in favor of a much smaller helper
   that exists only for T1's `deniedPaths` augmentation (see the
   "deniedPaths under ProjFS-T3 vs T1" section in step 2). About
   200 LOC dedicated to a single purpose, not 1080.
5. **Retire Phase 6 ancestor-traverse + `install_acls` entirely.**
   The whole reason for ancestor-traverse (microsoft/mxc#304) doesn't
   apply: the projection root is inside the AC profile, which the AC
   already has traverse on.
6. **Revise the threat model.** Almost every "out of scope" /
   "qualitative gap" item in
   `docs/downlevel-fallback-threat-model.md` either disappears or
   gets a different shape under ProjFS-T3. The 25H2-enumeration
   "empirically resolved" section in particular becomes moot.
7. **Add a deployment note for `Client-ProjFS`** to the SDK README
   covering the one-time admin enable (`Enable-WindowsOptionalFeature
   -Online -FeatureName Client-ProjFS`). See the "Optional-feature
   deployment story" follow-on PR for the full surface.

LOC swing, rough: −1300 (filesystem_dacl, install_acls, phase 6
recovery state, the orphan-reaper that exists only for crash safety
of ACL mutations) + 800 (filesystem_projfs based on the spike). Net
~500 LOC smaller. More importantly the *kind* of work is much narrower:
provider callbacks vs a crash-safe ACL-mutation state machine with
per-path mutex serialization.

## Known open work — follow-on PR-shaped pieces

These are deliberately *not* in step 3's scope. Each is small and
focused enough to land as its own PR.

### A. **Placeholder DACL to close the ro/create regression cell**

Attempted in step 3 commit (1/N) and reverted: `PrjWritePlaceholderInfo`
returned `ERROR_INTERNAL_ERROR` (Win32 1359) for every SD shape tried,
including the trivial `D:P(A;OICI;FA;;;SY)`. The failure is in
marshaling / API surface choice, not SDDL content. Plausible suspects
documented inline at `virt.rs::cb_get_placeholder_info`:

- buffer alignment when the variable-length `PRJ_PLACEHOLDER_INFO` is
  backed by a `Vec<u8>`;
- need to use `PrjWritePlaceholderInfo2` or `PrjUpdateFileIfNeeded`
  instead, especially for directory placeholders;
- self-relative SD offset semantics inside the variable-data block.

Until this lands, the ro/create cell is the **one cell where
ProjFS-T3 regresses vs DACL-T3**. The regression is bounded: AC
writes stay inside the AC profile's LocalCache, never reach the host
backing, never escalate privileges (see the "What the regression
actually is" discussion in step 2's findings doc + the corrected
Deny-ACE empirical results section).

Estimate: 0.5–1 day with focused debugging (probably a single API or
alignment fix; spike's `build_ro_security_descriptor` helper is the
correct shape per the empirical Deny-ACE test).

### B. **Performance characterization**

Cold-start cost of `PrjStartVirtualizing` + first-access cost of each
callback type, on workloads of representative shape (small repo,
large repo, many-small-files tree). Compare to the mxc.green
`Measure-AclIdempotence.ps1` numbers (822 ms cold / 20 ms warm on a
332k-file tree). The expected qualitative shape:

- Cold start: faster (no descendant walk to apply ACLs).
- Per-file first read: slower (callback IPC vs already-applied ACL).
- Bulk enumeration: faster (provider callback responses are tiny;
  no kernel-side traversal of host ACL chain).
- End-of-run cleanup: faster (no `SetNamedSecurityInfoW` to undo).

But the numbers should be measured, not assumed. Net for typical agent
workloads — open a few files, run a build — is almost certainly a win.

Estimate: 1–2 days including measurement harness.

### C. **Write-back semantics design call**

Today the spike leaves writes inside the projection — they don't reach
the host backing. Two production options:

1. **Sync proxy.** Notification callback for
   `PRJ_NOTIFY_FILE_HANDLE_CLOSED_FILE_MODIFIED` reads the dirty
   placeholder content and writes it back to the host. Other host
   processes see the agent's writes the moment the AC closes the file.
2. **End-of-run flush.** Walk the projection at session teardown;
   write any dirty files back. Host sees nothing until the run ends.

Sync proxy matches existing T3-DACL semantics (which mutates the
host directly). End-of-run flush is simpler and provides better
isolation. The MXC product owner should pick.

Estimate: 1 day for the implementation either way + 0.5 day of design
write-up.

### D. **Path remapping decision: per-run leaf vs stable + cleanup**

Documented in step 2's findings under "Path remapping in practice".
Tactical choice: either accept the per-run GUID leaf and expose
`MXC_POLICY_ROOT` to agent scripts, or use a stable leaf and ship a
`PrjGetOnDiskFileState`-aware cleanup helper. Either lands in step 3
follow-on. About 60 LOC + tests for the cleanup helper if option 2.

### E. **Pre-25H2 host coverage**

This entire spike was on Win11 25H2 build 26200. The supported floor
is 21H2 (build 22000). Re-run the matrix and the Deny-ACE semantics
test on 21H2, 22H2, 23H2 testbeds. Confirm:

- `Client-ProjFS` is enableable on each (it is, per the published
  docs; verify on real machines).
- Deny ACEs for AC SIDs still enforce (the Deny-ACE script result
  may differ — and if it does, the existing T3-DACL `add_deny_aces`
  has a real gap on those builds independent of this spike).
- Notification callback behavior is consistent.

Tracked separately because it requires real test hardware / VMs.

### F. **Optional-feature enablement deployment story**

How does an MXC user know whether `Client-ProjFS` is enabled, and
what's the workflow to enable it? Three surfaces:

- SDK: `spawnSandbox` returns a typed error if the feature is absent
  on a host where ProjFS-T3 would be selected. Today there's no such
  error code.
- CLI: `wxc-exec --probe` includes the feature state in its JSON
  output. (Today there is no probe surface for it.)
- Docs: SDK README + `docs/proposals/downlevel_support/` README pages
  document the one-time admin enable
  (`Enable-WindowsOptionalFeature`, DISM, or Windows Settings >
  Optional Features).

Estimate: 0.5 day.

### G. **AAP-grant gap in `mxc.green::filesystem_dacl::add_deny_aces`**

Side finding from step 2 (7/N): on Win11 25H2 a same-SID Deny ACE
does NOT override an `ALL APPLICATION PACKAGES` Allow ACE for a
regular AppContainer. mxc.green's `add_deny_aces` is therefore a
paper guarantee on paths that inherit AAP grants (the AC profile
root, several SDK directories). Either strip the AAP grant on
deniedPath targets, supplement with a Deny ACE for the AAP SID
itself, or document the limitation. **This is independent of the
ProjFS-T3 spike**; it's a gap in the existing T3-DACL design that
the spike's Deny-ACE empirical test exposed in passing. Should be
filed as its own issue against the current T3-DACL code regardless
of whether ProjFS-T3 lands.

## What this means for the unmerged DACL-T3 branches in `mxc.green`

The phase 3 / 4 / 5 / 6 branches on `mxc.green` represent real,
working, well-reviewed code. They are not wasted — they encode a
correct mental model of the threat surface, an empirical
characterization of the 25H2 enumeration behavior, and a working
T1 `deniedPaths` augmentation path. If ProjFS-T3 lands, the
`filesystem_dacl.rs` core retires; the threat model, the
fallback_detector design, and the Test-PathEnumeration matrix
become inputs to the ProjFS-T3 implementation.

Concretely:

- **Phase 2 (`fallback_detector`)** already merged to `main`. Stays;
  needs its T3 probe rewritten from `WRITE_DAC` to `Client-ProjFS`
  feature-detect.
- **Phase 3 (`filesystem_dacl`)** the core 1080 LOC retires. The
  ~200 LOC subset needed for T1's `deniedPaths` augmentation moves
  to a smaller standalone helper. The AAP-gap finding (G above)
  applies to whatever the smaller helper becomes.
- **Phase 4 (dispatcher integration)** the shape stands; the runner
  type swaps.
- **Phase 4.5 (Tier 2 removal)** unaffected.
- **Phase 5 (probe + e2e harness + threat model doc)** the harness
  shape stands; the threat model doc gets a sweeping rewrite (most
  "out of scope" items collapse).
- **Phase 6 (ancestor traverse + install_acls)** retires entirely.
  microsoft/mxc#304 closes by construction.

## Decision request

The spike has done its job. The next step is a product decision:

**Should we land ProjFS-T3 as the T3 implementation on the supported
floor, retiring the DACL-T3 path?**

If yes: queue up the follow-on PRs A–G above (A and B are blockers
for a defensible release; C–G can land incrementally). Estimated
total: 1–2 weeks of focused work for one engineer.

If no: keep the spike branch around as documented prior art and
proceed with DACL-T3, accepting microsoft/mxc#304 and threat-model
items #5/#6/#7. The AAP-grant finding in `add_deny_aces` (G) still
needs to be addressed regardless of this decision.

## Reproduce everything

From the spike branch:

```powershell
# Build everything
cd src
cargo build -p wxc_projfs_probe -p wxc_projfs_probe_child

# Step-1 quick-look (synthetic content):
.\target\debug\wxc-projfs-probe.exe

# Step-2 8-cell matrix + write probes + (optional) reparse refusal:
cd ..\test_scripts
.\Test-ProjfsMatrix.ps1
.\Test-ProjfsMatrix.ps1 -IncludeJunction

# Empirical OS semantics question that came up mid-spike:
.\Test-DenyAceSemantics.ps1
```

All scripts pass `-Json` for machine-parseable output and
`-KeepArtifacts` to preserve the scratch tree and virt root for
post-run inspection.

## Commit log

```text
54e5cc3 spike step 3 (1/N): attempted placeholder DACL fix (reverted, kept breadcrumb)
92239d3 spike step 2 (7/N): fold path remapping + Deny-ACE matrix into findings
36e13ad spike step 2 (6/N): Deny-ACE matrix — AAP interaction + LPAC sweep
543b122 spike step 2 (5/N): empirically test Deny-ACE-for-AC-SID semantics
39f7298 spike step 2 (4/N): PowerShell harness + step-2 findings doc
8f90036 spike step 2 (3/N): reparse-point refusal in placeholder + enumeration
6c64a9d spike step 2 (2/N): RO enforcement via PRE_CONVERT_TO_FULL notification
fad67c6 spike step 2 (1/N): policy-driven projection + matrix probe
d7edf0c docs: ProjFS-T3 spike step 1 findings
053119f spike: step 1d — AppContainer child reads + enumerates via ProjFS
cfcb1c6 spike: step 1c — PrjStartVirtualizing + launching-user smoke read
1ae7ca6 spike: ProjFS-T3 probe — feature-detect + AC profile (steps 1a/1b)
```
