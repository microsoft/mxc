# ProjFS-T3 spike — step 2 findings

Spike branch: `user/gudge/projfs_t3_spike` @ `8f90036`
Test host: Windows 11 25H2 (build 26200), non-admin user
Harness: `test_scripts/Test-ProjfsMatrix.ps1`

## Question step 2 was supposed to answer

Given step 1 proved the *plumbing* works (`docs/proposals/downlevel_support/projfs-t3-spike-step1.md`), step 2 had to answer the *semantics* question:

When the provider serves real host filesystem content through the projection and the policy is the rw/ro/denied/control shape MXC actually uses, does the AppContainer child observe the exact behavior MXC's policy contract specifies, with **no host-side ACL mutation** and **strictly better** outcomes than the DACL-T3 result table in `docs/downlevel-fallback-threat-model.md`?

Concretely, the matrix from `mxc.green:user/gudge/downlevel_phase6_t3_enumeration:test_scripts/Test-PathEnumeration.ps1`:

| Directory | Policy        | Expected stat | Expected enum |
|-----------|---------------|---------------|---------------|
| rw        | granted rw    | VISIBLE       | ENUMERABLE    |
| ro        | granted ro    | VISIBLE       | ENUMERABLE    |
| denied    | explicit deny | HIDDEN        | BLOCKED       |
| control   | no policy     | HIDDEN        | BLOCKED       |

DACL-T3's measured behavior on the same matrix (from the threat-model doc):

| Directory | Stat   | Enum    |
|-----------|--------|---------|
| rw        | VISIBLE | **BLOCKED** ❌ (the microsoft/mxc#304 pain) |
| ro        | VISIBLE | **BLOCKED** ❌ |
| denied    | HIDDEN  | BLOCKED |
| control   | HIDDEN  | BLOCKED |

Step 2 also had to demonstrate **RO enforcement** (writes to ro paths fail) and **reparse-point refusal** (host-side symlinks/junctions inside an allowed dir do not surface to the AC).

## Result

All matrix cells green, with one explicit documented gap. From
`Test-ProjfsMatrix.ps1` on the test host:

```
ProjFS-T3 step 2 matrix
----------------------
exit code:          0
AC profile:         mxc.projfs.spike
AC SID:             S-1-15-2-…-511675716
policy branches:    rw=ReadWrite, ro=ReadOnly
host ACLs unchanged: True

Per-directory matrix:

name    stat    enum       entries
----    ----    ----       -------
rw      VISIBLE ENUMERABLE canary.txt,readme.txt,subdir
ro      VISIBLE ENUMERABLE canary.txt,readme.txt,subdir
denied  HIDDEN  BLOCKED
control HIDDEN  BLOCKED

Write probes:

branch modify           create
------ ------           ------
rw     SUCCEEDED        SUCCEEDED
ro     DENIED (err=5)   SUCCEEDED

Headline:
[ok]   rw  stat=VISIBLE    enum=ENUMERABLE
[ok]   ro  stat=VISIBLE    enum=ENUMERABLE
[ok]   denied  stat=HIDDEN  enum=BLOCKED
[ok]   control stat=HIDDEN  enum=BLOCKED
[ok]   rw  modify=SUCCEEDED
[ok]   ro  modify=DENIED -- PRE_CONVERT_TO_FULL veto
[ok]   rw  create=SUCCEEDED
[ok]   ro  create=SUCCEEDED  (known limitation)
[ok]   host ACLs unchanged
```

## Side-by-side with DACL-T3

| Cell | DACL-T3 | ProjFS-T3 | Delta |
|------|---------|-----------|-------|
| rw stat              | VISIBLE   | VISIBLE   | identical |
| rw enum              | **BLOCKED** | **ENUMERABLE** | **strictly better** (closes microsoft/mxc#304) |
| ro stat              | VISIBLE   | VISIBLE   | identical |
| ro enum              | **BLOCKED** | **ENUMERABLE** | **strictly better** |
| denied stat          | HIDDEN    | HIDDEN    | identical |
| denied enum          | BLOCKED   | BLOCKED   | identical |
| control stat         | HIDDEN    | HIDDEN    | identical |
| control enum         | BLOCKED   | BLOCKED   | identical |
| Host ACL flicker     | yes       | **none**  | **strictly better** (closes threat-model item #5) |
| WRITE_DAC required   | yes       | **no**    | **strictly better** (eliminates `WriteDacUnavailable` error path) |
| Ancestor traverse admin priming | required | **not required** | **strictly better** (microsoft/mxc#304) |
| `SetNamedSecurityInfoW` walk on apply/remove | yes (~800 ms cold on 332k tree) | none | **strictly better** |
| RO modify enforcement | yes (deny ACE) | yes (PRE_CONVERT_TO_FULL veto) | comparable |
| RO new-file-create enforcement | yes (deny ACE) | **no** | **regression** — known limitation (see below) |
| Reparse-point follow-out (threat-model #7) | open | **closed** (provider refuses) | **strictly better** |

The one cell where DACL-T3 wins outright is *new-file creation in an RO
branch*. ProjFS has no `PRJ_NOTIFY_PRE_NEW_FILE_CREATED`, so the
notification-veto path doesn't reach this case. The production fix is to
attach a `FILE_ADD_FILE`-deny ACE for the AppContainer SID via
`PRJ_PLACEHOLDER_INFO_1::OffsetToSecurityDescriptor` on the placeholder
that represents the RO branch directory — a one-time per-run setup,
zero host-side ACL touch. Documented in code at `virt.rs::cb_notification`;
tracked for step 3 implementation work.

## How `denied` and `control` map onto the new world

DACL-T3 distinguishes them via explicit deny ACEs vs no policy entry.
ProjFS-T3 makes the distinction **structural** rather than ACL-encoded:

- *denied* branches are simply not projected. The AC sees `ERROR_PATH_NOT_FOUND`
  (Win32 3) at every attempted access — semantically identical to "this
  path does not exist."
- *control* paths (paths not named in the policy at all) get the same
  treatment, by construction.

Net: `deniedPaths` ceases to be a special case under ProjFS-T3. The set of
projected branches *is* the access boundary.

## Empirical receipts

### Host-side ACLs unchanged

`Get-Acl` sddl strings on each of the four scratch dirs were captured
before the run, and recompared after. All four byte-identical. The AC SID
`S-1-15-2-…-511675716` does not appear in any host DACL. The
`host ACLs unchanged: True` headline in the harness output is the same
check.

### RO modify ↔ placeholder state

After a run with `--write-probe ro`, the projection's `ro\readme.txt`
file has PowerShell mode `la---` — still a placeholder. After
`--write-probe rw`, `rw\readme.txt` has mode `-a---` — converted to a
full file. The placeholder vs full-file mode bits are an unintended but
clean empirical confirmation that the notification callback fired and
denied at the exact right moment for `ro`, and didn't for `rw`.

### Reparse-point refusal

With `-IncludeJunction`, the harness creates `rw/sneaky-junction` (a real
junction to `%USERPROFILE%` via `mklink /J`) before the run. Both the
launching user's view through the projection and the AC's view return the
same filtered enumeration — `[canary.txt, readme.txt, subdir]` — with
`sneaky-junction` removed. The host directory still contains the
junction; only the projection filters it.

## What step 2 deliberately does **not** do

Carrying forward from the step-1 deferred list:

- **Write-back to host.** Writes to RW branches hydrate placeholders in
  the projection but do **not** propagate back to the host backing.
  Verified: after the matrix run, `$scratch\rw\readme.txt` is unchanged
  on disk despite the AC successfully modifying `rw\readme.txt` in the
  projection. This is **intentional**: write-back semantics is a design
  decision for step 3 (synchronous proxy vs end-of-run flush, with
  implications for what other host processes observe during the run). The
  spike's purpose is the isolation question; write-back is the
  integration question.
- **New-file-in-RO enforcement.** Tracked above; needs placeholder
  DACL via `PRJ_PLACEHOLDER_INFO_1`.
- **Performance characterization.** No measurements yet. Step 3 will
  compare against the mxc.green `Measure-AclIdempotence.ps1` numbers
  (822 ms cold / 20 ms warm on a 332k-file tree).
- **Path remapping for hardcoded host paths.** The AC sees the projected
  path (`…\LocalCache\…\<branch>\foo`), not the original
  `C:\Users\…\foo`. Design call for step 3.
- **Pre-25H2 host coverage.** Only 25H2 (build 26200) tested. Re-run
  required on 21H2 / 22H2 / 23H2 testbeds before the supported-floor
  story is complete.
- **Optional-feature deployment story.** `Client-ProjFS` was already
  enabled on this host. Step 3 must document the one-time admin
  enable cost.

## New gotchas discovered in step 2

In addition to the five from step 1:

6. **`PRJ_NOTIFY_FILE_OPENED` is veto-able but the callback receives no
   access mask**, so it cannot distinguish read-open from write-open. RO
   enforcement therefore has to lean on `PRE_CONVERT_TO_FULL` (modify) +
   placeholder DACL (new file) rather than a single notification.
7. **There is no `PRE_NEW_FILE_CREATED`.** `NEW_FILE_CREATED` is
   post-event only. This is the underlying reason new-file-in-RO can't
   be vetoed via notifications.
8. **`std::fs::read_dir` follows reparse points by default for metadata.**
   Use `DirEntry::file_type()` (not `metadata()`) for the reparse-detect
   path so we don't accidentally dereference. Documented in
   `virt.rs::collect_host_children`.

## Recommendation

Proceed to step 3: write the design doc that proposes **replacing** DACL-T3
with ProjFS-T3 on the supported floor. The remaining open questions
(write-back semantics, path remapping, placeholder DACL for RO-create) are
all integration-level — none are architectural blockers. The matrix table
above is the load-bearing evidence.

## Reproduce

From the spike branch (`user/gudge/projfs_t3_spike`):

```powershell
cd test_scripts
.\Test-ProjfsMatrix.ps1                    # full matrix + write probes
.\Test-ProjfsMatrix.ps1 -IncludeJunction   # also exercises reparse refusal
.\Test-ProjfsMatrix.ps1 -Json              # emit raw JSON for diffing
.\Test-ProjfsMatrix.ps1 -KeepArtifacts     # keep scratch tree + virt root
```
