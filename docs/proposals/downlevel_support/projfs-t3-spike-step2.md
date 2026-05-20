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
| RO new-file-create enforcement | yes (deny ACE) | **yes (placeholder DACL)** | comparable |
| Reparse-point follow-out (threat-model #7) | open | **closed** (provider refuses) | **strictly better** |

The one cell where DACL-T3 wins outright is *new-file creation in an RO
branch*. ProjFS has no `PRJ_NOTIFY_PRE_NEW_FILE_CREATED`, so the
notification-veto path doesn't reach this case. The production fix is to
attach a `FILE_ADD_FILE`-deny ACE for the AppContainer SID via
`PRJ_PLACEHOLDER_INFO_1::OffsetToSecurityDescriptor` on the placeholder
that represents the RO branch directory — a one-time per-run setup,
zero host-side ACL touch. Documented in code at `virt.rs::cb_notification`;
tracked for step 3 implementation work.

**Update (step 3 (3/N) at `cc72d15`):** This cell is now closed
empirically. The placeholder DACL approach works on this host. The fix
is selective-Allow (no `FILE_ADD_FILE` on the AC SID grant), not a Deny
ACE, but the architectural conclusion is the same: a DACL attached to
the placeholder via `PRJ_PLACEHOLDER_INFO_1` enforces. Two non-obvious
prerequisites that the spike learned the hard way:

1. The user-mode SD address must be DWORD-aligned (`SeCaptureSecurityDescriptor`'s
   internal `ProbeForRead` raises `STATUS_DATATYPE_MISALIGNMENT` otherwise,
   surfacing in user-mode as `0x800703e6 = ERROR_NOACCESS` not as
   the more obvious `ERROR_INVALID_SECURITY_DESCR`). Pad `OffsetToSecurityDescriptor`
   to make `(path_bytes + offset) mod 8 == 0`.
2. The DACL must include an ACE that the launching user matches — `OW`
   (OWNER_RIGHTS, S-1-3-4) is unreliable because most user tokens
   don't have S-1-3-4 enabled (including Entra-style S-1-12-1 users).
   Use `AU` (Authenticated Users, S-1-5-11) instead.

See `virt.rs::cb_get_placeholder_info` and `build_ro_security_descriptor`
for the actual code, and the step 3 (3/N) commit message for the
root-cause walk through the ProjFS source.

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
  DACL via `PRJ_PLACEHOLDER_INFO_1`. The required ACE shape was settled
  empirically (see "Deny-ACE-for-AC-SID semantics" section below).
- **Performance characterization.** No measurements yet. Step 3 will
  compare against the mxc.green `Measure-AclIdempotence.ps1` numbers
  (822 ms cold / 20 ms warm on a 332k-file tree).
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

## Deny-ACE-for-AC-SID semantics (empirical)

The original write-up of this section claimed Deny ACEs targeting AC SIDs
do not enforce. That claim was wrong, and the wrongness was the user's
question that drove this whole investigation. The corrected, empirically
grounded picture follows. Harness: `test_scripts/Test-DenyAceSemantics.ps1`.

Five DACL variants × two AC modes (regular and LPAC opt-out via
`PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY` with
`PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT`), Win11 25H2
build 26200, non-admin user:

| Variant DACL on the host file | Regular AC | LPAC AC |
|---|---|---|
| **A** — SY:F BA:F user:F + `(A;;FR;;;<ac-sid>)` | SUCCEEDED | SUCCEEDED |
| **B** — A + `(D;;FA;;;<ac-sid>)` | **DENIED (5)** | **DENIED (5)** |
| **C** — SY:F BA:F user:F (no AC grant) | DENIED (5) | DENIED (5) |
| **D** — SY:F BA:F user:F + `(A;;FR;;;AAP)` + `(D;;FA;;;<ac-sid>)` | **SUCCEEDED** | DENIED (5) |
| **E** — SY:F BA:F user:F + `(A;;FR;;;AAP)` only | SUCCEEDED | DENIED (5) |

### Takeaways

1. **B confirms (against my earlier verbal claim) that Deny ACEs for
   specific AppContainer SIDs DO enforce in the AC access check.** Both
   regular and LPAC. The canonical-order processing (Deny ACE evaluated
   before same-SID Allow ACE) wins.

2. **D is the unanticipated finding worth flagging on mxc.green.** When
   the file's DACL also carries an `ALL APPLICATION PACKAGES` Allow
   grant, a same-SID Deny ACE *does not* override it on a regular
   AppContainer. The AAP grant reaches the AC via the AC's implicit AAP
   membership, and the kernel grants access. Result: `add_deny_aces` on
   a path that inherits AAP grants (e.g. anything under a parent
   directory that ever got an `ALL APPLICATION PACKAGES:(F)` ACE — which
   includes the AC's own profile folder, the user's profile under
   certain Windows installs, and several SDK-installed locations) is a
   paper guarantee for *normal* AppContainers. It works only if the
   target lacks any inherited AAP grant.

3. **E + E-LPAC confirms the LPAC opt-out is wired correctly.** AAP
   only grant: regular AC reads through it, LPAC AC does not.

4. **D under LPAC works.** Combining LPAC opt-out with a specific-SID
   Deny ACE gives clean enforcement even on paths inheriting AAP
   grants. This is a real but currently-unused deployment option for
   MXC (we don't apply LPAC today).

### Implication for the ProjFS-T3 RO-create-new fix

We control the placeholder DACL completely via
`PRJ_PLACEHOLDER_INFO_1::OffsetToSecurityDescriptor` and there is *no
inheritance* into our placeholders. The Deny-ACE finding from D
therefore doesn't bite us: as long as we don't *also* grant AAP on the
placeholder, a `(D;;FA;;;<ac-sid>)` ACE enforces. Equivalently, a
selective-Allow that omits `FILE_ADD_FILE` works. Either shape closes
the RO-create-new cell.

### Implication for existing T3-DACL in mxc.green

`filesystem_dacl::add_deny_aces` (`mxc.green:user/gudge/downlevel_phase6_t3_enumeration`)
relies on Deny ACEs for the specific AC SID on **host** paths, where
the DACL inherits from wherever the user happens to point it. The
implementation is correct **only when target paths do not inherit AAP
grants** — true for arbitrary user-controlled paths, *not* true for
paths under several common locations. Concrete cases that break:

- Anything under the AC profile root
  `%LOCALAPPDATA%\Packages\<profile>\` — the profile root carries
  `(A;OICI;FA;;;<this-ac-sid>)` *plus*, on some installs, AAP grants
  via parent inheritance.
- Several SDK-installed directories that carry `(A;OICI;0x1200a9;;;AC)`
  by design so that AppContainer apps can find their resources.

For a comprehensive fix, mxc.green's `add_deny_aces` should either
(a) strip AAP grants on the target before adding the Deny, or
(b) supplement the Deny with a Deny for the AAP SID itself, or
(c) document the limitation and accept that paths inheriting AAP can't
be denied via this mechanism alone.

This is a separate finding to log against the existing T3 design, not
a regression on the ProjFS-T3 spike.

## Path remapping in practice

Question that comes up immediately when explaining the design: if I
project `D:\git\…\mxc.yellow` into the AC, where does the AC see it?
Concrete answer using a real run of `wxc-projfs-probe`:

```
--rw  D:\git\microsoft\mxc\mxc.yellow                  (or the C:\etc\... junction;
                                                        Policy::from_flags canonicalizes)
```

`Policy::from_flags` runs `fs::canonicalize` on the host path, then
takes the last component as the branch name. The resulting policy:

```text
branch name = "mxc.yellow"
host root   = \\?\D:\git\microsoft\mxc\mxc.yellow
mode        = ReadWrite
```

What the AC child sees from `FindFirstFile` on the projected branch
root (real run, captured in step 1d/step 2 commits):

```text
.azure-pipelines, .cargo, .editorconfig, .git, .gitattributes, .github,
.gitignore, build-mac.sh, build.bat, build.sh, CONTRIBUTING.md, docs,
examples, external, LICENSE.md, playground, README.md, schemas, scripts,
sdk, SECURITY.md, src, SUPPORT.md, test_configs, test_scripts, tools,
TRADEMARKS.md
```

Path remap rule (the entire mapping rule, no caveats):

```text
<host_root>\<rel-path-from-host_root>
  ↦  <projection_root>\<branch_name>\<rel-path-from-host_root>
```

with `<projection_root>` = `%LOCALAPPDATA%\Packages\<ac-profile>\AC\projfs-probe-<run-id>`.

### Concrete example mappings

| Host path | What the AC sees |
|---|---|
| `D:\git\microsoft\mxc\mxc.yellow\src\Cargo.toml` | `…\projfs-probe-<id>\mxc.yellow\src\Cargo.toml` |
| `D:\git\microsoft\mxc\mxc.yellow\docs\schema.md` | `…\projfs-probe-<id>\mxc.yellow\docs\schema.md` |
| `D:\git\microsoft\mxc\mxc.yellow\.git\HEAD` | `…\projfs-probe-<id>\mxc.yellow\.git\HEAD` |
| `D:\git\microsoft\mxc\mxc.yellow\.github\copilot-instructions.md` | `…\projfs-probe-<id>\mxc.yellow\.github\copilot-instructions.md` |

### What works for an agent script

PowerShell-style usage running inside the AC with cwd set to
`<projection_root>\mxc.yellow`:

- `git status`, `git log`, `git checkout` — `git` works on relative
  paths from cwd and reads/writes `.git\…` through the projection.
- `cargo build`, `cargo test`, `cargo check` — same.
- `npm install`, `npm test`; `python script.py`; `pwsh ./build.ps1` —
  same. Anything driven from cwd with relative paths is invariant under
  the remap.
- Filesystem walks: `Get-ChildItem -Recurse`, `git ls-files`, IDE
  indexing — work, because the load-bearing finding from step 1d is
  that `FindFirstFile` succeeds on the projection from inside the AC.
- `$PWD`, `%CD%`, `[System.IO.Path]::GetFullPath('foo')` resolve to
  paths inside the projection. Whatever they produce is internally
  consistent for any process inside the AC.

### What does not work

- Hardcoded absolute host paths. `cd D:\git\microsoft\mxc\mxc.yellow`
  from inside the AC: the path does not exist in the AC's view of the
  world. No projection there; AppContainer baseline doesn't grant
  it. `Test-Path 'D:\git\microsoft\mxc\mxc.yellow'` from inside the AC
  returns `$false`. This applies to any script that resolves a path
  through a "well known" out-of-policy location.
- Cross-process path interchange with processes running *outside* the
  AC. An AC tool that emits `$PWD\result.json` and expects a host-side
  orchestrator to open the same string by name: the host doesn't know
  about the projection path. (The host can resolve it because
  `%LOCALAPPDATA%\Packages\…` exists for the launching user, but the
  semantics are surprising.)
- Stable absolute paths across runs. The current spike uses a per-run
  GUID-suffixed leaf in the projection root to dodge placeholder
  cleanup. So the projection path is *different on every run*. An
  agent script that records its working tree path in a log and expects
  the same path next run will be surprised.

### Design call for step 3

The per-run leaf is a **spike-only** workaround. Step 3 must choose
one of:

1. **Stable leaf name + proper placeholder cleanup.** Use a fixed
   subdir like `<projection_root>\projection\` and on the next run
   walk it via `PrjGetOnDiskFileState` + delete placeholder /
   hydrated / tombstone state explicitly. Production-quality.
   Trade-off: requires correct cleanup; cost ~60 LOC + tests.
2. **Per-run leaf + `MXC_POLICY_ROOT` env var.** Agent script
   discovers the path at startup. No cleanup cost; concurrent runs
   trivially isolated. Trade-off: the path is "different every run"
   which surprises some tooling.

Either makes paths inside the AC stable enough for agent scripts to
work. Hardcoded absolute host paths (e.g. `D:\git\…`) inside the AC
remain unsupported by design — same as DACL-T3 (and any other Windows
filesystem sandbox).

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
.\Test-DenyAceSemantics.ps1                # A-E variants × {regular, LPAC} matrix
```
