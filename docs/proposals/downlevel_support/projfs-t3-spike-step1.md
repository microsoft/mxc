# ProjFS-T3 spike — step 1 findings

Spike branch: `user/gudge/projfs_t3_spike` @ `053119f`
Worktree: `mxc.yellow`
Test host: Windows 11 25H2 (build 26200), non-admin user

## Question step 1 was supposed to answer

Is the architectural premise of "AppContainer + ProjFS-into-AC" viable as a
replacement for T3's "AppContainer + host-DACL augmentation"? Concretely:

1. Is the `Client-ProjFS` optional feature usable on the supported floor?
2. Can a non-admin user create an AppContainer profile and a virtualization
   root inside that profile?
3. Can a ProjFS provider in user mode start virtualizing such a root?
4. **Does an AppContainer process spawned with that profile's SID actually
   see + enumerate + read through the projection — without any host-side
   DACL mutation and without admin priming of `C:\`/`C:\Users\`?**

Question 4 is load-bearing. T3-DACL today fails it: `FindFirstFile` from
inside an AC is blocked unless an admin pre-grants
`ALL APPLICATION PACKAGES:(X)` on every ancestor up to the volume root
(microsoft/mxc#304, `docs/downlevel-fallback-threat-model.md` on the
phase 5 branch).

## Result

All four answered yes, on the test host, end-to-end, with **zero admin used
at runtime**.

| Step | What | Result | Evidence |
|------|------|--------|----------|
| 1a | `LoadLibraryExW("ProjectedFSLib.dll")` + six required exports resolved | ✅ | `feature_detect` (commit `1ae7ca6`) |
| 1b | `CreateAppContainerProfile` non-admin | ✅ — profile at `%LOCALAPPDATA%\Packages\mxc.projfs.spike\AC\`, SID `S-1-15-2-…-511675716` | `ac_profile::ensure_profile` (commit `1ae7ca6`) |
| 1c | `PrjMarkDirectoryAsPlaceholder` + `PrjStartVirtualizing` on a dir inside the AC's `LocalCache`-style folder | ✅ — instance GUID `2E66077F-…`, launching-user reads `hello.txt`/`subdir/inner.txt` through the projection | `virt::start` + smoke read (commit `cfcb1c6`) |
| 1d | AppContainer child spawned with `PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES` reads and **enumerates** via `FindFirstFile`/`ReadFile` through the projection | ✅ — every operation green, JSON below | `ac_launch` + `wxc_projfs_probe_child` (commit `053119f`) |

Raw AC-child JSON from the step-1d run:

```json
{
  "enum_root":   { "succeeded": true, "entries": ["hello.txt", "subdir"] },
  "enum_subdir": { "succeeded": true, "entries": ["inner.txt"] },
  "read_hello":  { "succeeded": true, "bytes_read": 18, "content": "hello from projfs\n" },
  "read_inner":  { "succeeded": true, "bytes_read": 14, "content": "inner content\n" }
}
```

## What this directly invalidates in the current T3-DACL design

| T3-DACL pain | ProjFS-into-AC status | Reference |
|--------------|------------------------|-----------|
| `FindFirstFile` blocked from AC even on granted paths | **Gone.** Every enumeration in the AC child succeeded against the projection. | mxc.green threat-model "Empirically resolved" §; microsoft/mxc#304 |
| Requires admin to grant `ALL APPLICATION PACKAGES:(X)` on `C:\` and `C:\Users\` to make traverse work | **Gone.** Projection lives inside `%LOCALAPPDATA%\Packages\<profile>\…\`; the AC SID owns the traverse chain by construction. | same |
| Requires launching user to have `WRITE_DAC` on every policy path | **Gone.** No host-side DACL is touched. | `WriteDacUnavailable` error path in `fallback_detector` |
| `SetNamedSecurityInfoW` walks descendants on every apply / remove (~800 ms cold on 332k-file tree) | **Gone for the AC-DACL tier.** No descendant walk happens at all. T1's `deniedPaths` augmentation still needs a small DACL helper. | mxc.green phase 6 session notes — perf numbers |
| Per-process named mutex needed to serialize concurrent runs on shared paths | **Gone.** Each run gets its own projection root inside the AC profile. | `filesystem_dacl::with_mutex` |
| `recover_orphaned_state` reaper for crash-safety | **Effectively gone.** No host ACL state to reap; placeholder dirs left over after a crash are inert (cleaned next run via per-run GUID-suffixed root). | `filesystem_dacl::recover_orphaned_state` |
| Concurrent same-`container_id` SID-leak hole | **Gone for filesystem.** Two concurrent runs share a SID but each has its own projection. | mxc.green phase 6 session notes "Concurrent same-name attack — RESIDUAL HOLE" |

The categorical gaps versus T1 listed in the threat model (filesystem
namespace visibility, host-side ACL flicker, TOCTOU between apply and
CreateProcess, reparse-point follow-out) also dissolve to the extent they
depended on the AC having to reach into the real host filesystem. Reparse
handling becomes a provider-side decision in our own callbacks rather than
a recursive walk during ACL apply.

## What step 1 does *not* yet answer

These are deferred to step 2 and step 3 deliberately:

- **RO enforcement.** This spike's `hello.txt` and `inner.txt` are read-only
  by happy accident — the provider's `GetFileData` callback serves the
  bytes but no write would land back on a host source because the host
  source doesn't exist (the content is hardcoded). Step 2 must wire up
  `PRJ_NOTIFICATION_FILE_PRE_CONVERT_TO_FULL` denial on RO branches and
  prove it stops the AC from writing.
- **Reparse-point refusal.** Provider should refuse to expose a placeholder
  for a host-side reparse point inside an allowed directory. Not tested
  here; step 2 work.
- **Path remapping.** The AC child sees the projected path
  (`…\LocalCache\…\projfs-probe-<id>\hello.txt`), not the original host
  path. For agent scripts that hardcode `C:\Users\Alice\proj`, this is a
  behavior change. Step 3 work — design decision, not an architectural
  blocker.
- **Performance characterization.** No real measurements yet. Step 2's
  matrix run produces the first numbers; step 3 compares against the mxc.green
  `Measure-AclIdempotence.ps1` baseline (822 ms cold / 20 ms warm on a
  332k-file tree).
- **Optional-feature enablement deployment story.** `Client-ProjFS` was
  already enabled on this host. Need to confirm what enabling looks like
  on a fresh machine — registry vs `Enable-WindowsOptionalFeature` vs DISM
  — and document the one-time admin cost in the same place we currently
  document MXC's other prerequisites.
- **Pre-21H2 behavior / 21H2 specifically.** Tested only on 25H2.
  Re-run required on 21H2 / 22H2 / 23H2 testbeds before declaring the spike
  done for the supported floor.

## Real bring-up gotchas worth carrying forward

1. **`PrjMarkDirectoryAsPlaceholder` parameter semantics flip between cases.**
   For a *new* virtualization root, `rootPathName` is the directory you are
   marking and `targetPathName` is `NULL` — opposite of what the parameter
   names suggest. Passing `rootPathName = NULL` returns `E_INVALIDARG`.
2. **Placeholders survive `PrjStopVirtualizing`.** The virt root becomes a
   reparse point; `std::fs::remove_dir_all` may not fully clear it, and a
   second `PrjMarkDirectoryAsPlaceholder` against the same path returns
   `STATUS_REPARSE_POINT_ENCOUNTERED` (0x8007112B). Spike uses a GUID-
   suffixed leaf per run; production needs a `PrjGetOnDiskFileState`-aware
   cleanup helper that distinguishes placeholder / hydrated / full /
   tombstone states.
3. **`ResumeThread` must run before `ConnectNamedPipe`.** Created the child
   `CREATE_SUSPENDED` initially "for ordering" — then blocked the probe
   forever in `ConnectNamedPipe` waiting on a suspended child. Resume
   first, then connect.
4. **AC SID needs `GA` (not `FW`) on the pipe DACL.** `FW` alone gives the
   client `ERROR_ACCESS_DENIED` at `CreateFileW`. Pipes need synchronize +
   read-attribute style rights even for write-only clients.
5. **`PRJ_CALLBACK_DATA::FilePathName` is empty for the virt root itself.**
   `StartDirectoryEnumeration` callback may receive an empty PCWSTR for
   the root — handle the empty case as "this is the root."

All five are documented in code comments at the call site so future maintainers
of `wxc_common::filesystem_projfs` don't have to rediscover them.

## Recommendation

Proceed to step 2: build the real provider on top of `virt.rs`/`ac_launch.rs`,
exercising the 8-cell rw/ro/denied/control matrix from
`mxc.green:user/gudge/downlevel_phase6_t3_enumeration:test_scripts/Test-PathEnumeration.ps1`.
The architectural premise has held up; the remaining risk is implementation
complexity, not "does the OS let us do this."

If the matrix run on step 2 is also green, the design-doc work in step 3
should propose **replacing** the current DACL-T3 stack rather than
augmenting it.

## Reproduce

From the spike branch:

```powershell
cd src
cargo build -p wxc_projfs_probe -p wxc_projfs_probe_child
.\target\debug\wxc-projfs-probe.exe
```

Stdout is a single JSON document with one section per step. Exit code
indicates step at which the probe failed:

| Code | Meaning |
|------|---------|
| `0`  | All four steps green |
| `2`  | `Client-ProjFS` not usable (1a) |
| `3`  | AC profile setup failed (1b) |
| `4`  | `PrjStartVirtualizing` failed (1c) |
| `5`  | Launching-user smoke read failed (1c) |
| `6`  | AC child binary not found / failed to launch (1d) |
