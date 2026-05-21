# MXC downlevel FS projection — design summary

Audience: familiar with Windows FS internals and minifilters; no
prior exposure to the bindflt or ProjFS codebases.

## TL;DR

Project parts of the host filesystem into an AppContainer on
Win11 23H2+ by layering **two minifilters with strictly separated
roles**:

- **bindflt = naming**. Per-Job, per-SID kernel-level path
  rewriting with R/O flag and per-mapping exception lists. The
  caller's token is what reaches the backing file.
- **ProjFS = access brokering**. Lazy-hydration cache backed by
  a user-mode provider; the provider opens backing files under
  *its* token and feeds bytes to the filter to materialize.

Each does only what it's best at. Naming is bindflt's whole job.
Brokering reads the AppContainer principal can't natively perform
is ProjFS's whole job. **R/O brokered reads use both filters in
tandem; R/W writes only ever go through bindflt — ProjFS is not
on the write path.**

The invariant that keeps the state machine sane is about *modes*,
not about which filters participate: a given path picks exactly
one of three modes —

> - **R/W direct**: bindflt R/W identity bind + package-SID grant ACE. ProjFS not involved.
> - **R/O brokered**: bindflt R/O redirect into the virt root + ProjFS provider. Both filters on the path.
> - **AAP-readable R/O**: bindflt R/O identity bind (or nothing). No broker.
>
> Modes never overlap on the same path. In particular ProjFS
> never sits under a writable bind, so the provider never sees
> convert-to-full, mirror-back-to-source, or rename-across-
> boundary cases.

## Naming vs access

The critical framing — and the reason the obvious "swap BFS for
bindflt" doesn't work:

- **bindflt rewrites names.** A bind `C:\virt → C:\real` lets
  `\??\C:\virt\foo` reach the backing object at `\??\C:\real\foo`,
  but the create still runs with the **caller's** token against
  the **backing** DACL. Bindflt does not impersonate. *Anything
  unreadable at the destination is unreadable through a bind.*
- **ProjFS brokers access.** The kernel filter (`prjflt.sys`)
  upcalls a user-mode provider to materialize placeholders; the
  provider opens the real file under *its* token and returns
  bytes via `PrjWriteFileData`. **The provider's token is the
  access principal.** The caller's token never touches the
  backing file.

BFS was an access broker too, but in kernel mode with its own
policy engine. ProjFS gives us the same broker property with our
policy in user mode, under code we own and can fix without a
Windows servicing event. Anything that's a *naming* problem
(rewriting, hiding, R/O flag, scoping) is bindflt's job; anything
that's an *access* problem (the principal isn't on the backing
DACL) is ProjFS's job.

## Composition

Per-run lifecycle inside `wxc-exec.exe`:

1. **AppContainer SID + Job.** SID is the leaf principal; Job is
   the scoping handle bindflt accepts.
2. **Private virt root** at
   `%LOCALAPPDATA%\Microsoft\MXC\runs\<run-id>\virt\`. User-owned;
   ACL'd to grant the package SID traverse + read.
3. **`PrjStartVirtualizing`** rooted at the virt dir. Provider
   runs on threads inside `wxc-exec.exe` under the **real user's
   token** — the access principal for brokered reads.
4. **bindflt mappings** via `BfSetupFilterEx` (per-Job, per-SID,
   exception list), more-specific wins:
   - **R/W identity** for each writable root (repo, scratch,
     temp, work dirs). `…\private` in the exception list when
     the policy denies a sub-path.
   - **R/O identity** for AAP-readable system roots
     (`C:\Windows`, `Program Files*`, `ProgramData`, `Users\Public`).
     Access flows through the package SID's inherited
     `ALL APPLICATION PACKAGES` ACE — native NTFS perf, no
     broker, no copy.
   - **R/O ProjFS-redirected** for the non-AAP-readable residual
     (`C:\Users\<u>` → `<virt>\Users\<u>`), with the R/W subtrees
     above in the exception list so they stay direct-bound.
5. **Grant ACE** for the package SID on each writable root
   (inheritable, descendant scope). Plus a deny ACE on any
   in-RW deny path. Paths are user-owned; `WRITE_DAC` available;
   tracked in the existing `filesystem_dacl` crash-restore.
6. **Spawn child** into AppContainer + Job.
7. **Teardown**: child exits → Job closes (bindflt mappings die
   with it) → `PrjStopVirtualizing` → recursive delete of virt
   root → revoke ACEs.

## Path-by-path behaviour (example policy)

Policy: R/W on `C:\etc\src\git\myrepo`, `…\temp`, `…\workinprogress`.
Wide R/O on the rest of `C:`. Deny `…\workinprogress\private`.
Deny non-existent `C:\temp\logs`.

| Container call | bindflt | ProjFS | Backing principal | Result |
|---|---|---|---|---|
| Read `C:\Windows\System32\kernel32.dll` | R/O identity | no | AppContainer via AAP | native NTFS |
| Read `C:\Program Files\Git\cmd\git.exe` | R/O identity | no | AppContainer via AAP | native NTFS |
| Read `C:\Users\<u>\.gitconfig` | ProjFS-redirected R/O | yes | provider (real user) | cold: upcall + hydrate. warm: page cache |
| Write `C:\Users\<u>\.gitconfig` | same | yes | provider rejects | `ACCESS_DENIED` |
| R/W `C:\etc\src\git\myrepo\…` | R/W identity | no | AppContainer via grant ACE | native NTFS |
| R/W `C:\Users\<u>\temp\…` | R/W identity (more specific) | no | AppContainer via grant ACE | native NTFS |
| Any access `…\workinprogress\private\…` | excluded by RW bind exception; provider also denies | yes, refused | n/a | fails; deny ACE is defence-in-depth |
| Create `C:\NonExistent\x.txt` | no match | no | AppContainer at raw `C:\` | fails at NTFS |
| Create `C:\temp\logs\app.log` | no match | no | AppContainer at raw `C:\` | fails at NTFS |
| `FindFirstFile C:\Users\<u>\*` | ProjFS-redirected | yes | provider enumerates real dir; merge with bindflt R/W subtree names | coherent, no dupes |

## Performance and disk-space model

| Class | Mechanism | Cold | Warm | Virt-root disk |
|---|---|---|---|---|
| R/W subtree | bindflt identity + grant ACE | native | native | 0 |
| AAP-readable system root | bindflt R/O identity | native | native | 0 |
| Brokered R/O residual | ProjFS via provider | one upcall per first-touched file | NTFS page cache | grows with touched-files set |
| Excluded path | bindflt exception + provider deny + optional deny ACE | n/a | n/a | 0 |
| Outside any bind | raw host | n/a | n/a | n/a (fails AppContainer ACL) |

**The heavy stuff doesn't go through the provider.** System DLLs,
SDK headers, toolchains, Git install, Node runtime — all bindflt
R/O direct, native, zero materialization cost. The provider's
working set is just the user-profile config and tool caches the
policy exposes R/O. Cold-start tax scales with that residual,
not with the size of the system roots a naïve "route all of
`C:\` through ProjFS" design would have pulled in.

## What ProjFS does on write — and what we do about it

This is worth being explicit about because BFS *did* broker
writes back to the source. ProjFS does not, and we don't want it
to.

**Out of the box**: ProjFS is not a write-through filter. A
write to a placeholder triggers a state-machine transition —
placeholder → full file — gated by the `PRJ_NOTIFICATION_FILE_
PRE_CONVERT_TO_FULL` notification. If allowed, the placeholder
is hydrated, the reparse point stripped, and the write lands in
the **virt root's on-disk file**. The source backing file is
never touched. Any mirror-back-to-source has to be implemented
by the provider, typically via the post-notification
`PRJ_NOTIFICATION_FILE_HANDLE_CLOSED_FILE_MODIFIED`. There is no
pre-write hook — convert-to-full is the chokepoint.

**Our provider blocks all writes at convert-to-full.** Notification
mask includes:

- `PRJ_NOTIFICATION_FILE_PRE_CONVERT_TO_FULL` — block write
  promotion.
- `PRJ_NOTIFICATION_NEW_FILE_CREATED` (rejected) — block new
  files created under the virt namespace.
- `PRJ_NOTIFICATION_PRE_DELETE`, `…_PRE_RENAME`,
  `…_PRE_SET_HARDLINK` — block mutations of existing names.

Returning a failing `HRESULT` from any pre-notification surfaces
as `STATUS_ACCESS_DENIED` to the container. Nothing materializes
in the virt root that wasn't a read-side hydration. No mirror
logic, no atomicity story, no conflict resolution, no tombstone
bookkeeping for deletes, no rename-across-bind-boundary edge
cases.

We sidestep every write-side complication by enforcing the
invariant from the top: writable paths never go through ProjFS.
If the policy needs to write at `C:\Users\<u>\something`, that
subtree is a bindflt R/W identity bind plus a grant ACE for the
package SID, and it sits in the exception list of the ProjFS
bind covering `C:\Users\<u>`. The write hits NTFS at the real
host path directly; ProjFS is not in the picture.

## Why this composition vs alternatives

- **bindflt alone**: a naming layer with no broker can't satisfy
  reads where the package SID isn't already on the backing DACL —
  collapses "wide read" to "AAP-default only", which misses things
  like `.gitconfig`.
- **DACL-only**: requires `WRITE_DAC` on every ancestor of every
  readable path. We don't own most of `C:\`. Blast radius and
  reversal cost out of proportion to the value.
- **Isolated local user**: solves wide-read trivially via natural
  Users-group ACEs, but it's a containment-model swap (loses
  Credential Manager, retargets WFP, needs admin to provision).
  Plausibly the right uplevel direction; not a downlevel point
  fix.
- **BaseContainer**: the OS does it for us via
  `Experimental_CreateProcessInSandbox`. Not available downlevel.
- **BFS**: structurally what we want, but hard-locks 25H2 hosts;
  the OS-side fixes have not been serviced downlevel.

ProjFS + bindflt gets us BFS's broker property under our own
code, keeps AppContainer (and its WFP/network/integrity story)
unchanged, preserves path identity for the contained process,
and limits host mutation to small ACEs on paths we own.

## Open points for review

- **`CreateBindLink` (public, `bindlink.h`, `NTDDI_WIN10_CU`) vs
  `BfSetupFilterEx` (internal `bindflt_pub.h`).** Strong suspicion
  we need the internal API for per-Job/per-SID + exception lists +
  batched configuration. Creates an internal-header build
  dependency for the SDK.
- **Name-bypass surface.** Bindflt is a name-based filter. File
  IDs and `\\?\Volume{…}` opens skip the *naming* contract,
  though AppContainer SID still gates *access*. Want ProcMon data
  against real workloads before declaring victory.
- **Defender on materialize.** `PrjWriteFileData` newly writes
  into the virt root → classic scan-on-write surface. Latency
  budget impact TBD.
- **Enumeration merging.** `FindFirstFile C:\Users\<u>\*` is
  ProjFS for the source rows + bindflt overlay for R/W subtree
  names; sketch in the in-repo doc, wants a careful read.
- **AAP allowlist drift.** The set of AAP-readable system roots
  varies across Windows releases. Captured as a versioned
  machine-readable capability profile per backend
  (`schemas/.../container-capabilities/`), CI-verified on a
  clean image.

## Pointer to the full plan

Branch `user/gudge/downlevel-fs-projection-plan`, doc at
`docs/proposals/downlevel_support/fs-projection-composition-plan.md`.
Contains the runtime walkthrough, performance model, two-day
spike plan, productization roadmap, risk register, and
capability-profile schema sketch.
