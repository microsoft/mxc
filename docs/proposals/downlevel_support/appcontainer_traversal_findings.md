# AppContainer ancestor-traversal — findings

**Status**: complete (initial findings)
**Date**: 2026-05-21
**Companion**:
[fs-projection-composition-plan.md](./fs-projection-composition-plan.md),
[policy_semantics_v1.md](./policy_semantics_v1.md)
**Origin investigation brief**: the file
`appcontainer_traversal_investigation_brief.md` produced by Copilot
CLI session `d739a782-d102-4c2b-b4f9-31b461abef5a` and handed off to
a parallel session.

This document captures the outcome of investigating whether the
previously-paused DACL-tier work and the implicit-traversal language
rule (`policy_semantics_v1.md` F10) are runtime-enforceable on
Windows 11 23H2+. The investigation was prompted by the realization
that `SeChangeNotifyPrivilege` may bypass intermediate-component
access checks during path walk, which would invalidate the
historical conclusion that ancestor ACE work on `C:\`, `C:\Users`,
etc. was required.

## Conclusion

**Implicit traversal (F10) is enforceable on 23H2+ without any
ancestor ACE work.** AppContainer tokens on this build retain
`SeChangeNotifyPrivilege`, and the kernel honors the "Bypass
traverse checking" semantics: intermediate-component `FILE_TRAVERSE`
checks during `IRP_MJ_CREATE` path walk are skipped. The target
object's own DACL still gates target-level access, which is what the
language requires.

**The DACL approach is not viable as a primary FS-policy strategy**,
but for a different reason than the team historically thought.
Traversal works fine. The killer is the **cost of stamping
inheritable ACEs on high-level directories**: NTFS propagates ACE
changes to every descendant of a directory with inheritance enabled,
and on a deep tree (a user profile, a build output tree, `Program
Files`) this is a multi-minute operation that serializes against I/O
on those descendants. Acceptable for the few small RW-root paths
the composition needs (`C:\Users\<u>\temp`, the repo root, etc.) —
not acceptable as a general mechanism for projecting arbitrary
host content.

The composition (AppContainer + bindflt + ProjFS + small owner-side
grant ACEs only on RW roots) remains the right answer. The DACL
tier is retained only for the small-ACE component of the
composition, not as a standalone strategy.

## Evidence

### Privilege presence

AppContainer tokens spawned by MXC on the test host hold
`SeChangeNotifyPrivilege` and have it enabled. (Confirmation method:
operational testing inside an AppContainer; details to be added if
a separate findings session captures them more formally.)

### Traversal behaviour

An AppContainer process can enumerate `C:\etc\src\git\myrepo` when
the `myrepo` directory has an ACE for either the AppContainer's
package SID or `ALL APPLICATION PACKAGES`. No ACE work was needed on
`C:\`, `C:\etc`, `C:\etc\src`, or `C:\etc\src\git` for the
enumeration to succeed.

This confirms:

- Path-walk through `C:\` and intermediate directories is permitted
  by the privilege bypass without ACEs.
- The terminal directory's own DACL still controls
  `FILE_LIST_DIRECTORY` (the right required by enumeration). This is
  exactly what F10 says — implicit traversal grants name resolution
  only, *not* enumeration.

### DACL-approach economics

Independently of traversal, the DACL tier's viability is limited by
the cost of ACE inheritance propagation. Stamping an inheritable
ACE on a directory with N descendants causes NTFS to walk and
update N descendants. For paths the composition would care about as
read roots (`%USERPROFILE%`, `Program Files`, etc.), N is large —
hundreds of thousands to millions. The wall-clock cost is multiple
minutes, and the I/O contention during that window is severe.

The composition's small RW grant ACEs (on `C:\Users\<u>\temp`,
`…\scratch`, `…\workinprogress`, the user's repo) are on
deliberately-bounded trees where N is small. Those remain
acceptable.

## Implications

### For the policy-semantics specification

F10 (implicit traversal) is enforceable as written. Risk R2 in
`policy_semantics_v1.md` is **resolved**. The implicit-traversal
grant is realized by the existing kernel privilege; no per-policy
ancestor ACE work is required at the runtime layer.

This unblocks `policy_semantics_v1.md` to lock implicit traversal
as a foundation rule without conditional language about
"enforceability depends on host privilege grants."

### For the composition

The composition's choice of "small grant ACEs on RW roots only,
nothing on read roots or ancestors" is validated. The composition
does not need to stamp ACEs anywhere for traversal purposes.

### For the DACL tier as a standalone option

The DACL tier (`wxc_common::filesystem_dacl`) is **not** a viable
standalone replacement for the composition, even though traversal
is no longer the killer. Reasoning:

1. **ACL inheritance propagation cost.** Stamping an inheritable
   grant ACE on, e.g., `%USERPROFILE%` or `Program Files` to make
   the AppContainer SID a read grantee is operationally expensive
   (multi-minute I/O storm) and disrupts host activity unrelated to
   MXC. Comparable to the BFS hard-lock in user impact, even though
   the failure mode is different.
2. **No mechanism for non-owned paths.** Even ignoring cost, the
   invoking user lacks `WRITE_DAC` on paths like `C:\Windows`,
   `Program Files`, and `ProgramData` — these are typically owned by
   `TrustedInstaller`. The DACL tier cannot make those paths
   readable for the AppContainer SID at all, so it cannot cover the
   wide-read part of the example policy.
3. **AAP-readable paths are already accessible.** For the parts of
   `C:\Windows` etc. that are AAP-readable, no DACL work is needed
   anyway — those flow through native NTFS access via the package
   SID's inherited AAP ACE. The composition's bindflt R/O identity
   bind on these roots is the cleaner mechanism.

The DACL code (`filesystem_dacl.rs`) is still useful for the
composition's small-ACE component. It is **not** revived as a
standalone tier in `fallback_detector.rs`. The fallback chain
remains:

1. BaseContainer (when available).
2. AppContainer + composition (bindflt + ProjFS + small grant ACEs).
3. Refuse (no viable composition).

The historical "Tier 3 — AppContainer + DACL" arm is retired for
non-composition use.

## Recommendation

1. **Lock F10 in `policy_semantics_v1.md`.** Done in the same commit
   that introduces this findings doc.
2. **Update `fallback_detector.rs` (in the productization phase) to
   remove the standalone DACL tier** as a fallback option. Retain
   the `filesystem_dacl` module as a utility used by the composition
   for small grant/deny ACEs on owned paths.
3. **Add an inheritance-cost note to `filesystem_dacl.rs`'s module
   docs** documenting why this module is for small bounded trees
   only and is not appropriate for high-level directories.
4. **Update `fs-projection-composition-plan.md`** to note that R2 is
   resolved and that the composition's traversal story relies on
   `SeChangeNotifyPrivilege`. Done as part of policy-semantics
   updates referencing this doc.

## Open follow-ups

- **`SeChangeNotifyPrivilege` portability across SKUs and policy
  configurations.** The finding holds on the tested host. Worth
  confirming on the full matrix (Home / Pro / Enterprise; 23H2 /
  24H2 / 25H2) in the same E2E test pass that exercises the
  composition. If any SKU drops the privilege from the AppContainer
  token (we have no evidence this happens, but it would be the
  natural variation point), F10 becomes conditionally enforceable
  and policy_semantics_v1.md would need a fallback story.
- **Group Policy implications.** `SeChangeNotifyPrivilege` is
  granted to `Everyone` by default policy. Enterprise environments
  can revoke it via Group Policy. If MXC is deployed into an
  environment where this has been done, the AppContainer token may
  not have the privilege regardless of the OS build. Worth a probe
  at MXC startup; if absent, refuse-to-run with a clear diagnostic
  is preferable to silent enforcement degradation.

## Cross-references

- Originating brief:
  `~/.copilot/session-state/d739a782-d102-4c2b-b4f9-31b461abef5a/files/appcontainer_traversal_investigation_brief.md`
- Policy semantics rule citing this:
  `policy_semantics_v1.md` § F10, § "Runtime enforcement notes" / R2
- Composition plan: `fs-projection-composition-plan.md`
