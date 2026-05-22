# Variant 2 — deny means access-denied (not hidden)

**Status**: draft variant, addresses reviewer feedback #2
**Base**: `../policy_semantics_v1.md`
**Branch**: `user/gudge/downlevel-fs-projection-plan`

This document specifies the MXC FS-policy language under the
assumption that **`D` produces access-denied, not hidden**. Denied
paths remain visible to the agent (enumeration lists them; stat
returns metadata); operations against them fail with
`ACCESS_DENIED`.

The reviewer's framing motivating this change: filesystem policy
should govern *access* (what the agent can do); *namespace policy*
should govern *visibility* (what the agent can see). Bundling
visibility into the FS policy conflates two distinct concerns.

It is otherwise identical to the base spec: leaf and subtree markers
both exist (F1 unchanged), most-specific path still wins (F6
unchanged), Position 3 unchanged, etc.

This variant is presented for review alongside two other
single-feedback variants and a merged variant.

## Changes from the base spec

| Aspect | Base spec | This variant |
|---|---|---|
| Effect of `D` | Path hidden (existence: N) | Path visible; operations return `ACCESS_DENIED` |
| Failure mode for ops on `D` paths | not-found | `ACCESS_DENIED` |
| Enumeration of parent of `D` path | omits the `D` path | includes the `D` path |
| `CreateFile CREATE_NEW` on `D` path | not-found | `ACCESS_DENIED` |
| Open by file ID / hardlink alias / volume-GUID of `D` object | not-found | depends — see F10 below |
| F10 (object-level hiding) | Strict: hidden via any route | Reduced: applies per-path; aliases listed separately |
| F11 (hidden = not-found) | Present | Removed |
| F12 (explicit `D` ≠ default-deny) | Distinction matters | Distinction collapses |
| F13 (enumeration mirrors existence) | Filters hidden children | Just enumerates real children |
| Runtime risk R1/R3 (object-level hiding via non-name routes) | Degrade-and-surface | Risk evaporates |
| Runtime risk R4 (hidden returns ACCESS_DENIED) | Mitigated by layer ordering | Risk evaporates (it's the spec'd behavior now) |
| Runtime risk R5 (enumeration filtering for deny in RW) | Bindflt exception list | Risk evaporates |
| Namespace mapping | (implicit; bundled with `D`) | Explicit future concern, separate policy |

The model becomes much closer to **Windows DACL deny ACEs**. The
agent can probe the namespace and see what's denied; it just can't
do anything to it.

## What we lose

- **Defense-in-depth via hiding.** An agent that's curious or
  compromised can enumerate denied paths and learn the host's
  directory structure. The data is inaccessible, but the *shape* is
  not.
- **A clean answer to "the agent should not even know this exists."**
  That intent is now reserved for a future namespace-mapping policy.
- **Implementability simplicity for object-level identity.** Under
  the base spec we said deny applied to the object via any route
  (file ID, hardlink, volume-GUID). Under this variant we don't
  promise that — the policy is path-based and aliases must be listed
  separately. The runtime is simpler; the language is slightly less
  expressive.

## What we gain

- **Sharper separation of concerns.** Access and visibility are
  distinct; the FS policy is only about access.
- **Simpler enforcement.** Several runtime risks evaporate; the
  enforcement layer does not need to special-case denied paths in
  enumeration callbacks or in the provider's create logic.
- **Predictability.** Every failure caused by the policy is
  `ACCESS_DENIED`. Not-found means the path doesn't exist on the
  host. The agent's error-handling code can be simpler.
- **Closer match to host semantics.** Windows ACLs use the same
  pattern — deny ACEs make operations fail with `ACCESS_DENIED`, not
  hide the path.

## Foundations

Numbered for cross-reference. Bold rule names indicate changes from
the base spec.

### F1 — Three intent lists, two markers

Unchanged from base spec.

### F2 — Paths must exist (v1)

Unchanged.

### F3 — Paths are host paths, identity-projected

Unchanged.

### F4 — Position 3 (delegation from the invoking user)

Unchanged.

### F5 — Default-deny + include fragments

Unchanged.

### F6 — Most-specific-wins precedence

Unchanged.

### F7 — Same-path multi-list is a validation error

Unchanged.

### F8 — Marker subsumption

Unchanged.

### F9 — Canonical paths

Unchanged.

### F10 — Implicit traversal

Unchanged.

### **F11 — `D` produces access-denied, not hidden** *(replaces base spec F11/F12)*

Operations against a denied path return `ACCESS_DENIED` (or whatever
NTFS would naturally return when access is refused — typically
`ERROR_ACCESS_DENIED`).

The denied path remains visible to the agent:

- `GetFileAttributes` returns the actual host attributes;
- `FindFirstFile` on the parent directory includes the denied path
  in its results;
- the path's name, size, timestamps, and other metadata are
  readable.

Operations refused under `D`:

- read (`CreateFile` with `GENERIC_READ` or with any access mask
  that implies read);
- write (any access mask implying write);
- enumeration of the denied path's *contents* if it is a directory
  (the directory entry itself is listed in its parent; opening it
  with `FILE_LIST_DIRECTORY` is refused);
- `CreateFile CREATE_NEW` at the denied path;
- delete, rename, modify DACL/timestamps, etc.

The path itself remains present in the namespace; only operations
on it are refused. This is structurally identical to how Windows
DACL deny ACEs behave.

### **F12 — Path-based, not object-based** *(replaces base spec F11 object-level hiding)*

The policy applies to **named paths**. If a denied object is also
reachable via another path (hardlink alias, junction target, alternate
mount point), that other path is governed independently by the
policy. If the user wants both names denied, they must list both.

The previous base-spec rule that "deny applies to the object via any
route" is dropped. Open-by-file-ID and volume-GUID opens follow the
host DACL; the policy mediates path-based opens. Under our
composition, this is what bindflt and ProjFS naturally provide.

### **F13 — Explicit `D` is no different from default-deny for refused operations** *(replaces base spec F13)*

Under the base spec, explicit `D` and default-deny differed because
explicit `D` *hid* the path while default-deny merely failed to
grant capability. Without hiding, both produce the same observable
behavior:

- An operation requiring capability on the path fails with
  `ACCESS_DENIED`, whether the path is in an explicit `D` entry or
  in no entry at all.
- An operation requiring capability on the parent (e.g.
  `CREATE_NEW`) succeeds if the parent grants it. Under default-deny,
  the new file is then accessible per whatever its closest covering
  entry says. Under explicit `D` on the new file's path, the
  creation is refused.

The distinction is now narrower: explicit `D` is a per-path
assertion that operations on the path are refused. Default-deny is
the absence of any assertion.

### F14 — Enumeration follows host directory contents *(replaces base spec F14)*

`FindFirstFile`/`FindNextFile` on a directory returns the real host
listing for that directory. Denied children appear in the listing
with their actual names. Opening any specific child for an operation
that the policy refuses returns `ACCESS_DENIED`.

This is a simplification: the enumeration logic does not need to
filter results based on policy. The policy is applied at open time,
not at enumeration time.

### F15 — Provenance is irrelevant

Unchanged from base spec semantics; if anything, the rule is simpler
under access-denied semantics: a file at a denied path is refused
regardless of who created it, with `ACCESS_DENIED` on access.

### F16 — `[L]` on a directory grants only the directory's own metadata

Unchanged.

### F16a — `RW[L]` on a directory without child coverage is a validation error

Unchanged.

### F17 — `RW` ⇒ `R`

Unchanged.

### F18 — Validator role

Unchanged.

## The four observables

| Observable | Under RO | Under RW | Under D |
|---|---|---|---|
| Existence | Y | Y | **Y (visible; agent can `GetFileAttributes`)** |
| Metadata | Y | Y | **Y (DACL/timestamps/attributes readable)** |
| Read | Y | Y | N (`ACCESS_DENIED`) |
| Write | N (`ACCESS_DENIED`) | Y | N (`ACCESS_DENIED`) |

Note the difference from the base spec: under `D`, *existence* and
*metadata* are Y; only read and write operations are refused.

## Each intent in isolation

### Readonly — unchanged from base spec.

### Readwrite — unchanged from base spec.

### **Deny** — substantial change.

| Observable | `D[S]` on directory | `D[L-file]` on file |
|---|---|---|
| existence(P) | Y | Y |
| metadata(P) | Y | Y |
| read(P) | N (`ACCESS_DENIED`) | N (`ACCESS_DENIED`) |
| write(P) | N (`ACCESS_DENIED`) | N (`ACCESS_DENIED`) |
| `FindFirstFile P\*` (enumerate contents of denied directory) | N (`ACCESS_DENIED`) | n/a |
| existence(descendant) | **Y per F14 — descendant names visible in P's parent listing** | n/a |
| metadata(descendant) | N (`ACCESS_DENIED`) | n/a |
| read(descendant) | N (`ACCESS_DENIED`) | n/a |
| write(descendant) | N (`ACCESS_DENIED`) | n/a |
| `CreateFile CREATE_NEW` at P | `ACCESS_DENIED` | `ACCESS_DENIED` |
| enumeration of `parent(P)` | **includes P** | **includes P** |
| open by file ID matching P | host DACL applies (per F12) | host DACL applies |
| open via `\\?\Volume{…}\…\P` | host DACL applies | host DACL applies |

Subtle case for `D[S]` on a directory + descendants: the descendant
*names* are visible (because the descendant directory's
`FindFirstFile *` is refused; the parent's enumeration shows the
denied directory by name; but the user *can* still walk through —
wait, no, opening the denied directory for enumeration is itself
refused).

Let me be precise: with `D[S] C:\foo`:

- `FindFirstFile C:\*` returns `foo` as one of the entries.
- `GetFileAttributes C:\foo` returns the actual attributes.
- `FindFirstFile C:\foo\*` returns `ACCESS_DENIED` (because opening
  the directory for enumeration requires `FILE_LIST_DIRECTORY`,
  which `D` denies).
- The names of children of `foo` are therefore **not** discoverable
  by the agent through enumeration. They are only discoverable if
  the agent already knows the names (e.g., `C:\foo\bar.txt` via
  prior knowledge, which then returns `ACCESS_DENIED` on open).

So enumeration-of-denied-directory-contents is the case where the
agent's view *is* restricted (the child names aren't visible).
Enumeration-of-the-parent-of-a-denied-directory is *not* restricted
(the denied directory's name is visible).

### Examples

```
RW C:\Users\gudge\Documents\workinprogress
D  C:\Users\gudge\Documents\workinprogress\private
```

| Operation | Path | Result | Reason |
|---|---|---|---|
| `GetFileAttributes` | `…\workinprogress\private` | success, real attrs | `D` doesn't hide |
| `FindFirstFile …\workinprogress\*` | listing | **includes `private`** | not hidden |
| `CreateFile … GENERIC_READ` | `…\workinprogress\private` | `ACCESS_DENIED` | `D` refuses read |
| `CreateFile … GENERIC_READ` | `…\workinprogress\private\secret.txt` | `ACCESS_DENIED` | `D[S]` covers descendants |
| `FindFirstFile …\workinprogress\private\*` | `ACCESS_DENIED` | enumeration of contents refused |
| `CreateFile CREATE_NEW` | `…\workinprogress\private\new.txt` | `ACCESS_DENIED` | F11 |
| `CreateDirectory` | `…\workinprogress\private\sub` | `ACCESS_DENIED` | F11 |

Worth contrasting with the base-spec results:

| | Base spec | This variant |
|---|---|---|
| `GetFileAttributes …\private` | not-found | success, real attrs |
| `FindFirstFile …\workinprogress\*` listing | omits `private` | includes `private` |
| `CreateFile …\private GENERIC_READ` | not-found | `ACCESS_DENIED` |
| `CreateFile …\private\secret.txt GENERIC_READ` | not-found | `ACCESS_DENIED` |

The agent under this variant *sees* there is a `private` directory
and *knows* the policy is refusing access to it. Under the base
spec the agent doesn't know `private` exists at all.

## Interaction matrix

### Category A — same path, two intents

Per F7: validation error in every form. Unchanged.

### Category B — outer subtree + inner subtree

| Cell | Outer at P | Inner at P\sub | Q (descendants of P\sub) | Between | Validator |
|---|---|---|---|---|---|
| B1 | `RO[S]` | `RW[S]` | RW | RO | OK |
| B2 | `RW[S]` | `RO[S]` | RO | RW | OK |
| B3 | `RO[S]` | `D[S]` | denied (access-denied) | RO | OK |
| B4 | `RW[S]` | `D[S]` | denied | RW | OK |
| B5 | `D[S]` | `RW[S]` | RW | denied | warn (allow-inside-deny) |
| B6 | `D[S]` | `RO[S]` | RO | denied | warn (allow-inside-deny) |

The cells are structurally identical to the base spec; the only
change is the meaning of "denied" — access-denied, not hidden.

#### Example — B4 (canonical RW + D)

```
RW[S] C:\Users\gudge\Documents\workinprogress
D[S]  C:\Users\gudge\Documents\workinprogress\private
```

(Same observable behavior as the in-isolation D example above.)

### Category C — outer subtree + inner leaf

| Cell | Outer at P | Inner at P\x | P\x itself | Descendants of P\x | Between | Validator |
|---|---|---|---|---|---|---|
| C1 | `RO[S]` | `RW[L]` file | RW | n/a | RO | OK |
| C2 | `RO[S]` | `RW[L]` dir | RW (metadata only) | RO (per outer) | RO | warn |
| C3 | `RW[S]` | `RO[L]` file | RO | n/a | RW | OK |
| C4 | `RW[S]` | `RO[L]` dir | RO (metadata only) | RW (per outer) | RW | OK |
| C5 | `RO[S]` | `D[L-file]` | denied | n/a | RO | OK |
| C6 | `RW[S]` | `D[L-file]` | denied | n/a | RW | OK |
| C7 | `D[S]` | `RW[L]` or `RO[L]` | per inner | denied if dir | denied | warn |

Structurally the same as the base spec; "hidden" cells become
"denied" (access-denied).

### Category D — outer leaf-on-directory + inner subtree

Unchanged structurally from base spec; D2 is still a validation
error per F16a.

### Category E — disjoint siblings

Trivial. Unchanged.

### Category F — multiple entries with the same intent

Unchanged.

### Category G — rename across regions

| Cell | Source | Destination | Result | Failure |
|---|---|---|---|---|
| G1 | RW (same subtree) | RW (same subtree) | succeeds | — |
| G2 | RW (subtree A) | RW (subtree B) | succeeds | — |
| G3 | RW | RO | fails at dest | `ACCESS_DENIED` |
| G4 | RW | D | fails at dest | **`ACCESS_DENIED`** (was not-found) |
| G5 | RO | RW | fails at source | `ACCESS_DENIED` |
| G6 | D | anywhere | fails at source | **`ACCESS_DENIED`** (was not-found) |
| G7 | implicit-traversal-only | RW | fails at source | `ACCESS_DENIED` |

The two cells that change are G4 and G6 — the denial-failure becomes
`ACCESS_DENIED` everywhere. Easier to reason about, easier to
diagnose.

### Category H — implicit default region

| Cell | Behavior |
|---|---|
| H1 | unlisted read fails-as-`ACCESS_DENIED` (was not-found in base under hiding; but default-deny was always closer to access-denied — both are unified now) |
| H2 | unlisted write fails-as-`ACCESS_DENIED` |
| H3 | read inside RW subtree succeeds |
| H4 | Position 3 grant honored if user has access; validation error otherwise |

Subtle change: under the base spec, unlisted paths "felt hidden" in
the sense that operations failed with not-found. Under this variant,
unlisted paths fail with `ACCESS_DENIED`. The agent can probe whether
a path exists (via `GetFileAttributes`, which is also access-denied)
— no, actually under default-deny, `GetFileAttributes` on an unlisted
path also fails with `ACCESS_DENIED`. So the agent can't actually
distinguish "path exists but I have no access" from "path doesn't
exist" except by listing the parent and seeing whether the name is
there.

So the *parent's* listing still leaks namespace shape (this is the
real difference between this variant and the base). For most workloads
this is fine; for high-sensitivity workloads where namespace
visibility matters, a separate namespace-mapping policy can provide
hiding on top.

## Namespace policy as a future concern

(New section, motivated by this variant.)

This variant separates FS access policy from namespace mapping
policy. The two are distinct concerns:

- **FS access policy** — what the agent is permitted to *do*. The
  subject of this document.
- **Namespace mapping policy** — what the agent is permitted to
  *see*. What names appear in the agent's view, which paths map to
  which host objects, whether some paths are hidden or renamed.

A future namespace policy could, for example:

- Hide specified paths entirely (the base-spec behavior of `D`);
- Mount host paths at different virtual paths in the container's
  view;
- Present a synthesized directory tree that differs from the host's
  layout;
- Selectively grant or refuse traversal through specific naming
  ancestors.

For v1, namespace mapping is out of scope. The FS access policy
gives the agent visibility consistent with what the OS would normally
show; access control restricts what the agent can do with what it
sees.

## End-to-end worked example

```
include "windows-dev-readonly-defaults"

RW[S] C:\etc\src\git\myrepo
RW[S] C:\Users\gudge\temp
RW[S] C:\Users\gudge\scratch
RW[S] C:\Users\gudge\Documents\workinprogress
D[S]  C:\Users\gudge\Documents\workinprogress\private
```

| Operation | Path | Result | Reason |
|---|---|---|---|
| read | `C:\Windows\System32\kernel32.dll` | success | include |
| read | `C:\Users\gudge\.gitconfig` | success | include |
| write | `C:\Users\gudge\.gitconfig` | `ACCESS_DENIED` | RO |
| `GetFileAttributes` | `…\workinprogress\private` | success, real attrs | **D doesn't hide** |
| `FindFirstFile …\workinprogress\*` | includes `private` | **D doesn't hide** |
| any op on contents | `…\workinprogress\private\anything` | `ACCESS_DENIED` | D refuses access |
| `FindFirstFile …\workinprogress\private\*` | `ACCESS_DENIED` | enum of denied dir refused |

The user *sees* there is a `private` directory in their working
area. The agent also sees it. Neither can read its contents.

For the agentic-dev-workflow use cases discussed, this is probably
fine: the agent's job is to do dev work, not to be unaware of the
user's directory layout. If the user wants the agent to be unaware,
they will request namespace policy in a future iteration.

## Validator pseudocode

Unchanged from base spec.

## Runtime enforcement notes

| Risk | Description | Status under this variant |
|---|---|---|
| R1 / R3 | Object-level hiding via file ID, hardlink alias | **Evaporates** — F12 explicitly path-based |
| R2 | Implicit traversal needing ancestor ACEs | Resolved per `appcontainer_traversal_findings.md` (unchanged) |
| R4 | Hidden returning ACCESS_DENIED instead of not-found | **Evaporates** — ACCESS_DENIED is the spec'd behavior |
| R5 | Enumeration filtering for deny inside RW | **Evaporates** — no filtering needed |
| R5b | Create-then-invisible at default-deny under writable parent | Resolved by F16a (unchanged) |

This variant **simplifies enforcement substantially**. The bindflt
layer does not need to filter enumeration through exception lists for
deny paths; the ProjFS provider does not need a denylist that
returns not-found on create attempts; the backstop deny ACE returns
the same error code as the language specifies (no mismatched-error-
code degradation). The composition becomes easier to implement and
to audit.

## Open questions and deferrals

- **OQ-S1**: Capability carve-outs. Deferred.
- **OQ-S2**: Deleted-and-recreated paths. Deferred.
- **OQ-S3**: Deny on non-existent paths. Under access-denied
  semantics this is simpler: a denied non-existent path means
  attempts to create the path fail with `ACCESS_DENIED`. Worth
  reconsidering whether to allow it in v1 separately.
- **OQ-S5**: Validator surfaces implicit-traversal? No.
- **OQ-S6**: Position 3 user-access probe API. Implementation detail.
- **OQ-S7**: Constraint-only alternative. Deferred.
- **OQ-S8**: Per-Windows-version include variants. Implementation detail.
- **OQ-V2 (variant-specific)**: Namespace mapping policy design.
  Reserved for future iteration; no v1 work.
- **OQ-V2b (variant-specific)**: Defense-in-depth implications of
  the agent being able to enumerate denied path *names* (not
  contents). For most use cases this is acceptable; high-sensitivity
  workloads may want namespace policy in addition to FS policy.
