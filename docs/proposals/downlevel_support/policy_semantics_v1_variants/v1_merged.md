# Merged variant — all three reviewer feedbacks combined

**Status**: draft variant, addresses reviewer feedbacks #1, #2, #3 together
**Base**: `../policy_semantics_v1.md`
**Branch**: `user/gudge/downlevel-fs-projection-plan`

This document specifies the MXC FS-policy language under the
assumption that **all three reviewer feedbacks are accepted**:

1. **No leaf marker.** Entries are subtree-implicit on directories;
   files have no descendants. (Variant 1.)
2. **`D` produces access-denied, not hidden.** Namespace visibility
   is reserved for a future namespace-mapping policy. (Variant 2.)
3. **`D` unconditionally trumps `RO`/`RW`.** Allow-inside-deny is a
   validation error. (Variant 3.)

The result is a substantially smaller, more conservative language
than the base spec. Sections that no longer apply are deleted rather
than carried with notes.

This variant is presented for review alongside the three
single-feedback variants.

## Summary of changes vs the base spec

| Aspect | Base spec | This merged variant |
|---|---|---|
| Markers | Two (`[L]`, `[S]`) | None; subtree implicit |
| Effect of `D` | Path hidden, ops not-found | Path visible; ops `ACCESS_DENIED` |
| `D` vs `RO`/`RW` precedence | Most-specific-wins | `D` always wins |
| Allow inside deny | Warned, allowed | Validation error |
| Object-level hiding | Strict | Dropped (policy is path-based) |
| Number of foundation rules | 18 | 14 |
| Interaction matrix categories | 8 (A–H) | 7 (D disappears, F shrinks, B/C lose cells) |
| Runtime risk register | 5 risks | 1 risk (R2 already resolved; R1/R3/R4/R5/R5b all evaporate) |

The language is **significantly simpler** under the merged variant:
shorter foundation list, smaller matrix, fewer enforcement risks,
sharper semantic roles for each intent. Reviewer concerns that
motivated each individual change reinforce each other when combined.

## Foundations

Numbered for cross-reference. Comments in parens indicate which
base-spec rule(s) each one corresponds to or replaces.

### F1 — Three intent lists, no marker

A policy contains three lists of host paths:

- `readonly` (`RO`)
- `readwrite` (`RW`)
- `deny` (`D`)

Each entry covers the named host object and, if that object is a
directory, every descendant.

(Replaces base F1.)

### F2 — Paths must exist (v1)

Every explicit entry must resolve to an extant host object at policy
load time. (Deny on non-existent paths deferred separately.)

### F3 — Paths are host paths, identity-projected

The policy language references host paths. The contained code
observes the same path strings.

### F4 — Position 3 (delegation from the invoking user)

For `RO`/`RW`: the agent receives the named access if and only if
the invoking user themselves has that access on the host. For `D`:
the agent is denied unconditionally.

Checked statically at validation time.

### F5 — Default-deny + include fragments

Unlisted paths are inaccessible to the agent. Includes contribute
named entries; after resolution the language behaves as if every
entry were typed explicitly.

### F6 — Deny trumps allow; among allows, most-specific wins

Precedence:

1. **If any `D` entry covers the path, the path is denied.** No
   `RO` or `RW` entry can override.

2. **Otherwise, among `RO` and `RW` entries covering the path, the
   one with the longest matching path prefix determines the
   semantics.**

(Combines base F6 with variant-3 changes.)

### F7 — Same-path multi-list is a validation error

If two entries on different lists reference the same canonical path,
the policy is rejected.

### F8 — `RO`/`RW` inside a `D` subtree is a validation error

If an `RO` or `RW` entry's path is a descendant of any `D` entry's
path, the policy is rejected. The user must either remove the `D`
entry (and rely on default-deny for everything else) or remove the
`RO`/`RW` entry.

(From variant-3 F8a.)

### F9 — Canonical paths

Before applying F6/F7/F8, every path is canonicalized: drive-letter
case, separator characters, trailing separator, `.`/`..` collapse,
environment-variable resolution. Symlinks and junctions are not
resolved at canonicalization.

### F10 — Implicit traversal

Every explicit entry at path P creates an implicit name-resolution
traversal grant on each strict ancestor of P, for the single child
name on the unique path from the host root to P. Does not confer
stat, DACL read, enumeration, or any other capability on the
ancestor.

Enforceable via `SeChangeNotifyPrivilege` on Windows 11 23H2+; see
[`../appcontainer_traversal_findings.md`](../appcontainer_traversal_findings.md).

### F11 — `D` produces access-denied, not hidden

Operations against a denied path return `ACCESS_DENIED`. The denied
path remains visible to the agent: `GetFileAttributes` returns the
host attributes; `FindFirstFile` on the parent directory includes
the denied path in its results.

Operations refused under `D`:

- read / write of any kind;
- enumeration of the denied path's contents (`FILE_LIST_DIRECTORY`
  on the denied directory);
- create, delete, rename, modify DACL or timestamps;
- `CreateFile CREATE_NEW` at the denied path.

The denied path's *existence* and *metadata* remain observable. Only
operations on it are refused.

(Replaces base F11 + F12.)

### F12 — Path-based, not object-based

The policy applies to **named paths**. If a denied object is also
reachable via another path (hardlink alias, junction target,
volume-GUID, file-ID), that other path is governed independently. To
deny both names, list both.

(Replaces base F11 object-level hiding.)

### F13 — Provenance is irrelevant

`D` applies to whatever object exists at the named path, regardless
of who created it. A file created during the run at a denied path
is refused going forward; the file may still exist on the host but
the agent cannot access it.

(Renumbered base F15. Base F13 — explicit-D vs default-deny — is
not a distinct rule under access-denied semantics; both produce
`ACCESS_DENIED` for refused operations.)

### F14 — Validator role

The validator performs:

- include resolution (recursive, with cycle detection);
- path canonicalization (F9);
- existence checks (F2);
- deduplication (entries that contribute nothing on top of others);
- conflict detection (F7);
- F8 ancestry check (`RO`/`RW` inside `D` subtree → error);
- suspicious-nesting warnings within the allow category (e.g.
  `RW` inside `RO` is fine but worth confirming);
- Position-3 access check (F4).

Outputs: normalized policy, errors, warnings.

(Renumbered. Base F8, F16, F16a, F17 either folded into F1/F6/F11 or
unnecessary under merged semantics.)

## The four observables

| Observable | What the agent does | Under RO | Under RW | Under D |
|---|---|---|---|---|
| Existence | `GetFileAttributes`, listed in parent enumeration | Y | Y | Y (path visible) |
| Metadata | DACL read, timestamps, attributes | Y | Y | Y |
| Read | open for `GENERIC_READ`, read bytes | Y | Y | N (`ACCESS_DENIED`) |
| Write | open for write, modify, delete, rename, mutate DACL or timestamps, create children | N (`ACCESS_DENIED`) | Y | N (`ACCESS_DENIED`) |

## Each intent in isolation

### Readonly (`RO`)

| Observable | `RO P` (on dir, subtree-implicit) | `RO P` (on file) |
|---|---|---|
| existence | Y | Y |
| metadata | Y | Y |
| read | Y | Y |
| enumerate(P) | Y | n/a |
| write | N (`ACCESS_DENIED`) | N (`ACCESS_DENIED`) |
| existence(descendant) | Y | n/a |
| read(descendant) | Y | n/a |
| write(descendant) | N (`ACCESS_DENIED`) | n/a |

### Readwrite (`RW`)

| Observable | `RW P` (on dir) | `RW P` (on file) |
|---|---|---|
| existence | Y | Y |
| metadata read | Y | Y |
| metadata write | Y | Y |
| read | Y | Y |
| enumerate(P) | Y | n/a |
| write children | Y | n/a |
| existence(descendant) | Y | n/a |
| read(descendant) | Y | n/a |
| write(descendant) | Y | n/a |

Full mutation rights including DACL, rename, delete.

### Deny (`D`)

| Observable | `D P` (on dir) | `D P` (on file) |
|---|---|---|
| existence | Y (path visible in parent enumeration) | Y |
| metadata | Y (`GetFileAttributes` returns host attrs) | Y |
| read | N (`ACCESS_DENIED`) | N (`ACCESS_DENIED`) |
| enumerate(P) (i.e., listing children of denied dir) | N (`ACCESS_DENIED`) | n/a |
| write | N (`ACCESS_DENIED`) | N (`ACCESS_DENIED`) |
| existence(descendant) | N (descendant names not discoverable, because parent enumeration is denied) | n/a |
| read(descendant) | N (`ACCESS_DENIED`) | n/a |
| write(descendant) | N (`ACCESS_DENIED`) | n/a |
| `CreateFile CREATE_NEW` at P | `ACCESS_DENIED` | `ACCESS_DENIED` |
| enumeration of `parent(P)` | **includes P** by name | **includes P** by name |
| open via alternate path (hardlink alias etc.) | host DACL applies (per F12) | host DACL applies |

So the agent sees a denied directory by name in its parent's listing
but cannot peer inside it. The agent sees a denied file by name and
can read its metadata but cannot read its contents.

### Examples

```
RO C:\Windows
RO C:\Users\gudge\.gitconfig
```

| Operation | Path | Result |
|---|---|---|
| read | `C:\Windows\System32\kernel32.dll` | success |
| write | `C:\Windows\System32\kernel32.dll` | `ACCESS_DENIED` |
| read | `C:\Users\gudge\.gitconfig` | success |
| write | `C:\Users\gudge\.gitconfig` | `ACCESS_DENIED` |
| read | `C:\Users\gudge\.bash_history` | `ACCESS_DENIED` (default-deny) |

```
RW C:\etc\src\git\myrepo
D  C:\etc\src\git\myrepo\.env
```

| Operation | Path | Result |
|---|---|---|
| read | `C:\etc\src\git\myrepo\src\main.rs` | success |
| `GetFileAttributes` | `C:\etc\src\git\myrepo\.env` | success, real attrs |
| `FindFirstFile C:\etc\src\git\myrepo\*` | listing | **includes `.env`** |
| read | `C:\etc\src\git\myrepo\.env` | `ACCESS_DENIED` |
| write | `C:\etc\src\git\myrepo\.env` | `ACCESS_DENIED` |
| `CreateFile CREATE_NEW` | `C:\etc\src\git\myrepo\.env` | `ACCESS_DENIED` |

## Interaction matrix

### Category A — same path, two intents

Per F7: validation error in every form.

| Cell | Entries (same path P) | Result |
|---|---|---|
| A1 | `RO P` + `RW P` | validation error |
| A2 | `RO P` + `D P` | validation error |
| A3 | `RW P` + `D P` | validation error |
| A4 | All three at P | validation error |

### Category B — outer + inner

| Cell | Outer at P | Inner at P\sub | Result |
|---|---|---|---|
| B1 | `RO` | `RW` | OK; inner wins for descendants of `sub` (most-specific within allows) |
| B2 | `RW` | `RO` | OK; inner wins |
| B3 | `RO` | `D` | OK; deny applied to `sub` |
| B4 | `RW` | `D` | OK; deny applied to `sub` (canonical pattern) |
| B5 | `D` | `RW` | **validation error (F8)** |
| B6 | `D` | `RO` | **validation error (F8)** |

#### Example — B4

```
RW C:\Users\gudge\Documents\workinprogress
D  C:\Users\gudge\Documents\workinprogress\private
```

| Path | Result |
|---|---|
| `…\workinprogress\notes.txt` (read/write) | success |
| `…\workinprogress\private` (any op against P itself) | `ACCESS_DENIED` |
| `…\workinprogress\private` (`GetFileAttributes`) | success, real attrs |
| `…\workinprogress\private\secret.txt` (any op) | `ACCESS_DENIED` |
| `FindFirstFile …\workinprogress\*` | **includes `private`** |
| `FindFirstFile …\workinprogress\private\*` | `ACCESS_DENIED` |

### Category C — outer subtree + inner deny on file

(With no leaf marker, RO/RW on files is just RO/RW on the file —
nothing distinct to enumerate. Category C is now only about
deny-of-file-inside-allow-subtree.)

| Cell | Outer at P | Inner at P\x (file) | Result |
|---|---|---|---|
| C1 | `RO` | `D` (file) | OK |
| C2 | `RW` | `D` (file) | OK (canonical) |

#### Example — C2

```
RW C:\etc\src\git\myrepo
D  C:\etc\src\git\myrepo\.env
```

(Already shown above in in-isolation D examples.)

### Categories D, F4 — disappear

Base spec's Category D was "outer leaf-on-directory + inner subtree."
With no leaf marker, the case does not exist.

Base spec's Category F4 was "same path, mismatched markers." With
no markers, the case does not exist.

### Category E — disjoint siblings

Trivial. Each entry governs its own scope independently.

### Category F — multiple entries with the same intent

| Cell | Combination | Result | Validator |
|---|---|---|---|
| F1 | Two same-intent entries, one nested in the other | inner is redundant; outer covers | dedupe + warn |
| F2 | Two identical entries | redundant | silent dedupe |

### Category G — rename across regions

| Cell | Source | Destination | Result | Failure |
|---|---|---|---|---|
| G1 | RW (same subtree) | RW (same subtree) | succeeds | — |
| G2 | RW (subtree A) | RW (subtree B) | succeeds | — |
| G3 | RW | RO | fails at dest | `ACCESS_DENIED` |
| G4 | RW | D | fails at dest | **`ACCESS_DENIED`** |
| G5 | RO | RW | fails at source | `ACCESS_DENIED` |
| G6 | D | anywhere | fails at source | **`ACCESS_DENIED`** |
| G7 | implicit-traversal-only | RW | fails at source | `ACCESS_DENIED` |

Every rename failure under this variant is `ACCESS_DENIED`. The
distinction the base spec drew between "destination is RO" vs
"destination is D" no longer surfaces in the error code; both fail
the same way. The user can distinguish by the path's listed
disposition (the destination exists with denied metadata vs the
source doesn't exist with denied metadata).

### Category H — implicit default region

| Cell | Behavior |
|---|---|
| H1 | unlisted read fails-as-`ACCESS_DENIED` |
| H2 | unlisted write fails-as-`ACCESS_DENIED` |
| H3 | read inside RW subtree succeeds |
| H4 | Position 3 grant honored if user has access; validation error otherwise |

All failures from policy are `ACCESS_DENIED`. The only not-found
errors the agent sees are for paths that genuinely don't exist on
the host.

## End-to-end worked example

```
include "windows-dev-readonly-defaults"

RW C:\etc\src\git\myrepo
RW C:\Users\gudge\temp
RW C:\Users\gudge\scratch
RW C:\Users\gudge\Documents\workinprogress
D  C:\Users\gudge\Documents\workinprogress\private
```

Include (illustrative) contributes:

```
RO C:\Windows
RO C:\Program Files
RO C:\Program Files (x86)
RO C:\ProgramData
RO C:\Users\Public
RO C:\Users\gudge\.gitconfig
RO C:\Users\gudge\.ssh\known_hosts
RO C:\Users\gudge\.cargo
RO C:\Users\gudge\.nuget
```

What the agent observes:

| Operation | Path | Result |
|---|---|---|
| read | `C:\Windows\System32\kernel32.dll` | success |
| read | `C:\Program Files\Git\cmd\git.exe` | success |
| read | `C:\Users\gudge\.gitconfig` | success |
| write | `C:\Users\gudge\.gitconfig` | `ACCESS_DENIED` |
| read/write | `C:\etc\src\git\myrepo\src\main.rs` | success |
| read/write | `C:\Users\gudge\temp\out.log` | success |
| read/write | `…\workinprogress\note.md` | success |
| `GetFileAttributes` | `…\workinprogress\private` | success, real attrs |
| `FindFirstFile …\workinprogress\*` | **includes `private`** |
| any op against contents | `…\workinprogress\private\anything` | `ACCESS_DENIED` |
| `FindFirstFile …\workinprogress\private\*` | `ACCESS_DENIED` |
| read | `C:\Users\gudge\.bash_history` | `ACCESS_DENIED` (default-deny) |
| `GetFileAttributes` | `C:\Users\gudge\.bash_history` | `ACCESS_DENIED` |

`git status`, `cargo build`, `pwsh -c 'Get-ChildItem'` against the
repo all work. The agent can see that `private` exists but cannot
access its contents. The agent can see that `.gitconfig` exists,
can read it, but cannot modify it. The agent's view of
`%USERPROFILE%` shows directory entries that exist on the host
including ones the agent has no access to.

## Validator pseudocode

```text
validate(policy):
  entries = resolve_includes(policy.entries, fragments)

  for e in entries:
    e.path = canonicalize(e.path)

  for e in entries:
    if not exists(e.path):
      error("path does not exist: " + e.path)

  # Bucket and detect conflicts/dedupes
  buckets = group_by(entries, e -> e.path)
  for path, bucket in buckets:
    intents = distinct(bucket, e -> e.intent)
    if len(intents) > 1:
      error("intent conflict at " + path, F7)
    bucket = dedupe(bucket)

  # F8: RO/RW inside D subtree is a validation error
  d_entries = [e for e in entries if e.intent == D]
  for e in entries:
    if e.intent in [RO, RW]:
      for d in d_entries:
        if is_descendant_of(e.path, d.path):
          error("entry " + e.path + " is shadowed by ancestor "
                + d.path + "; either remove the D or remove the "
                + "RO/RW", F8)

  # Nesting warnings (among allow entries only)
  for outer, inner in nesting_pairs(entries):
    if outer.intent == D or inner.intent == D:
      continue  # handled by F8
    if outer.intent == inner.intent:
      warn("redundant nested entry: " + inner.path)
    elif suspicious_nesting_among_allows(outer, inner):
      warn(suspicious_nesting_description(outer, inner))

  # Position 3 check
  for e in entries:
    if e.intent in [RO, RW]:
      if not user_has_access(invoking_user, e.path, e.intent):
        error("user cannot delegate access they lack at " + e.path, F4)

  return NormalizedPolicy(entries, errors, warnings)
```

## Runtime enforcement notes

Risk register dramatically reduced compared to base spec:

| Risk | Description | Status under this variant |
|---|---|---|
| R1 / R3 | Object-level hiding via file ID, hardlink, etc. | **Evaporates** (F12 explicitly path-based) |
| R2 | Implicit traversal needing ancestor ACEs | Resolved (`SeChangeNotifyPrivilege`) |
| R4 | Hidden returning ACCESS_DENIED instead of not-found | **Evaporates** (ACCESS_DENIED is the spec'd behavior) |
| R5 | Enumeration filtering for deny inside RW | **Evaporates** (no filtering needed) |
| R5b | Create-then-invisible at default-deny under writable parent | Doesn't arise (no `RW[L]` because no leaf marker) |

The only remaining "risk" worth noting is the soft one from variant
3: shipping include fragments must be authored carefully so that no
user policy will trigger F8 errors when an `include` is combined
with user `D` entries. This is a fragment-quality concern, not a
runtime risk per se.

## Namespace policy as a future concern

This variant separates FS access policy from namespace mapping
policy. The two are distinct concerns:

- **FS access policy** — what the agent is permitted to *do* with
  what it can see. The subject of this document.
- **Namespace mapping policy** — what the agent is permitted to
  *see*. Hiding paths, presenting alternate names, restricting
  enumeration.

For v1, namespace mapping is out of scope. The FS access policy
gives the agent visibility consistent with what the OS would normally
show; access control restricts what the agent can do.

Use cases that motivated the "hidden" behavior of `D` in the base
spec are not lost, but they are deferred:

- "Agent should not even know this exists" → future namespace policy.
- "Agent should not enumerate this directory" → already satisfied:
  `D` on a directory refuses `FILE_LIST_DIRECTORY`, so contents are
  not enumerable.
- "Agent should not be able to probe this filename" → partly
  satisfied: the agent can see the name if it appears in a parent's
  enumeration, but operations against it all fail with
  `ACCESS_DENIED`. Hiding the name itself is a namespace concern.

## Open questions and deferrals

- **OQ-S1**: Capability carve-outs within an intent. Deferred.
- **OQ-S2**: Deleted-and-recreated paths. Deferred.
- **OQ-S3**: Deny on non-existent paths. Under access-denied
  semantics this is conceptually simple: a denied non-existent path
  means future create attempts fail with `ACCESS_DENIED`. Worth
  re-opening separately in the same review round; not in this
  variant.
- **OQ-S5**: Validator surfaces implicit-traversal? No.
- **OQ-S6**: Position 3 user-access probe API. Implementation detail.
- **OQ-S7**: Constraint-only alternative. Deferred.
- **OQ-S8**: Per-Windows-version include variants. Implementation detail.
- **OQ-M1 (merged-variant-specific)**: When does the leaf marker
  get added back? What use cases drive it? Currently deferred
  indefinitely.
- **OQ-M2 (merged-variant-specific)**: Namespace mapping policy
  design. Reserved for future iteration.
- **OQ-M3 (merged-variant-specific)**: Allow-inside-deny via an
  explicit override marker (e.g. `RW!`). Not in v1; revisit if real
  use cases demand it.

## Cross-references

- Base spec: `../policy_semantics_v1.md`
- Per-feedback variants:
  - `v1_no_leaf.md` (feedback #1 only)
  - `v1_d_access_denied.md` (feedback #2 only)
  - `v1_d_trumps.md` (feedback #3 only)
- Composition plan: `../fs-projection-composition-plan.md`
- Composition summary: `../projfs_bindflt_summary.md`
- Traversal findings: `../appcontainer_traversal_findings.md`
- Originating session: `copilot --resume d739a782-d102-4c2b-b4f9-31b461abef5a`
