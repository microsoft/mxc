# Variant 1 — no leaf marker

**Status**: draft variant, addresses reviewer feedback #1
**Base**: `../policy_semantics_v1.md`
**Branch**: `user/gudge/downlevel-fs-projection-plan`

This document specifies the MXC FS-policy language under the
assumption that **only subtree-scoped entries exist** — there is no
leaf marker. Every entry covers the named host object and, if that
object is a directory, every descendant.

It is otherwise identical to the base spec: deny still means hidden
(F11/F12 unchanged), most-specific path still wins (F6 unchanged),
explicit `D` is still strictly stronger than default-deny (F13
unchanged), etc.

This variant is presented for review alongside two other
single-feedback variants and a merged variant.

## Changes from the base spec

| Aspect | Base spec | This variant |
|---|---|---|
| Markers | Two: `[L]` leaf, `[S]` subtree | None; subtree implicit |
| Schema surface | Each entry carries a marker | Each entry is just a path + intent |
| `RO[L]` on directory case | Useful, expressible | Inexpressible directly; user lists explicit children |
| `RW[L]` on directory case | Validation error (F16a) | Concept doesn't exist |
| Validator rule F8 (marker subsumption) | Present | Removed |
| Validator rule F16a (RW[L] on dir requires child coverage) | Present | Removed |
| Category C (subtree + leaf) | 7 cells | 1 cell (deny-of-a-file) |
| Category D (leaf-on-dir + subtree) | 2 cells | Category disappears |
| Category F4 (same path, mismatched markers) | Dedupe + note | N/A |

The change is **forward-compatible**: introducing leaf markers later
is a strictly-additive language change. Existing v1 policies continue
to mean what they meant (subtree); new policies can opt into a `[L]`
marker on entries that need it. The schema gains an optional field;
older readers treat its absence as "subtree" (i.e., the current
behavior).

Two real cases lose direct expression in this variant:

1. **"Agent may stat directory P but see no descendants."** Under the
   base spec this is `RO[L]` on a directory; under this variant the
   user must list explicit child entries for the contents they want
   exposed, and the directory's stat-ability is implicit via
   name-resolution traversal. The directory cannot be made
   stat-able *in isolation* — at least one descendant must be in the
   policy. For the dev-workflow use cases discussed so far, this
   does not appear to arise.

2. **"Agent may rename or modify metadata on directory P but not on
   its contents."** Under the base spec this is `RW[L]` on a
   directory; under this variant it cannot be expressed. The base
   spec already made this a validation error (F16a) because the
   resulting policy was confusing in practice, so the only loss is
   the option to *attempt* the expression.

## Foundations

Numbered for cross-reference. Bold rule names indicate changes from
the base spec.

### F1 — Three intent lists, no marker

A policy contains three lists, each of which holds entries referring
to host paths:

- `readonly` (`RO`)
- `readwrite` (`RW`)
- `deny` (`D`)

Each entry covers the named host object and, if that object is a
directory, every descendant of the directory.

`D` on a directory covers the directory and every descendant. `D` on
a file covers the file.

### F2 — Paths must exist (v1)

Every explicit entry must resolve to an extant host object at the
time the policy is loaded. (Deny on non-existent paths is deferred,
to be re-opened separately.)

### F3 — Paths are host paths, identity-projected

The policy language references host paths. The contained code
observes those same paths under the same string spelling.

### F4 — Position 3 (delegation from the invoking user)

For `RO`/`RW` entries: the agent receives the named access if and
only if the invoking user themselves has that access on the host. A
policy author cannot delegate access they do not possess. For `D`
entries: the agent is denied unconditionally.

Checked statically at validation time.

### F5 — Default-deny + include fragments

The language defaults to deny. Unlisted paths are inaccessible to
the agent. Includes contribute named entries; after resolution the
language behaves as if every entry were typed explicitly.

### F6 — Most-specific path wins

When multiple entries cover the same path, the entry with the
longest matching path prefix determines the path's semantics.

If two entries on different lists reference the same canonical path,
the policy is **invalid** (validation error) — see F7.

### F7 — Same-path multi-list is a validation error

If two entries on different lists reference the same canonical path,
the policy is rejected.

### F8 — Canonical paths *(formerly F9)*

Before applying F6/F7, every path in the policy is canonicalized:

- drive-letter case normalized;
- path-separator characters normalized;
- trailing separators stripped (except where they distinguish a root);
- `.` and `..` segments collapsed per OS rules;
- environment-variable references resolved.

Symbolic links and junctions are not resolved at canonicalization
time.

### F9 — Implicit traversal *(formerly F10)*

Every explicit entry at path P creates an implicit
name-resolution traversal grant on each strict ancestor of P, for
the single child name on the unique path from the host root to P.
The grant is the minimum capability required to resolve P's name
through its ancestors; it does **not** confer stat, DACL read,
enumeration, or any other capability on the ancestor.

### F10 — Object-level hiding *(formerly F11)*

Where the language says a path is *hidden*, that hiding applies to
the **object** at the path, not just the literal name. Alternative
routes to the same object (file ID, hardlink alias, junction target,
volume-GUID prefix, `\\?\` prefix, 8.3 short name) are also hidden.

### F11 — Hidden = not-found, not access-denied *(formerly F12)*

Operations against a hidden path fail with not-found error codes.
Write-rejection on an `RO` path uses `ACCESS_DENIED` — because RO
does not hide the path.

### F12 — Explicit `D` is strictly stronger than default-deny *(formerly F13)*

Both make paths inaccessible to the agent, but they differ on
operations that don't require capability on the leaf. See base spec
F13 for full detail; unchanged here.

### F13 — Enumeration mirrors existence *(formerly F14)*

`FindFirstFile`/`FindNextFile` on a directory return the names of
children that are themselves visible to the agent.

### F14 — Provenance is irrelevant *(formerly F15)*

Deny applies to whatever object exists at the named host path,
regardless of who created it.

### F15 — RW is always subtree-inheriting on directories *(replaces F16/F16a)*

`RW` on a directory grants full write authority — create, delete,
rename, modify metadata and DACL, add and remove children — on the
directory and every descendant.

There is no way to grant write authority on a directory's own
metadata without also granting write authority on its contents.
(This case existed in the base spec as `RW[L]` on a directory, but
was a validation error in the base spec, so the loss is theoretical.)

### F16 — `RW` ⇒ `R` *(formerly F17)*

`readwrite` includes read.

### F17 — Validator role *(formerly F18)*

The validator performs:

- include resolution (recursive, with cycle detection);
- path canonicalization (F8);
- deduplication (entries that contribute nothing on top of others);
- conflict detection (F7);
- suspicious-nesting warnings (cross-list ancestor/descendant pairs
  that might be unintended);
- Position-3 access check (F4).

Outputs: normalized policy, errors, warnings.

## The four observables

| Observable | What the agent does | Under RO | Under RW | Under D |
|---|---|---|---|---|
| Existence | `GetFileAttributes`, listed in parent enumeration | Y | Y | N (hidden) |
| Metadata | DACL read, timestamps, attributes | Y | Y | N |
| Read | open for `GENERIC_READ`, read bytes | Y | Y | N |
| Write | open for write, modify, delete, rename, mutate DACL or timestamps, create children (subtree) | N | Y | N |

## Each intent in isolation

### Readonly (`RO`)

| Observable | `RO P` (subtree on dir) | `RO P` (on file) |
|---|---|---|
| existence(P) | Y | Y |
| metadata(P) | Y | Y |
| read(P) | Y | Y |
| enumerate(P) | Y (subject to F13) | n/a |
| write(P) | N | N |
| existence(descendant) | Y | n/a |
| metadata(descendant) | Y | n/a |
| read(descendant) | Y | n/a |
| write(descendant) | N | n/a |

Corner operations (subtree RO): all listed return N with
`ACCESS_DENIED`: create, delete, rename, truncate, modify
attributes/timestamps, modify DACL, `DELETE_ON_CLOSE`, append, open-
for-write-then-don't-write, mmap read-write. mmap read-only returns
Y. `READ_CONTROL` / `SYNCHRONIZE` return Y.

### Readwrite (`RW`)

| Observable | `RW P` (subtree on dir) | `RW P` (on file) |
|---|---|---|
| existence(P) | Y | Y |
| metadata read(P) | Y | Y |
| metadata write(P) | Y | Y |
| read(P) | Y | Y |
| enumerate(P) | Y (subject to F13) | n/a |
| write children of P (`FILE_ADD_FILE`, etc.) | Y | n/a |
| existence(descendant) | Y | n/a |
| metadata(descendant) | Y | n/a |
| read(descendant) | Y | n/a |
| write(descendant) | Y | n/a |

All corner operations Y, including DACL mutation, rename, delete.

### Deny (`D`)

| Observable | `D P` (on dir) | `D P` (on file) |
|---|---|---|
| existence(P) | N | N |
| metadata(P) | N | N |
| read(P) | N | N |
| write(P) | N | N |
| existence(descendant) | N | n/a |
| metadata(descendant) | N | n/a |
| read(descendant) | N | n/a |
| write(descendant) | N | n/a |
| `CreateFile CREATE_NEW` at P | not-found | not-found |
| enumeration of `parent(P)` | omits P | omits P |
| open by file ID | not-found (F10) | not-found |
| open via `\\?\Volume{…}` | not-found (F10) | not-found |

### Examples

```
RO C:\Windows
RO C:\Users\gudge\.gitconfig
```

| Operation | Path | Result | Reason |
|---|---|---|---|
| read | `C:\Windows\System32\kernel32.dll` | success | RO subtree |
| write | `C:\Windows\System32\kernel32.dll` | `ACCESS_DENIED` | RO subtree denies writes |
| read | `C:\Users\gudge\.gitconfig` | success | RO on file |
| `SetFileTime` | `C:\Users\gudge\.gitconfig` | `ACCESS_DENIED` | RO denies metadata write |
| read | `C:\Users\gudge\.bash_history` | not-found | default-deny |

```
RW C:\etc\src\git\myrepo
RW C:\Users\gudge\temp
```

| Operation | Path | Result |
|---|---|---|
| write | `C:\etc\src\git\myrepo\src\main.rs` | success |
| `DeleteFile` | `C:\etc\src\git\myrepo\src\main.rs` | success |
| `MoveFile` `myrepo\foo.txt` → `myrepo\bar.txt` | success |
| `CreateFile CREATE_NEW` | `C:\Users\gudge\temp\new.log` | success |

```
RW C:\etc\src\git\myrepo
D  C:\etc\src\git\myrepo\.env
```

| Operation | Path | Result |
|---|---|---|
| read | `C:\etc\src\git\myrepo\src\main.rs` | success |
| read | `C:\etc\src\git\myrepo\.env` | not-found |
| `CreateFile CREATE_NEW` | `C:\etc\src\git\myrepo\.env` | not-found |
| `FindFirstFile C:\etc\src\git\myrepo\*` | omits `.env` |

## Interaction matrix

### Category A — same path, two intents

Per F7: validation error in every form.

| Cell | Entries (same path P) | Result |
|---|---|---|
| A1 | `RO P` + `RW P` | validation error |
| A2 | `RO P` + `D P` | validation error |
| A3 | `RW P` + `D P` | validation error |
| A4 | All three at same P | validation error (one diagnostic) |

### Category B — outer + inner (both subtree)

| Cell | Outer at P | Inner at P\sub | Inner scope (Q) | Between | Validator |
|---|---|---|---|---|---|
| B1 | `RO` | `RW` | RW | RO | OK |
| B2 | `RW` | `RO` | RO | RW | OK |
| B3 | `RO` | `D` | hidden | RO | OK |
| B4 | `RW` | `D` | hidden | RW | OK |
| B5 | `D` | `RW` | RW | hidden | warn (allow-inside-deny) |
| B6 | `D` | `RO` | RO | hidden | warn (allow-inside-deny) |

#### Example — B4 (canonical RW+D)

```
RW C:\Users\gudge\Documents\workinprogress
D  C:\Users\gudge\Documents\workinprogress\private
```

| Path | Result |
|---|---|
| `…\workinprogress\notes.txt` (read/write) | success |
| `…\workinprogress\private` (any op) | not-found |
| `…\workinprogress\private\secret.txt` (any op) | not-found |
| `FindFirstFile …\workinprogress\*` | omits `private` |

#### Example — B2 (RO carve-out inside RW)

```
RW C:\etc\src\git\myrepo
RO C:\etc\src\git\myrepo\.git
```

| Path | Result |
|---|---|
| `myrepo\src\main.rs` (write) | success |
| `myrepo\.git\config` (read) | success |
| `myrepo\.git\config` (write) | `ACCESS_DENIED` |
| `myrepo\.git\index` (write) | `ACCESS_DENIED` |

### Category C — outer subtree + inner deny on file leaf

(Category C in this variant only has the deny-of-a-single-file shape;
RO/RW leaf-on-file cases collapse because RO/RW on a file is just
RO/RW on that file under F1.)

| Cell | Outer at P | Inner at P\x (file) | P\x | Between | Validator |
|---|---|---|---|---|---|
| C1 | `RO` | `D` | hidden | RO | OK |
| C2 | `RW` | `D` | hidden | RW | OK |
| C3 | `D` | (RO/RW on a file inside D) | per inner | hidden | warn |

Note that `RO P` + `RO P\x` where `x` is a file is *redundant* — the
outer covers the inner. The validator deduplicates. This is the same
shape as the base spec's F1 (Category F), simplified.

#### Example — C2

```
RW C:\etc\src\git\myrepo
D  C:\etc\src\git\myrepo\.env
```

(Same as the in-isolation D example above.)

### Category D *(disappears)*

The base spec's Category D was "outer leaf-on-directory + inner
subtree." With no leaf marker, this category does not exist.

### Category E — disjoint siblings

Trivial: each entry governs its own scope; no interaction.

### Category F — multiple entries with the same intent

| Cell | Combination | Runtime | Validator |
|---|---|---|---|
| F1 | Two same-intent entries, one nested in the other | inner is redundant | dedupe + warn |
| F2 | Two identical entries | one is redundant | silent dedupe |

(The base spec's F4 — same path, same intent, mismatched markers —
does not arise in this variant.)

### Category G — rename across regions

Unchanged from base spec. Source needs write on source dir;
destination needs write on dest dir.

| Cell | Source | Destination | Result | Failure |
|---|---|---|---|---|
| G1 | RW (same subtree) | RW (same subtree) | succeeds | — |
| G2 | RW (subtree A) | RW (subtree B) | succeeds | — |
| G3 | RW | RO | fails at dest | `ACCESS_DENIED` |
| G4 | RW | D | fails at dest | not-found |
| G5 | RO | RW | fails at source | `ACCESS_DENIED` |
| G6 | D | anywhere | fails at source | not-found |
| G7 | implicit-traversal-only | RW | fails at source | `ACCESS_DENIED` |

### Category H — interactions with the implicit default region

| Cell | Behavior |
|---|---|
| H1 | unlisted read fails-as-not-found (default-deny) |
| H2 | unlisted write fails-as-not-found |
| H3 | read inside RW subtree succeeds (F16) |
| H4 | Position 3 grant honored if user has access; validation error otherwise |

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

| Operation | Path | Result |
|---|---|---|
| read | `C:\Windows\System32\kernel32.dll` | success |
| read | `C:\Program Files\Git\cmd\git.exe` | success |
| read | `C:\Users\gudge\.gitconfig` | success |
| write | `C:\Users\gudge\.gitconfig` | `ACCESS_DENIED` |
| read | `C:\Users\gudge\.cargo\config.toml` | success |
| read/write | `C:\etc\src\git\myrepo\src\main.rs` | success |
| read/write | `C:\Users\gudge\temp\out.log` | success |
| read/write | `…\workinprogress\note.md` | success |
| any op | `…\workinprogress\private` | not-found |
| read | `C:\Users\gudge\.bash_history` | not-found |
| `FindFirstFile C:\Users\gudge\*` | omits `private` |

## Validator pseudocode (informative)

```text
validate(policy):
  entries = resolve_includes(policy.entries, fragments)

  for e in entries:
    e.path = canonicalize(e.path)

  for e in entries:
    if not exists(e.path):
      error("path does not exist: " + e.path)

  # Bucket by path and detect conflicts/dedupes
  buckets = group_by(entries, e -> e.path)
  for path, bucket in buckets:
    intents = distinct(bucket, e -> e.intent)
    if len(intents) > 1:
      error("intent conflict at " + path, F7)
    bucket = dedupe(bucket)

  # Nesting checks
  for outer, inner in nesting_pairs(entries):
    if outer.intent == inner.intent:
      warn("redundant nested entry: " + inner.path)
    elif suspicious_nesting(outer, inner):
      warn(suspicious_nesting_description(outer, inner))

  # Position 3 check
  for e in entries:
    if e.intent in [RO, RW]:
      if not user_has_access(invoking_user, e.path, e.intent):
        error("user cannot delegate access they lack at " + e.path, F4)

  return NormalizedPolicy(entries, errors, warnings)
```

Compared to the base spec, this validator does not need an F16a
check (no leaf-on-dir-without-children case) or marker-subsumption
normalization (no markers).

## Runtime enforcement notes

Same risks R1/R3, R2, R4, R5 as the base spec, with the same
mitigations. R5b is irrelevant in this variant (the case it
addressed required `RW[L]` on a directory, which does not exist).

## Open questions and deferrals

- **OQ-S1**: Capability carve-outs within an intent. Deferred.
- **OQ-S2**: Policy behavior for paths deleted and recreated mid-run.
  Deferred.
- **OQ-S3**: Deny on non-existent paths. Deferred (separate discussion).
- **OQ-S5**: Should the validator surface implicit-traversal? No.
- **OQ-S6**: Position 3's user-access probe at validation time. Implementation detail.
- **OQ-S7**: Constraint-only alternative to default-deny. Deferred.
- **OQ-S8**: Per-Windows-version include variants. Implementation detail.
- **OQ-V1 (variant-specific)**: When does the leaf marker get added
  back, and what use cases drive it? Currently deferred indefinitely.
