# MXC FS-policy semantics — v1 language specification

**Status**: draft, language-only (enforcement-independent)
**Owner**: gudge (with Copilot CLI as pair)
**Branch**: `user/gudge/downlevel-fs-projection-plan`
**Companion docs**:
- `docs/proposals/downlevel_support/fs-projection-composition-plan.md`
- `docs/proposals/downlevel_support/projfs_bindflt_summary.md`

**Resume the originating Copilot CLI session**:

```
copilot --resume d739a782-d102-4c2b-b4f9-31b461abef5a
```

This document specifies the **semantic meaning** of an MXC FS policy.
It is intentionally enforcement-agnostic — it describes what the
contained code should observe given a policy, without committing to a
particular kernel filter, ACL strategy, or backend. Mapping these
semantics onto concrete primitives (AppContainer, bindflt, ProjFS,
DACL, BaseContainer, etc.) is the subject of the companion documents.

The policy semantics are derived from a sequence of conversations
captured in the Copilot CLI session above. Cross-references to that
derivation appear inline where helpful.

## Scope and non-goals

### In scope

- The semantics of the three policy intents (`readonly`, `readwrite`,
  `deny`), the two entry markers (leaf, subtree), and their
  interactions.
- The semantics of default-deny and include fragments.
- The static validation rules that catch malformed or contradictory
  policies.
- Behavior of common filesystem operations (open, read, write,
  enumerate, create, delete, rename, stat, modify metadata) under
  every policy combination.
- Expected error/return-value shape (not-found vs access-denied) for
  each rejection class.

### Out of scope (deferred to future versions)

- Capability carve-outs within an intent ("RW but not DACL-write",
  "RW but root-immutable").
- Policy behavior when a named path is deleted and re-created during
  a run.
- Deny entries on paths that do not yet exist (i.e. "prevent creation
  at P"). Currently any explicit entry must reference an extant host
  object.
- Copy-on-write semantics for RW subtrees (writes are *always* real
  host effects in v1).
- Cross-principal policies (e.g. agent-on-behalf-of-other-user). The
  policy author is implicitly the invoking user.

## Foundational rules

These rules govern every behavior described later in the document. They
are listed first so subsequent sections can cite them by name.

### F1 — Three intent lists, two markers

A policy contains three lists, each of which holds entries referring to
host paths:

- `readonly` (`RO`)
- `readwrite` (`RW`)
- `deny` (`D`)

Each entry carries one of two markers:

- `[L]` — **leaf**: the entry's semantics apply only to the named host
  object.
- `[S]` — **subtree**: the entry's semantics apply to the named host
  object and every descendant.

`D` on a directory is **always subtree-scoped**, regardless of marker.
The leaf marker on a directory deny entry is meaningless; if the named
path is a directory, the entry behaves as `D[S]`.

### F2 — Paths must exist (v1)

Every explicit entry must resolve to an extant host object at the time
the policy is loaded. A policy that names a non-existent path is
rejected by the validator. (Non-existent-path deny is deferred per the
non-goals.)

### F3 — Paths are host paths, identity-projected

The policy language references host paths. The contained code observes
those same paths under the same string spelling. A host path `H` appears
to the contained code as `H`. There is no separate "container path
space" in the language.

### F4 — Position 3 (delegation from the invoking user)

The policy is a **delegation from the invoking user to the contained
agent**. For `RO`/`RW` entries:

> The agent receives the named access if and only if the invoking user
> themselves has that access on the host. A policy author cannot
> delegate access they do not possess.

For `D` entries:

> The agent is denied the named access unconditionally, independent of
> the invoking user's access. Withdrawal does not require the
> withdrawer to have had the access being withdrawn.

The Position 3 check on `RO`/`RW` is performed at **policy-load time**
(static validation). Entries that exceed the invoking user's access
are rejected before the run starts; the agent never observes a
runtime "would-have-worked-but-user-can't" failure.

### F5 — Default-deny + include fragments

The language defaults to **deny**. Unlisted paths are inaccessible to
the agent. To make the language ergonomic, policies may `include`
shipped, versioned fragments that contribute named entries. A typical
policy is a thin user-specific layer plus one or two include lines
that pull in standard sets like `windows-dev-readonly-defaults`.

After include resolution, the language behaves as if the user typed
every entry explicitly.

### F6 — Most-specific-wins precedence

When multiple entries cover the same path, the entry with the longest
matching path prefix wins. If two entries cover the same exact path
with different intents, the policy is **invalid** (validation error)
— see F7.

`[S]` on path P covers P and all descendants of P. `[L]` on path P
covers only P. So `RW[L] C:\a\b` is more specific than `RW[S] C:\a` at
path `C:\a\b`, but the leaf says nothing about `C:\a\b\c`, which falls
back to `C:\a`'s subtree coverage.

### F7 — Same-path multi-list is a validation error

If two entries on different lists reference the same canonical path,
the policy is rejected. The user is contradicting themselves; the
runtime should not silently downgrade.

Same path, same intent, different markers is **not** a conflict; see
F8.

### F8 — Marker subsumption

Same path, same intent, mismatched markers: `[S]` strictly subsumes
`[L]`. The validator normalizes to `[S]` and emits a low-severity
note. (Not an error.)

### F9 — Canonical paths

Before applying F6/F7/F8, every path in the policy is canonicalized:

- drive-letter case normalized (upper-case);
- path-separator characters normalized;
- trailing separators stripped (except where they distinguish a root);
- `.` and `..` segments collapsed per OS rules;
- environment-variable references resolved (e.g. `%USERPROFILE%`).

Symbolic links and junctions are **not** resolved at canonicalization
time. The policy references the path as written; reparse-point
traversal is the runtime's concern.

### F10 — Implicit traversal

Every explicit entry at path P creates an **implicit name-resolution
traversal grant** on each strict ancestor of P, for the single child
name on the unique path from the host root to P. The grant is the
minimum capability required to resolve P's name through its ancestors;
it does **not** confer:

- stat on the ancestor;
- DACL read on the ancestor;
- enumeration of the ancestor (`FindFirstFile` does not list the
  child);
- any other capability on the ancestor.

If multiple entries share an ancestor, the ancestor receives an
implicit traversal grant for each relevant child name.

### F11 — Object-level hiding

Where the language says a path is *hidden*, that hiding applies to the
**object** at the path, not just the literal name. Alternative routes
to the same object (file ID, hardlink alias, junction target,
volume-GUID prefix, `\\?\` prefix, 8.3 short name) are also hidden by
the language. The enforcement layer may degrade to name-level hiding;
the language definition is strict.

### F12 — Hidden = not-found, not access-denied

Operations against a hidden path fail with **not-found** error codes
(`ERROR_FILE_NOT_FOUND` / `ERROR_PATH_NOT_FOUND` /
`INVALID_FILE_ATTRIBUTES`). They do not fail with `ACCESS_DENIED`.

In contrast, write-rejection on an `RO` path uses `ACCESS_DENIED` —
because RO does not hide the path.

### F13 — Explicit `D` is strictly stronger than default-deny

Both make paths inaccessible to the agent, but they differ on
operations that don't require capability on the leaf:

- **Default-deny** is the absence of a granting entry. The agent has
  no capability for the path. Operations *on* the path fail-as-not-
  found. But operations on the path's *parent* that don't need to open
  the path itself (e.g. creating a new child in a writable parent
  where the new child's name happens to be unlisted) succeed; the
  resulting object is then itself default-denied and invisible.
- **Explicit `D`** is the user actively asserting "no operation on
  this path appears to succeed from the container's perspective."
  Creates at an explicit-`D` path fail-as-not-found even when the
  parent grants `FILE_ADD_FILE`.

### F14 — Enumeration mirrors existence

`FindFirstFile`/`FindNextFile` on a directory return the names of
children that are themselves visible (existence = Y) to the agent.
Hidden or default-denied children are omitted.

### F15 — Q4: Provenance is irrelevant

Deny applies to whatever object exists at the named host path,
regardless of who created it. If the agent creates a file inside an
RW subtree at a path that is *also* covered by a `D` entry, the new
file is immediately invisible to the agent. (In practice, F13 catches
this earlier: under explicit `D`, the create itself fails-as-not-found.)

### F16 — `[L]` on a directory grants only the directory's own metadata

A leaf entry on a directory grants stat / metadata read / DACL read
(`RO[L]`) or stat / metadata write / DACL write / timestamps / etc.
(`RW[L]`) on the directory itself. It does **not** grant
`FILE_ADD_FILE` or `FILE_DELETE_CHILD` on the directory. Adding or
removing children requires entries that cover the children
themselves.

In particular: a `RW[L]` on a directory does *not* allow the agent to
create files inside the directory, nor does it allow `RemoveDirectory`
unless the directory is empty *from the agent's perspective* (and any
host-side hidden children are excluded — those still block the OS-
level remove).

**F16a — `RW[L]` on a directory with no covering children entry is a
validation error.** Because the language otherwise produces an
awkward "create succeeds but the result is invisible" corner under
F13/F15, the validator rejects this configuration. The user must
either change the entry to `RW[S]` (covering descendants) or add
explicit entries covering the descendants they intend to expose.
`RO[L]` on a directory does not have this restriction — it is
useful on its own (the directory's existence and metadata are
visible; descendants follow default-deny or whatever else covers
them).

### F17 — `RW` ⇒ `R`

`readwrite` semantics include read. A single `RW` entry suffices for
"the agent has full access to this path."

### F18 — Validator role

The validator performs active normalization and surfaces issues
explicitly:

- include resolution (recursive, with cycle detection);
- path canonicalization (F9);
- deduplication (F8 plus F1-collapsed shapes);
- conflict detection (F7);
- suspicious-nesting warnings (cross-list ancestor/descendant pairs
  that *might* be unintended);
- Position-3 access check (F4);
- redundancy detection (entries that contribute nothing on top of
  others).

Outputs are: a normalized policy ready for enforcement, a list of
errors, and a list of warnings.

## The four observables

Every entry's semantics are expressed as the four boolean observables
the contained code can perform on a path:

| Observable | What the agent does | Effect under RO | Effect under RW | Effect under D |
|---|---|---|---|---|
| **Existence** | `GetFileAttributes`, `FindFirstFile` listing in parent | Y | Y | N (hidden) |
| **Metadata** | DACL read, timestamps, attributes | Y | Y | N |
| **Read** | open for `GENERIC_READ`, read bytes | Y | Y | N |
| **Write** | open for write, modify, delete, rename, mutate DACL or timestamps, create children (subtree only) | **N** | Y | N |

## Each intent in isolation

The tables below show the four observables plus relevant
corner-operations for each intent, in each shape. The "example
paths" table after each shows what the corresponding policy looks
like in practice.

### Readonly in isolation

#### Observable table — RO

|  | `RO[S]` (subtree on directory) | `RO[L]` on file | `RO[L]` on directory |
|---|---|---|---|
| existence(P) | Y | Y | Y |
| metadata(P) | Y | Y | Y |
| read(P) — contents/data | Y | Y | (n/a — dir, contents = enumeration) |
| enumerate(P) | Y (subject to F14) | n/a | Y (subject to F14) |
| write(P) | N | N | N |
| existence(descendant of P) | Y | n/a | per default-deny / per other entries |
| metadata(descendant) | Y | n/a | per default-deny / per other entries |
| read(descendant) | Y | n/a | per default-deny / per other entries |
| write(descendant) | N | n/a | per default-deny / per other entries |

#### Corner operations under RO

All listed operations fail (N) under RO, with `ACCESS_DENIED`:

| Operation | Result |
|---|---|
| Create new file inside P | N |
| Create new subdirectory inside P | N |
| Delete an existing file in P | N |
| Rename a file within P | N |
| Rename a file out of P | N |
| Truncate-on-open of a file in P | N |
| Modify file timestamps / attributes in P | N |
| Modify DACL of P or descendants | N |
| `DELETE_ON_CLOSE` open of a file in P | N |
| Append-only write | N |
| Open for write but never write | N |
| Memory-map read-only | Y |
| Memory-map read-write | N |
| `READ_CONTROL` / `SYNCHRONIZE` | Y |

#### Example — RO

Policy fragment:

```
RO[S] C:\Windows
RO[L] C:\Users\gudge\.gitconfig
RO[L] C:\Users\gudge\Documents
```

What the agent observes:

| Operation | Path | Result | Reason |
|---|---|---|---|
| `CreateFile … GENERIC_READ` | `C:\Windows\System32\kernel32.dll` | success | `RO[S] C:\Windows` covers descendants |
| `CreateFile … GENERIC_WRITE` | `C:\Windows\System32\kernel32.dll` | `ACCESS_DENIED` | RO subtree denies writes |
| `CreateFile … GENERIC_READ` | `C:\Users\gudge\.gitconfig` | success | covered by leaf RO |
| `SetFileTime` | `C:\Users\gudge\.gitconfig` | `ACCESS_DENIED` | leaf RO denies metadata write |
| `FindFirstFile C:\Users\gudge\Documents\*` | — | empty result | leaf-RO on directory grants stat/DACL on dir, but descendants are default-denied |
| `GetFileAttributes` | `C:\Users\gudge\Documents` | success | leaf RO grants metadata read on the dir itself |
| `CreateFile … GENERIC_READ` | `C:\Users\gudge\Documents\notes.txt` | not-found | default-deny on the child |
| `CreateFile … GENERIC_READ` | `C:\Users\gudge\.cargo\config.toml` | not-found | unlisted, default-deny |

### Readwrite in isolation

#### Observable table — RW

|  | `RW[S]` (subtree on directory) | `RW[L]` on file | `RW[L]` on directory |
|---|---|---|---|
| existence(P) | Y | Y | Y |
| metadata read(P) | Y | Y | Y |
| metadata write(P) | Y | Y | Y |
| read(P) | Y | Y | n/a |
| enumerate(P) | Y (subject to F14) | n/a | Y (subject to F14) |
| write children of P (`FILE_ADD_FILE` etc.) | Y | n/a | **N** (per F16) |
| existence(descendant of P) | Y | n/a | per default-deny / per other entries |
| metadata(descendant) | Y | n/a | per default-deny / per other entries |
| read(descendant) | Y | n/a | per default-deny / per other entries |
| write(descendant) | Y | n/a | per default-deny / per other entries |

#### Corner operations under RW

All Y, including DACL mutation, rename, delete (except where parent
constraints apply per F16 for `[L]`-on-directory shapes).

#### Example — RW

Policy fragment:

```
RW[S] C:\etc\src\git\myrepo
RW[S] C:\Users\gudge\temp
RW[L] C:\Users\gudge\Documents\workinprogress
```

What the agent observes:

| Operation | Path | Result | Reason |
|---|---|---|---|
| `CreateFile … GENERIC_WRITE` | `C:\etc\src\git\myrepo\src\main.rs` | success | subtree RW |
| `DeleteFile` | `C:\etc\src\git\myrepo\src\main.rs` | success | subtree RW |
| `MoveFile` source `myrepo\foo.txt` → dest `myrepo\bar.txt` | both | success | same RW subtree |
| `CreateFile CREATE_NEW` | `C:\Users\gudge\temp\new.log` | success | subtree RW grants create |
| `CreateFile CREATE_NEW` | `C:\Users\gudge\Documents\workinprogress\new.txt` | `ACCESS_DENIED` | `RW[L]` on dir grants only the dir's own metadata; F16 says no `FILE_ADD_FILE` |
| `SetFileTime` | `C:\Users\gudge\Documents\workinprogress` | success | leaf RW on dir grants metadata write |
| `RemoveDirectory` | `C:\Users\gudge\temp` | succeeds *iff* the dir is empty *from the host's perspective* | F16 + NTFS empty-check |

### Deny in isolation

#### Observable table — D

|  | `D[S]` on directory (incl. `[L]` on directory, per F1) | `D[L-file]` on file |
|---|---|---|
| existence(P) | N | N |
| metadata(P) | N | N |
| read(P) | N | N |
| write(P) | N | N |
| existence(descendant of P) | N | n/a |
| metadata(descendant) | N | n/a |
| read(descendant) | N | n/a |
| write(descendant) | N | n/a |
| `CreateFile CREATE_NEW` at P | not-found (F13) | not-found |
| enumeration of `parent(P)` | omits P | omits P |
| open by file ID | not-found (F11) | not-found |
| open via `\\?\Volume{…}` | not-found (F11) | not-found |

#### Example — D

Policy fragment:

```
RW[S] C:\Users\gudge\Documents\workinprogress
D[S]  C:\Users\gudge\Documents\workinprogress\private
RW[S] C:\etc\src\git\myrepo
D[L-file] C:\etc\src\git\myrepo\.env
```

What the agent observes:

| Operation | Path | Result | Reason |
|---|---|---|---|
| `GetFileAttributes` | `C:\Users\gudge\Documents\workinprogress\private` | not-found | hidden per `D[S]` |
| `CreateFile CREATE_NEW` | `C:\Users\gudge\Documents\workinprogress\private\new.txt` | not-found | F11 + F13 |
| `FindFirstFile C:\Users\gudge\Documents\workinprogress\*` | — | omits `private` | F14 |
| `CreateFile … GENERIC_READ` | `C:\etc\src\git\myrepo\.env` | not-found | hidden per `D[L-file]` |
| `CreateFile CREATE_NEW` | `C:\etc\src\git\myrepo\.env` | not-found | F13 |
| `FindFirstFile C:\etc\src\git\myrepo\*` | — | omits `.env` | F14 |
| `CreateFile … GENERIC_READ` | `C:\etc\src\git\myrepo\src\main.rs` | success | within outer RW, no covering deny |

## Interaction matrix

The cells below describe what the agent observes when two policy
entries interact on overlapping paths. The legend:

- "Q" = the deepest path covered by the inner entry.
- "Between" = paths inside the outer scope but outside the inner scope.
- "Result" lines describe the observable behavior under most-specific-
  wins (F6).

### Category A — same path, two intents

Per F7: validation error in every case.

| Cell | Entries (same path P) | Result |
|---|---|---|
| A1 | `RO[L] P` + `RW[L] P` | validation error |
| A2 | `RO[S] P` + `RW[S] P` | validation error |
| A3 | `RO[L] P` + `RW[S] P` (or vice versa) | validation error |
| A4 | `RO[L] P` + `D[L-file] P` | validation error |
| A5 | `RO[S] P` + `D[S] P` | validation error |
| A6 | `RW[L] P` + `D[L-file] P` | validation error |
| A7 | `RW[S] P` + `D[S] P` | validation error |
| A8 | All three at same P | validation error (one diagnostic) |

#### Example — A

Policy fragment:

```
RW[S] C:\Users\gudge\temp
RO[S] C:\Users\gudge\temp
```

Validator emits:

```
ERROR: path C:\Users\gudge\temp has entries on both `readwrite` and
       `readonly` lists; intent conflict. Pick one.
```

### Category B — outer `[S]` + inner `[S]`

| Cell | Outer at P | Inner at P\sub | Q (descendants of P\sub) | Between | Validator |
|---|---|---|---|---|---|
| B1 | `RO[S]` | `RW[S]` | RW | RO | OK |
| B2 | `RW[S]` | `RO[S]` | RO | RW | OK |
| B3 | `RO[S]` | `D[S]` | hidden | RO | OK |
| B4 | `RW[S]` | `D[S]` | hidden | RW | OK |
| B5 | `D[S]` | `RW[S]` | RW | hidden | warn (allow-inside-deny) |
| B6 | `D[S]` | `RO[S]` | RO | hidden | warn (allow-inside-deny) |

#### Example — B (the canonical RW + D pattern, B4)

Policy fragment:

```
RW[S] C:\Users\gudge\Documents\workinprogress
D[S]  C:\Users\gudge\Documents\workinprogress\private
```

What the agent observes:

| Path | Result | Reason |
|---|---|---|
| `…\workinprogress\notes.txt` (read/write) | success | outer RW |
| `…\workinprogress\private` (exists?) | not-found | inner D |
| `…\workinprogress\private\secret.txt` (read) | not-found | inside D[S] |
| `FindFirstFile …\workinprogress\*` | omits `private` | F14 |

#### Example — B (RO carve-out inside RW, B2)

Policy fragment:

```
RW[S] C:\etc\src\git\myrepo
RO[S] C:\etc\src\git\myrepo\.git
```

What the agent observes:

| Path | Result | Reason |
|---|---|---|
| `myrepo\src\main.rs` (write) | success | outer RW |
| `myrepo\.git\config` (read) | success | inner RO grants read |
| `myrepo\.git\config` (write) | `ACCESS_DENIED` | inner RO denies write |
| `myrepo\.git\index` (write) | `ACCESS_DENIED` | inner RO denies write |

(`git status` works; `git add` does not.)

#### Example — B (allow-inside-deny, B5)

Policy fragment:

```
D[S]  C:\Users\gudge
RW[S] C:\Users\gudge\workspace
```

What the agent observes:

| Path | Result | Reason |
|---|---|---|
| `C:\Users\gudge\.gitconfig` (read) | not-found | outer D hides everything not carved |
| `C:\Users\gudge\workspace\foo.txt` (read/write) | success | inner RW |
| `FindFirstFile C:\Users\gudge\*` | shows only `workspace` | F14 + outer D |
| `GetFileAttributes C:\Users\gudge` | metadata accessible only along path-to-workspace per F10 | implicit traversal threads through |

Validator emits a warning: "Allow entry `RW[S] C:\Users\gudge\workspace`
nests inside deny entry `D[S] C:\Users\gudge`. Inner allow overrides
only for the named subtree, not for siblings. Confirm intent."

### Category C — outer `[S]` + inner `[L]`

The inner `[L]` covers only P\x itself; P\x's descendants remain
governed by the outer.

| Cell | Outer at P | Inner at P\x | P\x itself | Descendants of P\x | Between | Validator |
|---|---|---|---|---|---|---|
| C1 | `RO[S]` | `RW[L]` file | RW | n/a | RO | OK |
| C2 | `RO[S]` | `RW[L]` dir | RW (metadata only, per F16) | RO (per outer) | RO | warn |
| C3 | `RW[S]` | `RO[L]` file | RO | n/a | RW | OK |
| C4 | `RW[S]` | `RO[L]` dir | RO (metadata only) | RW (per outer) | RW | OK |
| C5 | `RO[S]` | `D[L-file]` | hidden | n/a | RO | OK |
| C6 | `RW[S]` | `D[L-file]` | hidden | n/a | RW | OK |
| C7 | `D[S]` | `RW[L]` or `RO[L]` | per inner | hidden if dir | hidden | warn |

#### Example — C1 (writable file carve-out inside RO subtree)

Policy fragment:

```
RO[S] C:\Users\gudge\.cargo
RW[L] C:\Users\gudge\.cargo\credentials.toml
```

What the agent observes:

| Path | Result | Reason |
|---|---|---|
| `…\.cargo\config.toml` (read) | success | outer RO |
| `…\.cargo\config.toml` (write) | `ACCESS_DENIED` | outer RO |
| `…\.cargo\credentials.toml` (read/write) | success | inner RW leaf |

#### Example — C6 (deny a specific file inside RW)

Policy fragment:

```
RW[S] C:\etc\src\git\myrepo
D[L-file] C:\etc\src\git\myrepo\.env
```

What the agent observes:

| Path | Result | Reason |
|---|---|---|
| `myrepo\src\main.rs` (read/write) | success | outer RW |
| `myrepo\.env` (any op) | not-found | inner D |
| `CreateFile CREATE_NEW myrepo\.env` | not-found | F13 |
| `FindFirstFile myrepo\*` | omits `.env` | F14 |

### Category D — outer `[L]`-on-directory + inner `[S]`

| Cell | Outer at P | Inner at P\sub | P itself | P\sub | Between (siblings of `sub`) | Validator |
|---|---|---|---|---|---|---|
| D1 | `RO[L]` (dir) | `RW[S]` | RO (metadata only) | RW | hidden (default-deny) | OK |
| D2 | `RW[L]` (dir) | `RO[S]` | RW (metadata only, F16) | RO | (the user must add coverage for siblings) | **error** (per F16a) |

D2 has no valid form. The user must either use `RW[S]` on the outer
(which covers all descendants) or add explicit entries for each
sibling of `sub` they want the agent to see. The "create-then-
invisible" corner that motivated F16a is eliminated by validation.

#### Example — D1

Policy fragment:

```
RO[L] C:\Users\gudge
RW[S] C:\Users\gudge\workspace
```

What the agent observes:

| Path | Result | Reason |
|---|---|---|
| `GetFileAttributes C:\Users\gudge` | success | outer RO leaf grants metadata read |
| `SetFileTime C:\Users\gudge` | `ACCESS_DENIED` | outer RO denies metadata write |
| `FindFirstFile C:\Users\gudge\*` | returns only `workspace` | F14: only granted children appear |
| `C:\Users\gudge\workspace\foo.txt` (read/write) | success | inner RW |
| `C:\Users\gudge\.gitconfig` (read) | not-found | default-deny on siblings |

### Category E — disjoint siblings

Trivial: each entry governs its own scope; no interaction.

#### Example — E

Policy fragment:

```
RW[S] C:\etc\src\git\myrepo
RW[S] C:\Users\gudge\temp
RO[S] C:\Windows
```

The three subtrees do not overlap. Each behaves as in isolation.

### Category F — multiple entries with the same intent

| Cell | Combination | Runtime effect | Validator |
|---|---|---|---|
| F1 | Two same-intent subtree entries, one nested in the other | inner is redundant | dedupe + warn |
| F2 | Same-intent subtree + descendant leaf inside it | leaf is redundant | dedupe + warn |
| F3 | Same-intent deny entries, one nested in the other | inner is redundant | dedupe + warn |
| F4 | Same path, same intent, mismatched markers | `[S]` subsumes `[L]` | dedupe + low-severity note |
| F-exact | Two identical entries | one is redundant | silent dedupe |

#### Example — F

Policy fragment:

```
RW[S] C:\Users\gudge\temp
RW[L] C:\Users\gudge\temp\log.txt
```

Validator emits:

```
NOTICE: entry `RW[L] C:\Users\gudge\temp\log.txt` is fully covered by
        `RW[S] C:\Users\gudge\temp`. Dropping the leaf entry. (F2)
```

### Category G — rename across regions

| Cell | Source | Destination | Result | Failure |
|---|---|---|---|---|
| G1 | RW (same subtree) | RW (same subtree) | succeeds | — |
| G2 | RW (subtree A) | RW (subtree B) | succeeds | — |
| G3 | RW | RO | fails at dest | `ACCESS_DENIED` |
| G4 | RW | D (subtree or file leaf) | fails at dest | not-found |
| G5 | RO | RW | fails at source | `ACCESS_DENIED` |
| G6 | D | anywhere | fails at source | not-found |
| G7 | implicit-traversal-only | RW | fails at source | `ACCESS_DENIED` |

#### Example — G3

Policy fragment:

```
RW[S] C:\Users\gudge\temp
RO[S] C:\Users\gudge\Documents
```

`MoveFile C:\Users\gudge\temp\notes.txt → C:\Users\gudge\Documents\notes.txt` →
`ACCESS_DENIED` at destination; source file untouched.

#### Example — G4

Policy fragment:

```
RW[S] C:\Users\gudge\temp
D[S]  C:\Users\gudge\Documents\private
```

`MoveFile C:\Users\gudge\temp\notes.txt → C:\Users\gudge\Documents\private\notes.txt` →
not-found at destination; source untouched.

### Category H — interactions with the implicit default region

Under default-deny, H mostly collapses.

| Cell | Behavior | Notes |
|---|---|---|
| H1 | unlisted read fails-as-not-found | default-deny |
| H2a | unlisted write fails-as-not-found | same as H1 |
| H2b | create in writable parent at unlisted child path succeeds, new file invisible | F13/F15 |
| H3 | read inside RW subtree succeeds | F17 |
| H4 | Position 3 grant honored if user has access; validation error otherwise | F4 — static check |

#### Example — H4 (Position 3 validation)

Policy fragment (invoking user is `gudge`, not admin):

```
RO[L] C:\System Volume Information\IndexerVolumeGuid
```

`gudge` cannot read this file on the host (only `SYSTEM` and admins
can). Validator emits:

```
ERROR: entry `RO[L] C:\System Volume Information\IndexerVolumeGuid`
       requires read access the invoking user does not have. Per
       Position 3 (delegation from invoking user), a policy author
       cannot delegate access they themselves lack.
```

## End-to-end worked example

Combining the elements: the policy from our derivation conversation.

```
include "windows-dev-readonly-defaults"

RW[S] C:\etc\src\git\myrepo
RW[S] C:\Users\gudge\temp
RW[S] C:\Users\gudge\scratch
RW[S] C:\Users\gudge\Documents\workinprogress
D[S]  C:\Users\gudge\Documents\workinprogress\private
```

The include fragment (illustrative; actual contents subject to
capability-profile work) contributes:

```
RO[S] C:\Windows
RO[S] C:\Program Files
RO[S] C:\Program Files (x86)
RO[S] C:\ProgramData
RO[S] C:\Users\Public
RO[L] C:\Users\gudge\.gitconfig
RO[L] C:\Users\gudge\.ssh\known_hosts
RO[S] C:\Users\gudge\.cargo
RO[S] C:\Users\gudge\.nuget
RO[L] C:\Users\gudge\Documents\PowerShell\Microsoft.PowerShell_profile.ps1
... (etc.)
```

After validation and normalization, what the agent observes:

| Operation | Path | Result | Reason |
|---|---|---|---|
| read | `C:\Windows\System32\kernel32.dll` | success | include RO subtree |
| read | `C:\Program Files\Git\cmd\git.exe` | success | include RO subtree |
| read | `C:\Users\gudge\.gitconfig` | success | include RO leaf |
| write | `C:\Users\gudge\.gitconfig` | `ACCESS_DENIED` | RO leaf |
| read | `C:\Users\gudge\.cargo\config.toml` | success | include RO subtree |
| read/write | `C:\etc\src\git\myrepo\src\main.rs` | success | user RW subtree |
| read/write | `C:\Users\gudge\temp\out.log` | success | user RW subtree |
| read/write | `C:\Users\gudge\Documents\workinprogress\note.md` | success | user RW subtree |
| any op | `C:\Users\gudge\Documents\workinprogress\private` | not-found | user D subtree |
| any op | `C:\Users\gudge\Documents\workinprogress\private\secret.txt` | not-found | user D subtree |
| read | `C:\Users\gudge\.bash_history` | not-found | default-deny (not in any entry) |
| `CreateFile CREATE_NEW` | `C:\temp\logs\app.log` | not-found | default-deny on the parent's parent; no implicit traversal grant for `C:\temp\logs` |
| `FindFirstFile C:\Users\gudge\*` | returns only the entries above (no `.bash_history`, no `private`) | F14 |
| read | `C:\Users\gudge\Documents` | metadata only (existence Y, no enumeration of unlisted children) | implicit traversal to reach `workinprogress` |

`git status`, `cargo build`, `pwsh -c 'Get-ChildItem'` against the
repo all work. The agent cannot read `.bash_history` or `.ssh\id_rsa`,
cannot write to `.gitconfig`, cannot see or create anything in or
under `private`.

## Validator pseudocode (informative)

For a clearer mental model. Not the authoritative spec; the rules
above are.

```text
validate(policy):
  # 1. Include resolution
  entries = resolve_includes(policy.entries, fragments)  # detect cycles

  # 2. Path canonicalization (F9)
  for e in entries:
    e.path = canonicalize(e.path)

  # 3. Existence check (F2)
  for e in entries:
    if not exists(e.path):
      error("path does not exist: " + e.path)

  # 4. Bucket by path and detect conflicts/dedupes
  buckets = group_by(entries, e -> e.path)
  for path, bucket in buckets:
    intents = distinct(bucket, e -> e.intent)
    if len(intents) > 1:
      error("intent conflict at " + path, F7)
    # F8: subtree subsumes leaf
    if has(bucket, [S]) and has(bucket, [L]):
      note("dropping leaf entry at " + path + " (subsumed by subtree)", F8)
      bucket = filter(bucket, e -> e.marker == [S])
    # F-exact: identical duplicates
    bucket = dedupe(bucket)

  # 5. Nesting checks
  for outer, inner in nesting_pairs(entries):
    if outer.intent == inner.intent:
      warn("redundant nested entry: " + inner.path, F1/F2/F3)
    elif suspicious_nesting(outer, inner):
      warn(suspicious_nesting_description(outer, inner), B5/B6/C2/C7)

  # 5b. F16a check: RW[L] on directory with no covering children
  for e in entries:
    if e.intent == RW and e.marker == [L] and is_directory(e.path):
      if not has_covering_child_entry(entries, e.path):
        error("RW[L] on directory " + e.path + " with no covering "
              "entry for descendants; use RW[S] or add explicit "
              "child entries", F16a)

  # 6. Position 3 check (F4)
  for e in entries:
    if e.intent in [RO, RW]:
      if not user_has_access(invoking_user, e.path, e.intent):
        error("user cannot delegate access they lack at " + e.path, F4)

  return NormalizedPolicy(entries, errors, warnings)
```

## Runtime enforcement notes

The language semantics above are intentionally enforcement-agnostic.
This section catalogues the known runtime-enforcement risks against
those semantics, names the resolved/open ones, and points each to the
relevant companion document.

The list is operationally useful: it tells implementers which
semantic guarantees come for free under the planned composition,
which are achieved by specific filter behavior, and which degrade
gracefully (with surfaced annotations) rather than fail loudly.

### R1 / R3 — Object-level hiding via non-name routes (F11)

F11 requires that a hidden object be hidden via *any* route — file
ID, hardlink alias, junction target, volume-GUID, `\\?\` prefix, 8.3
short name. Bindflt is a name-based filter and does not mediate
opens by file ID. ProjFS is rooted at a virt directory and similarly
does not see file-ID-based opens that don't traverse its root.

**Resolution**: degrade-and-surface. The enforcement layer
approximates F11 with name-level hiding plus the AppContainer SID's
own access check as a final gate. The composition plan's run-result
object includes a `bypass surface notes` field that explicitly
declares "object-level hiding is approximated by name-level hiding;
opens by file ID or volume-GUID prefix are not mediated by the
naming layer. Access still gated by the AppContainer SID's
NTFS rights." Callers who require strict F11 can refuse to run when
this annotation is present.

### R2 — Implicit traversal (F10) — **RESOLVED**

F10 requires that every explicit entry creates a name-resolution-only
traversal grant on each strict ancestor of the entry, without
granting stat, DACL read, or enumeration on those ancestors.

The enforcement question was whether this required explicit
`FILE_TRAVERSE` ACEs on ancestor directories — including paths the
invoking user typically cannot modify (`C:\`, `C:\Users`,
`C:\Program Files`, etc.).

**Resolution**: confirmed via investigation (see
`appcontainer_traversal_findings.md`). AppContainer tokens on
Windows 11 23H2+ retain `SeChangeNotifyPrivilege`. The kernel honors
the "Bypass traverse checking" semantics: intermediate-component
`FILE_TRAVERSE` checks during `IRP_MJ_CREATE` path walk are skipped
entirely. F10 is enforceable as written, with no ancestor ACE work
needed. The target's own DACL still gates target-level access, which
is consistent with the language (entries grant access on the named
path itself; ancestors get only name-resolution).

### R4 — Hidden-returns-not-found, not access-denied (F12)

F12 requires that operations on hidden paths return not-found error
codes rather than `ACCESS_DENIED`. The composition uses deny ACEs as
defence-in-depth alongside bindflt exception lists and provider
denylists. ACEs naturally return `ACCESS_DENIED`, not not-found.

**Resolution**: layer ordering. Bindflt exception lists and ProjFS
denylists run *before* a deny ACE would be consulted. Operations
that match the language-level hiding are caught by those layers and
return not-found per F12. The deny ACE backstops only operations that
*bypass* the naming layer — exactly the same shape as R1/R3. In
those cases the language considers the operation already "should not
have reached here," so `ACCESS_DENIED` is a correct (if not language-
preferred) error code. Surfaced in the run-result annotations.

### R5 — Enumeration filtering for deny inside RW (F14)

F14 requires that `FindFirstFile`/`FindNextFile` on a directory
return only children visible to the agent. For a directory served by
ProjFS, this falls out of the provider's `GetDirectoryEnumeration`
callback. For a directory served by a bindflt R/W identity bind,
NTFS's enumeration is passthrough — bindflt does not by itself
filter the listing.

**Resolution**: bindflt exception lists. When a deny entry sits
inside an RW subtree, the deny path is added to the bindflt R/W
bind's exception list. Excepted paths do not appear in enumeration
through the bind. Spike B in the FS-projection plan explicitly tests
this; if the spike confirms, F14 holds for the composition. If the
spike disconfirms, we revisit (likely by routing the affected
directory through ProjFS, which can filter, at the cost of breaking
the "no ProjFS under writable binds" invariant in that one location).

### R5b — Create-then-invisible at default-deny under writable parent — **RESOLVED**

F13 + F15 together imply a corner case: under `RW[L]` on a
directory with no covering children entry, the agent could create a
new file in the directory (the directory grants `FILE_ADD_FILE` —
wait, actually F16 already forbids this). On further inspection, the
corner only arises if the validator allows `RW[L]` on a directory
without covering children. Since F16a now makes that a validation
error, the corner cannot arise.

**Resolution**: prevented at validation. The validator's F16a check
ensures no policy produces a writable directory with default-denied
children, so the create-then-invisible asymmetry never reaches the
runtime.

### Summary table

| Risk | Description | Status |
|---|---|---|
| R1 / R3 | Object-level hiding via file ID, hardlink alias, etc. | Degraded, surfaced |
| R2 | Implicit traversal needing ancestor ACEs | Resolved (`SeChangeNotifyPrivilege`) |
| R4 | Hidden returning ACCESS_DENIED instead of not-found | Mitigated by layer ordering; backstop case surfaced |
| R5 | Enumeration filtering for deny inside RW | Bindflt exception list; spike verification |
| R5b | Create-then-invisible at default-deny under writable parent | Resolved by F16a |

## Open questions and deferrals

- **OQ-S1**: Capability carve-outs within an intent (e.g. "RW but not
  DACL-write"). Deferred.
- **OQ-S2**: Policy behavior for paths deleted and recreated mid-run.
  Deferred. v1 statement: the policy applies to whatever object
  exists at the path at any given moment; if the path's identity
  changes mid-run, the policy still applies to the new object.
- **OQ-S3**: Deny on non-existent paths ("prevent creation at P").
  Deferred. v1 requires explicit entries to exist; users wanting
  "deny-creation" semantics must currently create-and-deny.
- **OQ-S4**: Should redundant entries be dropped from the normalized
  representation or kept for diagnostics round-tripping? Defer
  decision; either choice is internally consistent.
- **OQ-S5**: Should the validator surface the implicit-traversal set
  to the user (informational)? Decided: no — too noisy. Implicit
  traversal is silent.
- **OQ-S6**: Position 3's user-access probe at validation time —
  what API and what scope? E.g. does the validator open every path
  with `READ_CONTROL` and check access mask, or use
  `AccessCheckByType` against a captured user token? Implementation
  detail; deferred to enforcement design.
- **OQ-S7**: Constraint-only as an *alternative* to default-deny. We
  said we'd explore both. v1 picks default-deny; constraint-only
  reserved for future consideration if the use cases warrant.
- **OQ-S8**: Fragments with per-Windows-version variants (per the
  capability-profile work in the FS-projection plan). The mechanism
  is open; the language allows includes to be resolved at policy-
  load time against whatever the host supports.

## Cross-references to enforcement work

Implementation mapping of these semantics onto specific Windows
primitives is in `fs-projection-composition-plan.md` and
`projfs_bindflt_summary.md`. Notably:

- `D` (hidden, F11/F12) maps cleanly onto bindflt exception lists plus
  ProjFS provider denylist plus deny ACEs (defence in depth).
- `RW[S]` maps onto bindflt R/W identity bind + package-SID grant ACE.
- `RO[S]` on AAP-readable system roots maps onto bindflt R/O identity
  bind (no broker needed).
- `RO[S]` on non-AAP-readable paths maps onto ProjFS provider + bindflt
  redirect into the virt root.
- Implicit traversal (F10) relies on `SeChangeNotifyPrivilege` being
  retained on the AppContainer token (under investigation per
  `files/appcontainer_traversal_investigation_brief.md`).

Where the enforcement layer cannot fully express a semantic — e.g.
object-level hiding via file ID is harder than name-level hiding —
the language preserves the strict reading and the enforcement layer
degrades gracefully with surfaced annotations on the run-result
object.
