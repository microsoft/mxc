# MXC FS-policy semantics — v1 language specification

**Status**: draft, language-only (enforcement-independent), round 2
**Owner**: gudgmi (with Copilot CLI as pair)
**Branch**: `user/gudge/downlevel-fs-projection-plan`
**Companion docs**:
- `fs-projection-composition-plan.md`
- `projfs_bindflt_summary.md`
- `appcontainer_traversal_findings.md`

**Round-2 decisions absorbed (from reviewer feedback)**:
- **No leaf marker** in v1. Entries are subtree-implicit on
  directories; files have no descendants. (Adding `[L]` back later
  is a strictly-additive change.)
- **`D` produces `ACCESS_DENIED`**, not hidden. The denied path
  remains visible in parent enumerations and via `GetFileAttributes`;
  operations against it fail with `ACCESS_DENIED`. Namespace
  visibility (hiding) is reserved for a future namespace-mapping
  policy.
- **Most-specific path wins, including for `D`.** The reviewer
  proposal to make `D` unconditionally trump `RO`/`RW` was
  considered and reverted; the language stays uniform across all
  three lists. `D` inside an allow region carves out denied
  sub-paths; allows inside a `D` region punch holes the user can
  use to expose specific sub-paths.

For history, see the four documents under
`policy_semantics_v1_variants/`, which present each individual
feedback as a standalone variant and a merged variant that accepts
all three. This canonical spec is closer to that merged variant but
without the `D`-trumps-all rule.

**Resume the originating Copilot CLI session**:

```
copilot --resume d739a782-d102-4c2b-b4f9-31b461abef5a
```

## Scope and non-goals

### In scope

- The semantics of the three policy intents (`readonly`,
  `readwrite`, `deny`) and their interactions.
- Default-deny and include fragments.
- Static validation rules.
- Behaviour of common filesystem operations under every policy
  combination.
- Expected error/return-value shape for each rejection class.

### Out of scope (deferred to future versions)

- **Leaf marker `[L]`.** v1 has subtree-only entries. Adding `[L]`
  back later is a strictly-additive language change.
- **Namespace mapping policy.** Hiding paths, renaming paths,
  mounting paths under different names — these are reserved for a
  future namespace-mapping policy, distinct from this FS access
  policy.
- **Capability carve-outs within an intent** ("RW but not
  DACL-write", "RW but root-immutable").
- **Deny on non-existent paths.** v1 requires explicit entries to
  reference extant host objects. Worth re-opening separately under
  access-denied semantics where the case is conceptually simpler.
- **Policy behaviour for paths deleted-and-recreated mid-run.**
- **Copy-on-write semantics for RW subtrees.** Writes are always real
  host effects in v1.
- **Cross-principal policies.** The policy author is implicitly the
  invoking user.

## Foundational rules

These rules govern every behavior described later. They are listed
first so subsequent sections can cite them by name.

### F1 — Three intent lists, no marker

A policy contains three lists, each of which holds entries referring
to host paths:

- `readonly` (`RO`)
- `readwrite` (`RW`)
- `deny` (`D`)

Each entry covers the named host object and, if that object is a
directory, every descendant of the directory. Files have no
descendants, so the subtree/leaf distinction is moot for file
entries.

`D` on a file covers that file. `D` on a directory covers the
directory and every descendant.

### F2 — Paths must exist (v1)

Every explicit entry must resolve to an extant host object at the
time the policy is loaded. A policy that names a non-existent path
is rejected by the validator. (Deny on non-existent paths is
deferred for separate discussion under access-denied semantics.)

### F3 — Paths are host paths, identity-projected

The policy language references host paths. The contained code
observes those same paths under the same string spelling. A host
path `H` appears to the contained code as `H`. There is no separate
"container path space" in the language.

### F4 — Position 3 (delegation from the invoking user)

The policy is a **delegation from the invoking user to the contained
agent**.

For `RO`/`RW` entries:

> The agent receives the named access if and only if the invoking
> user themselves has that access on the host. A policy author
> cannot delegate access they do not possess.

For `D` entries:

> The agent is denied the named access unconditionally, independent
> of the invoking user's access. Withdrawal does not require the
> withdrawer to have had the access being withdrawn.

The Position 3 check on `RO`/`RW` is performed at **policy-load
time** (static validation). Entries that exceed the invoking user's
access are rejected before the run starts; the agent never observes
a runtime "would-have-worked-but-user-can't" failure.

### F5 — Default-deny + include fragments

The language defaults to **deny**. Unlisted paths are inaccessible
to the agent. To make the language ergonomic, policies may `include`
shipped, versioned fragments that contribute named entries. A
typical policy is a thin user-specific layer plus one or two
include lines that pull in standard sets like
`windows-dev-readonly-defaults`.

After include resolution, the language behaves as if the user typed
every entry explicitly.

### F6 — Most-specific path wins

When multiple entries cover the same path, the entry with the
longest matching path prefix determines the path's semantics. This
applies uniformly across all three lists: a more-specific `D` wins
over a less-specific `RO` or `RW`, and a more-specific `RO` or `RW`
wins over a less-specific `D`.

If two entries on different lists cover the same exact canonical
path, the policy is **invalid** (validation error) — see F7.

### F7 — Same-object multi-list is a validation error

If two entries on different lists reference the same canonical
object, the policy is rejected. The user is contradicting
themselves; the runtime should not silently downgrade.

Object identity is determined per F8: paths are lexically
normalized and then resolved to the underlying host object.
Aliases discoverable at policy-load time (mount points,
junctions, hardlinks) produce same-object conflicts. Aliases
introduced after policy-load (e.g., a hardlink the agent
creates during the run) are not statically detectable but are
covered by F11's object-based enforcement at runtime.

### F8 — Canonical paths and object identity

Before applying F6/F7, every path in the policy is canonicalized
in two stages.

**Lexical normalization**, applied to each path string:

- drive-letter case normalized (upper-case);
- path-separator characters normalized;
- trailing separators stripped (except where they distinguish a
  root);
- `.` and `..` segments collapsed per OS rules;
- environment-variable references resolved (e.g. `%USERPROFILE%`).

**Object resolution**, applied to the lexically-normalized
result for policy-lookup purposes:

- symbolic links, junctions, mount points, and hardlinks in
  effect at policy-load time are resolved to a canonical object
  identity (e.g. `(VolumeId, FileId)` on Windows,
  `(st_dev, st_ino)` on Linux and macOS);
- two entries whose paths resolve to the same object identity
  are treated as referring to the same target under F6/F7.

The agent's runtime view of paths is **not** rewritten. The
agent continues to address objects through whatever path strings
it knows; object resolution is for policy-lookup matching only.

Object resolution is best-effort. Aliases that come into
existence after policy-load (a hardlink the agent creates, a
mount that appears later) are not statically detectable. Such
aliases are still governed by F11 at runtime because every
supported OS enforces access on object identity.

### F9 — Implicit traversal

Every explicit entry at path P creates an **implicit
name-resolution traversal grant** on each strict ancestor of P, for
the single child name on the unique path from the host root to P.
The grant is the minimum capability required to resolve P's name
through its ancestors; it does **not** confer:

- stat on the ancestor;
- DACL read on the ancestor;
- enumeration of the ancestor (`FindFirstFile` does not list the
  child as a side effect);
- any other capability on the ancestor.

If multiple entries share an ancestor, the ancestor receives an
implicit traversal grant for each relevant child name.

Implicit traversal is enforceable on Windows 11 23H2+ via
`SeChangeNotifyPrivilege`, which AppContainer tokens retain. See
`appcontainer_traversal_findings.md`.

### F10 — `D` produces access-denied, not hidden

Operations against a denied path return `ACCESS_DENIED` (or
whatever NTFS would naturally return when access is refused —
typically `ERROR_ACCESS_DENIED`).

The denied path remains visible to the agent:

- `GetFileAttributes` returns the actual host attributes;
- `FindFirstFile` on the parent directory **includes** the denied
  path in its results;
- the path's name, size, timestamps, and other metadata are
  readable.

Operations refused under `D`:

- read (`CreateFile` with `GENERIC_READ` or with any access mask
  that implies read);
- write (any access mask implying write);
- enumeration of the denied path's contents if it is a directory
  (the directory entry itself is listed in its parent; opening it
  with `FILE_LIST_DIRECTORY` is refused);
- `CreateFile CREATE_NEW` at the denied path;
- delete, rename, modify DACL/timestamps, etc.

The path itself remains present in the namespace; only operations
on it are refused. This is structurally identical to how Windows
DACL deny ACEs behave.

### F11 — Object-based

An entry's intent applies to the host **object** (the file or
directory) reached by the named path. If the same object is
reachable through multiple paths — junctions, mount points,
hardlinks, drive-letter aliases for the same volume, bind mounts,
firmlinks, volume-GUID prefixes, file-ID opens — the policy
applies uniformly to the object regardless of which path the
agent uses to reach it.

This matches the underlying access-control mechanism on every
supported OS: NTFS DACLs on Windows, POSIX permissions and ACLs
on Linux and macOS. All are object-based at their innermost
enforcement layer; the language matches that rather than
promising path-based behavior the runtime cannot deliver.

Naming and visibility — what paths reach which objects, whether
any path is rewritten or hidden from the agent — is a separate
concern (namespace policy), deferred to a future iteration.
Mandatory access control layers (SELinux, AppArmor, Seatbelt)
similarly sit above this policy and are configured
independently.

### F12 — Provenance is irrelevant

`D` applies to whatever object exists at the named host path,
regardless of who created it. A file created during the run at a
denied path is refused going forward; the file may still exist on
the host but the agent cannot access it.

### F13 — `RW` implies read

`readwrite` semantics include read. A single `RW` entry suffices for
"the agent has full access to this path."

### F14 — Validator role

The validator performs active normalization and surfaces issues
explicitly:

- include resolution (recursive, with cycle detection);
- path canonicalization (F8);
- existence checks (F2);
- deduplication (entries that contribute nothing on top of others);
- conflict detection (F7);
- suspicious-nesting warnings (cross-list ancestor/descendant pairs
  that *might* be unintended — e.g. an allow inside a `D` subtree,
  which is legal per F6 but worth confirming with the user);
- Position-3 access check (F4).

Outputs are: a normalized policy ready for enforcement, a list of
errors, and a list of warnings.

## The four observables

Every entry's semantics are expressed as the four boolean observables
the contained code can perform on a path:

| Observable | What the agent does | Under RO | Under RW | Under D |
|---|---|---|---|---|
| **Existence** | `GetFileAttributes`, listed in parent enumeration | Y | Y | **Y (path remains visible)** |
| **Metadata** | DACL read, timestamps, attributes | Y | Y | **Y (host metadata readable)** |
| **Read** | open for `GENERIC_READ`, read bytes | Y | Y | N (`ACCESS_DENIED`) |
| **Write** | open for write, modify, delete, rename, mutate DACL or timestamps, create children (subtree) | N (`ACCESS_DENIED`) | Y | N (`ACCESS_DENIED`) |

Note: under `D`, existence and metadata are Y; only read and write
operations are refused. This is the key behavioural difference from
the round-1 spec.

## Each intent in isolation

### Readonly (`RO`)

| Observable | `RO P` (on dir, subtree-implicit) | `RO P` (on file) |
|---|---|---|
| existence(P) | Y | Y |
| metadata(P) | Y | Y |
| read(P) | Y | Y |
| enumerate(P) | Y | n/a |
| write(P) | N (`ACCESS_DENIED`) | N (`ACCESS_DENIED`) |
| existence(descendant) | Y | n/a |
| metadata(descendant) | Y | n/a |
| read(descendant) | Y | n/a |
| write(descendant) | N (`ACCESS_DENIED`) | n/a |

Corner operations (subtree RO): all listed return N with
`ACCESS_DENIED`: create, delete, rename, truncate, modify
attributes/timestamps, modify DACL, `DELETE_ON_CLOSE`, append, open-
for-write-then-don't-write, mmap read-write. mmap read-only returns
Y. `READ_CONTROL` / `SYNCHRONIZE` return Y.

#### Example — RO

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
| read | `C:\Users\gudge\.bash_history` | `ACCESS_DENIED` | default-deny |
| `GetFileAttributes` | `C:\Users\gudge\.bash_history` | `ACCESS_DENIED` | default-deny |

### Readwrite (`RW`)

| Observable | `RW P` (on dir) | `RW P` (on file) |
|---|---|---|
| existence(P) | Y | Y |
| metadata read(P) | Y | Y |
| metadata write(P) | Y | Y |
| read(P) | Y | Y |
| enumerate(P) | Y | n/a |
| write children of P (`FILE_ADD_FILE`, etc.) | Y | n/a |
| existence(descendant) | Y | n/a |
| metadata(descendant) | Y | n/a |
| read(descendant) | Y | n/a |
| write(descendant) | Y | n/a |

All corner operations Y, including DACL mutation, rename, delete,
create-child.

#### Example — RW

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

### Deny (`D`)

| Observable | `D P` (on dir, subtree-implicit) | `D P` (on file) |
|---|---|---|
| existence(P) | **Y** (path visible in parent enumeration) | **Y** |
| metadata(P) | **Y** (DACL/timestamps/attributes readable) | **Y** |
| read(P) | N (`ACCESS_DENIED`) | N (`ACCESS_DENIED`) |
| enumerate(P) (i.e., listing children of denied dir) | N (`ACCESS_DENIED`) | n/a |
| write(P) | N (`ACCESS_DENIED`) | N (`ACCESS_DENIED`) |
| existence(descendant) | Y *in the host filesystem*, but **not discoverable by the agent** because enumeration of P is refused | n/a |
| metadata(descendant) | N (`ACCESS_DENIED`) — to query, agent must open the descendant by name, which fails | n/a |
| read(descendant) | N (`ACCESS_DENIED`) | n/a |
| write(descendant) | N (`ACCESS_DENIED`) | n/a |
| `CreateFile CREATE_NEW` at P | `ACCESS_DENIED` | `ACCESS_DENIED` |
| enumeration of `parent(P)` | **includes P** by name | **includes P** by name |
| open via alternate path (hardlink alias, file-ID, `\\?\Volume{…}`) | resolves to same denied object; `ACCESS_DENIED` (F11) | resolves to same denied object; `ACCESS_DENIED` (F11) |

Subtle case for `D` on a directory + descendants: the descendant
*names* are not discoverable through enumeration because
`FILE_LIST_DIRECTORY` on the denied directory is refused. The agent
can attempt to open `C:\foo\bar.txt` by name, but that returns
`ACCESS_DENIED` per F10. So descendants are *inaccessible* though
they exist on the host.

#### Example — D inside RW

```
RW C:\Users\gudge\Documents\workinprogress
D  C:\Users\gudge\Documents\workinprogress\private
```

| Operation | Path | Result | Reason |
|---|---|---|---|
| `GetFileAttributes` | `…\workinprogress\private` | success, real attrs | `D` doesn't hide |
| `FindFirstFile …\workinprogress\*` | listing | **includes `private`** | not hidden |
| read | `…\workinprogress\private` | `ACCESS_DENIED` | `D` refuses read |
| read | `…\workinprogress\private\secret.txt` | `ACCESS_DENIED` | descendant of D |
| `FindFirstFile …\workinprogress\private\*` | `ACCESS_DENIED` | enumeration of contents refused |
| `CreateFile CREATE_NEW` | `…\workinprogress\private\new.txt` | `ACCESS_DENIED` | per F10 |
| `CreateDirectory` | `…\workinprogress\private\sub` | `ACCESS_DENIED` | per F10 |

The agent sees `private` exists and knows the policy refuses access
to it. The agent does not know what's inside `private`.

## Interaction matrix

The cells below describe what the agent observes when two policy
entries interact on overlapping paths. Under F6 (most-specific
wins, uniformly across all three lists), the inner entry's intent
governs paths inside its scope; the outer governs paths in the
between region.

### Category A — same path, two intents

Per F7: validation error in every case.

| Cell | Entries (same path P) | Result |
|---|---|---|
| A1 | `RO P` + `RW P` | validation error |
| A2 | `RO P` + `D P` | validation error |
| A3 | `RW P` + `D P` | validation error |
| A4 | All three at P | validation error (one diagnostic) |

#### Example — A2

```
RW C:\Users\gudge\temp
D  C:\Users\gudge\temp
```

Validator emits:

```
ERROR: path C:\Users\gudge\temp has entries on both `readwrite` and
       `deny` lists; intent conflict. Pick one.
```

### Category B — outer + inner (both subtree on directories)

| Cell | Outer at P | Inner at P\sub | Inner scope | Between | Validator |
|---|---|---|---|---|---|
| B1 | `RO` | `RW` | RW | RO | OK |
| B2 | `RW` | `RO` | RO | RW | OK |
| B3 | `RO` | `D` | denied | RO | OK |
| B4 | `RW` | `D` | denied | RW | OK |
| B5 | `D` | `RW` | RW | denied | warn (allow-inside-deny) |
| B6 | `D` | `RO` | RO | denied | warn (allow-inside-deny) |

#### Example — B4 (canonical RW + D)

```
RW C:\Users\gudge\Documents\workinprogress
D  C:\Users\gudge\Documents\workinprogress\private
```

| Path | Result |
|---|---|
| `…\workinprogress\notes.txt` (read/write) | success |
| `…\workinprogress\private` (any op against contents) | `ACCESS_DENIED` |
| `…\workinprogress\private` (`GetFileAttributes`) | success, real attrs |
| `…\workinprogress\private\secret.txt` (any op) | `ACCESS_DENIED` |
| `FindFirstFile …\workinprogress\*` | **includes `private`** |
| `FindFirstFile …\workinprogress\private\*` | `ACCESS_DENIED` |

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

`git status` works (read-side only). `git add` does not (would need
to write to `.git\index`).

#### Example — B5 (allow inside deny)

```
D  C:\Users\gudge\Documents\workinprogress
RW C:\Users\gudge\Documents\workinprogress\drafts
```

| Path | Result |
|---|---|
| `…\workinprogress\notes.txt` (any op) | `ACCESS_DENIED` (outer D) |
| `…\workinprogress` (`GetFileAttributes`) | success, real attrs |
| `…\workinprogress` (`FILE_LIST_DIRECTORY` for enumeration) | `ACCESS_DENIED` |
| `…\workinprogress\drafts\foo.txt` (read/write) | success (inner RW) |
| `…\workinprogress\drafts` (`GetFileAttributes`) | success |
| `…\workinprogress\drafts` (`FILE_LIST_DIRECTORY`) | success |

Note that the outer `D` refuses enumeration of `workinprogress`,
so the agent cannot discover `drafts` by enumeration alone — but the
policy *itself* lists `drafts`, so the agent can address it by name.
Implicit traversal (F9) makes the path resolvable; the inner `RW`
makes operations succeed against it.

Validator emits: "Allow entry `RW C:\Users\gudge\Documents\workinprogress\drafts`
nests inside deny entry `D C:\Users\gudge\Documents\workinprogress`.
The inner allow overrides only for the named subtree; siblings of
`drafts` inside `workinprogress` remain denied. Confirm intent."

### Category C — outer subtree + inner deny (on a file)

(With no leaf marker, `RO`/`RW` on a file is just `RO`/`RW` on the
file — no separate "leaf vs subtree" enumeration. Category C is
about deny-of-a-single-file inside an allow subtree, plus the
inverse.)

| Cell | Outer at P | Inner at P\x (file) | Result | Validator |
|---|---|---|---|---|
| C1 | `RO` | `D` (file) | x: denied; rest: RO | OK |
| C2 | `RW` | `D` (file) | x: denied; rest: RW | OK |
| C3 | `D` | `RO` or `RW` on file | x: per inner; rest: denied | warn (allow-inside-deny) |

#### Example — C2

```
RW C:\etc\src\git\myrepo
D  C:\etc\src\git\myrepo\.env
```

| Operation | Path | Result |
|---|---|---|
| read | `C:\etc\src\git\myrepo\src\main.rs` | success |
| `GetFileAttributes` | `C:\etc\src\git\myrepo\.env` | success, real attrs |
| `FindFirstFile C:\etc\src\git\myrepo\*` | **includes `.env`** |
| read | `C:\etc\src\git\myrepo\.env` | `ACCESS_DENIED` |
| `CreateFile CREATE_NEW` | `C:\etc\src\git\myrepo\.env` | `ACCESS_DENIED` |

### Category D — disappears

The base spec's Category D was "outer leaf-on-directory + inner
subtree." With no leaf marker, this category does not exist in this
spec.

### Category E — disjoint siblings

Trivial: each entry governs its own scope; no interaction.

#### Example — E

```
RW C:\etc\src\git\myrepo
RW C:\Users\gudge\temp
RO C:\Windows
```

The three subtrees do not overlap. Each behaves as in isolation.

### Category F — multiple entries with the same intent

| Cell | Combination | Runtime effect | Validator |
|---|---|---|---|
| F1 | Two same-intent entries, one nested in the other | inner is redundant; outer covers | dedupe + warn |
| F2 | Two identical entries | one is redundant | silent dedupe |

#### Example — F1

```
RW C:\Users\gudge\temp
RW C:\Users\gudge\temp\subdir
```

Validator emits:

```
NOTICE: entry `RW C:\Users\gudge\temp\subdir` is fully covered by
        `RW C:\Users\gudge\temp`. Dropping the inner entry.
```

### Category G — rename across regions

| Cell | Source | Destination | Result | Failure |
|---|---|---|---|---|
| G1 | RW (same subtree) | RW (same subtree) | succeeds | — |
| G2 | RW (subtree A) | RW (subtree B) | succeeds | — |
| G3 | RW | RO | fails at dest | `ACCESS_DENIED` |
| G4 | RW | D | fails at dest | `ACCESS_DENIED` |
| G5 | RO | RW | fails at source | `ACCESS_DENIED` |
| G6 | D | anywhere | fails at source | `ACCESS_DENIED` |
| G7 | implicit-traversal-only | RW | fails at source | `ACCESS_DENIED` |

Note: under access-denied semantics, every rename failure caused by
the policy is `ACCESS_DENIED`. The only not-found errors the agent
sees are for paths that genuinely don't exist on the host.

#### Example — G3 and G4

```
RW C:\Users\gudge\temp
RO C:\Users\gudge\Documents\reference
D  C:\Users\gudge\Documents\private
```

| Rename | From | To | Result |
|---|---|---|---|
| G3 | `temp\notes.txt` | `reference\notes.txt` | `ACCESS_DENIED` at destination (RO doesn't allow create) |
| G4 | `temp\notes.txt` | `private\notes.txt` | `ACCESS_DENIED` at destination (D refuses) |

### Category H — interactions with the implicit default region

| Cell | Behavior | Notes |
|---|---|---|
| H1 | unlisted read fails-as-`ACCESS_DENIED` | default-deny |
| H2 | unlisted write fails-as-`ACCESS_DENIED` | default-deny |
| H3 | read inside RW subtree succeeds | F13 |
| H4 | Position 3 grant honored if user has access; validation error otherwise | F4 — static check |

The agent can probe whether a path is unlisted by stat'ing it:
`GetFileAttributes` returns `ACCESS_DENIED` for unlisted paths
(same as denied paths). So the agent cannot distinguish "path
exists but I have no access" from "path doesn't exist" except by
enumerating the parent.

The parent's listing leaks namespace shape: the agent can see what
exists on the host even if it can't access most of it. This is the
intended behavior under access-denied semantics. If a user needs
namespace hiding, that's a future namespace-mapping policy concern.

## End-to-end worked example

Combining the elements: the canonical example policy.

```
include "windows-dev-readonly-defaults"

RW C:\etc\src\git\myrepo
RW C:\Users\gudge\temp
RW C:\Users\gudge\scratch
RW C:\Users\gudge\Documents\workinprogress
D  C:\Users\gudge\Documents\workinprogress\private
```

The include fragment (illustrative; actual contents subject to
capability-profile work) contributes:

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
RO C:\Users\gudge\Documents\PowerShell\Microsoft.PowerShell_profile.ps1
... (etc.)
```

After validation and normalization, what the agent observes:

| Operation | Path | Result | Reason |
|---|---|---|---|
| read | `C:\Windows\System32\kernel32.dll` | success | include RO subtree |
| read | `C:\Program Files\Git\cmd\git.exe` | success | include RO subtree |
| read | `C:\Users\gudge\.gitconfig` | success | include RO on file |
| write | `C:\Users\gudge\.gitconfig` | `ACCESS_DENIED` | RO denies write |
| read | `C:\Users\gudge\.cargo\config.toml` | success | include RO subtree |
| read/write | `C:\etc\src\git\myrepo\src\main.rs` | success | user RW subtree |
| read/write | `C:\Users\gudge\temp\out.log` | success | user RW subtree |
| read/write | `…\workinprogress\note.md` | success | user RW subtree |
| `GetFileAttributes` | `…\workinprogress\private` | success, real attrs | F10 |
| `FindFirstFile …\workinprogress\*` | **includes `private`** | F10 |
| any op on contents | `…\workinprogress\private\anything` | `ACCESS_DENIED` | user D |
| `FindFirstFile …\workinprogress\private\*` | `ACCESS_DENIED` | enum of D refused |
| read | `C:\Users\gudge\.bash_history` | `ACCESS_DENIED` | default-deny |
| `GetFileAttributes` | `C:\Users\gudge\.bash_history` | `ACCESS_DENIED` | default-deny |
| `CreateFile CREATE_NEW` | `C:\temp\logs\app.log` | `ACCESS_DENIED` | default-deny on parent |

`git status`, `cargo build`, `pwsh -c 'Get-ChildItem'` against the
repo all work. The agent cannot read `.bash_history` or `.ssh\id_rsa`,
cannot write to `.gitconfig`, can see that `private` exists but
cannot access its contents.

## Validator pseudocode (informative)

For a clearer mental model. Not the authoritative spec; the rules
above are.

```text
validate(policy):
  # 1. Include resolution
  entries = resolve_includes(policy.entries, fragments)  # detect cycles

  # 2. Path canonicalization (F8)
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
    bucket = dedupe(bucket)

  # 5. Nesting checks
  for outer, inner in nesting_pairs(entries):
    if outer.intent == inner.intent:
      warn("redundant nested entry: " + inner.path, F1)
    elif suspicious_nesting(outer, inner):
      # e.g., RO or RW inside D — allow-inside-deny
      warn(suspicious_nesting_description(outer, inner), B5/B6/C3)

  # 6. Position 3 check (F4)
  for e in entries:
    if e.intent in [RO, RW]:
      if not user_has_access(invoking_user, e.path, e.intent):
        error("user cannot delegate access they lack at " + e.path, F4)

  return NormalizedPolicy(entries, errors, warnings)
```

## Runtime enforcement notes

The language semantics above are intentionally enforcement-agnostic.
This section catalogues the known runtime-enforcement risks and
their status under round-2 decisions.

### R1 / R3 — Object-level enforcement via non-name routes

**Resolved.** Under F11 the policy is object-based. Alternative
routes to an object (hardlink alias, junction target, file-ID,
volume-GUID, 8.3 short name, bind mounts on Linux, firmlinks on
macOS) all resolve to the same object identity and receive the
same access decision. This is the natural behavior of the
underlying DAC layer on every supported OS, so no additional
enforcement machinery is required at this level.

### R2 — Implicit traversal needing ancestor ACEs

**Resolved.** AppContainer tokens on Windows 11 23H2+ retain
`SeChangeNotifyPrivilege`. Intermediate-component `FILE_TRAVERSE`
checks during `IRP_MJ_CREATE` path walk are bypassed by the kernel.
F9 is enforceable as written, with no ancestor ACE work needed. See
`appcontainer_traversal_findings.md`.

### R4 — Hidden returning ACCESS_DENIED instead of not-found

**No longer applicable.** Under F10, `ACCESS_DENIED` *is* the
spec'd behavior. There's no mismatch between the language and what
enforcement layers naturally produce.

### R5 — Enumeration filtering for deny inside RW

**No longer applicable.** Under F10, denied paths are visible to
enumeration of their parent. Enumeration of the parent does not
need filtering. The bindflt R/W identity bind's passthrough
enumeration of host directory contents is correct as-is.

### R5b — Create-then-invisible at default-deny under writable parent

**Doesn't arise.** The corner this addressed required `RW[L]` on a
directory without children coverage; without a leaf marker (F1),
this case cannot be expressed.

### Summary table

| Risk | Description | Status |
|---|---|---|
| R1 / R3 | Object-level enforcement via non-name routes | Resolved (F11 object-based) |
| R2 | Implicit traversal needing ancestor ACEs | Resolved (`SeChangeNotifyPrivilege`) |
| R4 | Hidden returning ACCESS_DENIED instead of not-found | Not applicable (ACCESS_DENIED is spec'd) |
| R5 | Enumeration filtering for deny inside RW | Not applicable (no filtering needed) |
| R5b | Create-then-invisible at default-deny under writable parent | Doesn't arise (no leaf marker) |

All runtime risks identified in round 1 are addressed under
round-2 decisions. The composition's enforcement work simplifies
substantially: the bindflt and ProjFS layers no longer need to
implement special-case hiding logic; the only deny mechanism is
`ACCESS_DENIED` via the existing AppContainer SID denial path or
via a deny ACE on the user-owned RW root.

## Open questions and deferrals

- **OQ-S1**: Capability carve-outs within an intent (e.g. "RW but
  not DACL-write"). Deferred.
- **OQ-S2**: Policy behavior for paths deleted and recreated mid-run.
  Deferred.
- **OQ-S3**: Deny on non-existent paths. Worth reconsidering under
  access-denied semantics where the case is simpler ("attempts to
  create at this path fail with `ACCESS_DENIED`"). Reserved for
  separate discussion.
- **OQ-S4**: Should redundant entries be dropped from the normalized
  representation or kept for diagnostics round-tripping? Defer.
- **OQ-S5**: Should the validator surface the implicit-traversal set
  to the user (informational)? Decided: no — too noisy.
- **OQ-S6**: Position 3's user-access probe at validation time —
  what API and what scope? Implementation detail; deferred.
- **OQ-S7**: Constraint-only as an alternative to default-deny.
  Reserved for future consideration.
- **OQ-S8**: Fragments with per-Windows-version variants. Mechanism
  open; deferred.
- **OQ-R2a**: Namespace mapping policy design (hiding paths,
  renaming, mounting). Reserved for a future iteration; explicitly
  out of scope for v1 FS access policy.
- **OQ-R2b**: When does the leaf marker get added back, and what
  use cases drive it? Currently deferred indefinitely.

## Cross-references to enforcement work

Implementation mapping of these semantics onto specific Windows
primitives is in `fs-projection-composition-plan.md` and
`projfs_bindflt_summary.md`. Notably under round-2 decisions:

- `D` (access-denied) maps onto either (a) absence of any grant
  for the AppContainer SID on the path, which produces native
  NTFS access-denied; or (b) an explicit deny ACE for the package
  SID where the user owns the path and wants belt-and-braces.
  No hiding logic, no enumeration filtering, no provider denylist
  for new-file creation.
- `RW` maps onto bindflt R/W identity bind + package-SID grant ACE.
- `RO` on AAP-readable system roots maps onto bindflt R/O identity
  bind (no broker needed).
- `RO` on non-AAP-readable paths maps onto ProjFS provider + bindflt
  redirect into the virt root.
- Implicit traversal (F9) relies on `SeChangeNotifyPrivilege` per
  `appcontainer_traversal_findings.md`.

The composition is meaningfully simpler under round-2 decisions:
the ProjFS provider can drop its hiding callbacks, the bindflt
exception-list machinery is needed only for partitioning the
namespace (not for hiding), and the runtime risk register is
empty.
