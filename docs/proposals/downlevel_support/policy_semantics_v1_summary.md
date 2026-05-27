# MXC FS-policy semantics — review summary (round 2)

**Status**: high-level summary for review
**Owner**: gudgmi
**Branch**: `user/gudge/downlevel-fs-projection-plan`
**Full spec**:
[`policy_semantics_v1.md`](./policy_semantics_v1.md)
**Variants explored**:
[`policy_semantics_v1_variants/`](./policy_semantics_v1_variants/)

## What's new since round 1

Reviewer feedback prompted three potential changes to the spec.
After consideration, **two were accepted and one was reverted**:

- **Accepted: no leaf marker.** v1 entries are subtree-implicit on
  directories. Adding `[L]` back later is a strictly-additive
  language change. The base spec's `[L]` vs `[S]` distinction is
  gone; entries are just paths + intents.
- **Accepted: `D` means access-denied, not hidden.** A denied path
  remains visible in parent enumeration and via `GetFileAttributes`;
  operations against it fail with `ACCESS_DENIED`. Namespace
  visibility (true hiding) is reserved for a future namespace-
  mapping policy.
- **Reverted: `D` unconditionally trumps `RO`/`RW`.** This was
  considered but rejected; the language uses most-specific-wins
  uniformly across all three lists. A more-specific `D` denies a
  sub-path inside an allow region; a more-specific allow exposes a
  sub-path inside a `D` region (with a validator warning on the
  latter case).

This document summarises the v1 language under these round-2
decisions. For the full specification — every rule, every interaction
matrix cell, validator pseudocode, runtime enforcement notes — see
the full spec.

The MXC FS-policy language describes what the contained code can
observe about, and do to, the host filesystem. It is intentionally
enforcement-agnostic: it says what the contained code *should* see,
not how that's implemented. Mapping these semantics onto specific
Windows primitives is the subject of
[`fs-projection-composition-plan.md`](./fs-projection-composition-plan.md).

## The model in 30 seconds

- A policy is **three lists** of host paths: `readonly` (`RO`),
  `readwrite` (`RW`), `deny` (`D`).
- Each entry is just a path + intent. **No marker.** On a directory,
  entries cover the directory and all descendants. On a file,
  entries cover the file.
- Paths in the policy are **host paths**; the contained code sees
  the same path strings (identity projection — no separate
  "container namespace").
- Paths must **exist** at policy-load time. (Deny on non-existent
  paths is deferred separately.)
- The language defaults to **deny**. Unlisted paths are inaccessible.
- **Includes**: shipped, versioned policy fragments (e.g.
  `windows-dev-readonly-defaults`) carry the bulk of system-path
  entries so users don't have to type them.
- **Most-specific path wins** when multiple entries cover a path —
  uniformly across all three lists.
- Multiple entries at the *exact same path* on *different lists* is
  a **validation error**.
- The policy is interpreted as a **delegation from the invoking user
  to the agent**: `RO`/`RW` grants are bounded by the user's own
  access (checked statically at validation time); `D` is unbounded.
- **`D` produces `ACCESS_DENIED`, not "hidden".** The agent can see
  that a denied path exists; it just can't do anything to it.

## Eight headline decisions

These are the load-bearing choices a reviewer might want to push
back on.

### D1 — Default-deny, not default-allow

Unlisted paths are inaccessible to the agent. A policy that mentions
nothing is a policy that grants nothing.

**Why**: forgotten clauses fail closed (safer), the policy fully
describes the agent's view (auditable), and the same policy means
the same thing on different hosts (portable).

**Cost**: most policies would need to list many "obvious" paths.
Mitigated by `include` fragments (D2).

### D2 — Include fragments

Policies can `include` shipped, versioned fragments. A typical user
policy is a thin user-specific layer plus one or two includes:

```
include "windows-dev-readonly-defaults"
RW C:\etc\src\git\myrepo
RW C:\Users\gudge\temp
```

The include is the answer to default-deny's ergonomic cost. After
resolution the language behaves as if the user typed every entry.

### D3 — Position 3 (delegation from the invoking user)

The policy is a delegation, not a permission list and not a filter.
For `RO`/`RW`: the agent receives the named access if and only if
the *invoking user* themselves has it. For `D`: the agent is denied
unconditionally.

A user cannot delegate access they themselves don't possess. This
is checked **statically at validation time** — the policy load
fails before the run starts.

### D4 — Most-specific path wins, uniformly

When multiple entries cover the same path, the entry with the
longest matching path prefix wins. Applies the same way to all three
lists: a more-specific `D` wins over a less-specific `RO`/`RW`, and
vice versa. Same path with *different intents* is a validation
error.

A reviewer in round 1 proposed making `D` unconditionally trump
`RO`/`RW`. After consideration, that proposal was reverted —
uniform most-specific-wins is more expressive and preserves the
ability to express "deny most of X, allow some sub-paths" via
nested entries. The validator warns when an allow nests inside a
`D` subtree so the user can confirm the override is intentional.

### D5 — Deny is access-denied, not hidden

Operations on a denied path fail with `ACCESS_DENIED`. The denied
path remains visible: `GetFileAttributes` returns the actual host
attributes; `FindFirstFile` on the parent includes the denied
name in its results.

This is a meaningful change from the round-1 spec, where `D` meant
"hidden / not-found." The round-2 model is closer to how Windows
DACL deny ACEs naturally behave. Namespace visibility (true
hiding) is reserved for a future namespace-mapping policy,
**explicitly out of scope** for this FS access policy.

The denied directory's *contents* are still inaccessible — opening
a denied directory with `FILE_LIST_DIRECTORY` is refused — so the
agent sees that a denied directory exists but cannot enumerate its
children. This is intentional: the directory's existence is host-
namespace information, but its contents are not.

### D6 — Object-based

An entry's intent applies to the **object** the named path
reaches. If the same object is reachable through multiple paths
— junctions, mount points, hardlinks, drive-letter aliases,
bind mounts, firmlinks, volume-GUID prefixes — the policy
applies uniformly. Writing `RW C:\etc\src\git\myrepo` and
`RO D:\git\myrepo` for the same underlying repo (because `D:\`
is mounted under `C:\etc\src`) is a validation error: the user
has named the same target twice with conflicting intents.

This matches the underlying access-control mechanism on every
supported OS: NTFS DACLs on Windows, POSIX permissions and ACLs
on Linux and macOS. The language doesn't promise path-based
behavior the runtime can't deliver.

Naming and visibility — projecting one object at multiple
paths, hiding paths from the agent — is a separate concern
(namespace policy), deferred to a future iteration.

### D7 — Implicit traversal is name-resolution-only

When a policy lists a deep path like `RO C:\a\b\c`, the language
implicitly grants name-resolution traversal on `C:\a` and `C:\a\b`.
The user does not have to list ancestors.

The implicit grant is the *minimum* needed to make the named entry
functional. It does **not** confer stat, DACL read, enumeration, or
any other capability on the ancestors. If the user wants the
ancestor to be stat-able too, they list it explicitly.

This is enforceable on Windows 11 23H2+ via
`SeChangeNotifyPrivilege`, which AppContainer tokens retain. See
[`appcontainer_traversal_findings.md`](./appcontainer_traversal_findings.md).

### D8 — No leaf marker; subtree-implicit on directories

v1 has only one entry shape: a path with an intent. On a directory,
the entry covers the directory and all descendants. On a file, the
entry covers the file.

The base spec had a `[L]` (leaf, non-inheriting) and `[S]` (subtree,
inheriting) distinction. Round-2 drops `[L]`. The "stat a directory
without exposing its contents" use case that motivated `[L]` is
recoverable under default-deny: list whichever descendants you want
exposed, and the directory's existence is implicit via name-
resolution traversal to those descendants.

Adding `[L]` back later is a strictly-additive change: existing v1
policies continue to mean what they mean (subtree); new policies can
opt into a marker when needed.

## Selected non-obvious examples

The examples below illustrate the cases where the language's
behaviour might not match a reader's first guess.

### Example 1 — RO carve-out inside RW (most-specific-wins)

```
RW C:\etc\src\git\myrepo
RO C:\etc\src\git\myrepo\.git
```

| Operation | Path | Result |
|---|---|---|
| read | `myrepo\src\main.rs` | success — outer RW |
| write | `myrepo\src\main.rs` | success — outer RW |
| read | `myrepo\.git\config` | success — inner RO grants read |
| write | `myrepo\.git\config` | `ACCESS_DENIED` — inner RO denies write |

`git status` works (read-side only). `git add` does not (would need
to write to `.git\index`).

### Example 2 — Deny inside RW (the canonical pattern)

```
RW C:\Users\gudge\Documents\workinprogress
D  C:\Users\gudge\Documents\workinprogress\private
```

| Operation | Path | Result |
|---|---|---|
| read/write | `…\workinprogress\notes.txt` | success |
| `GetFileAttributes` | `…\workinprogress\private` | success, real attrs |
| `FindFirstFile …\workinprogress\*` | listing | **includes `private`** |
| read | `…\workinprogress\private` | `ACCESS_DENIED` |
| read | `…\workinprogress\private\secret.txt` | `ACCESS_DENIED` |
| `FindFirstFile …\workinprogress\private\*` | `ACCESS_DENIED` |
| `CreateFile CREATE_NEW` | `…\workinprogress\private\new.txt` | `ACCESS_DENIED` |

The agent sees `private` exists in the listing. It cannot read,
write, enumerate, or modify anything inside it. This is the round-2
shift: in round 1, `private` would have been *omitted* from the
parent listing.

### Example 3 — Allow inside deny (B5, warned but allowed)

```
D  C:\Users\gudge\Documents\workinprogress
RW C:\Users\gudge\Documents\workinprogress\drafts
```

| Operation | Path | Result |
|---|---|---|
| `GetFileAttributes` | `…\workinprogress` | success, real attrs |
| `FILE_LIST_DIRECTORY` | `…\workinprogress` | `ACCESS_DENIED` — outer D refuses enumeration |
| read | `…\workinprogress\notes.txt` | `ACCESS_DENIED` — outer D |
| read/write | `…\workinprogress\drafts\foo.txt` | success — inner RW |
| `FILE_LIST_DIRECTORY` | `…\workinprogress\drafts` | success — inner RW |

The user expresses "deny most of `workinprogress`, but allow
read/write in `drafts`." The inner `RW` punches a hole in the outer
`D`. Per most-specific-wins, the inner's intent applies for the
named subtree.

The agent cannot discover `drafts` through enumeration of
`workinprogress` (outer `D` refuses), but can address it by name
because the policy lists it explicitly (implicit traversal makes the
name resolvable).

Validator emits a warning: "Allow entry `RW C:\Users\gudge\Documents\
workinprogress\drafts` nests inside deny entry. The inner allow
overrides only for the named subtree; siblings of `drafts` remain
denied. Confirm intent."

### Example 4 — Same-path conflict (validation error)

```
RW C:\Users\gudge\temp
D  C:\Users\gudge\temp
```

Validator emits:

```
ERROR: path C:\Users\gudge\temp has entries on both `readwrite` and
       `deny` lists; intent conflict. Pick one.
```

The user is contradicting themselves at authoring time; the runtime
should not silently downgrade.

### Example 5 — Rename across regions

```
RW C:\Users\gudge\temp
RO C:\Users\gudge\Documents\reference
D  C:\Users\gudge\Documents\private
```

| Rename | From | To | Result |
|---|---|---|---|
| | `temp\notes.txt` | `reference\notes.txt` | `ACCESS_DENIED` at destination (RO doesn't allow create) |
| | `temp\notes.txt` | `private\notes.txt` | `ACCESS_DENIED` at destination (D refuses) |
| | `private\anything` | anywhere | `ACCESS_DENIED` at source (D refuses) |

Every policy-caused rename failure is `ACCESS_DENIED`. Under round-2
semantics, no not-found errors arise from the policy.

### Example 6 — Full policy combining everything

```
include "windows-dev-readonly-defaults"

RW C:\etc\src\git\myrepo
RW C:\Users\gudge\temp
RW C:\Users\gudge\scratch
RW C:\Users\gudge\Documents\workinprogress
D  C:\Users\gudge\Documents\workinprogress\private
```

Sampled observations:

| Path | Operation | Result |
|---|---|---|
| `C:\Windows\System32\kernel32.dll` | read | success (include) |
| `C:\Program Files\Git\cmd\git.exe` | read | success (include) |
| `C:\Users\gudge\.gitconfig` | read | success (include) |
| `C:\Users\gudge\.gitconfig` | write | `ACCESS_DENIED` |
| `C:\etc\src\git\myrepo\src\main.rs` | read/write | success |
| `C:\Users\gudge\temp\out.log` | read/write | success |
| `…\workinprogress\notes.md` | read/write | success |
| `…\workinprogress\private` | `GetFileAttributes` | success, real attrs |
| `…\workinprogress\private` | any op | `ACCESS_DENIED` |
| `…\workinprogress\private\*` | enumerate | `ACCESS_DENIED` |
| `C:\Users\gudge\.bash_history` | read | `ACCESS_DENIED` (default-deny) |
| `C:\Users\gudge\.bash_history` | `GetFileAttributes` | `ACCESS_DENIED` |

`git status`, `cargo build`, `pwsh -c 'Get-ChildItem'` against the
repo all work. The agent cannot read `.bash_history` or
`.ssh\id_rsa`; can see that `private` exists but cannot access its
contents; cannot write to `.gitconfig`.

## What we deferred

These were explicitly considered and pushed to a later iteration.
Listed so reviewers can flag any they think shouldn't have been
deferred.

- **Capability carve-outs within an intent.** E.g. "RW but not
  DACL-write," "RW but root-immutable." Out of scope; v1's `RW` is
  full write authority. Future capabilities, if needed, ship as
  separate intents.
- **Deny on non-existent paths.** v1 requires explicit entries to
  reference extant host objects. The case is conceptually simpler
  under access-denied semantics ("attempts to create at the path
  fail with `ACCESS_DENIED`"); worth re-opening separately as a
  follow-up.
- **Namespace mapping policy.** Hiding paths, presenting alternate
  names, restricting enumeration. Reserved for a future iteration,
  distinct from this FS access policy.
- **Leaf marker `[L]`.** v1 has subtree-only entries. Adding `[L]`
  back later is a strictly-additive change.
- **Policy behaviour for paths deleted-and-recreated mid-run.** v1
  statement: policy applies to whatever object exists at the path
  at any given moment.
- **Constraint-only as an alternative to default-deny.** Considered;
  default-deny + includes was chosen. Reserved if ergonomics turn
  out to be a problem in practice.

## Runtime risk register

All five enforcement risks identified during round 1 are now either
resolved or no longer applicable:

| Risk | Status under round 2 |
|---|---|
| R1 / R3 — object-level enforcement via non-name routes | Resolved (D6 is object-based) |
| R2 — implicit traversal needing ancestor ACEs | Resolved (`SeChangeNotifyPrivilege` works as expected on 23H2+) |
| R4 — hidden returning ACCESS_DENIED instead of not-found | Not applicable (`ACCESS_DENIED` is the spec'd behavior) |
| R5 — enumeration filtering for deny inside RW | Not applicable (denied paths are visible in enumeration) |
| R5b — create-then-invisible at default-deny under writable parent | Doesn't arise (no leaf marker) |

The composition's enforcement is meaningfully simpler under
round-2 decisions: bindflt and ProjFS don't need hiding callbacks
or denylist machinery; `ACCESS_DENIED` from the AppContainer SID's
natural denial path (or from a deny ACE on the RW root where
needed) is what the language asks for.

## Pointers

- **Full spec**: [`policy_semantics_v1.md`](./policy_semantics_v1.md)
- **Variants explored**:
  [`policy_semantics_v1_variants/`](./policy_semantics_v1_variants/)
  — three single-feedback variants and a merged variant for history.
- **Composition plan**: [`fs-projection-composition-plan.md`](./fs-projection-composition-plan.md)
- **Composition summary**: [`projfs_bindflt_summary.md`](./projfs_bindflt_summary.md)
- **Traversal finding**: [`appcontainer_traversal_findings.md`](./appcontainer_traversal_findings.md)
- **Originating Copilot CLI session**:
  `copilot --resume d739a782-d102-4c2b-b4f9-31b461abef5a`
