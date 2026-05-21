# MXC FS-policy semantics — review summary

**Status**: high-level summary for review
**Owner**: gudgmi
**Branch**: `user/gudge/downlevel-fs-projection-plan`
**Full spec**:
[`policy_semantics_v1.md`](./policy_semantics_v1.md) (16 pages, ~880 lines)

This document is a condensed summary of the MXC FS-policy semantics
suitable for sending around for design review. It covers the
headline decisions and illustrates the non-obvious cases with short
worked examples. For the full specification — every rule, every
interaction matrix cell, validator pseudocode, runtime enforcement
notes — see the full spec linked above.

The MXC FS-policy language describes what the contained code can
observe about, and do to, the host filesystem. It is intentionally
enforcement-agnostic: it says what the contained code *should* see,
not how that's implemented. Mapping these semantics onto specific
Windows primitives is the subject of
[`fs-projection-composition-plan.md`](./fs-projection-composition-plan.md)
and its companion docs.

## The model in 30 seconds

- A policy is **three lists** of host paths: `readonly` (`RO`),
  `readwrite` (`RW`), `deny` (`D`).
- Each entry carries one of two markers: **leaf** `[L]`
  (the named object only) or **subtree** `[S]` (the named object and
  every descendant). Deny on a directory is always treated as a
  subtree regardless of marker.
- Paths in the policy are **host paths**; the contained code sees the
  same path strings (identity projection — no separate "container
  namespace").
- Paths must **exist** at policy-load time. (Deny on non-existent
  paths is deferred.)
- The language defaults to **deny**. Unlisted paths are inaccessible.
- **Includes**: shipped, versioned policy fragments (e.g.
  `windows-dev-readonly-defaults`) carry the bulk of system-path
  entries so users don't have to type them.
- **Most-specific path wins** when multiple entries cover a path.
- Multiple entries at the *exact same path* on *different lists* is a
  **validation error** — the user is contradicting themselves.
- The policy is interpreted as a **delegation from the invoking user
  to the agent**: `RO`/`RW` grants are bounded by the user's own
  access (checked statically at validation time); `D` is unbounded.

## Ten headline decisions

These are the decisions where someone reviewing the spec might
reasonably have wanted a different answer. They are the load-bearing
choices.

### D1 — Default-deny, not default-allow

Unlisted paths are inaccessible to the agent. A policy that mentions
nothing is a policy that grants nothing.

**Why**: forgotten clauses fail closed (safer), the policy fully
describes the agent's view (auditable), and the same policy means
the same thing on different hosts (portable).

**Cost**: most policies would need to list many "obvious" paths
(`C:\Windows`, `C:\Program Files`, etc.). Mitigated by `include`
fragments.

### D2 — Include fragments

Policies can `include` shipped, versioned fragments. A typical
user policy is a thin user-specific layer plus one or two includes.

```
include "windows-dev-readonly-defaults"
RW[S] C:\etc\src\git\myrepo
RW[S] C:\Users\gudge\temp
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

**Alternative we considered**: "constraint-only" semantics (the
policy can only restrict, never grant) was rejected as too weak
under AppContainer's default-deny token. "Pure grant" (the policy
grants kernel-level access regardless of the user's rights) was
rejected as too strong (lets the user delegate access they don't
have).

### D4 — Most-specific path wins

When multiple entries cover the same path, the entry with the longest
matching path prefix determines the path's semantics. Same path with
*different intents* is a validation error.

**Alternative considered**: strict least-privilege (`D > RO > RW`)
regardless of specificity. Rejected because it makes intuitive
expressions like "writable scratch dir inside an otherwise-RO area"
unexpressible.

### D5 — Deny is hidden, not access-denied

Operations on a denied path fail as if the path **does not exist**
(`ERROR_FILE_NOT_FOUND` / `ERROR_PATH_NOT_FOUND` /
`INVALID_FILE_ATTRIBUTES`). Enumeration of the parent does not list
the path.

Failing-as-not-found is the language definition. Some enforcement
mechanisms (e.g. backstop deny ACEs) naturally return
`ACCESS_DENIED`; those cases are documented in the runtime
enforcement notes and surfaced to the caller, but they're
considered "shouldn't have reached here" degradations.

### D6 — Hiding is object-level, not just name-level

A denied object is hidden via *any* route — file ID, hardlink alias,
junction target, volume-GUID prefix, `\\?\` prefix, 8.3 short name.
The language is strict; the enforcement layer may approximate, with
annotations.

### D7 — Implicit traversal is name-resolution-only

When a policy lists a deep path like `RO[L] C:\a\b\c`, the language
implicitly grants name-resolution traversal on `C:\a` and `C:\a\b`.
The user does not have to list ancestors.

The implicit grant is the *minimum* needed to make the named entry
functional. It does **not** confer stat, DACL read, enumeration, or
any other capability on the ancestors. If the user wants the
ancestor to be stat-able too, they list it explicitly.

This is enforceable on Windows 11 23H2+ via
`SeChangeNotifyPrivilege`, which AppContainer tokens retain. See
[`appcontainer_traversal_findings.md`](./appcontainer_traversal_findings.md).

### D8 — Explicit `D` is strictly stronger than default-deny

Both make a path inaccessible, but:

- **Explicit `D`**: no operation against the path appears to succeed.
  `CreateFile(P, …, CREATE_NEW)` returns `ERROR_FILE_NOT_FOUND` even
  if the *parent directory* grants `FILE_ADD_FILE`.
- **Default-deny** (path simply unlisted): no capability is granted
  on the path itself. Operations requiring capability on the parent
  (like `CREATE_NEW` in a writable parent) still succeed.

In our v1 enforcement, the asymmetry doesn't actually surface because
the validator (see D10 below) makes the only way to reach the
default-deny corner a validation error. But the semantic distinction
is preserved.

### D9 — Leaf entries on directories are meaningful and useful

`RO[L]` on a directory grants stat / metadata read / DACL read on
the directory itself. It does **not** grant enumeration of contents
(F14 + default-deny on children).

`RO[L]` is useful when the user wants the agent to see that the
directory exists and access its metadata, but its contents should be
covered by separate entries (or be default-denied).

`RW[L]` on a directory is **forbidden** at validation time unless
some other entry covers the directory's descendants — see D10.

### D10 — `RW[L]` on a directory without children-coverage is a validation error

This is a sharp corner of the language. `RW[L]` on a directory grants
the agent rights on the directory's *own* metadata, but does *not*
grant `FILE_ADD_FILE` / `FILE_DELETE_CHILD`. So:

```
RW[L] C:\Users\gudge\Documents\workinprogress    # ← invalid
```

This is rejected at validation. The user must either change the
entry to `RW[S]` (covering descendants) or add explicit entries for
the children they intend to expose. Rationale: prevents a confusing
"the agent can rename the directory but can't add files to it"
corner from reaching production.

`RO[L]` on a directory has no such restriction.

## Selected non-obvious examples

The examples below illustrate the cases where the language's behaviour
might not match a reader's first guess.

### Example 1 — RO carve-out inside RW (most-specific-wins)

```
RW[S] C:\etc\src\git\myrepo
RO[S] C:\etc\src\git\myrepo\.git
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
RW[S] C:\Users\gudge\Documents\workinprogress
D[S]  C:\Users\gudge\Documents\workinprogress\private
```

| Operation | Path | Result |
|---|---|---|
| read/write | `…\workinprogress\notes.txt` | success |
| any op | `…\workinprogress\private` | not-found |
| any op | `…\workinprogress\private\secret.txt` | not-found |
| `FindFirstFile …\workinprogress\*` | listing | omits `private` |

The `private` directory does not appear in the agent's view at all.

### Example 3 — Leaf-RO on directory with inner subtree (D1, useful)

```
RO[L] C:\Users\gudge
RW[S] C:\Users\gudge\workspace
```

| Operation | Path | Result |
|---|---|---|
| `GetFileAttributes` | `C:\Users\gudge` | success (leaf RO) |
| `FindFirstFile C:\Users\gudge\*` | listing | returns only `workspace` |
| read | `C:\Users\gudge\.gitconfig` | not-found (default-deny, no covering entry) |
| read/write | `C:\Users\gudge\workspace\foo.txt` | success (inner RW) |

The agent sees `C:\Users\gudge` exists, sees one child (`workspace`),
and can use that child freely. It cannot see anything else inside
the user profile.

### Example 4 — Allow inside deny (B5, warned but allowed)

```
D[S]  C:\Users\gudge
RW[S] C:\Users\gudge\workspace
```

| Operation | Path | Result |
|---|---|---|
| read | `C:\Users\gudge\.gitconfig` | not-found — outer D |
| read/write | `C:\Users\gudge\workspace\foo.txt` | success — inner RW |
| `FindFirstFile C:\Users\gudge\*` | listing | returns only `workspace` |

The inner `RW[S]` punches a hole in the outer `D[S]`. Validator
emits a warning: "allow entry nests inside deny entry; the inner
allow overrides only for the named subtree, not for siblings.
Confirm intent."

### Example 5 — Rename across regions (G4 and G3 contrasted)

```
RW[S] C:\Users\gudge\temp
D[S]  C:\Users\gudge\Documents\private
RO[S] C:\Users\gudge\Documents\reference
```

| Rename | From | To | Result | Reason |
|---|---|---|---|---|
| G3 | `temp\foo.txt` | `reference\foo.txt` | `ACCESS_DENIED` at dest | RO dest doesn't allow create |
| G4 | `temp\foo.txt` | `private\foo.txt` | not-found at dest | D dest is hidden — destination doesn't exist from agent's view |
| (G6) | `private\anything` | anywhere | not-found at source | source is hidden |

The two failure-code answers are different: RO produces
`ACCESS_DENIED` because the destination is visible-but-not-writable;
D produces not-found because the destination is hidden. This is the
D5 principle in action.

### Example 6 — Default-deny vs explicit deny (D8 illustrated)

```
RW[L] C:\Users\gudge\Documents       # ← invalid (D10), but let's pretend
                                     #   for illustration
```

(In v1 this is a validation error. Setting that aside to show the
underlying semantics:)

If the policy *were* allowed, `CreateFile CREATE_NEW C:\Users\gudge\
Documents\newfile.txt` would succeed (the parent grants write — wait
no, F16 says `[L]` doesn't grant `FILE_ADD_FILE` either, so it would
fail with `ACCESS_DENIED`).

Where the distinction *would* show up: a hypothetical `RW[L]` that
*did* grant child-create plus a default-denied child path. Under
explicit `D` on that child, `CREATE_NEW` returns not-found. Under
default-deny on that child, `CREATE_NEW` returns success and the new
file is invisible.

D10 (validation error for `RW[L]` on directory without
children-coverage) was added specifically to ensure no valid v1
policy can produce this corner in practice.

### Example 7 — Full policy combining everything

```
include "windows-dev-readonly-defaults"

RW[S] C:\etc\src\git\myrepo
RW[S] C:\Users\gudge\temp
RW[S] C:\Users\gudge\scratch
RW[S] C:\Users\gudge\Documents\workinprogress
D[S]  C:\Users\gudge\Documents\workinprogress\private
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
| `…\workinprogress\private\anything` | any | not-found |
| `C:\Users\gudge\.bash_history` | read | not-found (default-deny) |
| `C:\temp\logs\app.log` | create | not-found (default-deny on parent path) |

`git status`, `cargo build`, `pwsh -c 'Get-ChildItem'` against the
repo work. The agent cannot read `.bash_history` or `.ssh\id_rsa`,
cannot write to `.gitconfig`, cannot see or modify `private` or
its contents.

## What we deferred

These were explicitly considered and pushed to a later iteration.
They are listed so reviewers can flag any they think shouldn't have
been deferred.

- **Capability carve-outs within an intent.** E.g. "RW but not
  DACL-write," "RW but root-immutable." Out of scope; v1's `RW` is
  full write authority. Future capabilities, if needed, ship as
  separate intents.
- **Deny on non-existent paths.** v1 requires explicit entries to
  reference extant host objects. The example-policy clause `deny
  C:\temp\logs` (where the directory doesn't yet exist) is currently
  invalid input. Users wanting "prevent creation here" must
  create-and-deny. A separate `deny-creation` capability is a
  candidate for v2.
- **Policy behaviour for paths deleted-and-recreated mid-run.**
  v1 statement: policy applies to whatever object exists at the path
  at any given moment; identity changes are not separately tracked.
- **Constraint-only as an alternative to default-deny.** We
  considered both and picked default-deny + includes; the
  constraint-only model is reserved if v1 ergonomics turn out to be
  a problem in practice.

## Pointers

- **Full spec**: [`policy_semantics_v1.md`](./policy_semantics_v1.md)
- **Composition plan** (how these semantics map onto Windows
  primitives): [`fs-projection-composition-plan.md`](./fs-projection-composition-plan.md)
- **Reviewer summary of the composition**:
  [`projfs_bindflt_summary.md`](./projfs_bindflt_summary.md)
- **Traversal-enforcement finding** (the underpinning of D7):
  [`appcontainer_traversal_findings.md`](./appcontainer_traversal_findings.md)
- **Originating session**: Copilot CLI session
  `d739a782-d102-4c2b-b4f9-31b461abef5a` —
  `copilot --resume d739a782-d102-4c2b-b4f9-31b461abef5a`
