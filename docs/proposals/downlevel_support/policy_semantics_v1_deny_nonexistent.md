# MXC FS-policy semantics — deny on non-existent paths

**Status**: draft adjunct, resolves OQ-S3 under round-2 semantics
**Owner**: gudgmi (with Copilot CLI as pair)
**Branch**: `user/gudge/downlevel-fs-projection-plan`
**Canonical spec**:
[`policy_semantics_v1.md`](./policy_semantics_v1.md)
**Summary**:
[`policy_semantics_v1_summary.md`](./policy_semantics_v1_summary.md)
**Related variant**:
[`policy_semantics_v1_variants/v1_d_access_denied.md`](./policy_semantics_v1_variants/v1_d_access_denied.md)

This adjunct answers the deferred OQ-S3 question from the canonical
round-2 spec: may a `deny` (`D`) entry name a host path that does not
currently exist?

The answer proposed here is **yes, for `D` only**. `RO` and `RW`
entries still must name extant host objects at policy-load time.

## Scope

This document is intentionally narrow. It refines F2 and the validator
rules needed to support non-existent `D` entries. It does not change:

- F1's no-marker, subtree-implicit model;
- F4's Position 3 delegation model;
- F6's uniform most-specific-wins rule;
- F7's same-object multi-list conflict rule;
- F8's canonicalization rule;
- F10's access-denied semantics for `D`;
- F11's object-based model;
- F12's provenance-irrelevant rule;
- default-deny.

If a point below seems to require changing one of those rules, treat it
as an open question rather than a normative change.

**Interaction with F11 (object-based).** A non-existent `D` path
has no host object to canonicalize against at load time, so F8's
object-resolution stage defers for that entry until the path
materializes. Before materialization the entry matches by
lexically-canonical path string. Once a host object exists at the
path, F11's object-identity match applies and the deny covers all
aliases that reach the object.

## Motivation

The motivating policy from the original design discussion contained a
clause like:

```text
D C:\temp\logs
```

where `C:\temp\logs` did not exist on the host at policy-load time.
The user's intent was not to hide an existing directory. The intent was:

> The agent must not be able to create this path going forward.

Round 1 deferred this case because `D` was then modeled as hiding. A
rule like "hide a thing that does not exist" was awkward: there was no
object to hide, no enumeration result to filter, and no clear answer for
creation races.

Round 2 changed the meaning of `D`: it now produces `ACCESS_DENIED`,
not not-found. That makes the case natural. A non-existent `D` path is a
standing refusal: if the agent addresses that path, or any descendant of
that path, operations that would materialize or access it fail with
`ACCESS_DENIED`. If another principal later creates the object on the
host, the agent's operations against the path are still denied.

## Language refinement

### F2' — Paths must exist, except `D`

Replace F2 for this adjunct with the following refinement:

> Every explicit `RO` or `RW` entry must resolve to an extant host
> object at the time the policy is loaded. A policy that names a
> non-existent `RO` or `RW` path is rejected by the validator.
>
> A `D` entry may name either an extant host object or a non-existent
> host path. If the `D` path exists, the ordinary round-2 `D` semantics
> apply. If the `D` path does not exist, the entry is retained in the
> normalized policy and applies to the named path and descendants if
> they are addressed or later come into existence.

This is an intentional asymmetry:

| Intent | May name non-existent path? | Reason |
|---|---|---|
| `RO` | No | grant requires an extant object and Position 3 access check |
| `RW` | No | grant requires an extant object and Position 3 access check |
| `D` | Yes | unconditional withdrawal; no delegated access to prove |

A non-existent `D` entry is still canonicalized under F8 before F6/F7
are evaluated. Symbolic links and junctions are not resolved during
canonicalization; the entry governs the named path string.

## Why the asymmetry is appropriate

F4 says the policy is a delegation from the invoking user to the agent.
For `RO` and `RW`, the validator must check at policy-load time that the
invoking user has the access being delegated. That check needs a real
host object. Without an extant object, there is no stable ACL, object
type, inherited state, or host capability to inspect.

`D` is different. F4 says `D` denies the named access
unconditionally, independent of the invoking user's access. Withdrawal
does not require the withdrawer to have had the access being withdrawn.
Therefore, a non-existent `D` path does not create a Position 3 problem:
there is no grant and no delegated authority to validate.

This mirrors ordinary policy authoring. It is meaningful to say "never
allow the agent to create `C:\repo\.cache`" even before `.cache` exists.
It is not meaningful, in this language, to say "grant `RW` to a future
object whose host ACL and object type are not yet known."

## Semantics under round-2 access-denied

Let `P` be a non-existent path named by a `D` entry.

### Existence probes

If `P` genuinely does not exist on the host, an existence probe such as
`GetFileAttributes(P)` returns the host's natural not-found result. This
is not policy hiding. It is the host reporting that no object currently
exists at that name.

The same distinction applies to simple probes of descendants whose
missing ancestor is `P`: if the operation is only asking whether the
object currently exists, host not-found is a natural result.

### Creation and access attempts

Operations that would create, open for access, rename into, or otherwise
materialize `P` or a descendant of `P` are refused by the `D` entry:

| Operation | Path | Result |
|---|---|---|
| `CreateFile CREATE_NEW` | `P` | `ACCESS_DENIED` |
| `CreateDirectory` | `P` | `ACCESS_DENIED` |
| `CreateFile CREATE_NEW` | `P\child.txt` | `ACCESS_DENIED` |
| rename destination | `P` or `P\child.txt` | `ACCESS_DENIED` at destination |
| open for read/write after object exists | `P` or descendant | `ACCESS_DENIED` |

This follows F10: `D` refuses creation at the denied path. For a
non-existent `D` directory path, the refusal also covers descendant
creation because the entry is subtree-implicit under F1.

### If the path later exists

If some action causes an object to exist at `P`, the entry stops being a
"future" denial and becomes an ordinary `D` entry over an extant object.
The agent observes the normal round-2 `D` behavior:

- `GetFileAttributes(P)` returns the real host attributes;
- enumeration of `parent(P)` includes `P` by name;
- read, write, delete, rename, and enumeration of `P`'s contents fail
  with `ACCESS_DENIED`;
- descendants are governed by the `D` subtree unless a more-specific
  entry wins under F6.

F12 is the foundation: provenance is irrelevant. The deny applies to
whatever object exists at the named host path, including a future object
created by the agent, by another host-side principal, or by a tool
running outside the sandbox.

## Validator impact

F14 should be read with the refined F2' existence check:

- canonicalize every entry under F8;
- require existence for `RO` and `RW` entries;
- do not require existence for `D` entries;
- still run F7 conflict detection after canonicalization;
- still run same-intent dedupe and nesting warnings;
- still run Position 3 checks only for `RO` and `RW`.

A validator may warn when a non-existent `D` path has a non-existent
parent. That warning is advisory, not an error. The user may be
intentionally denying a future subtree, but a missing parent also
increases the chance of a typo.

### Validator pseudocode (informative)

```text
validate(policy):
  # 1. Include resolution
  entries = resolve_includes(policy.entries, fragments)  # detect cycles

  # 2. Path canonicalization (F8)
  for e in entries:
    e.path = canonicalize(e.path)

  # 3. Existence check (F2')
  for e in entries:
    if e.intent in [RO, RW] and not exists(e.path):
      error("path does not exist for grant: " + e.path, F2')
    if e.intent == D and not exists(e.path) and not exists(parent(e.path)):
      warn("deny path and parent do not exist; confirm spelling: " + e.path)

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
      warn(suspicious_nesting_description(outer, inner), B5/B6/C3)

  # 6. Position 3 check (F4)
  for e in entries:
    if e.intent in [RO, RW]:
      if not user_has_access(invoking_user, e.path, e.intent):
        error("user cannot delegate access they lack at " + e.path, F4)

  return NormalizedPolicy(entries, errors, warnings)
```

## Interaction matrix implications

The existing interaction matrix remains structurally unchanged. A
non-existent `D` entry has the same precedence as an extant `D` entry;
the only difference is what the agent sees before any host object exists
at the denied name.

| Case | Entries | Result |
|---|---|---|
| B4, future deny inside existing `RW` | `RW P` + `D P\sub` where `P\sub` does not exist | valid; `P\sub` and descendants cannot be created by the agent |
| D outside any allow | `D P` where `P` does not exist and no `RO`/`RW` covers it | valid; redundant with default-deny for most operations, but documents intent |
| Existing allow inside non-existent D subtree | `D P` non-existent + `RW P\sub` | impossible if `P\sub` exists; if `P` does not exist, descendants cannot exist as ordinary paths, and F2' rejects non-existent `RW` |
| Future D under existing `RO` | `RO P` + `D P\sub` where `P\sub` does not exist | valid; most-specific `D` wins if the agent tries to create or later access `P\sub` |
| Two nested future D entries | `D P` + `D P\sub`, both non-existent | valid but redundant; F1 same-intent nesting warning applies |
| Same canonical path, D plus another intent | `D P` non-existent + `RO P` or `RW P` | F7 validation error; same-path multi-list conflict |

### Category B — outer + inner

The most common case is an existing allow subtree with a future deny
inside it:

```text
RW C:\etc\src\git\myrepo
D  C:\etc\src\git\myrepo\.cache
```

If `.cache` does not exist, `GetFileAttributes` on `.cache` naturally
returns not-found. Attempts to create `.cache`, rename into `.cache`, or
create descendants beneath `.cache` fail with `ACCESS_DENIED`. If an
external principal creates `.cache`, the agent then sees it as an
ordinary denied directory: visible in `myrepo`'s parent listing, but
inaccessible.

### Category C — inner deny on a future file

A future deny may also name a file path:

```text
RW C:\etc\src\git\myrepo
D  C:\etc\src\git\myrepo\.env
```

If `.env` does not exist, `GetFileAttributes` returns not-found and the
parent listing does not include `.env`. `CreateFile CREATE_NEW` at
`.env` fails with `ACCESS_DENIED`. If `.env` later exists, it is visible
but read/write/open/delete fail with `ACCESS_DENIED`.

### Category G — rename across regions

Rename behavior is unchanged. A rename to a denied future path fails at
the destination with `ACCESS_DENIED`. A rename from a denied path fails
at the source with `ACCESS_DENIED` if an object exists there; if no
object exists at the source, host not-found is natural.

The rule of thumb remains: policy-caused refusals are `ACCESS_DENIED`;
not-found means the named host object is genuinely absent.

## Race conditions and runtime considerations

A non-existent `D` entry is persistent policy state, not a one-time
validation observation. It remains in force throughout the run.

| Race | Result |
|---|---|
| Agent creates `P` | refused with `ACCESS_DENIED`; the agent cannot materialize the denied path |
| Agent creates `P\child` | refused with `ACCESS_DENIED`; descendant creation is covered by the subtree `D` |
| Another principal creates `P` host-side | allowed or refused by host policy outside MXC; the agent's later access to `P` is denied |
| Another principal creates `P\child` host-side | same; MXC mediates the agent's access by path, not provenance |
| `P` exists, is deleted, then comes back | the `D` entry still applies whenever an object exists at `P` |
| `P` is replaced by a different object | the `D` entry applies to the replacement object because F12 ignores provenance |

This resolves OQ-S2 only for the narrow case covered here: `D` on a
non-existent path. It does not otherwise redesign deletion/recreation
semantics for all intents.

The outcomes above are the **intended language semantics**. Whether a
given backend can actually deliver them depends on the tier — see
"Enforceability by tier" below. In particular, the
agent-creates-`P` and future-object rows are enforceable on the
name-mediating tiers (BFS, overlay) but **not** on the DACL tier.

## Worked examples

### Example 1 — canonical future deny

```text
RW C:\Users\gudge\temp
D  C:\temp\logs
```

Assume `C:\temp\logs` does not exist when the policy is loaded.

| Operation | Path | Result | Reason |
|---|---|---|---|
| `GetFileAttributes` | `C:\temp\logs` | not-found | object genuinely absent; not policy hiding |
| `CreateDirectory` | `C:\temp\logs` | `ACCESS_DENIED` | `D` refuses creation at the denied path |
| `CreateFile CREATE_NEW` | `C:\temp\logs\app.log` | `ACCESS_DENIED` | descendant creation under subtree `D` |
| host creates directory, then agent stats | `C:\temp\logs` | success, real attrs | extant `D` is visible per F10 |
| host creates directory, then agent opens | `C:\temp\logs\app.log` | `ACCESS_DENIED` | descendant of `D` |

The unrelated `RW C:\Users\gudge\temp` grant behaves normally. The
`D C:\temp\logs` entry is a standing refusal for the future path.

### Example 2 — non-existent deny outside any allow

```text
D C:\some-other-path
```

Assume no `RO` or `RW` entry covers `C:\some-other-path`.

| Operation | Path | Result | Reason |
|---|---|---|---|
| read existing unrelated path | `C:\unlisted\file.txt` | `ACCESS_DENIED` | default-deny |
| `GetFileAttributes` while absent | `C:\some-other-path` | not-found | object genuinely absent |
| create while absent | `C:\some-other-path` | `ACCESS_DENIED` | explicit `D` refuses materialization |

This entry is often redundant with default-deny. It is still useful as
documentation: the policy author is recording that this path must remain
unavailable even if a broader allow is added later.

### Example 3 — future deny with existing parent in RW

```text
RW C:\etc\src\git\myrepo
D  C:\etc\src\git\myrepo\.cache
```

Assume `C:\etc\src\git\myrepo` exists and `.cache` does not.

| Operation | Path | Result | Reason |
|---|---|---|---|
| create file | `C:\etc\src\git\myrepo\out.log` | success | outer `RW` |
| `GetFileAttributes` | `C:\etc\src\git\myrepo\.cache` | not-found | `.cache` genuinely absent |
| `CreateDirectory` | `C:\etc\src\git\myrepo\.cache` | `ACCESS_DENIED` | most-specific `D` wins |
| `CreateFile CREATE_NEW` | `C:\etc\src\git\myrepo\.cache\index` | `ACCESS_DENIED` | descendant of future `D` |
| host creates `.cache`, parent listing | `C:\etc\src\git\myrepo\*` | includes `.cache` | visible per F10 |
| host creates `.cache`, enumerate contents | `C:\etc\src\git\myrepo\.cache\*` | `ACCESS_DENIED` | enumeration of denied dir refused |

This is the ergonomic case the refinement primarily serves: allow the
repo, but reserve a subpath the agent must not create or use.

## Enforceability by tier

Non-existent `D` is not enforceable on every backend. It is a
**name predicate** — "no object may come into existence at this
name" — and only backends that mediate the namespace can enforce a
name predicate. Backends that enforce on object identity cannot,
because there is no object to bind a rule to until the path
materializes, and by then it is too late.

This is the sharp edge of the object-based model (F11): the
language is object-based *once an object exists*, but a
non-existent `D` entry is unavoidably name-predicated until
materialization (F8 defers object resolution for absent paths).
Enforcement splits along exactly that line.

### What each backend can do

| Backend | Mechanism | Non-existent `D` |
|---|---|---|
| Tier 1 — BFS (post-25H2) | Name-intercepting broker: sees the path of every operation before the FS object is consulted | **Enforceable.** Matches the denied path by name and returns `STATUS_ACCESS_DENIED` on the create, while passing sibling creates through. Existence-independent. The absent-path probe still returns natural not-found because the real FS has nothing there. |
| Overlay tiers (ProjFS / namespace-mediating filters) | Same property: name-conditional interception | **Enforceable**, same reasoning as BFS. |
| Tier 3 — DACL | Access-control entries bound to existing objects | **Not enforceable.** See below. |

### Why DACL (Tier 3) cannot do it

Three independent failures, any one of which is fatal:

1. **No object to ACE.** The denied path does not exist, so there
   is nowhere to attach a deny ACE. DACLs are object-bound.

2. **ACEs have no name dimension.** The only available lever is the
   *parent* directory's DACL. But creating a child requires
   `FILE_ADD_FILE` / `FILE_ADD_SUBDIRECTORY` on the parent, and
   there is no ACE that grants "create any child except one named
   `.cache`." Create rights are whole-directory. You either grant
   ADD on the parent (the agent can create the denied name) or deny
   it (the agent can create *nothing* — the `RW` grant is broken).
   Selective create-deny of a single name in an otherwise-writable
   directory is inexpressible.

3. **Future-object deny loses a TOCTOU race.** Because DACLs cannot
   prevent the create, the agent does create the object. To deny it
   retroactively, something must watch for the creation and race to
   stamp an ACE. Between the agent's `CreateFile` and the ACL stamp
   the agent already holds a writable handle. The deny never catches
   up, so F12 (provenance-irrelevant; deny binds to future objects)
   is also unenforceable on this tier.

### Why the obvious DACL workaround does not work

Pre-creating the denied path as an empty object and stamping a
deny-all ACE fails on two counts:

- **It materializes the path.** The intent of a non-existent `D` is
  usually "this must never come into existence." Creating it as a
  side effect of starting the container is exactly the host mutation
  the design avoids. (It also forces a file-vs-directory guess we
  cannot make.)
- **It produces the wrong observable behavior.** A real object with a
  deny ACE is *visible* — `GetFileAttributes` succeeds and only
  access is refused. The semantics in this adjunct require an absent
  denied path to read as **natural not-found** (object genuinely
  absent). Pre-creation flips not-found into visible-but-denied,
  which is a spec violation.

Note the contrast with **existing**-path deny, which Tier 3 *can*
enforce: when the object exists, stamping a deny ACE for the
sandbox principal matches the round-2 `D` semantics exactly
(visible, real metadata, `ACCESS_DENIED` on operations). It is
specifically the non-existent and future-object cases that DACLs
cannot reach.

### Design response

1. **Capability-profile entry.** Mark "name-conditional create-deny /
   non-existent-path deny / future-object deny" as a capability of
   the name-mediating tiers (BFS, overlay) and *not* of the DACL
   tier, in the machine-readable backend capability profile.
2. **Selector / validator check.** If a policy contains a
   non-existent `D` entry (or otherwise relies on future-object deny
   inside an `RW` subtree) and the host can offer only the DACL tier,
   the policy is **unenforceable on that host**.
3. **Required vs best-effort per deny clause.** Let the caller mark
   each deny. *Required* → refuse to run on a host that cannot
   enforce it. *Best-effort* → run, but surface a structured
   degradation ("this deny could not be enforced; the path can be
   created"). This is the honest alternative to silently
   under-enforcing.

## Open questions and deferrals

- **Warning policy for missing parents.** A `D` path whose parent is
  also non-existent is semantically fine: if the path materializes, the
  deny applies. Should validators warn by default, or only in a strict
  diagnostics mode?
- **Fragment-authored future denies.** A fragment may contribute a `D`
  entry for a non-existent path that the invoking user could not have
  accessed if it existed. Under F4 this is fine, because `D` is
  unconditional withdrawal. No Position 3 grant is involved.
- **Symlinks and junctions.** Under the object-based model (F11),
  once an object exists at a `D` path the deny binds to the object
  and all aliases that reach it. While the path is still absent,
  F8's object-resolution stage defers and the entry matches by
  canonical path string only. The open question is the transition:
  if a future `D` path is first reached through a reparse point,
  does enforcement bind at the named path, the resolved target, or
  both? This adjunct defers stronger alias handling for the
  not-yet-materialized window.
- **Required vs best-effort deny clauses.** Per "Enforceability by
  tier" above, a non-existent `D` clause cannot be enforced on a
  DACL-only host. Should the policy language carry a per-clause
  required/best-effort marker, and what is the default? A safe
  default (required → refuse on incapable hosts) trades availability
  for guarantee; a permissive default (best-effort → run with
  surfaced degradation) trades the reverse.
- **Case-insensitive future materialization.** F8 normalizes drive-letter
  case and path spelling before comparison. The exact implementation
  details for case-insensitive matching of future creates are runtime
  work, not a language change.
- **Precise error for existence probes of missing descendants.** This
  adjunct requires `ACCESS_DENIED` for creation/materialization under a
  future `D`. Pure existence probes for objects that genuinely do not
  exist may naturally return not-found.

## Cross-references

- Canonical round-2 spec:
  [`policy_semantics_v1.md`](./policy_semantics_v1.md)
  - F2: original existence requirement and OQ-S3 deferral
  - F4: Position 3 delegation and static validation
  - F6/F7: most-specific-wins and same-object conflicts
  - F8: lexical canonicalization plus object resolution
  - F10: `D` produces `ACCESS_DENIED`, not hidden
  - F11/F12: object-based policy; provenance is irrelevant
  - F14: validator role
- Review summary:
  [`policy_semantics_v1_summary.md`](./policy_semantics_v1_summary.md)
- Access-denied variant background:
  [`policy_semantics_v1_variants/v1_d_access_denied.md`](./policy_semantics_v1_variants/v1_d_access_denied.md)
