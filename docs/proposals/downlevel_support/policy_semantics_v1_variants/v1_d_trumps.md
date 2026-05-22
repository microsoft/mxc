# Variant 3 — `D` unconditionally trumps `RO`/`RW`

**Status**: draft variant, addresses reviewer feedback #3
**Base**: `../policy_semantics_v1.md`
**Branch**: `user/gudge/downlevel-fs-projection-plan`

This document specifies the MXC FS-policy language under the
assumption that **`D` always wins regardless of specificity**. If
any `D` entry covers a path (the path equals or is a descendant of
the `D` entry), the path is denied, period. RO/RW entries on
descendants of `D` paths are validation errors.

The reviewer's framing motivating this change: in security-conscious
authoring, a `D` entry is the policy author's "stop, do not go below
this line" assertion. Allowing a deeper RO or RW entry to override
that creates a footgun — the user thinks they denied an area, then
an include fragment or a later entry surreptitiously punches a hole.
Reviewer's concrete example:

```
D    C:\a
RW   C:\a\b
D    C:\a\b\c
RO   C:\a\b\c\d
```

Is the user really expressing four nested overrides, or did they
make four uncoordinated assertions and the inner RO is a bug? Under
strict deny-wins, the policy is invalid (the RW and RO are shadowed
by ancestor denies and are no-ops) and the user is told so.

It is otherwise identical to the base spec: leaf and subtree markers
both exist, deny still means hidden, Position 3 unchanged.

This variant is presented for review alongside two other
single-feedback variants and a merged variant.

## Changes from the base spec

| Aspect | Base spec | This variant |
|---|---|---|
| F6 precedence rule | Most-specific-wins, across all lists | Most-specific-wins for RO/RW; **`D` always wins regardless of specificity** |
| `RO`/`RW` entry inside a `D` subtree | Allowed; inner overrides per most-specific-wins | **Validation error** |
| Validator suspicious-nesting warning for allow-inside-deny | Warn, but allow | Error |
| Cell B5 (`D[S]` outer + `RW[S]` inner) | Warn, runtime delivers RW for inner | Validation error |
| Cell B6 (`D[S]` outer + `RO[S]` inner) | Warn, runtime delivers RO for inner | Validation error |
| Cell C7 (`D[S]` outer + RW or RO leaf inner) | Warn, runtime delivers per inner | Validation error |
| User who wants "deny most of X, allow some sub-paths" | Writes outer `D` with inner `RW`/`RO` | Writes only the `RW`/`RO`; relies on default-deny for the rest |

The change is **conservatively restrictive**: any policy that's
valid under this variant is also valid under the base spec, and they
produce the same observable behavior. The base spec accepts more
policies (those that mix allow-inside-deny); this variant rejects
them. So this is a tightening of the language, not a change in
runtime semantics for accepted policies.

## What we lose

- **The "deny most of X, allow some sub-paths" expressive pattern**
  is rejected. Users wanting that pattern must instead write only
  the allow entries (the things they want exposed) and rely on
  default-deny to cover the rest. Slightly more verbose in some
  cases.
- **The validator emits errors where the base spec emitted warnings.**
  Policies that previously passed (with a warning) now fail. This is
  a behavior-breaking change for any caller currently relying on
  warned-but-accepted allow-inside-deny patterns. Worth being explicit
  about — there were none in our worked examples, but include
  fragments shipping in the wild might.

## What we gain

- **No surreptitious overrides.** A `D` entry the user writes is the
  bottom line; nothing below it can override. The user does not have
  to audit deeper entries to verify their deny is effective.
- **Cleaner shipping fragments.** A `windows-dev-readonly-defaults`
  include cannot accidentally grant access to something a user
  policy `D`'d, because if it tries, the policy load fails.
- **Smaller interaction matrix.** B5, B6, C7 disappear as runtime
  scenarios.
- **Sharper semantic role for `D`.** Under this variant, `D` is
  unambiguously a withdrawal. Use it to remove access; do not use it
  as scaffolding around carve-outs.

## Foundations

Numbered for cross-reference. Bold rule names indicate changes from
the base spec.

### F1 — Three intent lists, two markers

Unchanged.

### F2 — Paths must exist (v1)

Unchanged.

### F3 — Paths are host paths, identity-projected

Unchanged.

### F4 — Position 3 (delegation from the invoking user)

Unchanged.

### F5 — Default-deny + include fragments

Unchanged.

### **F6 — Deny trumps allow; among allows, most-specific wins**

Replaces base-spec F6.

> When multiple entries cover the same path, precedence is:
>
> 1. **If any `D` entry covers the path (the path equals or is a
>    descendant of the `D` entry's path), the path is denied.** No
>    `RO` or `RW` entry can override this, regardless of how
>    specific.
>
> 2. **Otherwise, among `RO` and `RW` entries covering the path,
>    the one with the longest matching path prefix determines the
>    semantics.** Most-specific-wins applies only within the allow
>    category.

Two entries on different lists at the same canonical path is a
validation error (F7, unchanged). A more-specific RO/RW entry inside
a `D` subtree is also a validation error (F8a, new — see below).

### F7 — Same-path multi-list is a validation error

Unchanged.

### F8 — Marker subsumption

Unchanged.

### **F8a — `RO`/`RW` inside a `D` subtree is a validation error** *(new)*

If an `RO` or `RW` entry's path is a descendant of any `D` entry's
path (i.e., the `D` entry's subtree covers the `RO`/`RW` entry's
path), the policy is rejected.

The user has two ways to fix this:

1. **Remove the `D` entry.** If the user wanted the allow to take
   effect, the surrounding `D` was the mistake. Under default-deny,
   removing the `D` leaves everything else inaccessible anyway;
   only the allow region is granted.

2. **Remove the inner `RO`/`RW`.** If the user wanted the `D` to
   take effect, the inner allow was the mistake. The denied region
   stays denied.

The validator's diagnostic should name both entries so the user
sees the conflict:

```
ERROR: entry `RW[S] C:\a\b` is shadowed by ancestor `D[S] C:\a`.
       Either remove the `D` (and rely on default-deny for the
       rest), or remove the `RW`. F8a / F6.
```

### F9 — Canonical paths

Unchanged.

### F10 — Implicit traversal

Unchanged.

### F11 — Object-level hiding

Unchanged.

### F12 — Hidden = not-found, not access-denied

Unchanged.

### F13 — Explicit `D` is strictly stronger than default-deny

Unchanged.

### F14 — Enumeration mirrors existence

Unchanged.

### F15 — Provenance is irrelevant

Unchanged.

### F16 — `[L]` on a directory grants only the directory's own metadata

Unchanged.

### F16a — `RW[L]` on a directory without child coverage is a validation error

Unchanged.

### F17 — `RW` ⇒ `R`

Unchanged.

### F18 — Validator role

Unchanged, with one addition: the validator runs the F8a check after
nesting analysis. Any RO/RW entry whose path is a descendant of any
D entry's path is flagged as an error.

## The four observables

Unchanged from base spec.

## Each intent in isolation

Unchanged from base spec.

## Interaction matrix

### Category A — same path, two intents

Per F7: validation error in every form. Unchanged.

### Category B — outer subtree + inner subtree

| Cell | Outer at P | Inner at P\sub | Result |
|---|---|---|---|
| B1 | `RO[S]` | `RW[S]` | OK; inner wins for descendants of `sub` (most-specific within allows) |
| B2 | `RW[S]` | `RO[S]` | OK; inner wins for descendants of `sub` |
| B3 | `RO[S]` | `D[S]` | OK; deny applied to `sub` |
| B4 | `RW[S]` | `D[S]` | OK; deny applied to `sub` |
| B5 | `D[S]` | `RW[S]` | **validation error (F8a)** |
| B6 | `D[S]` | `RO[S]` | **validation error (F8a)** |

B5 and B6 are the canonical "allow inside deny" pattern. Under this
variant they are not expressible. The user expresses the equivalent
intent by:

```
# Instead of:
D[S]  C:\Users\gudge
RW[S] C:\Users\gudge\workspace

# Write:
RW[S] C:\Users\gudge\workspace
# (relies on default-deny for the rest of C:\Users\gudge)
```

The observable behavior is identical to what the base spec would
have produced under B5; the only difference is that the policy
doesn't include the redundant outer `D`.

### Category C — outer subtree + inner leaf

| Cell | Outer at P | Inner at P\x | Result |
|---|---|---|---|
| C1 | `RO[S]` | `RW[L]` file | OK |
| C2 | `RO[S]` | `RW[L]` dir | warn (per base spec) |
| C3 | `RW[S]` | `RO[L]` file | OK |
| C4 | `RW[S]` | `RO[L]` dir | OK |
| C5 | `RO[S]` | `D[L-file]` | OK |
| C6 | `RW[S]` | `D[L-file]` | OK |
| C7 | `D[S]` | `RW[L]` or `RO[L]` | **validation error (F8a)** |

C7 is the leaf-form of B5/B6 and is rejected on the same grounds.

### Category D — outer leaf-on-directory + inner subtree

Unchanged from base spec; D2 is still a validation error per F16a.

Note: the F8a rule does not apply to D1/D2 because the outer is
RO/RW (not D).

### Category E — disjoint siblings

Unchanged.

### Category F — multiple entries with the same intent

Unchanged.

### Category G — rename across regions

Unchanged. Rename within or across allow regions follows the
unchanged rules; renames involving a D region fail per the unchanged
rules.

### Category H — implicit default region

Unchanged.

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
    if has(bucket, [S]) and has(bucket, [L]):
      note("dropping leaf entry at " + path + " (subsumed by subtree)", F8)
    bucket = dedupe(bucket)

  # F8a: RO/RW inside D subtree is a validation error
  d_entries = [e for e in entries if e.intent == D]
  for e in entries:
    if e.intent in [RO, RW]:
      for d in d_entries:
        if is_descendant_of(e.path, d.path):
          error("entry " + e.path + " is shadowed by ancestor "
                + d.path + "; either remove the D or remove the "
                + "RO/RW", F8a)

  # F16a: RW[L] on directory without child coverage
  for e in entries:
    if e.intent == RW and e.marker == [L] and is_directory(e.path):
      if not has_covering_child_entry(entries, e.path):
        error("RW[L] on directory " + e.path + " with no covering "
              "entry for descendants", F16a)

  # Nesting warnings (only among allow entries now;
  # cross-D nesting is errors above)
  for outer, inner in nesting_pairs(entries):
    if outer.intent == D or inner.intent == D:
      continue  # handled by F8a above
    if outer.intent == inner.intent:
      warn("redundant nested entry: " + inner.path, F1/F2/F3)
    elif suspicious_nesting_among_allows(outer, inner):
      warn(suspicious_nesting_description(outer, inner))

  # Position 3 check
  for e in entries:
    if e.intent in [RO, RW]:
      if not user_has_access(invoking_user, e.path, e.intent):
        error("user cannot delegate access they lack at " + e.path, F4)

  return NormalizedPolicy(entries, errors, warnings)
```

## End-to-end worked example

The canonical policy is unchanged from the base spec — it does not
use allow-inside-deny patterns and so is unaffected by the variant.

```
include "windows-dev-readonly-defaults"

RW[S] C:\etc\src\git\myrepo
RW[S] C:\Users\gudge\temp
RW[S] C:\Users\gudge\scratch
RW[S] C:\Users\gudge\Documents\workinprogress
D[S]  C:\Users\gudge\Documents\workinprogress\private
```

All observable behavior identical to the base spec.

A policy that *would* have worked under the base spec but is rejected
under this variant:

```
D[S]  C:\Users\gudge
RW[S] C:\Users\gudge\workspace
```

Validator emits:

```
ERROR: entry `RW[S] C:\Users\gudge\workspace` is shadowed by ancestor
       `D[S] C:\Users\gudge`. Either remove the D (workspace will
       still be the only granted region under default-deny) or
       remove the RW. F8a / F6.
```

User rewrites:

```
RW[S] C:\Users\gudge\workspace
```

Same observable behavior; cleaner policy.

A policy involving an include fragment that would have surreptitiously
overridden a user deny:

```
include "broad-system-readonly"   # might include RO[S] C:\Windows\Temp

D[S] C:\Windows\Temp              # user wants to deny this
```

Under the base spec, the include's `RO` entry would be more specific
than the user's `D` and could… wait, in this case `RO C:\Windows\Temp`
and `D C:\Windows\Temp` are the *same path* on different lists, so
this is already an F7 validation error. Let me use a better example:

```
include "broad-system-readonly"   # contains RO[S] C:\Windows

D[S]  C:\Windows\security-sensitive-subdir
```

Under base spec: the user's `D` is more specific than the include's
RO; most-specific-wins; the deny is honored. Same under this variant.
No conflict here either, because the deny is *inside* the RO subtree
(B3 in the matrix), which is fine in both variants.

Let me try once more with an actual demonstrative case:

```
include "permissive-default"      # might contain RW[S] C:\Users\gudge

D[S]  C:\Users\gudge\Documents\private
```

Under both variants: the inner `D` is fine (B4 / C-equivalent), the
deny is honored. No conflict.

The case that *would* differ between variants:

```
D[S]  C:\Users\gudge
include "user-helper-defaults"    # contains RW[S] C:\Users\gudge\AppData
```

- **Base spec**: `RW[S] C:\Users\gudge\AppData` is more specific
  than `D[S] C:\Users\gudge`; the inner RW is honored. The user's
  `D` does *not* protect `AppData`. (Validator warns about
  allow-inside-deny but accepts the policy.)
- **This variant**: validation error. The user must either remove
  the outer `D` (in which case `AppData` is the only thing granted)
  or remove the include (in which case `D` is honored). The
  surprise is averted.

This is the kind of footgun this variant prevents.

## Runtime enforcement notes

Risks R1/R3, R2, R4, R5, R5b unchanged from base spec. R5b still
addressed by F16a. No new risks introduced.

The variant makes enforcement *slightly* easier: there are no
allow-inside-deny scenarios at runtime, so the most-specific-wins
lookup doesn't need to handle the case where a deny ancestor exists
above an allow descendant. The validator catches it earlier.

## Open questions and deferrals

- **OQ-S1**: Capability carve-outs. Deferred.
- **OQ-S2**: Deleted-and-recreated paths. Deferred.
- **OQ-S3**: Deny on non-existent paths. Deferred.
- **OQ-S5**: Validator surfaces implicit-traversal? No.
- **OQ-S6**: Position 3 user-access probe API. Implementation detail.
- **OQ-S7**: Constraint-only alternative. Deferred.
- **OQ-S8**: Per-Windows-version include variants. Implementation detail.
- **OQ-V3 (variant-specific)**: Should there be an explicit override
  marker that lets a user opt back in to the base-spec semantics
  for a specific allow-inside-deny case? (E.g., `RW!` to assert
  "I really mean this RW even inside a D".) Probably no for v1;
  the use case isn't compelling enough.
- **OQ-V3b (variant-specific)**: How do shipping fragments interact
  with user `D` entries? In particular: if a user `D` somewhere
  shadows a fragment entry, is that a fragment quality issue or a
  user policy issue? Should the validator's diagnostic distinguish
  "your entry shadows a fragment entry" from "your entry shadows
  another of your own entries"?
