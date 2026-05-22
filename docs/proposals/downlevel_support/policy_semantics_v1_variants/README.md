# Policy semantics variants — explored alternatives

This directory contains four exploratory variants of
`policy_semantics_v1.md` produced during round 2 of design review.
Each variant presents a self-contained version of the FS-policy
language under a different combination of reviewer-proposed
changes.

The variants are kept here for history. **The canonical v1 spec
(in `../policy_semantics_v1.md`) incorporates the two variants that
were accepted (no-leaf + D-access-denied) and reverts the third
(D-trumps-all).**

| File | Adopts feedback | Status |
|---|---|---|
| `v1_no_leaf.md` | #1: drop the leaf marker | **Accepted** into canonical |
| `v1_d_access_denied.md` | #2: `D` produces `ACCESS_DENIED` not hidden | **Accepted** into canonical |
| `v1_d_trumps.md` | #3: `D` unconditionally trumps `RO`/`RW` | **Reverted** — not in canonical |
| `v1_merged.md` | All three | Closest to canonical, except for the reverted change |

## What the canonical took from each

- **From `v1_no_leaf.md`**: F1 has no marker; entries are subtree-
  implicit on directories. Several base-spec rules (marker
  subsumption, `RW[L]` validation) become unnecessary. Adding `[L]`
  back later is a strictly-additive change.
- **From `v1_d_access_denied.md`**: F10 says `D` produces
  `ACCESS_DENIED`; denied paths remain visible. F11 makes the policy
  path-based, not object-based. Several runtime risks evaporate.
  A note on namespace mapping as a future concern is added.

## What was reverted from `v1_d_trumps.md`

The reviewer proposed making `D` unconditionally trump `RO`/`RW`
regardless of specificity, with allow-inside-deny becoming a
validation error. After consideration this was reverted in favor of
uniform most-specific-wins across all three lists. Rationale:

- Allow-inside-deny is a legitimate expressive pattern ("deny most
  of X, allow some sub-paths"). Rejecting it forces users to either
  drop the `D` (and rely on default-deny + explicit allows) or to
  restructure the policy in ways that may be less readable.
- The validator-warning on B5/B6 patterns already surfaces the
  case to the user. A warning is sufficient; an error is over-strict.
- Most-specific-wins is uniform and easier to teach: the same rule
  applies to all three lists.
- The footgun the reviewer worried about — shipping fragments
  surreptitiously overriding user deny entries via more-specific
  RO/RW — is real but manageable. Fragments are versioned and
  auditable (D2 in the canonical); their interactions with user
  entries can be surfaced by validator warnings if needed.

## How to use these documents

If you want to understand the canonical spec, start with
`../policy_semantics_v1.md` or its summary
`../policy_semantics_v1_summary.md`. The variants are useful for:

- **Understanding why we made each decision.** Each variant
  documents the trade-offs it accepts and what it costs.
- **Reconsidering rejected paths.** If real use cases later argue
  for `D`-trumps-all, `v1_d_trumps.md` is a starting point. If
  hiding semantics become important enough to revive, the base
  spec has them and the variants show how to back them out cleanly.
- **Onboarding new reviewers.** A new reviewer can read one variant
  to see what one design choice looks like in isolation, then read
  the canonical to see how the accepted ones compose.
