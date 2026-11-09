# ProcessContainer filesystem access

> **Audience:** MXC consumers and developers

Windows ProcessContainer uses BaseContainer and can receive filesystem access
from both explicit MXC policy and Windows access control list (ACL) entries.
This guide describes the directory-access baseline supplied by
`ALL_APPLICATION_PACKAGES`: one source of access, not the complete policy
enforced for a process.

For request fields, host requirements, overlapping explicit policies, volume
roots, and upward traversal, see the
[filesystem policy reference](../../schema.md#filesystem-policy).

## Implicit group grants and explicit policy

Applicable Windows ACL entries for `ALL_APPLICATION_PACKAGES` can supply access
independently of explicit `readonlyPaths` or `readwritePaths` entries. Each
directory's own applicable entries matter; a readable parent does not establish
that every descendant supplies the same access.

An applicable explicit MXC `deniedPaths` rule takes precedence over access
supplied by the group. Conversely, the absence of a group grant is not an
explicit denial and does not by itself cancel access supplied by explicit
policy. Overlapping explicit grants and denies follow
[BaseContainer's documented precedence](../../schema.md#overlapping-paths-for-windows-basecontainer);
do not treat all denials as unconditional subtraction from every grant.

**Baseline exceptions are not explicit MXC policy denials.** Explicit policy may
independently grant access to an exception, or deny access normally supplied by
the group. Do not merge baseline exceptions into an actual request's
`deniedPaths` as though they were authored denials.

## Common baseline

The checked-in
[common filesystem baseline](common-filesystem-baseline.json)
contains entries shared by several sampled Windows C-drive exports. The comparison
was made on **2026-10-27**, using `ALL_APPLICATION_PACKAGES`.

This is an observed sample, not a Windows default-policy guarantee.

