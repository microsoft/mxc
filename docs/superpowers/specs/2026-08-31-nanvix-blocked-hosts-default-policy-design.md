# NanVix `blockedHosts` Default-Policy Design

## Problem

The NanVix backend currently enables host networking whenever `blockedHosts` is
non-empty. When `network.defaultPolicy` is `block`, this changes a deny-by-default
request into allow-by-default networking with exceptions, silently widening the
requested boundary.

## Policy Contract

- `allowedHosts` with `defaultPolicy=block` remains a valid allowlist.
- `blockedHosts` is valid only with `defaultPolicy=allow`.
- `allowedHosts` and `blockedHosts` remain mutually exclusive.
- `defaultPolicy=block` must never enable host networking solely because
  `blockedHosts` is non-empty.

## Implementation

Keep the change local to `nanvix_runner`.

1. Preserve the existing mutual-exclusion validation for both host lists.
2. Add a dedicated preflight validation error when `blockedHosts` is non-empty
   and `defaultPolicy` is not `allow`. The error will explain that a blocklist is
   allow-by-default and requires an allow default.
3. Change `host_networking_enabled` to depend only on `defaultPolicy=allow` or a
   non-empty `allowedHosts` list. This provides a fail-safe invariant even if a
   caller reaches the helper without validation.
4. Update the module-level networking documentation and
   `docs/nanvix-microvm/nanvix.md` to describe the supported combinations.

No shared schema or `nanvixd` protocol changes are required.

## Error Handling

The incompatible request fails during NanVix policy validation before hostname
resolution or process launch. The existing both-lists diagnostic retains
precedence when both lists are supplied.

No warning or audit event is needed: the backend rejects the request rather than
executing with a relaxed boundary.

## Tests

NanVix runner unit tests will verify:

- implicit and explicit `defaultPolicy=block` reject `blockedHosts`;
- `defaultPolicy=allow` accepts `blockedHosts` and enables networking;
- `defaultPolicy=block` still accepts `allowedHosts` and enables filtered
  networking;
- a blocked-host list alone cannot make `host_networking_enabled` return true;
- the existing both-lists rejection remains unchanged.

Run the targeted NanVix runner tests and the repository's existing Rust format
and lint checks applicable to the changed crate.
