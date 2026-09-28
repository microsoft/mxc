# Hyperlight path-overlap preflight design

## Context

The Hyperlight backend rejects configurations where a path appears in
`filesystem.deniedPaths` and either allow list. The current comparison uses
`std::fs::canonicalize` when possible and falls back to raw `PathBuf` equality
when a path does not exist yet.

On Windows, the raw fallback can miss case-only collisions for missing paths,
while the underlying filesystem normally resolves those spellings to the same
location. Hyperlight also intentionally supports auto-creating missing mount
directories when their parent exists, so a strict "canonicalize or reject"
policy would be a behavior break.

## Design

Keep the canonicalize-first behavior because it remains the strongest path
identity check when both paths exist. Replace the fallback comparison with a
small helper:

1. If both paths canonicalize, compare the canonical `PathBuf`s.
2. If either path cannot canonicalize, compare lexical fallback forms.
3. On Windows, normalize fallback separators to `\`, trim redundant trailing
   separators without changing root-like paths, and compare ASCII
   case-insensitively.
4. On non-Windows platforms, preserve the existing exact fallback comparison.

The change is scoped to `src/backends/hyperlight/common/src/lib.rs`; no schema,
wire contract, SDK surface, or backend routing changes are required.

## Error handling

The existing preflight error remains unchanged:

```text
path "<path>" appears in both deniedPaths and an allow list
```

This keeps callers' failure handling and tests stable while making the Windows
case-collision path fail closed before any mount is built.

## Tests

Add unit coverage beside the existing Hyperlight policy tests:

- A Windows-only test where `deniedPaths` and `readwritePaths` point at the
  same missing path with different casing and are rejected.
- A non-Windows test showing fallback comparison remains case-sensitive.

The targeted validation command is:

```text
cargo test -p hyperlight_common --features hyperlight policy_rejects_denied
```
