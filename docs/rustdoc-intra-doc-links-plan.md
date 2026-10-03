# Rustdoc intra-doc link cleanup

## Starting point

At `origin/main` `81936d318`, the command
`cargo doc --workspace --all-features --no-deps` completed on Windows with
61 warnings. With
`RUSTDOCFLAGS="-D warnings"`, it failed on a link in
`src/testing/wxc_e2e_tests/src/lib.rs`. The unmerged
`user/gudge/fix-intra-doc-links` branch (`50398b5e6`) fixes that example and
provides a useful checklist, but it is 197 commits behind this main snapshot.
Several source paths have moved, notably from `appcontainer` to
`process_container`; do not rebase or cherry-pick the old patch wholesale.

## Plan

1. Start a fresh branch from current `origin/main`. Inventory rustdoc warnings
   on Windows and in applicable Linux/macOS target builds, including warnings
   introduced since the old branch.
2. Port only the still-needed fixes to their current files. Keep links to
   reachable public items; use inline code for private, unavailable, or
   unresolvable external items. Do not widen API visibility or suppress
   warnings to satisfy rustdoc.
3. Verify zero warnings with
   `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps`
   on Windows and targeted documentation builds for other available targets.
   Record any platform coverage that cannot be run locally.
4. Add a strict documentation CI gate once the baseline is clean. Retire the
   old branch after the replacement fix lands.
