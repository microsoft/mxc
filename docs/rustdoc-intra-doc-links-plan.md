# Rustdoc intra-doc link cleanup

Status: open. Windows warning inventory checked against `origin/main`
`c6f301d53` (October 9, 2026) on October 12, 2026.

## Current baseline

From `src/`, `cargo doc --workspace --all-features --no-deps` completed on
Windows with 51 warnings: 47 in the `mxc-sdk` library documentation, one in
`wxc-exec`, one in `wxc-windows-sandbox-daemon`, and two in `wxc-host-prep`.
They include unresolved links and public documentation that links to private
items. No Linux or macOS documentation build was run for this inventory.

The earlier inventory at `81936d318` found 61 warnings and a failing link
in `src/testing/wxc_e2e_tests/src/lib.rs`; neither count nor path describes
the current tree. The unmerged `user/gudge/fix-intra-doc-links` branch
(`50398b5e6`) is 242 commits behind this main snapshot. Its old layout
predates consolidation under `src/mxc-sdk/src/` and the move from
`appcontainer` to `process_container`. Use it as a checklist, not a patch
to rebase or cherry-pick wholesale.

## Plan

1. Start from current `origin/main` and update the warning inventory,
   including Linux/macOS target documentation builds where available.
2. Fix only warnings still present in current files. Keep links to
   reachable public items; use inline code for private, unavailable, or
   unresolvable external items. Do not widen API visibility or suppress
   warnings to satisfy rustdoc.
3. Verify zero warnings with
   `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps`
   on Windows and targeted documentation builds for other available targets.
   Record any platform coverage that cannot be run locally.
4. Add a strict documentation CI gate once the baseline is clean. Retire the
   old branch after the replacement fix lands.
