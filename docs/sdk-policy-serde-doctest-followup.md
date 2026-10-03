# Rust SDK policy serde negative-test follow-up

Merged #1352 removed private FFI request deserialization and SDK authoring
serde. #1353 moved the plain authoring types into `mxc-sdk`.

The two `compile_fail` examples beside `SandboxPolicy` in
`src/core/mxc-sdk/src/policy.rs` still name
`mxc_engine::policy::SandboxPolicy`. That path no longer exists, so the examples
pass without proving that the public policy type lacks `serde::Deserialize`
and `serde::Serialize`.

## Follow-up

1. Change both examples to use `mxc_sdk::v1::SandboxPolicy`.
2. Verify each failure diagnoses the missing serde trait, not an unresolved
   path, and run `cargo test -p mxc-sdk --doc`.
3. Keep public SDK authoring types serde-free. Test-only serde for conformance
   fixtures remains appropriate; do not restore the removed private FFI parser
   or rebase `user/gudge/rust_policy_types_without_serde`.
