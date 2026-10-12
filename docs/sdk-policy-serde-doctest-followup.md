# Rust SDK policy serde negative-test follow-up

Status: outstanding against `origin/main` `c6f301d53` (October 9, 2026).

#1352 removed private FFI request deserialization and SDK authoring serde.
#1353 moved authoring types into `mxc-sdk`, and #1390 consolidated the
Rust SDK under `src/mxc-sdk/`. The two `compile_fail` examples beside the
crate-private `ContainerPolicy` in `src/mxc-sdk/src/policy.rs` still name
`mxc_engine::policy::ContainerPolicy`. That path does not exist, so the
examples can pass without proving that a public authoring type lacks
`serde::Deserialize` and `serde::Serialize`.

The public V1 one-shot authoring type is `mxc_sdk::v1::ContainerRequest`.
There is no public `mxc_sdk::v1::SandboxPolicy` or `ContainerPolicy`.

## Follow-up

1. Replace or move the two examples so they check the public
   `mxc_sdk::v1::ContainerRequest` through its consumer-facing path. For
   example, deserialize into `ContainerRequest` and serialize
   `ContainerRequest::new("echo")`; neither operation should compile.
2. Verify that both failures diagnose the missing serde trait, not an
   unresolved or inaccessible type, then run `cargo test -p mxc-sdk --doc`
   from `src/`.
3. Keep public SDK authoring types serde-free. Test-only serde for
   conformance fixtures remains appropriate; do not restore the private FFI
   parser or rebase `user/gudge/rust_policy_types_without_serde`.
