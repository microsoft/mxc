# Version-specific parser migration inventory

Generated from commit `2d4b094b32feedbf00afd55d875a8fa9e3a0bb6f`
on 2026-09-03. The inventory covers every JSON document named by the
differential harness's `expected_corpus_divergences` table before migration.
The post-migration corpus baseline was refreshed at commit
`6cc6830aa01bcf45f24f1c88e108d420fedacf98` on 2026-09-11 after rebasing
over newer configuration fixtures, primarily the Seatbelt validation corpus
from #1125. The rebase added 73 JSON documents and removed one, producing 67
additional equivalent accepts and five additional shared rejections without
changing the seven classified exact-stricter results.

This branch is a combined delivery: it makes exact contracts authoritative
and completes the v0.9 directional-network cutover. The latter is a breaking
contract/backend migration rather than parser plumbing, and is documented
separately below so reviewers can evaluate and revert the two concerns
independently.

## Summary

| Classification | Documents | Migration |
| --- | ---: | --- |
| Missing version | 55 | Declare `0.9.0-alpha` |
| Development containment under published version | 45 | Declare `0.9.0-alpha` |
| Experimental content under published version | 2 | Declare `0.9.0-alpha` |
| State-aware request under published version | 21 | Declare `0.9.0-alpha` |
| Published comment rejected first | 2 | Declare `0.9.0-alpha` |
| **Total** | **125** | |

All migrated documents target the mutable exact development contract because every document is state-aware, uses a development-only containment or experimental field, or is the telemetry example whose closed shape is defined on the development line. Existing `$schema` references are updated when present; no new schema reference is added.

Three versionless files under `tests/policy` are intentionally absent from this inventory: `request-directional-network.json`, `request-process-container.json`, and `request-wslc.json` are policy-builder inputs rather than complete request documents, and both parsers already reject them in the nine-document shared-rejection set.

## Phase 9B post-migration disposition

At the Phase 9B checkpoint, version migration removed 118 of the 125 recorded
divergences. The remaining
seven now characterize only the test-scoped rolling parser; authoritative
public loading rejects every document through its exact contract:

- `isolation_session_configid_rejected.json` and
  `isolation_session_one_shot_stray_config_rejected.json` retain the rolling
  parser's historical parse-and-ignore behavior as a differential
  characterization. The public one-shot surface now expects structural
  rejection from the closed 0.9 contract.
- Four IsolationSession provision rejection fixtures carry filesystem, UI, or
  a non-canonical network posture. Their E2E assertions now expect
  `malformed_request` from the request-specific 0.9 root. Direct
  `isolation_session_common::policy` tests preserve backend validation.
- `wslc_state_aware_exec_rejected_filesystem.json` exercises immutable
  post-provision policy. Its E2E assertion now expects structural rejection
  from the 0.9 exec root, while `wslc_common::policy` retains direct backend
  validation coverage.

At that checkpoint, the differential harness recorded seven exact-stricter results
so later contract changes cannot accidentally weaken the exact boundary. It
also compares every corpus document through the public loader and the exact
parser oracle. After the development-contract cutover moved three formerly convergent
documents into the explicit removal inventory, the retained rolling
characterization is platform-sensitive: Windows records 330 equivalent accepts
and 14 shared rejections, while Linux records 329 equivalent accepts and 15
shared rejections. Both retain no exact-looser acceptance and no accepted-model
mismatch. Assertion failures list the shared-rejection files so future
platform-specific movement is attributable rather than represented only by
aggregate counts.

## Validation

The full-suite validation below ran on 2026-09-04 after exact dispatch became
authoritative. The config-corpus count was refreshed on 2026-09-11 after the
producer-migration rebase:

- Rust formatting, workspace check, and workspace clippy completed without
  warnings.
- The Rust workspace passed 4,148 tests with 23 ignored.
- The Node SDK passed its build and 304 tests, with 19 skipped.
- The .NET SDK passed 118 tests, with 24 skipped.
- The config validator examined 349 documents: 341 validated successfully and
  eight were confirmed as intentionally invalid exemptions.
- Schema-version, exact-contract codegen, SDK wire-type codegen, and package
  version-sync gates passed.
- The seven residual fixtures at that checkpoint were exercised through the rebuilt
  `wxc-exec.exe`; their public diagnostics matched the structural exact-contract
  expectations retained by the E2E scripts.

## Typed-payload acceptance

The typed-payload migration replaces production raw state-aware payloads with
typed operations and checked backend binding. The
independent rolling request/extraction reference remains test-only; its
accepted-value comparisons, explicit presence expectations, and classified
exact-stricter rejections are retained. No registered contract, corpus request,
or generated artifact changes in this phase.

Local implementation evidence:

| Gate | Result |
| --- | --- |
| Common parser, normalization, binding, and regression tests | 1,146 passed; the recording matrix covers all three backends and five phases, presence, validation order/failure, dry runs, and piped/relayed exec |
| Removed production APIs | Seven compile-fail documentation tests passed, including five guards for parsed-request construction, raw/source fields, and reparsing |
| CLI output and entry-point regressions | 62 passed |
| Windows default | Engine 25, FFI 17, Rust SDK 11 passed |
| Windows `isolation_session` only | Engine 25, FFI 18, Rust SDK 12 passed |
| Windows `wslc` only | Engine 24, FFI 17, Rust SDK 11 passed |
| Windows `isolation_session,wslc` | Engine 24, FFI 18, Rust SDK 12 passed |
| Backend state-aware unit tests | IsolationSession 31, Windows Sandbox 52, WSLC 30 passed, including backend-owned defaulting and piped-exec refusals |
| Format and lint | `cargo fmt --all -- --check`; affected packages' `cargo clippy --all-targets -- -D warnings` passed in all four separate Windows configurations and for all three backend crates |
| Artifacts | `check-contract-codegen.js`, `check-schema-codegen.js`, and `check-sdk-types-codegen.js` passed unchanged |
| Linux/macOS default | Common, engine, Rust SDK, and FFI cross-compiled with `--all-targets` for `x86_64-unknown-linux-gnu` and `x86_64-apple-darwin`; only the pre-existing telemetry-consent dead-code warnings also observed before cutover remain |

The engine/FFI commands select `--lib state_aware`; the Rust SDK command selects
`--test state_aware`. Backend commands select `--lib state_aware`. Linux and
macOS test targets were compiled, **not executed**: the Windows host has no
macOS runtime, and the existing WSL distribution has no native Rust toolchain.

Live lifecycle suites were rerun against a combined x64 release build with
`isolation_session` and `wslc` on a host capable of all three Windows
state-aware backends. No lifecycle suite skipped:

- IsolationSession passed 62/62.
- WSLC passed 57/57.
- Windows Sandbox passed 9/10. Provision, start, repeated exec, PowerShell,
  timeout recovery, stop, and deprovision passed. The Python workload failed
  because the guest image had no Python installation on `PATH`, not because
  state-aware dispatch failed. The guest also logged one 10-second stdio
  bridge-drain timeout after an echo, but later execs remained healthy.

The Windows runs provide successful provision-through-teardown evidence for
all three state-aware backends. Native Unix test execution remains outstanding;
cross-compilation is not counted as native execution evidence.

## IsolationSession unrestricted-network implementation

The implementation builds on typed state-aware payload dispatch.
The new form uses the standard directional network shape with
`egress.default`, `ingress.default`, and `ingress.hostLoopback` all explicitly
set to `allow`. Legacy network fields are rejected.

The implementation preserves validation boundaries, authored policy presence,
legacy policy hashes, and published contracts. Node and C# expose pre-build
directional authoring; Rust's existing state-aware JSON entry point accepts the
new form. No Rust/C# one-shot backend support was added.

Local evidence for the public integration:

| Gate | Result |
| --- | --- |
| Common parser/adapter/identity tests | 1,165 passed; seven documentation tests passed |
| IsolationSession backend unit tests | 194 passed |
| CLI unit tests | 62 passed |
| Contract/schema tests | All contract feature suites passed; schema emitter tests passed |
| Rust feature matrix | Check, clippy, and engine/FFI/Rust SDK state-aware suites passed separately for default, isolation_session, wslc, and both |
| Node SDK | 381 passed, 19 skipped; compile-time wire conformance included |
| C# lifecycle/native-boundary tests | 51 passed in each of the four Windows feature configurations |
| Native CLI | Dry runs covered one-shot/provision legacy and directional forms plus missing/empty/restrictive cases; no sandbox was created |
| Generated schema | Twenty-six new-form acceptance/rejection cases passed through the existing AJV validator |
| Artifacts/corpus | Exact/rolling/SDK codegen, schema-version, and existing 277-config corpus gates passed |
| Linux/macOS | Default cross-target checks passed, with existing telemetry-consent warnings; native tests were not executed locally |

The native CI build jobs now explicitly select the common/contract and
engine/FFI/Rust SDK state-aware suites that dependency compilation alone did
not execute. The existing macOS common-crate test selection is retained.
The Azure Linux additions follow its existing native-x64 test restriction;
the GitHub Linux matrix runs on its native x64 and ARM64 runners.
New contract fixtures also put the network-posture matrix under the existing
Rust fixture and generated-schema gates rather than relying only on a manual
schema probe.

**Acceptance limitations remain explicit:** native Unix CI execution is not
established merely by adding those steps. No skipped suite, cross-target check,
or dry run is counted as live execution. The inherited denied-path/debug-output
issue is not attributed to this implementation.

## Phase 10B-10D directional cutover

This atomic cutover is based on rebased Phase 10A at `16ed3c81`.
Exact v0.9 removes the six legacy networking fields from every request root;
published v0.6/v0.7/v0.8 contracts remain unchanged. IsolationSession requires
the explicit backend acknowledgment, and state-aware runtime proxy moves to
top-level `runtimeConfig.networkProxy` on exec.

The user approved a constrained WSLC directional mapping: deny/deny/deny is
isolated, while explicit allow/allow/allow is unrestricted bridged networking.
Mixed postures, including allowed egress with implicit denied ingress, are
rejected rather than claiming independent firewall enforcement. Proxy-only
exec inherits the provisioned posture, and its endpoint is kept guest-routable.

Review also identified the missing NanVix host-network mapping. The approved
resolution supports disabled all-deny or explicitly unrestricted all-allow,
wires that mode into the actual daemon launch, and rejects directional
filtering that the legacy IPv4/DNS-exception filter cannot faithfully enforce.
Positive network fixtures declare all three allows; the negative suite checks
full isolation and explicit unsupported-filter rejection instead of retaining
removed `blockedHosts` syntax.

Corpus migration retains older published-version fixtures and higher-level
v0.8 authoring goldens. It updates 65 JSON files and the corresponding request
producers, including all 15 bridged WSLC fixtures. The final differential
inventory reported by the native gate is 282 documents: 263 convergent parser
accepts, nine shared rejects, and ten explicitly classified exact-stricter
cases.

Three additional schema-negative fixtures are deliberate, not migration
omissions:

- `hyperlight_networking.json` and `hyperlight_networking_blocked.json`
  retain unsupported hostname-policy input as removed-syntax rejection tests.
  The implementation does not resolve DNS at migration time or replace a
  hostname restriction with allow-all.
- `wslc_state_aware_provision_rejected_proxy.json` verifies that provision
  does not accept exec-only `runtimeConfig`; it is not a valid provision
  template.

The retained rolling model remains a test/reference and compatibility
representation, not an alternate production parser. Native Unix execution and
live lifecycle/enforcement evidence are distinct from local compile, unit,
schema, and dry-run results; unsupported hosts and skipped cases must not be
reported as successful E2E runs.

### Cutover verification

The final local ladder ran against one unchanged source snapshot after review
fixes, with actual exit codes retained for each command:

| Check | Result |
| --- | --- |
| Rust format / workspace check | Passed |
| Affected Rust check and clippy | Passed with default, IsolationSession, WSLC, and combined features; microvm feature check also passed |
| Common parser / documentation | 1,167 unit tests and seven documentation tests passed |
| Exact contracts / emitter | All contract feature suites and ten emitter tests passed |
| Backend units | IsolationSession 194; WSLC policy 90 and state-aware 30; NanVix 40 passed |
| CLI units | 62 passed |
| Node SDK | Build and integration type-check passed; 343 unit tests passed, 19 skipped |
| Managed SDK | 64 lifecycle and 81 sandbox tests passed in each of the four native-feature configurations |
| Versioning logic | 70 tests passed through the existing CI `npm test` command, including the recursive cutover guard |
| Generated artifacts / corpus | Exact, rolling, SDK-type, version and corpus gates passed; 277 raw configs validated with 11 explicit negatives |
| Native CLI boundaries | 23 contract/WSLC/IsolationSession dry runs and eight NanVix posture dry runs passed without lifecycle execution |
| Cross-target checks | Linux/macOS checks passed; native Unix tests and live backend runs were not performed |

Review findings were resolved before publication: shared C# Boolean and
initialized-list APIs remain source-compatible with published-version
authoring, including historical serialization defaults; NanVix mode selection
now drives actual host-network enablement instead of merely advertising
capability bits. The new schema-guard regressions reside in the existing
versioning test discovery directory.

## Documents

| Path | Request kind | Classification | Current version | Target version | Existing schema reference | Owner |
| --- | --- | --- | --- | --- | --- | --- |
| `tests/configs/basic_windows_sandbox.json` | one-shot | PublishedDevelopmentContainment | `0.6.0-alpha` | `0.9.0-alpha` | (none) | backend/config test |
| `tests/configs/experimental_hello_lxc.json` | one-shot | PublishedExperimental | `0.6.0-alpha` | `0.9.0-alpha` | (none) | backend/config test |
| `tests/configs/experimental_hello_processcontainer.json` | one-shot | PublishedExperimental | `0.6.0-alpha` | `0.9.0-alpha` | (none) | backend/config test |
| `tests/configs/hyperlight_exit_code.json` | one-shot | MissingVersion | `(missing)` | `0.9.0-alpha` | (none) | backend/config test |
| `tests/configs/hyperlight_fs.json` | one-shot | MissingVersion | `(missing)` | `0.9.0-alpha` | (none) | backend/config test |
| `tests/configs/hyperlight_hello.json` | one-shot | MissingVersion | `(missing)` | `0.9.0-alpha` | (none) | backend/config test |
| `tests/configs/hyperlight_networking.json` | one-shot | MissingVersion | `(missing)` | `0.9.0-alpha` | (none) | backend/config test |
| `tests/configs/hyperlight_networking_blocked.json` | one-shot | MissingVersion | `(missing)` | `0.9.0-alpha` | (none) | backend/config test |
| `tests/configs/hyperlight_pandas.json` | one-shot | MissingVersion | `(missing)` | `0.9.0-alpha` | (none) | backend/config test |
| `tests/configs/hyperlight_timeout.json` | one-shot | MissingVersion | `(missing)` | `0.9.0-alpha` | (none) | backend/config test |
| `tests/configs/isolation_session_concurrent_A.json` | one-shot | PublishedDevelopmentContainment | `0.6.0-alpha` | `0.9.0-alpha` | (none) | backend/config test |
| `tests/configs/isolation_session_concurrent_B.json` | one-shot | PublishedDevelopmentContainment | `0.6.0-alpha` | `0.9.0-alpha` | (none) | backend/config test |
| `tests/configs/isolation_session_concurrent_C.json` | one-shot | PublishedDevelopmentContainment | `0.6.0-alpha` | `0.9.0-alpha` | (none) | backend/config test |
| `tests/configs/isolation_session_concurrent_D.json` | one-shot | PublishedDevelopmentContainment | `0.6.0-alpha` | `0.9.0-alpha` | (none) | backend/config test |
| `tests/configs/isolation_session_configid_rejected.json` | one-shot | PublishedDevelopmentContainment | `0.6.0-alpha` | `0.9.0-alpha` | (none) | backend/config test |
| `tests/configs/isolation_session_exit42.json` | one-shot | PublishedDevelopmentContainment | `0.6.0-alpha` | `0.9.0-alpha` | (none) | backend/config test |
| `tests/configs/isolation_session_hello.json` | one-shot | PublishedDevelopmentContainment | `0.6.0-alpha` | `0.9.0-alpha` | (none) | backend/config test |
| `tests/configs/isolation_session_one_shot_lifecycle_rejected.json` | one-shot | PublishedDevelopmentContainment | `0.6.0-alpha` | `0.9.0-alpha` | (none) | backend/config test |
| `tests/configs/isolation_session_one_shot_network_rejected.json` | one-shot | PublishedDevelopmentContainment | `0.6.0-alpha` | `0.9.0-alpha` | (none) | backend/config test |
| `tests/configs/isolation_session_one_shot_network_rejected_hosts.json` | one-shot | PublishedDevelopmentContainment | `0.6.0-alpha` | `0.9.0-alpha` | (none) | backend/config test |
| `tests/configs/isolation_session_one_shot_network_rejected_no_local.json` | one-shot | PublishedDevelopmentContainment | `0.6.0-alpha` | `0.9.0-alpha` | (none) | backend/config test |
| `tests/configs/isolation_session_one_shot_stray_config_rejected.json` | one-shot | PublishedDevelopmentContainment | `0.6.0-alpha` | `0.9.0-alpha` | (none) | backend/config test |
| `tests/configs/isolation_session_one_shot_ui_rejected.json` | one-shot | PublishedDevelopmentContainment | `0.6.0-alpha` | `0.9.0-alpha` | (none) | backend/config test |
| `tests/configs/isolation_session_powershell_interactive.json` | one-shot | PublishedDevelopmentContainment | `0.6.0-alpha` | `0.9.0-alpha` | (none) | backend/config test |
| `tests/configs/isolation_session_state_aware_deprovision.json` | state-aware deprovision | MissingVersion | `(missing)` | `0.9.0-alpha` | (none) | backend/config test |
| `tests/configs/isolation_session_state_aware_exec_basic.json` | state-aware exec | MissingVersion | `(missing)` | `0.9.0-alpha` | (none) | backend/config test |
| `tests/configs/isolation_session_state_aware_exec_cwd.json` | state-aware exec | MissingVersion | `(missing)` | `0.9.0-alpha` | (none) | backend/config test |
| `tests/configs/isolation_session_state_aware_exec_env_absent.json` | state-aware exec | MissingVersion | `(missing)` | `0.9.0-alpha` | (none) | backend/config test |
| `tests/configs/isolation_session_state_aware_exec_env_initial.json` | state-aware exec | MissingVersion | `(missing)` | `0.9.0-alpha` | (none) | backend/config test |
| `tests/configs/isolation_session_state_aware_exec_env_modified.json` | state-aware exec | MissingVersion | `(missing)` | `0.9.0-alpha` | (none) | backend/config test |
| `tests/configs/isolation_session_state_aware_exec_exit_0.json` | state-aware exec | MissingVersion | `(missing)` | `0.9.0-alpha` | (none) | backend/config test |
| `tests/configs/isolation_session_state_aware_exec_exit_1.json` | state-aware exec | MissingVersion | `(missing)` | `0.9.0-alpha` | (none) | backend/config test |
| `tests/configs/isolation_session_state_aware_exec_exit_2.json` | state-aware exec | MissingVersion | `(missing)` | `0.9.0-alpha` | (none) | backend/config test |
| `tests/configs/isolation_session_state_aware_exec_read_marker.json` | state-aware exec | MissingVersion | `(missing)` | `0.9.0-alpha` | (none) | backend/config test |
| `tests/configs/isolation_session_state_aware_exec_read_persist.json` | state-aware exec | MissingVersion | `(missing)` | `0.9.0-alpha` | (none) | backend/config test |
| `tests/configs/isolation_session_state_aware_exec_setx_initial.json` | state-aware exec | MissingVersion | `(missing)` | `0.9.0-alpha` | (none) | backend/config test |
| `tests/configs/isolation_session_state_aware_exec_setx_modified.json` | state-aware exec | MissingVersion | `(missing)` | `0.9.0-alpha` | (none) | backend/config test |
| `tests/configs/isolation_session_state_aware_exec_write_marker.json` | state-aware exec | MissingVersion | `(missing)` | `0.9.0-alpha` | (none) | backend/config test |
| `tests/configs/isolation_session_state_aware_provision.json` | state-aware provision | MissingVersion | `(missing)` | `0.9.0-alpha` | (none) | backend/config test |
| `tests/configs/isolation_session_state_aware_provision_appid.json` | state-aware provision | MissingVersion | `(missing)` | `0.9.0-alpha` | (none) | backend/config test |
| `tests/configs/isolation_session_state_aware_provision_appid_control.json` | state-aware provision | MissingVersion | `(missing)` | `0.9.0-alpha` | (none) | backend/config test |
| `tests/configs/isolation_session_state_aware_provision_appid_empty.json` | state-aware provision | MissingVersion | `(missing)` | `0.9.0-alpha` | (none) | backend/config test |
| `tests/configs/isolation_session_state_aware_provision_appid_too_long.json` | state-aware provision | MissingVersion | `(missing)` | `0.9.0-alpha` | (none) | backend/config test |
| `tests/configs/isolation_session_state_aware_provision_rejected_denied.json` | state-aware provision | MissingVersion | `(missing)` | `0.9.0-alpha` | (none) | backend/config test |
| `tests/configs/isolation_session_state_aware_provision_rejected_network.json` | state-aware provision | MissingVersion | `(missing)` | `0.9.0-alpha` | (none) | backend/config test |
| `tests/configs/isolation_session_state_aware_provision_rejected_ui.json` | state-aware provision | MissingVersion | `(missing)` | `0.9.0-alpha` | (none) | backend/config test |
| `tests/configs/isolation_session_state_aware_provision_with_filesystem.json` | state-aware provision | MissingVersion | `(missing)` | `0.9.0-alpha` | (none) | backend/config test |
| `tests/configs/isolation_session_state_aware_start.json` | state-aware start | MissingVersion | `(missing)` | `0.9.0-alpha` | (none) | backend/config test |
| `tests/configs/isolation_session_state_aware_stop.json` | state-aware stop | MissingVersion | `(missing)` | `0.9.0-alpha` | (none) | backend/config test |
| `tests/configs/isolation_session_stderr.json` | one-shot | PublishedDevelopmentContainment | `0.6.0-alpha` | `0.9.0-alpha` | (none) | backend/config test |
| `tests/configs/isolation_session_stdout_stderr_interleaved.json` | one-shot | PublishedDevelopmentContainment | `0.6.0-alpha` | `0.9.0-alpha` | (none) | backend/config test |
| `tests/configs/isolation_session_streaming_smoke.json` | one-shot | PublishedDevelopmentContainment | `0.6.0-alpha` | `0.9.0-alpha` | (none) | backend/config test |
| `tests/configs/isolation_session_timeout.json` | one-shot | PublishedDevelopmentContainment | `0.6.0-alpha` | `0.9.0-alpha` | (none) | backend/config test |
| `tests/configs/microvm_error.json` | one-shot | MissingVersion | `(missing)` | `0.9.0-alpha` | (none) | backend/config test |
| `tests/configs/microvm_error_linux.json` | one-shot | MissingVersion | `(missing)` | `0.9.0-alpha` | (none) | backend/config test |
| `tests/configs/microvm_exit_code.json` | one-shot | MissingVersion | `(missing)` | `0.9.0-alpha` | (none) | backend/config test |
| `tests/configs/microvm_exit_code_linux.json` | one-shot | MissingVersion | `(missing)` | `0.9.0-alpha` | (none) | backend/config test |
| `tests/configs/microvm_hello.json` | one-shot | MissingVersion | `(missing)` | `0.9.0-alpha` | (none) | backend/config test |
| `tests/configs/microvm_hello_linux.json` | one-shot | MissingVersion | `(missing)` | `0.9.0-alpha` | (none) | backend/config test |
| `tests/configs/microvm_large_output.json` | one-shot | MissingVersion | `(missing)` | `0.9.0-alpha` | (none) | backend/config test |
| `tests/configs/microvm_large_output_linux.json` | one-shot | MissingVersion | `(missing)` | `0.9.0-alpha` | (none) | backend/config test |
| `tests/configs/microvm_multiline.json` | one-shot | MissingVersion | `(missing)` | `0.9.0-alpha` | (none) | backend/config test |
| `tests/configs/microvm_multiline_linux.json` | one-shot | MissingVersion | `(missing)` | `0.9.0-alpha` | (none) | backend/config test |
| `tests/configs/microvm_network.json` | one-shot | MissingVersion | `(missing)` | `0.9.0-alpha` | (none) | backend/config test |
| `tests/configs/microvm_network_linux.json` | one-shot | MissingVersion | `(missing)` | `0.9.0-alpha` | (none) | backend/config test |
| `tests/configs/microvm_stdlib.json` | one-shot | MissingVersion | `(missing)` | `0.9.0-alpha` | (none) | backend/config test |
| `tests/configs/microvm_stdlib_linux.json` | one-shot | MissingVersion | `(missing)` | `0.9.0-alpha` | (none) | backend/config test |
| `tests/configs/microvm_timeout.json` | one-shot | MissingVersion | `(missing)` | `0.9.0-alpha` | (none) | backend/config test |
| `tests/configs/microvm_timeout_linux.json` | one-shot | MissingVersion | `(missing)` | `0.9.0-alpha` | (none) | backend/config test |
| `tests/configs/windows_sandbox_custom_timeout.json` | one-shot | PublishedDevelopmentContainment | `0.6.0-alpha` | `0.9.0-alpha` | (none) | backend/config test |
| `tests/configs/windows_sandbox_echo.json` | one-shot | MissingVersion | `(missing)` | `0.9.0-alpha` | (none) | backend/config test |
| `tests/configs/windows_sandbox_exit_code.json` | one-shot | MissingVersion | `(missing)` | `0.9.0-alpha` | (none) | backend/config test |
| `tests/configs/windows_sandbox_powershell.json` | one-shot | MissingVersion | `(missing)` | `0.9.0-alpha` | (none) | backend/config test |
| `tests/configs/windows_sandbox_powershell_env.json` | one-shot | MissingVersion | `(missing)` | `0.9.0-alpha` | (none) | backend/config test |
| `tests/configs/windows_sandbox_stderr.json` | one-shot | MissingVersion | `(missing)` | `0.9.0-alpha` | (none) | backend/config test |
| `tests/configs/windows_sandbox_timeout.json` | one-shot | MissingVersion | `(missing)` | `0.9.0-alpha` | (none) | backend/config test |
| `tests/configs/wslc_custom_registry.json` | one-shot | PublishedDevelopmentContainment | `0.6.0-alpha` | `0.9.0-alpha` | (none) | backend/config test |
| `tests/configs/wslc_custom_registry_ghcr.json` | one-shot | PublishedDevelopmentContainment | `0.6.0-alpha` | `0.9.0-alpha` | (none) | backend/config test |
| `tests/configs/wslc_custom_registry_quay.json` | one-shot | PublishedDevelopmentContainment | `0.6.0-alpha` | `0.9.0-alpha` | (none) | backend/config test |
| `tests/configs/wslc_denied_dotdot_alias.json` | one-shot | PublishedDevelopmentContainment | `0.8.0-alpha` | `0.9.0-alpha` | (none) | backend/config test |
| `tests/configs/wslc_denied_masking.json` | one-shot | PublishedDevelopmentContainment | `0.8.0-alpha` | `0.9.0-alpha` | (none) | backend/config test |
| `tests/configs/wslc_destroy_on_exit_false_rejected.json` | one-shot | PublishedComment | `0.6.0-alpha` | `0.9.0-alpha` | (none) | backend/config test |
| `tests/configs/wslc_destroy_on_exit_true.json` | one-shot | PublishedComment | `0.6.0-alpha` | `0.9.0-alpha` | (none) | backend/config test |
| `tests/configs/wslc_env_vars.json` | one-shot | PublishedDevelopmentContainment | `0.6.0-alpha` | `0.9.0-alpha` | (none) | backend/config test |
| `tests/configs/wslc_exit_code.json` | one-shot | PublishedDevelopmentContainment | `0.6.0-alpha` | `0.9.0-alpha` | (none) | backend/config test |
| `tests/configs/wslc_filesystem.json` | one-shot | PublishedDevelopmentContainment | `0.6.0-alpha` | `0.9.0-alpha` | (none) | backend/config test |
| `tests/configs/wslc_filesystem_object.json` | one-shot | PublishedDevelopmentContainment | `0.8.0-alpha` | `0.9.0-alpha` | (none) | backend/config test |
| `tests/configs/wslc_large_output.json` | one-shot | PublishedDevelopmentContainment | `0.6.0-alpha` | `0.9.0-alpha` | (none) | backend/config test |
| `tests/configs/wslc_most_specific_denied_parent.json` | one-shot | PublishedDevelopmentContainment | `0.8.0-alpha` | `0.9.0-alpha` | (none) | backend/config test |
| `tests/configs/wslc_network_isolated.json` | one-shot | PublishedDevelopmentContainment | `0.6.0-alpha` | `0.9.0-alpha` | (none) | backend/config test |
| `tests/configs/wslc_network_proxy.json` | one-shot | PublishedDevelopmentContainment | `0.6.0-alpha` | `0.9.0-alpha` | (none) | backend/config test |
| `tests/configs/wslc_port_mapping_multiple.json` | one-shot | PublishedDevelopmentContainment | `0.8.0-alpha` | `0.9.0-alpha` | (none) | backend/config test |
| `tests/configs/wslc_port_mapping_tcp.json` | one-shot | PublishedDevelopmentContainment | `0.8.0-alpha` | `0.9.0-alpha` | (none) | backend/config test |
| `tests/configs/wslc_python_hello.json` | one-shot | PublishedDevelopmentContainment | `0.6.0-alpha` | `0.9.0-alpha` | (none) | backend/config test |
| `tests/configs/wslc_python_stdlib.json` | one-shot | PublishedDevelopmentContainment | `0.6.0-alpha` | `0.9.0-alpha` | (none) | backend/config test |
| `tests/configs/wslc_readonly_mount.json` | one-shot | PublishedDevelopmentContainment | `0.6.0-alpha` | `0.9.0-alpha` | (none) | backend/config test |
| `tests/configs/wslc_state_aware_deprovision.json` | state-aware deprovision | PublishedStateAware | `0.8.0-alpha` | `0.9.0-alpha` | (none) | backend/config test |
| `tests/configs/wslc_state_aware_exec_basic.json` | state-aware exec | PublishedStateAware | `0.8.0-alpha` | `0.9.0-alpha` | (none) | backend/config test |
| `tests/configs/wslc_state_aware_exec_drip.json` | state-aware exec | PublishedStateAware | `0.8.0-alpha` | `0.9.0-alpha` | (none) | backend/config test |
| `tests/configs/wslc_state_aware_exec_env.json` | state-aware exec | PublishedStateAware | `0.8.0-alpha` | `0.9.0-alpha` | (none) | backend/config test |
| `tests/configs/wslc_state_aware_exec_exit_0.json` | state-aware exec | PublishedStateAware | `0.8.0-alpha` | `0.9.0-alpha` | (none) | backend/config test |
| `tests/configs/wslc_state_aware_exec_exit_1.json` | state-aware exec | PublishedStateAware | `0.8.0-alpha` | `0.9.0-alpha` | (none) | backend/config test |
| `tests/configs/wslc_state_aware_exec_exit_7.json` | state-aware exec | PublishedStateAware | `0.8.0-alpha` | `0.9.0-alpha` | (none) | backend/config test |
| `tests/configs/wslc_state_aware_exec_proxy.json` | state-aware exec | PublishedStateAware | `0.8.0-alpha` | `0.9.0-alpha` | (none) | backend/config test |
| `tests/configs/wslc_state_aware_exec_read_marker.json` | state-aware exec | PublishedStateAware | `0.8.0-alpha` | `0.9.0-alpha` | (none) | backend/config test |
| `tests/configs/wslc_state_aware_exec_rejected_filesystem.json` | state-aware exec | PublishedStateAware | `0.8.0-alpha` | `0.9.0-alpha` | (none) | backend/config test |
| `tests/configs/wslc_state_aware_exec_write_marker.json` | state-aware exec | PublishedStateAware | `0.8.0-alpha` | `0.9.0-alpha` | (none) | backend/config test |
| `tests/configs/wslc_state_aware_provision.json` | state-aware provision | PublishedStateAware | `0.8.0-alpha` | `0.9.0-alpha` | (none) | backend/config test |
| `tests/configs/wslc_state_aware_provision_bridged.json` | state-aware provision | PublishedStateAware | `0.8.0-alpha` | `0.9.0-alpha` | (none) | backend/config test |
| `tests/configs/wslc_state_aware_provision_rejected_denied.json` | state-aware provision | PublishedStateAware | `0.8.0-alpha` | `0.9.0-alpha` | (none) | backend/config test |
| `tests/configs/wslc_state_aware_provision_rejected_hosts.json` | state-aware provision | PublishedStateAware | `0.8.0-alpha` | `0.9.0-alpha` | (none) | backend/config test |
| `tests/configs/wslc_state_aware_provision_rejected_proxy.json` | state-aware provision | PublishedStateAware | `0.8.0-alpha` | `0.9.0-alpha` | (none) | backend/config test |
| `tests/configs/wslc_state_aware_provision_with_filesystem.json` | state-aware provision | PublishedStateAware | `0.8.0-alpha` | `0.9.0-alpha` | (none) | backend/config test |
| `tests/configs/wslc_state_aware_start.json` | state-aware start | PublishedStateAware | `0.8.0-alpha` | `0.9.0-alpha` | (none) | backend/config test |
| `tests/configs/wslc_state_aware_stop.json` | state-aware stop | PublishedStateAware | `0.8.0-alpha` | `0.9.0-alpha` | (none) | backend/config test |
| `tests/configs/wslc_stderr.json` | one-shot | PublishedDevelopmentContainment | `0.6.0-alpha` | `0.9.0-alpha` | (none) | backend/config test |
| `tests/configs/wslc_tar_import_docker_save.json` | one-shot | PublishedDevelopmentContainment | `0.6.0-alpha` | `0.9.0-alpha` | (none) | backend/config test |
| `tests/configs/wslc_tar_import_rootfs.json` | one-shot | PublishedDevelopmentContainment | `0.6.0-alpha` | `0.9.0-alpha` | (none) | backend/config test |
| `tests/configs/wslc_timeout.json` | one-shot | PublishedDevelopmentContainment | `0.6.0-alpha` | `0.9.0-alpha` | (none) | backend/config test |
| `tests/examples/09_windows_sandbox_hello_world.json` | one-shot | PublishedDevelopmentContainment | `0.6.0-alpha` | `0.9.0-alpha` | (none) | example |
| `tests/examples/10_windows_sandbox_network_isolated.json` | one-shot | PublishedDevelopmentContainment | `0.6.0-alpha` | `0.9.0-alpha` | (none) | example |
| `tests/examples/28_telemetry_enabled.json` | one-shot | MissingVersion | `(missing)` | `0.9.0-alpha` | `../../schemas/dev/mxc-config.schema.0.9.0-alpha.json` | example |
| `tests/examples/wslc_hello_world.json` | one-shot | PublishedDevelopmentContainment | `0.6.0-alpha` | `0.9.0-alpha` | (none) | example |
| `tests/policy/state-aware-wslc-exec.json` | state-aware exec | PublishedStateAware | `0.8.0-alpha` | `0.9.0-alpha` | (none) | SDK/FFI policy fixture |
| `tests/policy/state-aware-wslc-provision.json` | state-aware provision | PublishedStateAware | `0.8.0-alpha` | `0.9.0-alpha` | (none) | SDK/FFI policy fixture |
