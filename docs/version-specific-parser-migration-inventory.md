# Version-specific parser migration inventory

Generated from commit `2d4b094b32feedbf00afd55d875a8fa9e3a0bb6f`
on 2026-09-03. The inventory covers every JSON document named by the
differential harness's `expected_corpus_divergences` table before migration.

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

## Post-migration disposition

Version migration removed 118 of the 125 recorded divergences. The remaining
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

The differential harness continues to record the seven exact-stricter results
so later contract changes cannot accidentally weaken the exact boundary. It
also compares every corpus document through the public loader and the exact
parser oracle. The retained rolling characterization remains 266 equivalent
accepts, nine shared rejections, seven classified exact-stricter rejections, no
exact-looser acceptance, and no accepted-model mismatch.

## Validation

Validated on 2026-09-04 after exact dispatch became authoritative:

- Rust formatting, workspace check, and workspace clippy completed without
  warnings.
- The Rust workspace passed 4,148 tests with 23 ignored.
- The Node SDK passed its build and 304 tests, with 19 skipped.
- The .NET SDK passed 118 tests, with 24 skipped.
- The config validator accepted 277 documents.
- Schema-version, exact-contract codegen, SDK wire-type codegen, and package
  version-sync gates passed.
- The seven residual fixtures were exercised through the rebuilt
  `wxc-exec.exe`; their public diagnostics matched the structural exact-contract
  expectations retained by the E2E scripts.

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
| `tests/examples/28_telemetry_enabled.json` | one-shot | MissingVersion | `(missing)` | `0.9.0-alpha` | `../../schemas/dev/mxc-config.schema.0.9.0-dev.json` | example |
| `tests/examples/wslc_hello_world.json` | one-shot | PublishedDevelopmentContainment | `0.6.0-alpha` | `0.9.0-alpha` | (none) | example |
| `tests/policy/state-aware-wslc-exec.json` | state-aware exec | PublishedStateAware | `0.8.0-alpha` | `0.9.0-alpha` | (none) | SDK/FFI policy fixture |
| `tests/policy/state-aware-wslc-provision.json` | state-aware provision | PublishedStateAware | `0.8.0-alpha` | `0.9.0-alpha` | (none) | SDK/FFI policy fixture |
