// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Windows E2E integration tests.
//!
//! Each test invokes a PowerShell script from `test_scripts/` via `pwsh`.
//! Tests skip gracefully when prerequisites (binaries, admin, features) are missing.

use wxc_e2e_tests::{assert_ps1_success, has_daemon, has_nanvix_binaries, has_test_driver, has_wxc_exe};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn test_appcontainer_basic() {
    if !has_wxc_exe() { return; }
    assert_ps1_success("run_basicac_test.ps1");
}

#[test]
fn test_appcontainer_lpac() {
    if !has_wxc_exe() { return; }
    assert_ps1_success("run_lpacac_test.ps1");
}

#[test]
fn test_filesystem_bfs() {
    if !has_wxc_exe() { return; }
    assert_ps1_success("run_filesystem_bfs_test.ps1");
}

#[test]
fn test_filesystem_bfs_readonly() {
    if !has_wxc_exe() { return; }
    assert_ps1_success("run_filesystem_bfsreadonly_test.ps1");
}

#[test]
fn test_filesystem_bfs_spaces() {
    if !has_wxc_exe() { return; }
    assert_ps1_success("run_filesystem_bfs_spaces_test.ps1");
}

#[test]
fn test_pwsh_setlocation() {
    if !has_wxc_exe() { return; }
    assert_ps1_success("run_pwsh_test.ps1");
}

#[test]
fn test_test_configs() {
    if !has_test_driver() { return; }
    assert_ps1_success("run_test_configs.ps1");
}

#[test]
fn test_examples() {
    if !has_test_driver() { return; }
    assert_ps1_success("run_examples.ps1");
}

#[test]
fn test_microvm_basic() {
    if !has_wxc_exe() { return; }
    if !has_nanvix_binaries() { return; }
    assert_ps1_success("run_microvm_basic_test.ps1");
}

#[test]
fn test_windows_sandbox() {
    if !has_wxc_exe() { return; }
    if !has_daemon() { return; }
    assert_ps1_success("run_windows_sandbox_tests.ps1");
}

#[test]
fn test_microvm_suite() {
    if !has_wxc_exe() { return; }
    if !has_nanvix_binaries() { return; }
    assert_ps1_success("run_microvm_tests.ps1");
}

#[test]
fn test_appcontainer_proxy() {
    if !has_wxc_exe() { return; }
    assert_ps1_success("run_appcontainer_proxy_tests.ps1");
}

#[test]
#[ignore] // Stress test — run explicitly with `cargo test -p wxc_e2e_tests -- --ignored`
fn test_on_repeat() {
    if !has_wxc_exe() { return; }
    assert_ps1_success("run_on_repeat.ps1");
}
