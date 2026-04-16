// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Windows E2E integration tests.
//!
//! Each test invokes a PowerShell script from `test_scripts/` via `pwsh`.
//! Tests skip gracefully when prerequisites (binaries, admin, features) are missing.

use std::sync::OnceLock;

use wxc_e2e_tests::{
    assert_ps1_success, has_daemon, has_nanvix_binaries, has_test_driver, has_wxc_exe,
};

static HAS_WXC_EXE: OnceLock<bool> = OnceLock::new();
static HAS_TEST_DRIVER: OnceLock<bool> = OnceLock::new();
static HAS_NANVIX_BINARIES: OnceLock<bool> = OnceLock::new();
static HAS_DAEMON: OnceLock<bool> = OnceLock::new();

/// Caches the `wxc-exec.exe` prerequisite probe so repeated tests do not
/// rescan the filesystem or print duplicate status lines.
fn cached_has_wxc_exe() -> bool {
    *HAS_WXC_EXE.get_or_init(has_wxc_exe)
}

/// Caches the test driver probe for the duration of the test process.
fn cached_has_test_driver() -> bool {
    *HAS_TEST_DRIVER.get_or_init(has_test_driver)
}

/// Caches the NanVix binary probe to avoid repeated prerequisite work.
fn cached_has_nanvix_binaries() -> bool {
    *HAS_NANVIX_BINARIES.get_or_init(has_nanvix_binaries)
}

/// Caches the daemon probe to keep logs readable across multiple tests.
fn cached_has_daemon() -> bool {
    *HAS_DAEMON.get_or_init(has_daemon)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn test_appcontainer_basic() {
    if !cached_has_wxc_exe() {
        return;
    }
    assert_ps1_success("run_basicac_test.ps1");
}

#[test]
fn test_appcontainer_lpac() {
    if !cached_has_wxc_exe() {
        return;
    }
    assert_ps1_success("run_lpacac_test.ps1");
}

#[test]
fn test_filesystem_bfs() {
    if !cached_has_wxc_exe() {
        return;
    }
    assert_ps1_success("run_filesystem_bfs_test.ps1");
}

#[test]
fn test_filesystem_bfs_readonly() {
    if !cached_has_wxc_exe() {
        return;
    }
    assert_ps1_success("run_filesystem_bfsreadonly_test.ps1");
}

#[test]
fn test_filesystem_bfs_spaces() {
    if !cached_has_wxc_exe() {
        return;
    }
    assert_ps1_success("run_filesystem_bfs_spaces_test.ps1");
}

#[test]
fn test_pwsh_setlocation() {
    if !cached_has_wxc_exe() {
        return;
    }
    assert_ps1_success("run_pwsh_test.ps1");
}

#[test]
fn test_test_configs() {
    if !cached_has_test_driver() {
        return;
    }
    assert_ps1_success("run_test_configs.ps1");
}

#[test]
fn test_examples() {
    if !cached_has_test_driver() {
        return;
    }
    assert_ps1_success("run_examples.ps1");
}

#[test]
fn test_microvm_basic() {
    if !cached_has_wxc_exe() {
        return;
    }
    if !cached_has_nanvix_binaries() {
        return;
    }
    assert_ps1_success("run_microvm_basic_test.ps1");
}

#[test]
fn test_windows_sandbox() {
    if !cached_has_wxc_exe() {
        return;
    }
    if !cached_has_daemon() {
        return;
    }
    assert_ps1_success("run_windows_sandbox_tests.ps1");
}

#[test]
fn test_microvm_suite() {
    if !cached_has_wxc_exe() {
        return;
    }
    if !cached_has_nanvix_binaries() {
        return;
    }
    assert_ps1_success("run_microvm_tests.ps1");
}

#[test]
fn test_appcontainer_proxy() {
    if !cached_has_wxc_exe() {
        return;
    }
    assert_ps1_success("run_appcontainer_proxy_tests.ps1");
}

#[test]
#[ignore] // Stress test — run explicitly with `cargo test -p wxc_e2e_tests -- --ignored`
fn test_on_repeat() {
    if !cached_has_wxc_exe() {
        return;
    }
    assert_ps1_success("run_on_repeat.ps1");
}
