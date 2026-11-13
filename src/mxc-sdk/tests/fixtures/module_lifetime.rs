// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![cfg(not(test))]

use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Duration;

#[cfg(windows)]
use mxc_internal::mxc_common;

#[allow(dead_code)]
#[path = "../../src/core/mxc_common/config_deserialize.rs"]
mod config_deserialize;
#[path = "../../src/core/mxc_common/filesystem_probe.rs"]
mod filesystem_probe;
#[path = "../../src/core/mxc_common/module_lifetime.rs"]
mod module_lifetime;
#[cfg(windows)]
#[allow(dead_code)]
#[path = "../../src/core/mxc_common/process_util.rs"]
mod process_util;

#[no_mangle]
unsafe extern "C" fn timed_out_worker(state: *const AtomicU8) -> bool {
    let started = Arc::new(AtomicBool::new(false));

    // SAFETY: the test host keeps state alive until its subprocess exits.
    let state = unsafe { &*state };
    let worker_started = Arc::clone(&started);
    let result = filesystem_probe::FilesystemProbe::default().run("stalled-path", move |_| {
        worker_started.store(true, Ordering::Release);
        while state.load(Ordering::Acquire) == 0 {
            std::thread::sleep(Duration::from_millis(1));
        }

        state.store(2, Ordering::Release);
    });
    match result {
        Err(error) if error.contains("timed out after 5000ms") => started.load(Ordering::Acquire),
        result => {
            eprintln!("expected a production probe timeout, got {result:?}");
            false
        }
    }
}

#[cfg(all(windows, target_arch = "x86_64", feature = "microvm"))]
#[no_mangle]
unsafe extern "C" fn nvx_error_with_pending_worker(state: *const AtomicU8) -> bool {
    use mxc_internal::v1::{dev, ErrorCode};

    // Native validation rejects this proxy before provisioning; no filesystem probe pins MXC.
    let result = dev::run_json(
        r#"{"version":"1.1.0-alpha","containment":"microvm","microvm":{"image":"mcr.microsoft.com/azurelinux/base/core:3.0"},"runtimeConfig":{"networkProxy":"http://[::1]:3128"},"process":{"commandLine":"printf forbidden"}}"#,
        dev::JsonOptions { experimental: true },
    );
    match result {
        Err(error)
            if error.code == ErrorCode::PolicyValidation
                && error.message
                    == "NVX signed bundled agent: policy_validation: OpenVMM reaches host \
                        loopback over IPv4 only; name 127.0.0.1 or localhost" => {}
        result => {
            eprintln!("expected native proxy validation failure, got {result:?}");
            return false;
        }
    }

    // Model a crate-owned pump surviving an error return without inducing native teardown failure.
    let started = Arc::new(AtomicBool::new(false));
    let worker_started = Arc::clone(&started);
    // SAFETY: the isolated test host retains state until process exit.
    let state = unsafe { &*state };
    std::thread::spawn(move || {
        worker_started.store(true, Ordering::Release);
        while state.load(Ordering::Acquire) == 0 {
            std::thread::sleep(Duration::from_millis(1));
        }
        state.store(2, Ordering::Release);
    });
    while !started.load(Ordering::Acquire) {
        std::thread::sleep(Duration::from_millis(1));
    }
    true
}
