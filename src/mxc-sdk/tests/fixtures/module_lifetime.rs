// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![cfg(not(test))]

use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Duration;

#[cfg(windows)]
use mxc_sdk::mxc_common;

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
