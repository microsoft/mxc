// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::{Duration, Instant};

const CHILD_ENV: &str = "MXC_MODULE_LIFETIME_TEST_CHILD";

#[test]
fn detached_worker_survives_library_unload() {
    if std::env::var_os(CHILD_ENV).is_some() {
        exercise_library_unload();
        return;
    }

    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "detached_worker_survives_library_unload",
            "--nocapture",
        ])
        .env(CHILD_ENV, "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(15);
    while child.try_wait().unwrap().is_none() {
        if Instant::now() >= deadline {
            child.kill().unwrap();
            let output = child.wait_with_output().unwrap();
            panic!(
                "library-unload regression subprocess hung: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "library-unload regression failed: {}\n{}\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn exercise_library_unload() {
    let executable = std::env::current_exe().unwrap();
    let library_path = executable
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("examples")
        .join(format!(
            "{}module_lifetime_fixture{}",
            std::env::consts::DLL_PREFIX,
            std::env::consts::DLL_SUFFIX
        ));
    assert!(
        library_path.exists(),
        "build the regression fixture with: cargo build -p mxc-sdk --example module_lifetime_fixture"
    );
    let state = Box::leak(Box::new(AtomicU8::new(0)));

    // SAFETY: the fixture contains the production probe and its dependencies.
    let library = unsafe { libloading::Library::new(&library_path) }.unwrap();

    // SAFETY: the fixture exports this signature and state remains alive for process lifetime.
    unsafe {
        let start: libloading::Symbol<unsafe extern "C" fn(*const AtomicU8) -> bool> =
            library.get(b"timed_out_worker").unwrap();
        assert!(
            start(state),
            "the worker must time out before it is released"
        );
    }
    drop(library);
    state.store(1, Ordering::Release);
    let deadline = Instant::now() + Duration::from_secs(5);
    while state.load(Ordering::Acquire) != 2 {
        assert!(
            Instant::now() < deadline,
            "the detached worker did not resume after the library handle was closed"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
}
