// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Measures whether the IsolationSession lifecycle runs from a given COM
//! apartment, against a live host.
//!
//! Re-measuring the underlying deadlock means temporarily relaxing the refusal
//! in `current_apartment` and re-running `sta`.
//!
//! ```text
//! sta_probe.exe sta    # expect a refusal — the lifecycle deadlocks there
//! sta_probe.exe mta    # expect the full lifecycle
//! sta_probe.exe none   # expect the full lifecycle — MXC enters the apartment
//! sta_probe.exe handle-outlives-thread
//!                      # expect the handle to outlive the thread that made it
//! ```
//!
//! Must run as an interactive user.

use std::io::Write;
use std::time::{Duration, Instant};

/// Provision on a healthy host takes a couple of seconds, so this is well past
/// slow and into hung.
const WATCHDOG: Duration = Duration::from_secs(90);

static STEP: std::sync::Mutex<String> = std::sync::Mutex::new(String::new());
/// Lets the watchdog tear down a sandbox the wedged main thread cannot reach.
static SANDBOX: std::sync::Mutex<String> = std::sync::Mutex::new(String::new());

fn checkpoint(name: &str) {
    *STEP.lock().unwrap() = name.to_string();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    println!("[{now}] -> {name}");
    let _ = std::io::stdout().flush();
}

/// Tears down on a dedicated thread so the caller's apartment state is left
/// untouched, which `handle-outlives-thread` depends on.
#[cfg(all(target_os = "windows", feature = "isolation_session"))]
fn teardown(id: &str, who: &str) {
    if id.is_empty() {
        return;
    }
    let id = id.to_string();
    let who = who.to_string();
    let worker = std::thread::spawn(move || {
        println!("    [{who}] tearing down {id}");
        let _ = std::io::stdout().flush();
        let stop = format!(r#"{{"phase":"stop","sandboxId":"{id}"}}"#);
        match mxc_sdk::run_state_aware_json(&stop, false, true) {
            Ok(_) => println!("    [{who}] stopped"),
            Err(e) => println!("    [{who}] stop failed: {e:?}"),
        }
        let deprovision = format!(r#"{{"phase":"deprovision","sandboxId":"{id}"}}"#);
        match mxc_sdk::run_state_aware_json(&deprovision, false, true) {
            Ok(_) => println!("    [{who}] deprovisioned"),
            Err(e) => println!("    [{who}] WARNING: deprovision failed, account may leak: {e:?}"),
        }
        let _ = std::io::stdout().flush();
    });
    let _ = worker.join();
}

/// Enters an apartment on the calling thread, so a mode can choose the state the
/// lifecycle will see.
///
/// Declared raw rather than taking a `windows` dev-dependency for one call.
#[cfg(all(target_os = "windows", feature = "isolation_session"))]
fn co_initialize(multi_threaded: bool) -> i32 {
    #[link(name = "ole32")]
    extern "system" {
        fn CoInitializeEx(reserved: *mut core::ffi::c_void, co_init: u32) -> i32;
    }
    const COINIT_APARTMENTTHREADED: u32 = 0x2;
    const COINIT_MULTITHREADED: u32 = 0x0;

    let flags = if multi_threaded {
        COINIT_MULTITHREADED
    } else {
        COINIT_APARTMENTTHREADED
    };
    // SAFETY: standard COM init. Deliberately unbalanced.
    unsafe { CoInitializeEx(core::ptr::null_mut(), flags) }
}

fn main() {
    let mode = std::env::args().nth(1).unwrap_or_else(|| "sta".to_string());

    // Reports a stall from outside the wedged thread: if the apartment choice
    // deadlocks the lifecycle, nothing else in this process runs again.
    std::thread::spawn(|| {
        let started = Instant::now();
        loop {
            std::thread::sleep(Duration::from_secs(2));
            if started.elapsed() > WATCHDOG {
                let step = STEP.lock().map(|s| s.clone()).unwrap_or_default();
                println!("\nRESULT: HUNG");
                println!("last step: {step}");
                let _ = std::io::stdout().flush();

                // `process::exit` skips destructors, so tear down first or the
                // provisioned OS account leaks. `teardown` owns an MTA thread,
                // so it works regardless of this thread's apartment and is not
                // subject to whatever wedged main.
                #[cfg(all(target_os = "windows", feature = "isolation_session"))]
                {
                    let id = SANDBOX.lock().map(|s| s.clone()).unwrap_or_default();
                    teardown(&id, "watchdog");
                }

                std::process::exit(99);
            }
        }
    });

    #[cfg(all(target_os = "windows", feature = "isolation_session"))]
    if mode == "handle-outlives-thread" {
        measure_handle_outliving_its_thread();
        return;
    }

    #[cfg(all(target_os = "windows", feature = "isolation_session"))]
    {
        checkpoint(&format!("CoInitializeEx({mode}) on the main thread"));
        match mode.as_str() {
            "sta" => println!("    hr = 0x{:08x}", co_initialize(false)),
            "mta" => println!("    hr = 0x{:08x}", co_initialize(true)),
            "none" => println!("    (no apartment entered by this process)"),
            other => {
                eprintln!("unknown mode: {other}");
                std::process::exit(2);
            }
        }
        let _ = std::io::stdout().flush();

        checkpoint("available_backends() — activation from this apartment");
        let backends = mxc_sdk::available_backends();
        let supported = backends.iter().any(|b| b.backend == "isolation_session");
        println!("    isolation_session available: {supported}");
        if !supported {
            println!("\nRESULT: SKIPPED (IsolationSession is not available on this host)");
            return;
        }

        checkpoint("provision — the first async join");
        let provision = r#"{"phase":"provision","containment":"isolation_session",
            "network":{"defaultPolicy":"allow","allowLocalNetwork":true}}"#;
        let response = match mxc_sdk::run_state_aware_json(provision, false, true) {
            Ok(r) => r,
            Err(e) => {
                println!("\nRESULT: FAILED (not hung) at provision");
                println!("error: {e:?}");
                return;
            }
        };
        let sandbox_id = response
            .split(r#""sandboxId":""#)
            .nth(1)
            .and_then(|s| s.split('"').next())
            .unwrap_or_default()
            .to_string();
        if sandbox_id.is_empty() {
            println!("\nRESULT: FAILED — no sandboxId in: {response}");
            return;
        }
        println!("    provisioned: {sandbox_id}");
        *SANDBOX.lock().unwrap() = sandbox_id.clone();

        // Provision mints a real OS account; every exit path must tear it down.
        let _teardown = Teardown(sandbox_id.clone());

        checkpoint("start — a second async join, on a live session");
        if let Err(e) = mxc_sdk::run_state_aware_json(
            &format!(r#"{{"phase":"start","sandboxId":"{sandbox_id}"}}"#),
            false,
            true,
        ) {
            println!("\nRESULT: FAILED (not hung) at start");
            println!("error: {e:?}");
            return;
        }
        println!("    started");

        // Exec spawns relay and waiter threads that call into WinRT without
        // initialising COM themselves.
        checkpoint("exec — worker threads call WinRT with no apartment of their own");
        let exec = format!(
            r#"{{"phase":"exec","sandboxId":"{sandbox_id}",
                "process":{{"commandLine":"cmd.exe /c echo sta-probe-marker","timeout":30000}}}}"#
        );
        let mut exec_ok = false;
        match mxc_sdk::exec_sandbox(&exec, true) {
            Ok(mut sandbox) => {
                let out = sandbox.take_stdout();
                let reader = std::thread::spawn(move || {
                    use std::io::Read;
                    let mut buf = Vec::new();
                    if let Some(mut s) = out {
                        let _ = s.read_to_end(&mut buf);
                    }
                    buf
                });
                match sandbox.wait() {
                    Ok(outcome) => {
                        let captured = reader.join().unwrap_or_default();
                        let text = String::from_utf8_lossy(&captured);
                        let marker = text.contains("sta-probe-marker");
                        println!("    outcome: {outcome:?}");
                        println!("    marker seen: {marker}");
                        exec_ok = marker;
                    }
                    Err(e) => println!("    wait failed: {e:?}"),
                }
            }
            Err(e) => println!("    exec failed: {e:?}"),
        }

        checkpoint("teardown (stop + deprovision, both async)");
        drop(_teardown);

        if !exec_ok {
            println!("\nRESULT: FAILED — the lifecycle ran under '{mode}' but exec did not");
            return;
        }

        println!("\nRESULT: COMPLETED — the full lifecycle ran under '{mode}'");
    }

    #[cfg(not(all(target_os = "windows", feature = "isolation_session")))]
    {
        let _ = mode;
        println!("RESULT: SKIPPED (built without windows + isolation_session)");
    }
}

#[cfg(all(target_os = "windows", feature = "isolation_session"))]
struct Teardown(String);

#[cfg(all(target_os = "windows", feature = "isolation_session"))]
impl Drop for Teardown {
    fn drop(&mut self) {
        teardown(&self.0, "main");
    }
}

/// Measures whether a streaming handle survives the exit of the thread that
/// created it.
///
/// `SandboxProcess` is `Send`, so a host may create a handle on one thread and
/// use it on another. The main thread deliberately does not enter an apartment,
/// so the worker is the only MTA member while it lives.
#[cfg(all(target_os = "windows", feature = "isolation_session"))]
fn measure_handle_outliving_its_thread() {
    use std::io::Read;

    checkpoint("worker thread: provision + start + exec, then exit");

    let (tx, rx) = std::sync::mpsc::channel();
    let (exec_tx, exec_rx) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        let provision = r#"{"phase":"provision","containment":"isolation_session",
            "network":{"defaultPolicy":"allow","allowLocalNetwork":true}}"#;
        let response = match mxc_sdk::run_state_aware_json(provision, false, true) {
            Ok(r) => r,
            Err(e) => {
                let _ = tx.send(Err(format!("provision failed: {e:?}")));
                return;
            }
        };
        let sandbox_id = response
            .split(r#""sandboxId":""#)
            .nth(1)
            .and_then(|s| s.split('"').next())
            .unwrap_or_default()
            .to_string();
        if sandbox_id.is_empty() {
            let _ = tx.send(Err(format!("no sandboxId in: {response}")));
            return;
        }
        *SANDBOX.lock().unwrap() = sandbox_id.clone();
        // Sent before anything else can fail, so main owns cleanup from here.
        let _ = tx.send(Ok(sandbox_id.clone()));

        let start = format!(r#"{{"phase":"start","sandboxId":"{sandbox_id}"}}"#);
        if let Err(e) = mxc_sdk::run_state_aware_json(&start, false, true) {
            let _ = exec_tx.send(Err(format!("start failed: {e:?}")));
            return;
        }

        // Long enough that the workload is certainly still running when this
        // thread exits, so the handle under test is live, but short enough to
        // end on its own so no kill races the read path.
        let exec = format!(
            r#"{{"phase":"exec","sandboxId":"{sandbox_id}",
                "process":{{"commandLine":"cmd.exe /c echo marker-before && ping -n 4 127.0.0.1","timeout":120000}}}}"#
        );
        match mxc_sdk::exec_sandbox(&exec, true) {
            Ok(sandbox) => {
                let _ = exec_tx.send(Ok(sandbox));
            }
            Err(e) => {
                let _ = exec_tx.send(Err(format!("exec failed: {e:?}")));
            }
        }
    });

    let sandbox_id = match rx.recv() {
        Ok(Ok(id)) => id,
        Ok(Err(e)) => {
            println!("\nRESULT: FAILED before the measurement could start\n{e}");
            return;
        }
        Err(e) => {
            println!("\nRESULT: FAILED — worker sent nothing: {e:?}");
            return;
        }
    };
    let _teardown = Teardown(sandbox_id);

    let mut sandbox = match exec_rx.recv() {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            println!("\nRESULT: FAILED before the measurement could start\n{e}");
            return;
        }
        Err(e) => {
            println!("\nRESULT: FAILED — worker sent nothing: {e:?}");
            return;
        }
    };

    worker.join().expect("worker thread panicked");
    checkpoint("worker thread has exited; handle now used from main");

    // Every step below is a separate WinRT touch on the escaped handle.
    let stdout = sandbox.take_stdout();
    let reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(mut s) = stdout {
            let _ = s.read_to_end(&mut buf);
        }
        buf
    });

    checkpoint("read stdout on the escaped handle, to EOF");
    let captured = reader.join().unwrap_or_default();
    let text = String::from_utf8_lossy(&captured);
    let marker = text.contains("marker-before");
    println!(
        "    stdout carried the marker: {marker}  ({} bytes)",
        captured.len()
    );

    checkpoint("wait() on the escaped handle");
    let waited = sandbox.wait();
    println!("    wait: {waited:?}");

    match (marker, &waited) {
        (true, Ok(_)) => println!(
            "\nRESULT: HANDLE SURVIVED — output and wait both worked after its thread exited"
        ),
        (false, Ok(_)) => println!(
            "\nRESULT: PARTIAL — wait worked but output written before the thread exited was lost"
        ),
        _ => println!("\nRESULT: HANDLE DIED — the escaped handle failed after its thread exited"),
    }
}
