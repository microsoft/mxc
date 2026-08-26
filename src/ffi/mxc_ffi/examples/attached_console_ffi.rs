// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Drives a full isolation-session lifecycle **across the C ABI** — the surface
//! the C# SDK binds to — ending in an interactive shell attached to this
//! console.
//!
//! What this proves that no test can: that `mxc_state_aware_exec_attached`
//! reaches a real workload and relays it onto the caller's console. That needs
//! the OS-side service and a real terminal, so it has no unattended oracle.
//!
//! ```text
//! cargo run -p mxc_ffi --features isolation_session --example attached_console_ffi -- [<command line>]
//! ```
//!
//! Defaults to `powershell.exe -NoLogo`. Look for what the SDK-level
//! `isolation_session_console` example asks for: the prompt draws and redraws,
//! input works, and `exit 7` comes back as `exit_code: 7`. Running both isolates
//! whether a failure is in the ABI or beneath it.
//! Must run at a real interactive console.

use std::ffi::{CStr, CString};

use mxc_ffi::{
    mxc_error_detail_free, mxc_state_aware, mxc_state_aware_exec_attached,
    mxc_state_aware_result_free, MxcErrorDetail, MxcExecOutcome, MxcStateAwareResult,
};

/// Runs one envelope phase and returns its response JSON.
///
/// Panics on failure: this is an operator driver, and a failed phase means the
/// scenario cannot continue.
fn phase(request: &str) -> String {
    let json = CString::new(request).expect("request holds no interior NUL");
    // A C caller writes `MxcStateAwareResult r = {0};`. Zeroing is the faithful
    // equivalent, and the ABI requires the detail to start empty.
    // SAFETY: every field is a pointer or an integer, for which zero is valid.
    let mut result: MxcStateAwareResult = unsafe { std::mem::zeroed() };

    // SAFETY: valid NUL-terminated request, and `result` is live writable
    // storage holding no detail yet.
    let status = unsafe { mxc_state_aware(json.as_ptr(), 0, 1, &mut result) };
    if status != 0 {
        let message = if result.error.message_utf8.is_null() {
            String::from("(no message)")
        } else {
            // SAFETY: non-null and produced by this crate.
            unsafe { CStr::from_ptr(result.error.message_utf8) }
                .to_string_lossy()
                .into_owned()
        };
        // SAFETY: filled by the call and not yet freed.
        unsafe { mxc_state_aware_result_free(&mut result) };
        panic!("phase failed with status {status}: {message}");
    }

    // SAFETY: success guarantees a non-null response string.
    let response = unsafe { CStr::from_ptr(result.response_json_utf8) }
        .to_string_lossy()
        .into_owned();
    // SAFETY: frees the strings this call allocated; not used afterwards.
    unsafe { mxc_state_aware_result_free(&mut result) };
    response
}

/// Tears the sandbox down across the same ABI. Provision mints a real OS
/// account, so an early return or a panic would otherwise leave one behind.
struct Teardown(String);

impl Drop for Teardown {
    fn drop(&mut self) {
        let id = self.0.clone();
        eprintln!("\n[driver] tearing down…");
        // Best-effort: a failed stop must not prevent the deprovision that
        // releases the account.
        let stop = format!(r#"{{"phase":"stop","sandboxId":"{id}"}}"#);
        let _ = std::panic::catch_unwind(move || phase(&stop));
        let deprovision = format!(r#"{{"phase":"deprovision","sandboxId":"{id}"}}"#);
        match std::panic::catch_unwind(move || phase(&deprovision)) {
            Ok(_) => eprintln!("[driver] deprovisioned."),
            Err(_) => eprintln!("[driver] WARNING: deprovision failed, account may leak"),
        }
    }
}

fn main() {
    let command = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "powershell.exe -NoLogo".into());

    let provisioned = phase(
        r#"{"phase":"provision","containment":"isolation_session",
            "network":{"defaultPolicy":"allow","allowLocalNetwork":true}}"#,
    );
    // The sandbox id is opaque by contract — carried verbatim, never parsed.
    let sandbox_id = provisioned
        .split(r#""sandboxId":""#)
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .map(str::to_string);
    let Some(sandbox_id) = sandbox_id else {
        // Panicking here would strand the account this provision just minted,
        // with no id to reclaim it by, so print the payload a human needs.
        eprintln!("[driver] provision returned no sandboxId; reclaim by hand from: {provisioned}");
        std::process::exit(1);
    };
    let _teardown = Teardown(sandbox_id.clone());
    eprintln!("[driver] provisioned.");

    phase(&format!(
        r#"{{"phase":"start","sandboxId":"{sandbox_id}"}}"#
    ));
    eprintln!("[driver] started. Running: {command}");
    eprintln!("[driver] everything below runs inside the isolation session.\n");

    let escaped = command.replace('\\', "\\\\").replace('"', "\\\"");
    let exec = CString::new(format!(
        r#"{{"phase":"exec","sandboxId":"{sandbox_id}",
            "process":{{"commandLine":"{escaped}","timeout":3600000}}}}"#
    ))
    .expect("request holds no interior NUL");

    let mut outcome = MxcExecOutcome {
        timed_out: -1,
        exit_code: -1,
    };
    // SAFETY: as above — zero is a valid MxcErrorDetail (all-null).
    let mut error: MxcErrorDetail = unsafe { std::mem::zeroed() };
    // SAFETY: valid request string; both out-parameters are live writable
    // storage holding no detail yet. Blocks until the workload exits.
    let status =
        unsafe { mxc_state_aware_exec_attached(exec.as_ptr(), 1, &mut outcome, &mut error) };

    if status == 0 {
        println!(
            "\n[driver] status: 0, timed_out: {}, exit_code: {}",
            outcome.timed_out, outcome.exit_code
        );
    } else {
        let message = if error.message_utf8.is_null() {
            String::from("(no message)")
        } else {
            // SAFETY: non-null and produced by this crate.
            unsafe { CStr::from_ptr(error.message_utf8) }
                .to_string_lossy()
                .into_owned()
        };
        println!("\n[driver] status: {status}, error: {message}");
        // SAFETY: filled by the call and not yet freed.
        unsafe { mxc_error_detail_free(&mut error) };
    }
}
