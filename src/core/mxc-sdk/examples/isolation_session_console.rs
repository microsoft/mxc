// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Hosts an interactive terminal inside an isolation session, in-process, from
//! a console application. Takes the same request JSON as `wxc-exec`.
//!
//! # Operator scenarios
//!
//! These have no automated oracle — an operator runs them and judges what they
//! see.
//!
//! ```text
//! cargo run -p mxc-sdk --features isolation_session --example isolation_session_console -- interactive
//! ```
//!
//! | Scenario | What it proves |
//! |---|---|
//! | `interactive` | ConPTY rendering, input, and exit-code propagation (`exit 7` → `Exited(7)`) |
//! | `streaming` | Output arrives progressively, not as a burst at exit |
//! | `resize` | The sandboxed process sees window-size changes live |
//!
//! The driver exits with the workload's exit code.
//!
//! Any other argument is treated as a literal command line.
//!
//! Must run at a real interactive console.

use mxc_sdk::WaitOutcome;

/// Provision mints a real OS account, so an early return or a panic would
/// otherwise leave one behind on the host.
struct Teardown(String);

impl Drop for Teardown {
    fn drop(&mut self) {
        let id = &self.0;
        eprintln!("\n[driver] tearing down…");
        let stop = format!(r#"{{"version":"0.9.0-alpha","phase":"stop","sandboxId":"{id}"}}"#);
        let _ = mxc_sdk::run_state_aware_json(&stop, false, true);
        let deprovision =
            format!(r#"{{"version":"0.9.0-alpha","phase":"deprovision","sandboxId":"{id}"}}"#);
        match mxc_sdk::run_state_aware_json(&deprovision, false, true) {
            Ok(_) => eprintln!("[driver] deprovisioned."),
            Err(e) => eprintln!("[driver] WARNING: deprovision failed, account may leak: {e:?}"),
        }
    }
}

/// The scenarios differ only in command line; what they check is console
/// behaviour, not the SDK surface.
struct Scenario {
    name: &'static str,
    command: &'static str,
    what_to_look_for: &'static str,
}

const SCENARIOS: &[Scenario] = &[
    Scenario {
        name: "interactive",
        command: "powershell.exe -NoLogo",
        what_to_look_for: "The prompt draws and redraws. Colours, cursor movement and \
                           tab-completion behave. Type commands, then `exit 7` — the outcome \
                           printed at the end must be Exited(7).",
    },
    Scenario {
        name: "streaming",
        command: "cmd.exe /c echo line_1 & ping -n 3 127.0.0.1 >nul & echo line_2 & \
                  ping -n 3 127.0.0.1 >nul & echo line_3",
        what_to_look_for: "The three lines must appear ~2s apart as they are produced, NOT \
                           all at once when the process exits.",
    },
    Scenario {
        name: "resize",
        command: "powershell.exe -NoLogo -NoProfile -Command \"while ($true) { \
                  $w = $Host.UI.RawUI.WindowSize.Width; \
                  Write-Host ('{0,-4}' -f $w) -NoNewline; \
                  Write-Host ('.' * [Math]::Max(0, $w - 6) + '|'); \
                  Start-Sleep -Milliseconds 500 }\"",
        what_to_look_for: "A ruler is drawn to the full window width, with the width printed \
                           at the left. RESIZE THE WINDOW while it runs: the ruler must track \
                           the new width. Ctrl-C to finish.",
    },
];

fn usage() -> i32 {
    eprintln!("usage: isolation_session_console [interactive|streaming|resize|<command line>]");
    eprintln!();
    for s in SCENARIOS {
        eprintln!("  {:<12} {}", s.name, s.command);
    }
    eprintln!();
    eprintln!("Anything else is treated as a literal command line to run in the session.");
    2
}

/// Returns the exit code rather than calling `std::process::exit`, which would
/// skip the `Teardown` guard.
fn run() -> i32 {
    let arg = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "interactive".into());
    if arg == "--help" || arg == "-h" {
        return usage();
    }

    let (label, command, guidance) = match SCENARIOS.iter().find(|s| s.name == arg) {
        Some(s) => (s.name, s.command.to_string(), Some(s.what_to_look_for)),
        None => ("custom", arg, None),
    };

    if !mxc_sdk::available_backends()
        .iter()
        .any(|b| b.backend == "isolation_session")
    {
        eprintln!("IsolationSession is not available on this host.");
        return 2;
    }

    let provision = r#"{"version":"0.9.0-alpha","phase":"provision","containment":"isolation_session",
        "network":{"defaultPolicy":"allow","allowLocalNetwork":true}}"#;
    let response = mxc_sdk::run_state_aware_json(provision, false, true).expect("provision");
    // The sandbox id is opaque by contract — carried verbatim, never parsed.
    let sandbox_id = response
        .split(r#""sandboxId":""#)
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .expect("provision returned no sandboxId")
        .to_string();
    let _teardown = Teardown(sandbox_id.clone());
    eprintln!("[driver] provisioned.");

    let start =
        format!(r#"{{"version":"0.9.0-alpha","phase":"start","sandboxId":"{sandbox_id}"}}"#);
    mxc_sdk::run_state_aware_json(&start, false, true).expect("start");
    eprintln!("[driver] started. Scenario: {label}");
    if let Some(g) = guidance {
        eprintln!("[driver] WHAT TO LOOK FOR: {g}");
    }
    eprintln!("[driver] everything below runs inside the isolation session.\n");

    let escaped = command.replace('\\', "\\\\").replace('"', "\\\"");
    let exec = format!(
        r#"{{"version":"0.9.0-alpha","phase":"exec","sandboxId":"{sandbox_id}",
            "process":{{"commandLine":"{escaped}","timeout":3600000}}}}"#
    );

    match mxc_sdk::exec_attached(&exec, true) {
        Ok(outcome) => {
            println!("\n[driver] outcome: {outcome:?}");
            match outcome {
                WaitOutcome::Exited(code) => code,
                WaitOutcome::TimedOut => 1,
            }
        }
        Err(e) => {
            println!("\n[driver] exec failed: {e:?}");
            1
        }
    }
}

fn main() {
    std::process::exit(run())
}
