// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Decode a sealed learning-mode `.etl` into the captureDenials NDJSON
//! output stream, or dump its raw ETW events for schema discovery.
//!
//! Usage:
//!
//! ```text
//! # Emit the DeniedResource NDJSON stream (0x1E-framed) to stdout:
//! cargo run -p learning_mode_windows --example lm_analyze -- <path-to.etl> --exit-code <code>
//!
//! # Dump every decoded event (id + property name/value pairs):
//! cargo run -p learning_mode_windows --example lm_analyze -- <path-to.etl> --raw
//! ```
//!
//! Exit codes: `0` = decoded; `2` = wrong platform / bad args; `1` = decode
//! failed.

#[cfg(not(target_os = "windows"))]
fn main() {
    eprintln!("lm_analyze is Windows-only");
    std::process::exit(2);
}

#[cfg(target_os = "windows")]
fn main() {
    std::process::exit(windows_impl::run());
}

#[cfg(target_os = "windows")]
mod windows_impl {
    use std::collections::BTreeMap;
    use std::io::Write;
    use std::path::Path;

    use learning_mode_core::{emit, DenialAnalyzer, DenialSummary};
    use learning_mode_windows::{decode_raw_events, EtlDenialAnalyzer};

    pub fn run() -> i32 {
        let args: Vec<String> = std::env::args().skip(1).collect();
        let Some(etl_path) = args.first() else {
            eprintln!("usage: lm_analyze <path-to.etl> [--raw | --exit-code <code>]");
            return 2;
        };
        let raw = args.iter().any(|a| a == "--raw");
        let path = Path::new(etl_path);

        if raw {
            dump_raw(path)
        } else {
            let Some(exit_code) = parse_exit_code(&args) else {
                eprintln!("--exit-code <code> is required unless --raw is used");
                return 2;
            };
            emit_ndjson(path, exit_code)
        }
    }

    fn parse_exit_code(args: &[String]) -> Option<i32> {
        let index = args.iter().position(|arg| arg == "--exit-code")?;
        args.get(index + 1)?.parse().ok()
    }

    /// Decodes denials and writes the 0x1E-framed NDJSON stream to stdout.
    fn emit_ndjson(path: &Path, exit_code: i32) -> i32 {
        let analysis = match EtlDenialAnalyzer.analyze(path) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("analyze failed: {e}");
                return 1;
            }
        };
        let summary = DenialSummary::new(
            exit_code,
            analysis.denials.len(),
            analysis.denied_resources_truncated,
        );
        let stdout = std::io::stdout();
        let mut handle = stdout.lock();
        if let Err(e) = emit::write_stream(&mut handle, &analysis.denials, &summary) {
            eprintln!("write failed: {e}");
            return 1;
        }
        eprintln!(
            "lm_analyze: {} unique denial(s){}",
            analysis.denials.len(),
            if analysis.denied_resources_truncated {
                " (truncated)"
            } else {
                ""
            }
        );
        0
    }

    /// Dumps every decoded event, plus a per-event-id histogram, so the
    /// real provider/ID/field schema can be confirmed against hardware.
    fn dump_raw(path: &Path) -> i32 {
        let events = match decode_raw_events(path) {
            Ok(e) => e,
            Err(e) => {
                eprintln!("decode failed: {e}");
                return 1;
            }
        };

        let mut histogram: BTreeMap<u16, usize> = BTreeMap::new();
        let stdout = std::io::stdout();
        let mut out = stdout.lock();
        for ev in &events {
            *histogram.entry(ev.event_id).or_default() += 1;
            let props: Vec<String> = ev.props.iter().map(|(k, v)| format!("{k}={v}")).collect();
            let _ = writeln!(out, "event {} | {}", ev.event_id, props.join(" | "));
        }
        let _ = writeln!(out, "--- {} event(s) total ---", events.len());
        for (id, count) in &histogram {
            let _ = writeln!(out, "  id {id}: {count}");
        }
        0
    }
}
