// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::process::Child;
use std::thread;
use std::time::{Duration, Instant};

use crate::bwrap_common::proxy_network::{has_exited_unreaped, STARTUP_TIMEOUT};

// CapBnd can stay non-empty: Bubblewrap clears it only up to the newest
// capability it was built with, and no-new-privileges keeps exec from granting the rest.
const EMPTY_SETS: [&str; 4] = ["CapInh", "CapPrm", "CapEff", "CapAmb"];

pub(crate) fn wait_for_capability_drop(child_pid: u32, launcher: &Child) -> Result<(), String> {
    let path = format!("/proc/{child_pid}/status");
    let deadline = Instant::now() + STARTUP_TIMEOUT;
    loop {
        let status = std::fs::read_to_string(&path).map_err(|error| {
            format!("Bubblewrap: could not read the sandbox's capabilities from {path}: {error}")
        })?;
        if capabilities_dropped(&status)? {
            return Ok(());
        }
        if has_exited_unreaped(launcher.id())
            .map_err(|error| format!("Bubblewrap: failed to inspect bwrap startup: {error}"))?
        {
            return Err("Bubblewrap: bwrap exited during sandbox setup".into());
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "Bubblewrap: the sandbox still held capabilities {}s after startup ({}), so the \
                 workload was not started. Bubblewrap ignores a refused capability drop when run \
                 as root; check whether the host's seccomp or security policy blocks capset or \
                 PR_CAPBSET_DROP",
                STARTUP_TIMEOUT.as_secs(),
                capability_summary(&status),
            ));
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn capabilities_dropped(status: &str) -> Result<bool, String> {
    let field = |name: &str| {
        status
            .lines()
            .find_map(|line| line.strip_prefix(name)?.strip_prefix(':'))
            .map(str::trim)
            .ok_or_else(|| format!("Bubblewrap: the sandbox's process status has no {name} field"))
    };
    for name in EMPTY_SETS {
        let value = field(name)?;
        let mask = u64::from_str_radix(value, 16)
            .map_err(|error| format!("Bubblewrap: unreadable {name} value '{value}': {error}"))?;
        if mask != 0 {
            return Ok(false);
        }
    }
    Ok(field("NoNewPrivs")? == "1")
}

fn capability_summary(status: &str) -> String {
    status
        .lines()
        .filter(|line| line.starts_with("Cap") || line.starts_with("NoNewPrivs"))
        .map(|line| line.split_whitespace().collect::<Vec<_>>().join(" "))
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    const DROPPED: &str = "Name:\tsh\nCapInh:\t0000000000000000\nCapPrm:\t0000000000000000\n\
        CapEff:\t0000000000000000\nCapBnd:\t0000010000000000\nCapAmb:\t0000000000000000\n\
        NoNewPrivs:\t1\n";

    #[test]
    fn empty_sets_with_no_new_privileges_count_as_dropped() {
        assert_eq!(capabilities_dropped(DROPPED), Ok(true));
    }

    #[test]
    fn a_held_capability_or_missing_no_new_privileges_is_not_dropped() {
        for (from, to) in [
            ("CapInh:\t0000000000000000", "CapInh:\t0000000000000400"),
            ("CapPrm:\t0000000000000000", "CapPrm:\t000001ffffffffff"),
            ("CapAmb:\t0000000000000000", "CapAmb:\t0000000000002000"),
            ("NoNewPrivs:\t1", "NoNewPrivs:\t0"),
        ] {
            assert_eq!(
                capabilities_dropped(&DROPPED.replace(from, to)),
                Ok(false),
                "{to}"
            );
        }
    }

    #[test]
    fn a_status_without_a_checked_field_is_rejected() {
        let error = capabilities_dropped(&DROPPED.replace("CapAmb:\t0000000000000000\n", ""))
            .expect_err("a status without CapAmb must not pass");
        assert!(error.contains("CapAmb"), "{error}");
    }
}
