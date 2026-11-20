// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::process::Child;
use std::thread;
use std::time::{Duration, Instant};

use crate::bwrap_common::proxy_network::{has_exited_unreaped, STARTUP_TIMEOUT};

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
    };
    let empty = |name: &str| -> Result<bool, String> {
        let value = field(name).ok_or_else(|| {
            format!("Bubblewrap: the sandbox's process status has no {name} field")
        })?;
        u64::from_str_radix(value, 16)
            .map(|mask| mask == 0)
            .map_err(|error| format!("Bubblewrap: unreadable {name} value '{value}': {error}"))
    };

    for name in ["CapInh", "CapPrm", "CapEff"] {
        if !empty(name)? {
            return Ok(false);
        }
    }

    // Kernels before 4.3 have no ambient set.
    if field("CapAmb").is_some() && !empty("CapAmb")? {
        return Ok(false);
    }

    // Bubblewrap clears CapBnd only up to the newest capability it knows, and
    // no-new-privileges keeps exec from granting the rest. Kernels before 4.10
    // do not report NoNewPrivs.
    match field("NoNewPrivs") {
        Some(value) => Ok(value == "1"),
        None => empty("CapBnd"),
    }
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
    fn a_held_capability_or_unset_no_new_privileges_is_not_dropped() {
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
    fn without_no_new_privileges_the_bounding_set_must_be_empty() {
        let old_kernel = DROPPED
            .replace("CapAmb:\t0000000000000000\n", "")
            .replace("NoNewPrivs:\t1\n", "");
        assert_eq!(capabilities_dropped(&old_kernel), Ok(false));
        assert_eq!(
            capabilities_dropped(&old_kernel.replace("0000010000000000", "0000000000000000")),
            Ok(true)
        );
    }

    #[test]
    fn a_status_without_a_checked_field_is_rejected() {
        let error = capabilities_dropped(&DROPPED.replace("CapPrm:\t0000000000000000\n", ""))
            .expect_err("a status without CapPrm must not pass");
        assert!(error.contains("CapPrm"), "{error}");
    }
}
