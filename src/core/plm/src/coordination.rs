//! Cross-process coordination primitives shared by `plm.exe` and the
//! `wxc-exec --audit` driver in the `wxc` crate.
//!
//! Round-7 coverage finding #1: the env-var name and the bypass check
//! used to be a string literal in `plm/src/main.rs` and a separate
//! `Command::env("MXC_PLM_AUDIT_SINGLETON_HELD", "1")` literal in
//! `wxc/src/main.rs`. If either drifted from the other, the child
//! `plm.exe` would attempt to re-acquire `Global\Mxc_Plm_Audit` while
//! its parent already held it — instant deadlock — and no test would
//! catch it. This module centralises both the name and the bypass
//! check; the `wxc` crate now depends on `plm` (lib) so they both
//! import the same constant.
//!
//! Round-7 testability finding #3: the bounded "wait for an
//! `AtomicBool` to clear" loop used by both console-control handlers
//! (`dacl_ctrl_handler` in wxc-exec and `plm_ctrl_handler` in
//! plm.exe) used to be inlined inside `unsafe extern "system"`
//! functions — unreachable from tests. Lift it here as a pure free
//! function so both handlers call the same tested implementation.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// Set to `true` while a standalone `plm log` invocation is spawning
/// `wpr -start` and has not yet returned. Read by `plm.exe`'s console-
/// control handler so a Ctrl+C arriving in the spawn window is
/// bounded-waited for, instead of issuing `wpr -cancel` against a
/// not-yet-engaged kernel session and leaking it. Lifted into the
/// shared library (rather than living as a `static` inside
/// `plm/src/main.rs`) so the `log` module can flip it directly
/// without a callback round-trip.
pub static PLM_LOG_START_IN_FLIGHT: AtomicBool = AtomicBool::new(false);

/// Env var set by `wxc-exec --audit` before spawning `plm.exe`. When
/// present, the spawned `plm` binary skips its own singleton mutex
/// acquisition because the outer `wxc-exec` already holds it for the
/// whole audit window. Avoids a deadlock between parent and child on
/// the same `Global\Mxc_Plm_Audit` name.
pub const SINGLETON_HELD_BY_PARENT_ENV: &str = "MXC_PLM_AUDIT_SINGLETON_HELD";

/// True when the env-var set by the audit-driving parent process is
/// present. Extracted from `acquire_singleton_if_needed` so the
/// bypass branch is reachable from unit tests (round-7 coverage #2).
pub fn singleton_bypass_requested() -> bool {
    std::env::var_os(SINGLETON_HELD_BY_PARENT_ENV).is_some()
}

/// Spin until `flag` reads `false`, or `timeout` elapses. Polls every
/// `poll_interval`. Returns `true` if the flag cleared in time,
/// `false` on timeout.
///
/// Used by both `wxc-exec`'s `dacl_ctrl_handler` (waiting for `plm
/// start` to drain before issuing `wpr -cancel`) and `plm.exe`'s
/// `plm_ctrl_handler` (round-7 reliability #1 — same race in the
/// standalone `plm log` flow).
pub fn wait_until_cleared(flag: &AtomicBool, timeout: Duration, poll_interval: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while flag.load(Ordering::SeqCst) {
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(poll_interval);
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    // ---- singleton bypass ------------------------------------------------
    //
    // The env-var lookup is process-global, so multiple tests racing
    // on it would interfere. Serialise them with a module-local mutex.
    // (We can't use `serial_test` without pulling in a new dep, and a
    // bespoke mutex is sufficient for these two tests.)
    use std::sync::Mutex;
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn singleton_bypass_requested_returns_false_when_env_unset() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        // SAFETY: the lock above serializes env mutation within this
        // test binary. Other test binaries can't see this env var
        // (Cargo runs each integration test in its own process), and
        // production callers always inherit it from wxc-exec.
        std::env::remove_var(SINGLETON_HELD_BY_PARENT_ENV);
        assert!(!singleton_bypass_requested());
    }

    #[test]
    fn singleton_bypass_requested_returns_true_when_env_set() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        std::env::set_var(SINGLETON_HELD_BY_PARENT_ENV, "1");
        let observed = singleton_bypass_requested();
        std::env::remove_var(SINGLETON_HELD_BY_PARENT_ENV);
        assert!(observed);
    }

    // Round-7 coverage #1: the bypass also fires for any non-empty
    // value (Windows env "0" is still set), so the parent only needs
    // the env var to be present, not equal to "1". Pin that contract
    // so a future refactor doesn't tighten the check.
    #[test]
    fn singleton_bypass_requested_returns_true_for_any_value() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        std::env::set_var(SINGLETON_HELD_BY_PARENT_ENV, "");
        let observed_empty = singleton_bypass_requested();
        std::env::set_var(SINGLETON_HELD_BY_PARENT_ENV, "0");
        let observed_zero = singleton_bypass_requested();
        std::env::remove_var(SINGLETON_HELD_BY_PARENT_ENV);
        assert!(observed_empty, "empty string should still count as set");
        assert!(observed_zero, "\"0\" should still count as set");
    }

    // ---- wait_until_cleared ---------------------------------------------

    #[test]
    fn wait_until_cleared_returns_true_when_flag_already_false() {
        let flag = AtomicBool::new(false);
        let started = Instant::now();
        assert!(wait_until_cleared(
            &flag,
            Duration::from_secs(5),
            Duration::from_millis(10)
        ));
        // Should be effectively instantaneous (well under the timeout).
        assert!(
            started.elapsed() < Duration::from_millis(500),
            "no-wait path must not sleep"
        );
    }

    #[test]
    fn wait_until_cleared_returns_false_on_timeout() {
        let flag = AtomicBool::new(true);
        let started = Instant::now();
        let result =
            wait_until_cleared(&flag, Duration::from_millis(150), Duration::from_millis(20));
        assert!(!result, "timeout must surface as false");
        // Allow generous CI scheduling slop: must wait at least the
        // timeout, but not wildly longer.
        let elapsed = started.elapsed();
        assert!(
            elapsed >= Duration::from_millis(140),
            "must wait at least the timeout, waited {elapsed:?}"
        );
        assert!(
            elapsed < Duration::from_secs(2),
            "must not vastly exceed the timeout, waited {elapsed:?}"
        );
    }

    #[test]
    fn wait_until_cleared_returns_true_when_flag_clears_mid_wait() {
        let flag = Arc::new(AtomicBool::new(true));
        let writer_flag = Arc::clone(&flag);
        // Clear the flag from a background thread after ~50ms; the
        // wait should observe the change and return true well before
        // the 5s timeout.
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            writer_flag.store(false, Ordering::SeqCst);
        });
        let started = Instant::now();
        let result = wait_until_cleared(&flag, Duration::from_secs(5), Duration::from_millis(10));
        assert!(result, "flag clearing mid-wait must surface as true");
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "must observe the clear well before the timeout"
        );
    }
}
