// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Process-level cleanup so containers don't leak when `lxc-exec` is killed.
//!
//! `LxcScriptRunner::run_internal` calls `container.destroy()` after
//! `attach_run` returns, but if the runner is killed by SIGHUP/SIGTERM/SIGINT
//! (its parent exited or sent a kill) the in-flight `attach_run` is
//! interrupted and the destroy block is never reached. The container then
//! survives the runner and shows up forever in `lxc-ls`.
//!
//! This module installs a watchdog thread that synchronously waits for those
//! signals via `sigwait`, destroys whichever container the runner most
//! recently announced as active, and exits with `128 + signo` so the parent
//! observes a normal signal-style exit.

use std::sync::{Mutex, OnceLock};

#[cfg(target_os = "linux")]
use std::thread;

#[cfg(target_os = "linux")]
use nix::sys::signal::{SigSet, Signal};

#[cfg(target_os = "linux")]
use crate::lxc_bindings::LxcContainer;
use crate::network_iptables::CreatedResources;
#[cfg(target_os = "linux")]
use crate::network_iptables::NetworkIptablesManager;
#[cfg(target_os = "linux")]
use wxc_common::logger::{Logger, Mode};

/// How much of the active sandbox a fatal signal should roll back.
///
/// The one-shot runner and the state-aware lifecycle both install a firewall
/// chain, but they own the container very differently, and rolling back the
/// wrong amount is damaging in both directions. Destroying a provisioned
/// state-aware container would discard a resource its owner expects to survive
/// the process; leaving a one-shot container behind would leak it forever.
#[derive(Default, Clone, Copy, PartialEq, Eq, Debug)]
enum SignalRollback {
    /// One-shot: this process created the container to run a single script, so
    /// a signal takes the firewall and the container with it.
    #[default]
    DestroyContainer,
    /// State-aware: the container is provisioned and deliberately outlives this
    /// process, so a signal removes only the firewall this process installed.
    /// The container is stopped, not destroyed, and left for a later `stop` or
    /// `deprovision` to reclaim.
    NetworkOnly,
    /// State-aware `exec`: the container, its firewall, and its ingress rules
    /// are all meant to survive.  Only the processes this exec started inside
    /// the container are rolled back, because killing this process kills the
    /// host-side attach and nothing else -- the container is persistent, so its
    /// descendants would otherwise run on into the next exec.
    ReapExec,
}

/// One action the watchdog takes on a fatal signal.
///
/// The watchdog is Linux-only, so this is dead code elsewhere. It stays
/// compiled on every target rather than being `cfg`-gated so Windows and macOS
/// CI still type-check and test the ordering.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum RollbackStep {
    /// Halt the container without discarding it.
    StopContainer,
    /// Remove the firewall chain and hooks this process created.
    RemoveFirewall,
    /// Discard the container entirely.
    DestroyContainer,
    /// Kill the processes one exec started inside the container, found by the
    /// marker that exec was stamped with.
    ReapExec,
}

/// The steps a signal rollback runs, in the order they must run.
///
/// Ordering is the whole content of this function, and it differs by rollback
/// kind for a reason.
///
/// A state-aware start installs the chain *before* `lxc-start` so the container
/// is never up without it. The rollback has to preserve that invariant in
/// reverse: `lxc-start` may already have succeeded when the signal lands, so
/// removing the firewall first would leave a running container unfiltered with
/// no process left to notice. Stopping first cannot produce that state.
///
/// The one-shot path runs the same invariant rather than the mirror of it. Its
/// container is going away entirely and `destroy` subsumes stopping it, which
/// once argued for removing the firewall first, while the name is still
/// unambiguous. But `lxc-destroy` can fail, and that order would then have
/// stripped the egress chain off a container that is still up. Destroy runs
/// first and the firewall is removed only once it has succeeded, which is what
/// the ordinary deprovision path already does.
///
/// The inbound rules are different in kind. They live inside the container's
/// own network namespace, reachable only by entering it through the init PID,
/// so they cease to exist when the container does. That is why only the
/// one-shot path removes them, and why it does so before `destroy` -- after
/// that there is no namespace left to enter. The stop path deliberately omits
/// them: the only moment it could remove them is *before* the stop, which is
/// exactly the unfiltered-and-still-running state this ordering exists to
/// prevent, and stopping discards them anyway.
///
/// A process that never created the chain must not remove one: the chain name
/// depends only on the container name, so the name may by now answer for a
/// different, live container.
///
/// The exec rollback shares none of that. Nothing it touches was installed by
/// start, so it removes no firewall and stops no container -- it kills only the
/// processes carrying this exec's marker, which no other owner can be holding.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn rollback_plan(rollback: SignalRollback, owns_firewall: bool) -> Vec<RollbackStep> {
    let mut plan = Vec::new();
    match rollback {
        SignalRollback::ReapExec => {
            plan.push(RollbackStep::ReapExec);
        }
        SignalRollback::NetworkOnly => {
            plan.push(RollbackStep::StopContainer);
            if owns_firewall {
                plan.push(RollbackStep::RemoveFirewall);
            }
        }
        SignalRollback::DestroyContainer => {
            // No ingress step: those rules live inside the container's own
            // netns, so the destroy takes them with it. Running one first would
            // buy nothing when the destroy succeeds and cost real exposure when
            // it fails -- a container left running with its inbound deny
            // already stripped off. The firewall goes last, after the destroy
            // has actually succeeded -- see `execute_rollback`.
            plan.push(RollbackStep::DestroyContainer);
            if owns_firewall {
                plan.push(RollbackStep::RemoveFirewall);
            }
        }
    }
    plan
}

/// Runs `plan`, asking `run_step` to perform each step and report whether it
/// succeeded.
///
/// A failed `StopContainer` abandons the rest of the plan. The steps after it
/// exist to clean up a container that is no longer running, and the only one
/// that follows it is `RemoveFirewall` -- so continuing would strip the egress
/// chain off a container that is still up, which is precisely the state the
/// ordering above exists to prevent. Ordering alone does not achieve that;
/// `lxc-stop` can fail, and then the order it ran in no longer matters.
///
/// A failed `DestroyContainer` abandons the rest for the same reason. The only
/// step that follows it is `RemoveFirewall`, and a destroy that failed may well
/// have left the container running, so continuing would unfilter it.
///
/// Bailing out leaks the chain rather than exposing the container, which is the
/// same trade the ordinary stop path already makes deliberately: it propagates
/// the stop error and leaves the rules in place rather than unfilter a
/// still-running container (`state_aware.rs`, `stop`).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn execute_rollback(plan: &[RollbackStep], run_step: &mut impl FnMut(RollbackStep) -> bool) {
    for &step in plan {
        let ok = run_step(step);
        if !ok
            && matches!(
                step,
                RollbackStep::StopContainer | RollbackStep::DestroyContainer
            )
        {
            return;
        }
    }
}

/// What the watchdog needs to roll back on a fatal signal: the container
/// name (so we can `lxc-destroy` it), the host-side veth interface when
/// known (so we can also remove the iptables FORWARD hook the runner
/// installed against it), the set of egress chains and hooks the runner has
/// actually created so far (so we remove only those), and the container's init
/// PID when known (so we can also remove the container-netns iptables INPUT
/// rules the inbound chain installed inside it, before the container is
/// destroyed).
///
/// All live behind one mutex on purpose. The watchdog takes a single
/// snapshot of the whole struct, so it can never pair one container's
/// identity with another's ownership record.
#[derive(Default)]
struct ActiveSandbox {
    name: Option<String>,
    veth: Option<String>,
    /// Read only by the Linux watchdog, but written on every target.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    rollback: SignalRollback,
    /// Which per-family chains and FORWARD hooks this process created for
    /// `name`, so the watchdog removes only what this process installed.
    ///
    /// The chain name is derived from the container name, so two processes
    /// starting the same sandbox target the same chain and only one of them
    /// creates it. Without this the watchdog would tear the chain down on a
    /// signal no matter which process it interrupted, and interrupting the
    /// loser would strip the firewall off the winner's running container. The
    /// record is published the moment a creating command succeeds, so the
    /// whole window in which the resource exists is covered and no wider.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    created: CreatedResources,
    /// The marker stamped on the exec currently running in `name`, when one is
    /// running, so a signal can reap the processes it started inside the
    /// container.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    exec_marker: Option<String>,
}

static ACTIVE_CONTAINER: OnceLock<Mutex<ActiveSandbox>> = OnceLock::new();
#[cfg(target_os = "linux")]
static INSTALLED: OnceLock<()> = OnceLock::new();

fn lock_slot() -> std::sync::MutexGuard<'static, ActiveSandbox> {
    ACTIVE_CONTAINER
        .get_or_init(|| Mutex::new(ActiveSandbox::default()))
        .lock()
        .unwrap_or_else(|p| p.into_inner())
}

/// Records `name` as the currently active container so the cleanup watchdog
/// can destroy it if a fatal signal arrives. Replaces any previous value
/// (including any previously registered veth and created-resource record,
/// since the new container has not had its veth discovered and has not
/// created anything yet).
pub fn set_active(name: &str) {
    let mut slot = lock_slot();
    slot.name = Some(name.to_owned());
    slot.veth = None;
    slot.rollback = SignalRollback::DestroyContainer;
    slot.created = CreatedResources::default();
    slot.exec_marker = None;
}

/// Records `name` as the currently active container for the *state-aware*
/// lifecycle, where a fatal signal must remove the firewall this process
/// installed but must not destroy the container.
///
/// The state-aware `start` phase installs the chain before the container runs,
/// so a signal in that window would otherwise leave the chain behind with no
/// one to remove it — the watchdog only acts on a registered name, and until
/// now only the one-shot runner ever registered one. Registering with
/// [`set_active`] instead would be worse than leaking: it would destroy a
/// container that was provisioned to outlive this process.
///
/// Call [`clear_active`] once the start has succeeded. Leaving the
/// registration in place past that point would let a later signal strip the
/// firewall off a container that is up and running.
pub fn set_active_network_only(name: &str) {
    let mut slot = lock_slot();
    slot.name = Some(name.to_owned());
    slot.veth = None;
    slot.rollback = SignalRollback::NetworkOnly;
    slot.created = CreatedResources::default();
    slot.exec_marker = None;
}

/// Records the exec running in `name` under `marker`, so a fatal signal reaps
/// the processes it started inside the container.
///
/// The exec phase registered nothing before this. `start` clears the
/// registration once it succeeds -- correctly, since a later signal must not
/// strip the firewall off a running container -- which left the whole exec
/// window uncovered. A signal there killed the host-side `lxc-attach` and
/// returned, while the script's descendants carried on inside a container that
/// is persistent by design and would hand them to the next exec.
///
/// This does not resurrect the start-time registration. Nothing here stops the
/// container or touches its rules; they are all meant to survive the exec, and
/// the marker reaches only what this exec started.
///
/// Call [`clear_active`] as soon as the attach returns.
pub fn set_active_exec(name: &str, marker: &str) {
    let mut slot = lock_slot();
    slot.name = Some(name.to_owned());
    slot.veth = None;
    slot.rollback = SignalRollback::ReapExec;
    slot.created = CreatedResources::default();
    slot.exec_marker = Some(marker.to_owned());
}

/// Records which iptables chains and FORWARD hooks this process created for
/// the active container, so the watchdog removes exactly those on a fatal
/// signal.
///
/// Called by [`crate::network_iptables::NetworkIptablesManager`] the moment a
/// creating command succeeds — the instant the resource starts existing, and
/// not before. Registering a name is deliberately not enough on its own: a
/// process whose `-N` lost the race to a concurrent start of the same sandbox
/// owns nothing, and a signal must not make it delete the winner's chain and
/// leave the winner's container running unfiltered.
///
/// Publication is whole-record rather than incremental: each call supersedes
/// the previous one, so callers pass the complete set they own.
///
/// No-op if no container is currently registered.
pub(crate) fn set_active_created(created: CreatedResources) {
    let mut slot = lock_slot();
    if slot.name.is_some() {
        slot.created = created;
    }
}

/// Unregisters the active sandbox, so a later signal rolls nothing back.
///
/// Used at the end of a successful state-aware start: the chain and the
/// container are both meant to persist from there on, and rolling either back
/// would be the bug rather than the fix.
///
/// Also the mirror of [`set_active_created`] after a successful teardown.
/// Chain names depend only on the container name, so an ownership record left
/// published after a successful teardown would let a later signal run cleanup
/// against a name that by then may answer for a different, live container —
/// stripping its firewall while it runs.
pub fn clear_active() {
    *lock_slot() = ActiveSandbox::default();
}

/// Records the host-side veth interface for the active container so the
/// watchdog can also remove the iptables FORWARD hook on a fatal signal.
/// No-op if no container is currently registered.
pub fn set_active_veth(veth: &str) {
    let mut slot = lock_slot();
    if slot.name.is_some() {
        slot.veth = Some(veth.to_owned());
    }
}

/// Reads back what the watchdog would act on. Test-only: production code has
/// exactly one reader, and it is the watchdog itself.
#[cfg(test)]
fn active_snapshot() -> (Option<String>, Option<String>, CreatedResources) {
    let slot = lock_slot();
    (slot.name.clone(), slot.veth.clone(), slot.created)
}

/// Block SIGHUP/SIGTERM/SIGINT in the calling thread and spawn a watchdog
/// that synchronously waits (`sigwait`) for any of them. On delivery the
/// watchdog destroys the active container, then exits with `128 + signo`.
///
/// MUST be called once, early in `main`, before any other threads are
/// spawned: `pthread_sigmask` only changes the mask of the calling thread,
/// but new threads inherit the mask at creation time. If a thread starts
/// before `install()`, that thread's mask leaves the signals unblocked and
/// the kernel may deliver them there instead of to the watchdog.
#[cfg(target_os = "linux")]
pub fn install() -> Result<(), String> {
    if INSTALLED.get().is_some() {
        return Ok(());
    }
    let mut mask = SigSet::empty();
    mask.add(Signal::SIGHUP);
    mask.add(Signal::SIGTERM);
    mask.add(Signal::SIGINT);
    mask.thread_block()
        .map_err(|e| format!("pthread_sigmask: {}", e))?;

    match thread::Builder::new()
        .name("lxc-signal-cleanup".into())
        .spawn(move || run_watchdog(mask))
    {
        Ok(_) => {
            // Only mark INSTALLED after the watchdog is actually running, so
            // a retry after a transient spawn failure can re-attempt install.
            let _ = INSTALLED.set(());
            Ok(())
        }
        Err(err) => {
            // The watchdog never started, so leaving the signals blocked
            // would make the whole process unkillable by SIGHUP/SIGTERM/SIGINT.
            // Restore the original mask before bubbling up the error.
            let _ = mask.thread_unblock();
            Err(format!("spawn lxc-signal-cleanup thread: {err}"))
        }
    }
}

/// Non-Linux stub. `lxc-exec` is Linux-only at runtime, but the workspace
/// still builds on Windows (clippy CI) and macOS (dev), so the signature
/// has to exist on every target. Signal-driven cleanup is a no-op on
/// non-Linux targets — the watchdog relies on POSIX `sigwait` semantics
/// that aren't meaningful on Windows.
#[cfg(not(target_os = "linux"))]
pub fn install() -> Result<(), String> {
    Ok(())
}

/// Whether a stop attempt left the container safe to unfilter.
///
/// `lxc-stop -k` exits non-zero on a container that is not running, so a kill
/// that reported failure does not on its own mean the container survived. A
/// state that could not be read stays a failure, keeping the filtering in
/// place for a container that might still be transmitting.
///
/// Only the Linux watchdog calls this, but it stays compiled on every target
/// so Windows and macOS CI still type-check and test the decision.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn stop_left_container_down(killed: bool, running_after: Option<bool>) -> bool {
    killed || running_after == Some(false)
}

#[cfg(target_os = "linux")]
fn run_watchdog(mask: SigSet) -> ! {
    loop {
        // sigwait isn't normally interruptible; on the unlikely failure, retry.
        let Ok(sig) = mask.wait() else { continue };
        let active = std::mem::take(&mut *lock_slot());
        if let Some(name) = active.name {
            // Best-effort, with a buffered logger so signal-time output doesn't
            // interleave with whatever else might still be writing to the
            // host's stdio. The order comes from `rollback_plan`, which is
            // where the reasoning about it lives.
            let mut buf_logger = Logger::new(Mode::Buffer);
            let plan = rollback_plan(active.rollback, !active.created.is_empty());
            execute_rollback(&plan, &mut |step| match step {
                RollbackStep::StopContainer => {
                    let container = LxcContainer::new(&name, None);
                    // A signal can land after the firewall is installed and
                    // before the start, where there is nothing to kill.
                    // Reading that as a failed stop strands the chain, which
                    // then blocks every later start of this name.
                    let killed = container.kill().is_ok();
                    stop_left_container_down(killed, container.is_running().ok())
                }
                RollbackStep::RemoveFirewall => {
                    NetworkIptablesManager::force_cleanup(
                        &name,
                        active.veth.as_deref(),
                        active.created,
                        &mut buf_logger,
                    );
                    true
                }
                RollbackStep::DestroyContainer => LxcContainer::new(&name, None).destroy().is_ok(),
                // Without a marker there is nothing to match on, and matching
                // too widely would kill processes this exec never started.
                RollbackStep::ReapExec => {
                    if let Some(marker) = active.exec_marker.as_deref() {
                        let _ = LxcContainer::new(&name, None).reap_marked_processes(marker);
                    }
                    true
                }
            });
        }
        std::process::exit(128 + sig as i32);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Records the steps `execute_rollback` actually ran, failing whichever
    /// steps `failing` names.
    fn run_plan(plan: &[RollbackStep], failing: &[RollbackStep]) -> Vec<RollbackStep> {
        let mut ran = Vec::new();
        execute_rollback(plan, &mut |step| {
            ran.push(step);
            !failing.contains(&step)
        });
        ran
    }

    #[test]
    fn an_exec_rollback_touches_nothing_but_the_exec() {
        // The container, its firewall, and its ingress rules are all meant to
        // survive an exec.  A rollback that stopped the container or removed
        // its rules would turn a cancelled command into a destroyed sandbox.
        assert_eq!(
            rollback_plan(SignalRollback::ReapExec, true),
            vec![RollbackStep::ReapExec],
            "cancelling an exec must not stop the container or remove its rules"
        );
    }

    #[test]
    fn an_exec_rollback_still_reaps_when_this_process_owns_the_firewall() {
        // Ownership of the firewall is a start-phase fact and says nothing
        // about an exec.  The plan must not vary with it.
        assert_eq!(
            rollback_plan(SignalRollback::ReapExec, false),
            rollback_plan(SignalRollback::ReapExec, true),
            "firewall ownership must not change what an exec rollback does"
        );
    }

    #[test]
    fn a_stop_that_failed_does_not_unfilter_the_container_anyway() {
        // Ordering the stop first is not enough on its own: `lxc-stop` can
        // fail, and then removing the firewall next leaves a running container
        // with no egress policy -- the exact state the ordering exists to
        // prevent, reached by a different route. The rollback must abandon the
        // rest of the plan instead.
        //
        // Leaking the chain is the correct trade here, and the ordinary stop
        // path already makes it deliberately: it propagates the stop error and
        // leaves the rules in place rather than unfilter a still-running
        // container (`state_aware.rs`, `stop`).
        let plan = rollback_plan(SignalRollback::NetworkOnly, true);
        assert_eq!(
            run_plan(&plan, &[RollbackStep::StopContainer]),
            vec![RollbackStep::StopContainer],
            "a failed stop must not be followed by removing the firewall"
        );
    }

    #[test]
    fn a_kill_that_failed_on_a_container_already_down_still_clears_the_way() {
        // A signal can land between installing the firewall and starting the
        // container.  `lxc-stop -k` exits non-zero with nothing to kill, and
        // treating that as a failed stop strands the chain -- which then blocks
        // every later start of this name with "its chain already exists".
        assert!(
            stop_left_container_down(false, Some(false)),
            "a container that is already down must not strand its chain"
        );
    }

    #[test]
    fn a_kill_that_failed_on_a_running_container_retains_the_firewall() {
        // This is the case the ordering exists to protect: the container is
        // still transmitting, so its egress rules must stay.
        assert!(
            !stop_left_container_down(false, Some(true)),
            "a still-running container must keep its filtering"
        );
    }

    #[test]
    fn a_container_state_that_could_not_be_read_retains_the_firewall() {
        // An unreadable state is indistinguishable from a running one, and
        // guessing wrong here unfilters a live container.
        assert!(
            !stop_left_container_down(false, None),
            "an unreadable container state must be treated as still running"
        );
    }

    #[test]
    fn a_stop_that_succeeded_still_removes_the_firewall() {
        // The negative control for the test above. Bailing out is only correct
        // when the stop actually failed; a rollback that never removed the
        // firewall would leak the chain on every signal, so "always bail" must
        // not pass.
        let plan = rollback_plan(SignalRollback::NetworkOnly, true);
        assert_eq!(
            run_plan(&plan, &[]),
            vec![RollbackStep::StopContainer, RollbackStep::RemoveFirewall],
            "a successful stop must still be followed by removing the firewall"
        );
    }

    #[test]
    fn a_destroy_that_succeeded_still_removes_the_firewall() {
        // The negative control for the test below. The gate is specific to a
        // step that actually failed; a rollback that never removed the firewall
        // would leak the chain on every signal, so "always bail" must not pass.
        let plan = rollback_plan(SignalRollback::DestroyContainer, true);
        assert_eq!(
            run_plan(&plan, &[]),
            vec![RollbackStep::DestroyContainer, RollbackStep::RemoveFirewall],
            "a destroy rollback must still remove the firewall it created"
        );
    }

    #[test]
    fn a_destroy_that_failed_does_not_unfilter_the_container_anyway() {
        // A failed `lxc-destroy` may well have left the container running, so
        // removing the firewall afterwards would strip egress filtering off a
        // live container with no process left to notice -- the same fail-open
        // the stop path already guards against. Ordering alone does not achieve
        // this: destroy runs first precisely so that its failure is observable
        // before anything unfilters the container.
        let plan = rollback_plan(SignalRollback::DestroyContainer, true);
        assert_eq!(
            run_plan(&plan, &[RollbackStep::DestroyContainer]),
            vec![RollbackStep::DestroyContainer],
            "a failed destroy must not be followed by removing the firewall"
        );
    }

    #[test]
    fn a_state_aware_rollback_stops_the_container_before_unfiltering_it() {
        // The start phase installs the chain before lxc-start so the container
        // is never up without it. A signal can land after lxc-start has already
        // succeeded, so a rollback that removed the firewall first would create
        // exactly the state the ordering exists to prevent -- a running,
        // unfiltered container with no process left to notice. Nothing later
        // repairs it: the watchdog exits the process immediately afterward.
        let plan = rollback_plan(SignalRollback::NetworkOnly, true);
        assert_eq!(
            plan,
            vec![RollbackStep::StopContainer, RollbackStep::RemoveFirewall],
            "a state-aware rollback must stop the container before removing its firewall"
        );

        // The container is provisioned to outlive this process, so the rollback
        // stops it and never destroys it.
        assert!(
            !plan.contains(&RollbackStep::DestroyContainer),
            "a provisioned container must survive a signal"
        );

        // The inbound rules live inside the container netns and are reachable
        // only through its init PID, so the sole moment this plan could remove
        // them is before the stop -- which is the unfiltered-and-still-running
        // state the ordering above exists to prevent. Stopping discards them
        // anyway, so there is nothing to gain for the exposure. No plan removes
        // them for that reason, which is why there is no step left to name.
        assert!(
            !plan.contains(&RollbackStep::StopContainer)
                || plan
                    .iter()
                    .all(|s| !matches!(s, RollbackStep::DestroyContainer)),
            "a stop rollback must not also destroy the container"
        );

        // A process that created no chain must remove none: the name depends
        // only on the container name, so the chain may by now belong to a
        // different live container. The container this process was starting is
        // still stopped, because that start is what is being rolled back.
        assert_eq!(
            rollback_plan(SignalRollback::NetworkOnly, false),
            vec![RollbackStep::StopContainer],
            "a rollback that owns no chain must not remove one"
        );
    }

    #[test]
    fn a_one_shot_rollback_destroys_the_container_before_unfiltering_it() {
        // This container is going away entirely and destroy subsumes stopping
        // it, which once argued for removing the chain first, while the name
        // still unambiguously referred to this container. But `lxc-destroy` can
        // fail, and that order would then have unfiltered a container that is
        // still running.
        //
        // Inbound is not a step at all. Those rules live inside the container's
        // own netns, so the destroy takes them with it: removing them first
        // would change nothing on success and would strip the inbound deny off
        // a still-running container on failure.
        assert_eq!(
            rollback_plan(SignalRollback::DestroyContainer, true),
            vec![RollbackStep::DestroyContainer, RollbackStep::RemoveFirewall],
        );

        // Same ownership rule, and the destroy is unconditional: a one-shot
        // container is this process's to reclaim whether or not a chain was
        // ever created.
        assert_eq!(
            rollback_plan(SignalRollback::DestroyContainer, false),
            vec![RollbackStep::DestroyContainer],
        );
    }

    /// The registration slot is process-global, so these assertions cannot be
    /// split across test functions without racing each other.
    #[test]
    fn registration_records_who_owns_the_container_not_just_its_name() {
        // One-shot: this process made the container, so a signal takes it.
        set_active("box");
        {
            let slot = lock_slot();
            assert_eq!(slot.name.as_deref(), Some("box"));
            assert_eq!(slot.rollback, SignalRollback::DestroyContainer);
        }

        // State-aware: the container is provisioned and must survive a signal,
        // so only the firewall this process installed is rolled back.
        set_active_network_only("provisioned-box");
        {
            let slot = lock_slot();
            assert_eq!(slot.name.as_deref(), Some("provisioned-box"));
            assert_eq!(slot.rollback, SignalRollback::NetworkOnly);
        }

        // A veth discovered later attaches to whichever registration is live.
        set_active_veth("mxcv-abc");
        assert_eq!(lock_slot().veth.as_deref(), Some("mxcv-abc"));

        // Registering a name is not by itself a claim on the firewall chain.
        // The watchdog gates its ownership-blind force_cleanup on this record,
        // so a process whose `iptables -N` lost the race to a concurrent start
        // must not be holding one — otherwise a signal would make the loser
        // delete the winner's chain and leave the winner unfiltered.
        assert!(lock_slot().created.is_empty());

        // The manager publishes it the moment its own creating command succeeds.
        let v4_only = CreatedResources::for_test(true, false, true, false);
        set_active_created(v4_only);
        assert_eq!(lock_slot().created, v4_only);

        // A successful teardown gives the claim back. Without this the record
        // outlives the chain it describes, and since the chain name depends
        // only on the container name, a signal arriving afterwards would run
        // cleanup against a name that may by then answer for a different, live
        // container.
        set_active_network_only("torn-down-box");
        set_active_created(v4_only);
        assert!(!lock_slot().created.is_empty());
        set_active_created(CreatedResources::default());
        assert!(lock_slot().created.is_empty());

        // Giving the claim back is not the same as unregistering: the container
        // is still the active one, so a signal must still roll back whatever
        // else the registration covers.
        assert_eq!(lock_slot().name.as_deref(), Some("torn-down-box"));

        // Re-registering a different container drops the claim with it.
        set_active_network_only("yet-another-box");
        assert!(lock_slot().created.is_empty());
        set_active_created(v4_only);
        assert!(!lock_slot().created.is_empty());
        set_active("one-shot-box");
        assert!(lock_slot().created.is_empty());

        // Clearing leaves nothing to roll back. Without this, a signal after a
        // successful start would strip the firewall off a running container.
        clear_active();
        {
            let slot = lock_slot();
            assert!(slot.name.is_none());
            assert!(slot.veth.is_none());
            assert!(slot.created.is_empty());
        }

        // Neither late registration may resurrect a cleared slot.
        set_active_veth("mxcv-def");
        set_active_created(v4_only);
        {
            let slot = lock_slot();
            assert!(slot.veth.is_none());
            assert!(slot.created.is_empty());
        }

        // Re-registering resets the veth, since the new container has not had
        // one discovered yet.
        set_active_network_only("another-box");
        assert!(lock_slot().veth.is_none());
        clear_active();
    }

    /// `ACTIVE_CONTAINER` is process-global and the test binary runs tests in
    /// parallel, so the whole publication contract is asserted in one test.
    /// Splitting it would let two tests race on the same slot.
    #[test]
    fn the_watchdogs_view_of_a_container_is_built_and_reset_as_a_single_unit() {
        clear_active();

        // Before any container registers, ownership publication is a no-op.
        // Bubblewrap builds the same firewall manager but never registers, so
        // its resources must not become something the watchdog would remove.
        set_active_created(CreatedResources::for_test(true, true, true, true));
        let (name, veth, created) = active_snapshot();
        assert_eq!(name, None, "no container should be registered yet");
        assert_eq!(
            created,
            CreatedResources::default(),
            "ownership published with no registered container must be discarded"
        );
        assert_eq!(veth, None);

        // Registering a container opens the slot.
        set_active("ctr-a");
        set_active_veth("veth-a");
        let v4_chain_only = CreatedResources::for_test(true, false, false, false);
        set_active_created(v4_chain_only);
        assert_eq!(
            active_snapshot(),
            (
                Some("ctr-a".to_owned()),
                Some("veth-a".to_owned()),
                v4_chain_only,
            ),
            "a registered container must see its own identity and ownership"
        );

        // Publication is incremental: each creation site republishes the whole
        // record, so a later publish supersedes an earlier one rather than
        // merging with it.
        let both_chains = CreatedResources::for_test(true, true, false, false);
        set_active_created(both_chains);
        assert_eq!(
            active_snapshot().2,
            both_chains,
            "the most recent publication is what the watchdog must act on"
        );

        // A new container must not inherit the previous one's ownership record.
        // The chain name depends only on the container name, so acting on a
        // stale record can tear down a chain that is still in use.
        set_active("ctr-b");
        assert_eq!(
            active_snapshot(),
            (Some("ctr-b".to_owned()), None, CreatedResources::default()),
            "registering a new container must reset both veth and ownership"
        );

        clear_active();
    }
}
