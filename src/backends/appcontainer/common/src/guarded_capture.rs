// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Dependency-injection boundary for the guarded WPR capture fallback.
//!
//! `appcontainer_common` implements the legacy containment tiers (BaseContainer
//! SBOX, AppContainer + BFS, AppContainer + DACL) that a host without the
//! native V2 PSEC + Learning Mode APIs still needs `captureDenials` on.
//! Elevated WPR capture lives in `plm` (the host's guarded PLM tool), and
//! `appcontainer_common` MUST NOT depend on `plm` directly: `plm` links the
//! Windows ETL decoder (`learning_mode_windows`) and elevation/pipe machinery
//! that is unrelated to this crate's job, and the crate-layering rule
//! (backend-support crates don't cross-depend on one another) forbids it.
//!
//! Instead, this module defines the minimal traits a legacy-tier runner needs
//! to start and stop a guarded WPR capture scoped to its own sandboxed process
//! tree. `mxc_engine` (which already depends on `plm` for the executor
//! binaries' guarded-PLM lifecycle) implements them by adapting
//! `plm::elevated::{start_guarded_session_with_executable, GuardedSession}`,
//! and hands the concrete factory to the dispatcher only when it explicitly
//! opts a request into the fallback (see
//! `dispatcher::dispatch_with_fallback_and_capture` /
//! `dispatcher::spawn_with_fallback_and_capture`) — a runner never picks up
//! guarded capture silently.

use learning_mode_core::{AnalysisResult, ProcessLifetime};

/// A live guarded WPR capture session scoped to one sandboxed process tree.
///
/// Implementations own the elevated PLM child connection. [`stop_analyzed`]
/// asks the guardian to stop the host-wide WPR trace and decode it, returning
/// only the bounded, process-scoped [`AnalysisResult`] — the raw ETL never
/// crosses back into this process, satisfying the "raw host-wide ETL must
/// never cross into SDK output" requirement.
///
/// [`stop_analyzed`]: GuardedCaptureSession::stop_analyzed
pub trait GuardedCaptureSession: Send {
    /// Stops the guarded capture and analyzes it, scoping every accepted
    /// denial event to one of `lifetimes` (an inclusive PID + timestamp
    /// window observed by the sandbox's tracked job object). Returns the
    /// bounded, de-duplicated result.
    ///
    /// # Errors
    ///
    /// Returns a human-readable message if the guardian connection is gone,
    /// the stop/analyze round trip fails, or the guardian reports a decode
    /// error.
    fn stop_analyzed(&mut self, lifetimes: &[ProcessLifetime]) -> Result<AnalysisResult, String>;

}

/// Starts a [`GuardedCaptureSession`] for the calling (unelevated) process.
///
/// Implementations are constructed by a higher layer (`mxc_engine`) that can
/// depend on `plm`; `appcontainer_common` only ever sees the trait object.
pub trait GuardedCaptureFactory: Send + Sync {
    /// Starts a new guarded WPR capture session.
    ///
    /// `owner_pid` is the calling (unelevated) process's own OS process id —
    /// used by the elevated guardian to authenticate the connection — **not**
    /// the sandboxed child's pid, which is not yet known when the guarded
    /// session must start (before the job is assigned a running process).
    ///
    /// # Errors
    ///
    /// Returns a human-readable message on failure (elevation refused,
    /// guardian unreachable, a WPR session is already active, etc.). The
    /// caller must terminate the still-suspended sandboxed child on failure
    /// rather than resume it, so no active trace is ever left behind.
    fn start(&self, owner_pid: u32) -> Result<Box<dyn GuardedCaptureSession>, String>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use learning_mode_core::{AccessType, DeniedResource, ResourceType};

    /// A fake session/factory pair proving both traits are object-safe and
    /// usable behind `dyn` references — the shape the dispatcher stores them
    /// in ([`crate::guarded_capture`] traits are only ever consumed as trait
    /// objects across the `appcontainer_common` / `mxc_engine` boundary).
    struct FakeSession {
        analysis: AnalysisResult,
    }

    impl GuardedCaptureSession for FakeSession {
        fn stop_analyzed(
            &mut self,
            lifetimes: &[ProcessLifetime],
        ) -> Result<AnalysisResult, String> {
            if lifetimes.is_empty() {
                return Err("no tracked process lifetimes".to_string());
            }
            Ok(self.analysis.clone())
        }

    }

    struct FakeFactory;

    impl GuardedCaptureFactory for FakeFactory {
        fn start(&self, owner_pid: u32) -> Result<Box<dyn GuardedCaptureSession>, String> {
            if owner_pid == 0 {
                return Err("owner pid must be non-zero".to_string());
            }
            Ok(Box::new(FakeSession {
                analysis: AnalysisResult::complete(vec![DeniedResource {
                    resource: r"C:\blocked.txt".to_string(),
                    resource_type: ResourceType::File,
                    access_type: AccessType::Read,
                    pid: owner_pid,
                    filetime: 1,
                }]),
            }))
        }
    }

    #[test]
    fn factory_and_session_are_object_safe() {
        let factory: Box<dyn GuardedCaptureFactory> = Box::new(FakeFactory);
        let mut session = factory.start(1234).expect("start should succeed");
        let lifetimes = [ProcessLifetime {
            pid: 1234,
            start_filetime: 0,
            end_filetime: 10,
        }];
        let analysis = session
            .stop_analyzed(&lifetimes)
            .expect("stop_analyzed should succeed");
        assert_eq!(analysis.denials.len(), 1);
    }

    #[test]
    fn factory_rejects_zero_owner_pid() {
        let factory: Box<dyn GuardedCaptureFactory> = Box::new(FakeFactory);
        let error = match factory.start(0) {
            Ok(_) => panic!("owner pid 0 must be rejected"),
            Err(error) => error,
        };
        assert!(error.contains("owner pid"));
    }

}
