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

use learning_mode_core::AnalysisResult;

/// Guarded WPR returns only bounded process-scoped analysis; its raw host-wide
/// ETL cannot be exposed through caller-visible output.
pub const RETAIN_ETL_UNSUPPORTED_MSG: &str =
    "processContainer.captureDenials.retainEtl requires native PSEC/V2 capture; \
     guarded-WPR fallback cannot return the raw host-wide ETL";

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
    /// Duplicates and attaches the caller's sandbox job and still-owned
    /// suspended root process in the elevated guardian. Both values must be
    /// HANDLEs owned by the authenticated unelevated process.
    fn attach_process_tree(
        &mut self,
        job_handle: usize,
        root_process_handle: usize,
    ) -> Result<(), String>;

    /// Stops the owned WPR trace and securely discards its raw ETL without
    /// analysis. Used when job attachment, sandbox launch, or sandbox
    /// termination fails.
    ///
    /// This method must not return, on either success or error, until the
    /// elevated guardian has terminated and released every duplicated sandbox
    /// handle. Runners rely on that guarantee before allowing firewall,
    /// filesystem, and DACL enforcement guards to drop.
    fn discard(&mut self) -> Result<(), String>;

    /// Stops the guarded capture and analyzes it against exact process
    /// generations: the guardian-attested root handle lifetime plus descendants
    /// reconciled from retained handles and job membership accounting.
    ///
    /// # Errors
    ///
    /// Returns a human-readable message if the guardian connection is gone,
    /// the stop/analyze round trip fails, or the guardian reports a decode
    /// error.
    fn stop_analyzed(&mut self) -> Result<AnalysisResult, String>;
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
    /// the sandboxed child's pid. The child identity and lifetime are attested
    /// later from its duplicated process handle; no caller-supplied child PID
    /// or timestamp is trusted.
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
        fn attach_process_tree(
            &mut self,
            job_handle: usize,
            root_process_handle: usize,
        ) -> Result<(), String> {
            if job_handle == 0 || root_process_handle == 0 {
                return Err("handles must be non-zero".to_string());
            }
            Ok(())
        }

        fn discard(&mut self) -> Result<(), String> {
            Ok(())
        }

        fn stop_analyzed(&mut self) -> Result<AnalysisResult, String> {
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
        session
            .attach_process_tree(42, 43)
            .expect("attach_process_tree should succeed");
        let analysis = session
            .stop_analyzed()
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
