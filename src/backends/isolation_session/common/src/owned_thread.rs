// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Makes IsolationSession API calls from a thread of their own.
//!
//! The backend makes every call into the in-proc API through [`call`], so all
//! of them are made from one apartment whatever the caller's thread is in: the
//! thread never initializes COM, so it runs in the process's multi-threaded
//! apartment, which an [`MtaReference`] keeps alive for the call. It makes the
//! call under the [`Impersonation`] it is given, takes on the calling thread's
//! diagnostic sink, and a panic on it resumes on the calling thread.
//!
//! The backend waits for every async call's result through [`wait_for`].

use std::sync::Arc;

use wxc_common::logger::Logger;
use wxc_common::process_util::{OwnedHandle, SendOwnedHandle};

use windows::Win32::Foundation::{ERROR_NO_TOKEN, HANDLE};
use windows::Win32::Security::{
    DuplicateTokenEx, SecurityImpersonation, TokenImpersonation, TOKEN_DUPLICATE, TOKEN_IMPERSONATE,
};
use windows::Win32::System::Threading::{GetCurrentThread, OpenThreadToken, SetThreadToken};
use windows_core::RuntimeType;
use windows_future::IAsyncOperation;

use super::error::{identity_refusal, lifecycle_err, transport_err, IsolationSessionError};
use super::manager::MtaReference;

const THREAD_NAME: &str = "isolation-session-call";

/// The impersonation token [`call`] makes calls under: that of the thread
/// [`Impersonation::of_this_thread`] ran on.
#[derive(Clone)]
pub(super) struct Impersonation {
    /// `None` when that thread was not impersonating: calls are then made as the
    /// process.
    token: Option<Arc<SendOwnedHandle>>,
}

impl Impersonation {
    /// Refused when this thread is impersonating with a token this process
    /// cannot duplicate at `SecurityImpersonation` level.
    pub(super) fn of_this_thread() -> Result<Self, IsolationSessionError> {
        let token = duplicate_thread_token().map_err(identity_refusal)?;
        Ok(Self {
            token: token.map(Arc::new),
        })
    }
}

/// Runs `f` on a thread of its own, under `impersonation`, and returns its
/// result.
///
/// Fails without running `f` when it cannot run there.
pub(super) fn call<T: Send>(
    impersonation: &Impersonation,
    f: impl FnOnce() -> Result<T, IsolationSessionError> + Send,
) -> Result<T, IsolationSessionError> {
    let _mta = MtaReference::acquire()?;
    let sink = Logger::inherit_thread_diagnostic_sink();
    let sink = sink.has_diagnostic_sink().then_some(sink);
    let joined = std::thread::scope(|scope| {
        std::thread::Builder::new()
            .name(THREAD_NAME.to_string())
            .spawn_scoped(scope, move || {
                if let Some(token) = &impersonation.token {
                    // SAFETY: `token` is a live impersonation token; `None`
                    // targets the current thread.
                    unsafe { SetThreadToken(None, Some(token.get())) }.map_err(|e| {
                        lifecycle_err(format!(
                            "could not impersonate on the thread for the IsolationSession \
                             call: {e}"
                        ))
                    })?;
                }
                let _sink = sink.as_ref().map(Logger::install_thread_diagnostic_sink);
                f()
            })
            .map(|thread| thread.join())
    })
    .map_err(|e| {
        lifecycle_err(format!(
            "could not create a thread for the IsolationSession call: {e}"
        ))
    })?;
    joined.unwrap_or_else(|panic| std::panic::resume_unwind(panic))
}

/// Waits for the result of the async API call that returned `started`.
pub(super) fn wait_for<T: RuntimeType>(
    operation: &str,
    started: windows_core::Result<IAsyncOperation<T>>,
) -> Result<T, IsolationSessionError> {
    started
        .map_err(|e| transport_err(operation, "call failed", &e))?
        .join()
        .map_err(|e| transport_err(operation, "wait failed", &e))
}

/// Duplicates the calling thread's impersonation token for another thread to
/// set as its own. `None` when the thread is not impersonating.
fn duplicate_thread_token() -> windows_core::Result<Option<SendOwnedHandle>> {
    let mut token = HANDLE::default();
    // SAFETY: the out-parameter is a valid, writable local.
    let opened = unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_DUPLICATE, true, &mut token) };
    match opened {
        Ok(()) => {}
        Err(e) if e.code() == ERROR_NO_TOKEN.to_hresult() => return Ok(None),
        Err(e) => return Err(e),
    }
    let token = OwnedHandle::new(token);

    let mut duplicate = HANDLE::default();
    // SAFETY: `token` is a live token handle; the out-parameter is a valid,
    // writable local.
    unsafe {
        DuplicateTokenEx(
            token.get(),
            TOKEN_IMPERSONATE,
            None,
            SecurityImpersonation,
            TokenImpersonation,
            &mut duplicate,
        )
    }?;
    let mut duplicate = OwnedHandle::new(duplicate);
    Ok(Some(SendOwnedHandle::take(&mut duplicate)))
}

#[cfg(test)]
mod tests {
    use wxc_common::logger::Mode;

    use windows::Win32::Security::{
        CreateRestrictedToken, CreateWellKnownSid, GetTokenInformation, ImpersonateSelf,
        IsTokenRestricted, RevertToSelf, SecurityIdentification, TokenImpersonationLevel,
        WinWorldSid, CREATE_RESTRICTED_TOKEN_FLAGS, PSID, SECURITY_IMPERSONATION_LEVEL,
        SECURITY_MAX_SID_SIZE, SID_AND_ATTRIBUTES, TOKEN_QUERY,
    };
    use windows::Win32::System::Com::{
        CoGetApartmentType, CoInitializeEx, CoUninitialize, APTTYPE, APTTYPEQUALIFIER,
        APTTYPEQUALIFIER_IMPLICIT_MTA, APTTYPE_MAINSTA, APTTYPE_MTA, APTTYPE_STA,
        COINIT_APARTMENTTHREADED,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    use super::*;
    use crate::error::LifecycleFailure;

    /// A single-threaded apartment on the test thread while it lives.
    struct Sta;

    impl Sta {
        fn enter() -> Self {
            // SAFETY: balanced by `CoUninitialize` in `drop`.
            let hr = unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED) };
            assert!(hr.is_ok(), "CoInitializeEx failed: {hr:?}");
            Self
        }
    }

    impl Drop for Sta {
        fn drop(&mut self) {
            // SAFETY: balances `enter`.
            unsafe { CoUninitialize() };
        }
    }

    /// The test thread impersonating while it lives.
    struct Impersonating;

    impl Impersonating {
        fn process_token(level: SECURITY_IMPERSONATION_LEVEL) -> Self {
            // SAFETY: impersonation of the process token on this thread, ended
            // in `drop`.
            unsafe { ImpersonateSelf(level) }.expect("ImpersonateSelf failed");
            Self
        }

        fn token(token: &OwnedHandle) -> Self {
            // SAFETY: `token` is a live impersonation token; `None` targets the
            // current thread. Ended in `drop`.
            unsafe { SetThreadToken(None, Some(token.get())) }.expect("SetThreadToken failed");
            Self
        }
    }

    impl Drop for Impersonating {
        fn drop(&mut self) {
            // SAFETY: ends the impersonation the constructor began.
            let _ = unsafe { RevertToSelf() };
        }
    }

    /// An impersonation copy of the process token, restricted so that a thread
    /// holding it can be told apart from one running as the process.
    fn restricted_token() -> OwnedHandle {
        let mut process_token = HANDLE::default();
        // SAFETY: the out-parameter is a valid, writable local.
        unsafe {
            OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_DUPLICATE | TOKEN_QUERY,
                &mut process_token,
            )
        }
        .expect("OpenProcessToken failed");
        let process_token = OwnedHandle::new(process_token);

        let mut everyone = [0u8; SECURITY_MAX_SID_SIZE as usize];
        let mut size = everyone.len() as u32;
        // SAFETY: `everyone` is writable for `size` bytes.
        unsafe {
            CreateWellKnownSid(
                WinWorldSid,
                None,
                Some(PSID(everyone.as_mut_ptr().cast())),
                &mut size,
            )
        }
        .expect("CreateWellKnownSid failed");
        let restricting = [SID_AND_ATTRIBUTES {
            Sid: PSID(everyone.as_mut_ptr().cast()),
            Attributes: 0,
        }];

        let mut restricted = HANDLE::default();
        // SAFETY: `process_token` is live, `restricting` points at a valid SID
        // for the call, and the out-parameter is a valid, writable local.
        unsafe {
            CreateRestrictedToken(
                process_token.get(),
                CREATE_RESTRICTED_TOKEN_FLAGS(0),
                None,
                None,
                Some(&restricting),
                &mut restricted,
            )
        }
        .expect("CreateRestrictedToken failed");
        let restricted = OwnedHandle::new(restricted);

        let mut impersonation = HANDLE::default();
        // SAFETY: `restricted` is live; the out-parameter is a valid, writable
        // local.
        unsafe {
            DuplicateTokenEx(
                restricted.get(),
                TOKEN_QUERY | TOKEN_IMPERSONATE,
                None,
                SecurityImpersonation,
                TokenImpersonation,
                &mut impersonation,
            )
        }
        .expect("DuplicateTokenEx failed");
        OwnedHandle::new(impersonation)
    }

    fn apartment() -> (APTTYPE, APTTYPEQUALIFIER) {
        let mut apartment = APTTYPE::default();
        let mut qualifier = APTTYPEQUALIFIER::default();
        // SAFETY: both out-parameters are valid, writable locals.
        unsafe { CoGetApartmentType(&mut apartment, &mut qualifier) }
            .expect("CoGetApartmentType failed");
        (apartment, qualifier)
    }

    /// Whether this thread's impersonation token is restricted, and its level;
    /// `None` when the thread is not impersonating.
    fn thread_token() -> Option<(bool, SECURITY_IMPERSONATION_LEVEL)> {
        let mut token = HANDLE::default();
        // SAFETY: the out-parameter is a valid, writable local.
        unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, true, &mut token) }.ok()?;
        let token = OwnedHandle::new(token);

        // SAFETY: `token` is live.
        let restricted = unsafe { IsTokenRestricted(token.get()) }.is_ok();
        let mut level = SECURITY_IMPERSONATION_LEVEL::default();
        let mut size = 0;
        // SAFETY: `level` is writable for the length passed, and `size` is a
        // valid, writable local.
        unsafe {
            GetTokenInformation(
                token.get(),
                TokenImpersonationLevel,
                Some(std::ptr::from_mut(&mut level).cast()),
                std::mem::size_of::<SECURITY_IMPERSONATION_LEVEL>() as u32,
                &mut size,
            )
        }
        .expect("GetTokenInformation failed");
        Some((restricted, level))
    }

    fn sees_a_sink() -> bool {
        Logger::inherit_thread_diagnostic_sink().has_diagnostic_sink()
    }

    #[test]
    fn calls_from_a_single_threaded_apartment_run_in_the_multi_threaded_one() {
        let _sta = Sta::enter();
        let caller = apartment();
        assert!(
            caller.0 == APTTYPE_STA || caller.0 == APTTYPE_MAINSTA,
            "{caller:?}"
        );

        let implicit_mta = (APTTYPE_MTA, APTTYPEQUALIFIER_IMPLICIT_MTA);
        let impersonation = Impersonation::of_this_thread().unwrap();
        assert_eq!(
            call(&impersonation, || Ok(apartment())).unwrap(),
            implicit_mta
        );
        assert_eq!(
            apartment(),
            caller,
            "the caller's apartment must be untouched"
        );
    }

    #[test]
    fn a_call_runs_under_the_captured_token_at_impersonation_level() {
        let token = restricted_token();
        let _impersonating = Impersonating::token(&token);
        let caller = thread_token();
        assert_eq!(caller, Some((true, SecurityImpersonation)));

        let impersonation = Impersonation::of_this_thread().unwrap();
        assert_eq!(call(&impersonation, || Ok(thread_token())).unwrap(), caller);
        assert_eq!(
            thread_token(),
            caller,
            "the caller's token must be untouched"
        );
    }

    #[test]
    fn a_call_runs_under_the_captured_token_not_the_calling_threads() {
        let impersonation = std::thread::spawn(|| {
            let token = restricted_token();
            let _impersonating = Impersonating::token(&token);
            Impersonation::of_this_thread().unwrap()
        })
        .join()
        .unwrap_or_else(|panic| std::panic::resume_unwind(panic));

        std::thread::spawn(move || {
            let _sta = Sta::enter();
            let _impersonating = Impersonating::process_token(SecurityIdentification);
            assert!(
                Impersonation::of_this_thread().is_err(),
                "this thread's own token must be one that cannot be captured"
            );
            let caller = (apartment(), thread_token());

            assert_eq!(
                call(&impersonation, || Ok((apartment(), thread_token()))).unwrap(),
                (
                    (APTTYPE_MTA, APTTYPEQUALIFIER_IMPLICIT_MTA),
                    Some((true, SecurityImpersonation))
                )
            );
            assert_eq!(
                (apartment(), thread_token()),
                caller,
                "the calling thread must be untouched"
            );
        })
        .join()
        .unwrap_or_else(|panic| std::panic::resume_unwind(panic));
    }

    #[test]
    fn a_caller_that_is_not_impersonating_passes_no_token() {
        assert_eq!(thread_token(), None);

        let impersonation = Impersonation::of_this_thread().unwrap();
        assert_eq!(call(&impersonation, || Ok(thread_token())).unwrap(), None);
    }

    /// An identification-level token is one that cannot be carried onto the
    /// call's thread.
    #[test]
    fn an_uncarriable_token_is_refused() {
        let _impersonating = Impersonating::process_token(SecurityIdentification);

        let refused = Impersonation::of_this_thread().map(|_| ());
        assert!(
            matches!(
                refused,
                Err(IsolationSessionError::Lifecycle(
                    LifecycleFailure::Refused { .. }
                ))
            ),
            "{refused:?}"
        );
    }

    #[test]
    fn a_sink_installed_on_the_caller_is_the_one_the_call_writes_to() {
        let path = std::env::temp_dir().join(format!(
            "isolation-session-owned-thread-{}.log",
            std::process::id()
        ));
        let mut logger = Logger::new(Mode::Buffer);
        logger
            .enable_file_sink(&path)
            .expect("enable_file_sink failed");
        let installed = logger.install_thread_diagnostic_sink();

        let write = |marker: &str| {
            Logger::inherit_thread_diagnostic_sink().log_diagnostic_line(marker);
        };
        let impersonation = Impersonation::of_this_thread().unwrap();
        call(&impersonation, || {
            write("call-marker");
            Ok(())
        })
        .unwrap();

        drop(installed);
        drop(logger);
        let written = std::fs::read_to_string(&path).expect("reading the sink's file failed");
        let _ = std::fs::remove_file(&path);
        assert!(written.contains("call-marker"), "{written}");
    }

    #[test]
    fn a_caller_with_no_sink_passes_none() {
        assert!(!sees_a_sink());

        let impersonation = Impersonation::of_this_thread().unwrap();
        assert!(!call(&impersonation, || Ok(sees_a_sink())).unwrap());
    }

    #[test]
    fn a_panic_during_the_call_resumes_on_the_caller() {
        let caught = std::panic::catch_unwind(|| {
            let impersonation = Impersonation::of_this_thread().unwrap();
            call(&impersonation, || -> Result<(), IsolationSessionError> {
                panic!("inside the call")
            })
        });
        let payload = caught.expect_err("the panic must reach the caller");
        assert_eq!(payload.downcast_ref::<&str>(), Some(&"inside the call"));
    }
}
