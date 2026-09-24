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
