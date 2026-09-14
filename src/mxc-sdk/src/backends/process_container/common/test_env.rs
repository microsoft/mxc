//! Shared synchronization for tests that mutate process-global probe seams.

pub(crate) use crate::mxc_common::test_env::lock;
use std::sync::MutexGuard;

pub(crate) struct CaptureCapabilityGuard {
    _lock: MutexGuard<'static, ()>,
}

impl CaptureCapabilityGuard {
    pub(crate) fn set(base_container_usable: bool, native_capture_usable: bool) -> Self {
        let guard = lock();
        unsafe {
            std::env::set_var(
                "MXC_FORCE_BC_USABLE",
                if base_container_usable { "1" } else { "0" },
            );
            std::env::set_var(
                "MXC_FORCE_NATIVE_CAPTURE_USABLE",
                if native_capture_usable { "1" } else { "0" },
            );
        }
        Self { _lock: guard }
    }
}

impl Drop for CaptureCapabilityGuard {
    fn drop(&mut self) {
        unsafe {
            std::env::remove_var("MXC_FORCE_BC_USABLE");
            std::env::remove_var("MXC_FORCE_NATIVE_CAPTURE_USABLE");
        }
    }
}
