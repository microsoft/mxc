// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Process mitigation policy values for use with
//! `PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY` on `UpdateProcThreadAttribute`.
//!
//! The attribute identifier itself is available from the `windows` crate as
//! [`windows::Win32::System::Threading::PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY`].
//! Call sites cast it to `usize` because `UpdateProcThreadAttribute`'s
//! `dwAttribute` parameter is `DWORD_PTR`.
//!
//! The Win32k-syscall-disable mitigation flag below is documented in
//! `winnt.h` but is not generated into the `windows` crate metadata, so it
//! lives here. If a future `windows` crate release adds it, the local
//! constant and helper become redundant and this module can be deleted.
//! These mitigations are applied by the kernel before the child's first
//! user-mode instruction runs, so there is no race window. The
//! parent-applied attribute path (this module) is the documented
//! equivalent of the OS-internal `AIC_AGENTIC_LAUNCH_WIN32K_SYSTEM_CALL_DISABLED`
//! flag used by the BaseContainer SandboxSpec path.

/// `PROCESS_CREATION_MITIGATION_POLICY_WIN32K_SYSTEM_CALL_DISABLE_ALWAYS_ON`
/// from `winnt.h`. When set on the mitigation `DWORD64`, the child cannot
/// make Win32k syscalls.
pub const PROCESS_CREATION_MITIGATION_POLICY_WIN32K_SYSTEM_CALL_DISABLE_ALWAYS_ON: u64 =
    0x1u64 << 28;

/// Returns the mitigation `DWORD64` value that disables Win32k syscalls.
///
/// Pass this through `UpdateProcThreadAttribute` with attribute
/// `windows::Win32::System::Threading::PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY`
/// (cast to `usize`). Combine with other mitigation flags via
/// bitwise-OR if/when more are added.
#[inline]
pub fn win32k_disable_value() -> u64 {
    PROCESS_CREATION_MITIGATION_POLICY_WIN32K_SYSTEM_CALL_DISABLE_ALWAYS_ON
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn win32k_disable_bit_position() {
        // PROCESS_CREATION_MITIGATION_POLICY_WIN32K_SYSTEM_CALL_DISABLE_ALWAYS_ON
        // is documented as "(0x00000001 << 28)" in winnt.h.
        assert_eq!(
            PROCESS_CREATION_MITIGATION_POLICY_WIN32K_SYSTEM_CALL_DISABLE_ALWAYS_ON,
            1u64 << 28
        );
        assert_eq!(win32k_disable_value(), 1u64 << 28);
    }
}
