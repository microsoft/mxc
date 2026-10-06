// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

pub mod bubblewrap {
    pub mod common;
}

pub mod hyperlight {
    pub mod common;
}

#[cfg(target_os = "windows")]
pub mod isolation_session {
    #[cfg(feature = "isolation_session")]
    pub mod bindings;
    #[cfg(feature = "isolation_session")]
    pub mod common;
}

pub mod lxc {
    pub mod common;
}

#[cfg(any(target_os = "windows", target_os = "linux"))]
pub mod nanvix {
    #[cfg(feature = "microvm")]
    pub mod binaries;
    #[cfg(feature = "microvm")]
    pub mod common;
    #[cfg(feature = "microvm")]
    pub mod runner;
}

#[cfg(target_os = "windows")]
pub mod process_container {
    pub mod common;
}

pub mod seatbelt {
    pub mod common;
}

#[cfg(target_os = "windows")]
pub mod windows_sandbox {
    pub mod common;
    pub mod lifecycle;
}

#[cfg(target_os = "windows")]
pub mod wslc {
    #[cfg(feature = "wslc")]
    pub mod common;
}
