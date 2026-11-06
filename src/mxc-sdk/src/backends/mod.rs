// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#[cfg(all(target_os = "windows", feature = "aci"))]
pub mod aci;

pub mod bubblewrap {
    pub mod common;
}

mod w365agents;
pub(crate) use w365agents::{deferred as w365_deferred, Runner as W365AgentsRunner};

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

#[cfg(all(target_os = "windows", target_arch = "x86_64", feature = "microvm"))]
pub mod nvx;

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
