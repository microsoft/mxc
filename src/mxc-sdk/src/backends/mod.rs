// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

pub mod bubblewrap {
    pub mod common;
}

pub mod hyperlight {
    pub mod common;
}

pub mod isolation_session {
    #[cfg(all(target_os = "windows", feature = "isolation_session"))]
    pub mod bindings;
    #[cfg(all(target_os = "windows", feature = "isolation_session"))]
    pub mod common;
}

pub mod lxc {
    pub mod common;
}

pub mod nanvix {
    #[cfg(feature = "microvm")]
    pub mod binaries;
    #[cfg(feature = "microvm")]
    pub mod common;
    #[cfg(feature = "microvm")]
    pub mod runner;
}

pub mod process_container {
    pub mod common;
}

pub mod seatbelt {
    pub mod common;
}

pub mod windows_sandbox {
    pub mod common;
    pub mod lifecycle;
}

pub mod wslc {
    #[cfg(all(target_os = "windows", feature = "wslc"))]
    pub mod common;
}
