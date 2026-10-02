// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Engine-owned backend registration metadata.
//!
//! Registration classifies authorization independently of contract publication,
//! build features, and host availability. Probing and dispatch stay in their
//! existing engine modules; wire names stay on the shared backend enum.

use wxc_common::models::ContainmentBackend;

#[derive(Debug)]
pub(crate) struct BackendRegistration {
    pub(crate) backend: ContainmentBackend,
    pub(crate) experimental: bool,
}

static BACKENDS: [BackendRegistration; 10] = [
    BackendRegistration {
        backend: ContainmentBackend::ProcessContainer,
        experimental: false,
    },
    BackendRegistration {
        backend: ContainmentBackend::Wslc,
        experimental: false,
    },
    BackendRegistration {
        backend: ContainmentBackend::Lxc,
        experimental: false,
    },
    BackendRegistration {
        backend: ContainmentBackend::Vm,
        experimental: false,
    },
    BackendRegistration {
        backend: ContainmentBackend::MicroVm,
        experimental: true,
    },
    BackendRegistration {
        backend: ContainmentBackend::Hyperlight,
        experimental: true,
    },
    BackendRegistration {
        backend: ContainmentBackend::WindowsSandbox,
        experimental: true,
    },
    BackendRegistration {
        backend: ContainmentBackend::IsolationSession,
        experimental: false,
    },
    BackendRegistration {
        backend: ContainmentBackend::Seatbelt,
        experimental: false,
    },
    BackendRegistration {
        backend: ContainmentBackend::Bubblewrap,
        experimental: false,
    },
];

/// Every new backend must select a registration; there is no implicit default.
pub(crate) fn registration(backend: &ContainmentBackend) -> &'static BackendRegistration {
    let index = match backend {
        ContainmentBackend::ProcessContainer => 0,
        ContainmentBackend::Wslc => 1,
        ContainmentBackend::Lxc => 2,
        ContainmentBackend::Vm => 3,
        ContainmentBackend::MicroVm => 4,
        ContainmentBackend::Hyperlight => 5,
        ContainmentBackend::WindowsSandbox => 6,
        ContainmentBackend::IsolationSession => 7,
        ContainmentBackend::Seatbelt => 8,
        ContainmentBackend::Bubblewrap => 9,
    };
    &BACKENDS[index]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn registrations_have_unique_backend_keys_and_matching_lookups() {
        let mut names = BTreeSet::new();
        for entry in &BACKENDS {
            assert!(names.insert(entry.backend.wire_name()));
            assert!(std::ptr::eq(registration(&entry.backend), entry));
        }
        assert_eq!(names.len(), 10);
    }

    #[test]
    fn registration_preserves_the_experimental_backend_set() {
        let experimental: BTreeSet<_> = BACKENDS
            .iter()
            .filter(|entry| entry.experimental)
            .map(|entry| entry.backend.wire_name())
            .collect();
        assert_eq!(
            experimental,
            BTreeSet::from(["microvm", "hyperlight", "windows_sandbox"])
        );
    }
}
