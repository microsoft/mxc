// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Engine-owned backend registration metadata.
//!
//! Registration classifies authorization independently of contract publication,
//! build features, and host availability. Probing and dispatch stay in their
//! existing engine modules; wire names stay on the shared backend enum.

use crate::mxc_common::models::ContainmentBackend;

/// Whether `available_backends()` has host detection for a backend.
///
/// Declaring this is mandatory, so a new backend cannot reach the enum without
/// someone deciding whether the host probe reports it.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ProbeCoverage {
    /// Reported by `available_backends()` on the listed `target_os` values
    /// whenever its host detection succeeds.
    Detected(&'static [&'static str]),
    /// Never reported, with the reason it has no host detector.
    NotDetected(&'static str),
}

#[derive(Debug)]
pub(crate) struct BackendRegistration {
    pub(crate) backend: ContainmentBackend,
    pub(crate) experimental: bool,
    /// Read by the probe-coverage invariant tests rather than at runtime.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) probe_coverage: ProbeCoverage,
}

static BACKENDS: [BackendRegistration; 10] = [
    BackendRegistration {
        backend: ContainmentBackend::ProcessContainer,
        experimental: false,
        probe_coverage: ProbeCoverage::Detected(&["windows"]),
    },
    BackendRegistration {
        backend: ContainmentBackend::Wslc,
        experimental: false,
        probe_coverage: ProbeCoverage::Detected(&["windows"]),
    },
    BackendRegistration {
        backend: ContainmentBackend::Lxc,
        experimental: false,
        probe_coverage: ProbeCoverage::Detected(&["linux"]),
    },
    BackendRegistration {
        backend: ContainmentBackend::Vm,
        experimental: false,
        probe_coverage: ProbeCoverage::NotDetected(
            "abstract VM intent; resolves to a concrete backend per host, and that backend is \
             detected in its own right",
        ),
    },
    BackendRegistration {
        backend: ContainmentBackend::MicroVm,
        experimental: true,
        probe_coverage: ProbeCoverage::Detected(&["windows"]),
    },
    BackendRegistration {
        backend: ContainmentBackend::Hyperlight,
        experimental: true,
        probe_coverage: ProbeCoverage::Detected(&["windows", "linux"]),
    },
    BackendRegistration {
        backend: ContainmentBackend::WindowsSandbox,
        experimental: true,
        probe_coverage: ProbeCoverage::Detected(&["windows"]),
    },
    BackendRegistration {
        backend: ContainmentBackend::IsolationSession,
        experimental: false,
        probe_coverage: ProbeCoverage::Detected(&["windows"]),
    },
    BackendRegistration {
        backend: ContainmentBackend::Seatbelt,
        experimental: false,
        probe_coverage: ProbeCoverage::Detected(&["macos"]),
    },
    BackendRegistration {
        backend: ContainmentBackend::Bubblewrap,
        experimental: false,
        probe_coverage: ProbeCoverage::Detected(&["linux"]),
    },
];

/// Every registered backend, for callers that must stay exhaustive over them.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn all() -> &'static [BackendRegistration] {
    &BACKENDS
}

/// Canonical wire names held as literals, so renaming one is a deliberate edit
/// rather than a silent consequence of changing `wire_name()`. Shared by the
/// probe and platform-support tests so the two cannot disagree.
#[cfg(test)]
pub(crate) const CANONICAL_BACKEND_NAMES: &[(ContainmentBackend, &str)] = &[
    (ContainmentBackend::ProcessContainer, "processcontainer"),
    (ContainmentBackend::Wslc, "wslc"),
    (ContainmentBackend::Lxc, "lxc"),
    (ContainmentBackend::Vm, "vm"),
    (ContainmentBackend::MicroVm, "microvm"),
    (ContainmentBackend::Hyperlight, "hyperlight"),
    (ContainmentBackend::WindowsSandbox, "windows_sandbox"),
    (ContainmentBackend::IsolationSession, "isolation_session"),
    (ContainmentBackend::Seatbelt, "seatbelt"),
    (ContainmentBackend::Bubblewrap, "bubblewrap"),
];

/// Every canonical backend wire name.
#[cfg(test)]
pub(crate) fn all_containment_names() -> Vec<String> {
    all()
        .iter()
        .map(|entry| entry.backend.wire_name().to_string())
        .collect()
}

/// Wire names of the backends the registry claims the probe detects on the
/// target this build runs on.
#[cfg(test)]
pub(crate) fn detected_on_current_target() -> Vec<&'static str> {
    all()
        .iter()
        .filter(|entry| match &entry.probe_coverage {
            ProbeCoverage::Detected(targets) => targets.contains(&std::env::consts::OS),
            ProbeCoverage::NotDetected(_) => false,
        })
        .map(|entry| entry.backend.wire_name())
        .collect()
}

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

    #[test]
    fn canonical_names_match_the_backend_wire_names() {
        for (backend, expected) in CANONICAL_BACKEND_NAMES {
            assert_eq!(backend.wire_name(), *expected, "{backend:?}");
        }
    }

    /// Fails when a backend is added to the enum without a canonical name,
    /// which would leave it invisible to every name-based probe assertion.
    #[test]
    fn the_canonical_name_table_covers_every_registered_backend() {
        let registered: BTreeSet<_> = BACKENDS
            .iter()
            .map(|entry| entry.backend.wire_name())
            .collect();
        let canonical: BTreeSet<_> = CANONICAL_BACKEND_NAMES
            .iter()
            .map(|(_, name)| *name)
            .collect();
        assert_eq!(registered, canonical);
    }

    #[test]
    fn undetected_backends_explain_why() {
        for entry in all() {
            if let ProbeCoverage::NotDetected(reason) = &entry.probe_coverage {
                assert!(
                    !reason.trim().is_empty(),
                    "{:?} must say why it has no host detector",
                    entry.backend
                );
            }
        }
    }

    /// An empty or unrecognized target list would satisfy the probe-coverage
    /// gate vacuously, so a detected backend must name real targets.
    #[test]
    fn detected_backends_name_supported_targets() {
        for entry in all() {
            if let ProbeCoverage::Detected(targets) = &entry.probe_coverage {
                assert!(
                    !targets.is_empty(),
                    "{:?} is registered as Detected but names no target",
                    entry.backend
                );
                for target in *targets {
                    assert!(
                        ["windows", "linux", "macos"].contains(target),
                        "{:?} names the unknown target {target:?}",
                        entry.backend
                    );
                }
            }
        }
    }
}
