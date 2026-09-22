// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::ContractVersion;

/// The publication lifecycle state of a configuration contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContractStatus {
    /// An immutable published contract.
    Published,
    /// A mutable development contract.
    Development,
}

impl ContractStatus {
    /// Returns the stable lowercase spelling used by code-generation metadata.
    pub const fn as_str(self) -> &'static str {
        match self {
            ContractStatus::Published => "published",
            ContractStatus::Development => "development",
        }
    }
}

/// One request root exposed by an exact configuration contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContractRequestRoot {
    fixture_directory: &'static str,
    schema_definition: &'static str,
}

impl ContractRequestRoot {
    /// Directory name used by the exact-contract fixture corpus.
    pub const fn fixture_directory(&self) -> &'static str {
        self.fixture_directory
    }

    /// JSON Schema definition dispatched for this request root.
    pub const fn schema_definition(&self) -> &'static str {
        self.schema_definition
    }
}

/// Lifecycle metadata for one registered configuration contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContractDescriptor {
    version: ContractVersion,
    status: ContractStatus,
    schema_id: &'static str,
    schema_path: &'static str,
    typescript_path: Option<&'static str>,
    generates_artifacts: bool,
    request_roots: &'static [ContractRequestRoot],
}

impl ContractDescriptor {
    /// Returns the contract version.
    pub const fn version(&self) -> ContractVersion {
        self.version
    }

    /// Returns the contract's lifecycle status.
    pub const fn status(&self) -> ContractStatus {
        self.status
    }

    /// Returns whether this is a mutable development contract.
    pub const fn is_development(&self) -> bool {
        matches!(self.status, ContractStatus::Development)
    }

    /// Returns the canonical identifier embedded in this contract's schema.
    pub const fn schema_id(&self) -> &'static str {
        self.schema_id
    }

    /// Returns the repository-relative path of this contract's schema.
    pub const fn schema_path(&self) -> &'static str {
        self.schema_path
    }

    /// Returns the repository-relative path of this contract's TypeScript wire
    /// oracle when one is registered.
    pub const fn typescript_path(&self) -> Option<&'static str> {
        self.typescript_path
    }

    /// Returns whether this contract has a renderable exact Rust model whose
    /// schema and TypeScript artifacts are regenerated in CI.
    pub const fn generates_artifacts(&self) -> bool {
        self.generates_artifacts
    }

    /// Returns generated request-root metadata.
    ///
    /// Empty for legacy contracts without a renderable exact Rust model.
    pub const fn request_roots(&self) -> &'static [ContractRequestRoot] {
        self.request_roots
    }
}

const NO_GENERATED_ROOTS: &[ContractRequestRoot] = &[];

const V0_9_ROOTS: &[ContractRequestRoot] = &[
    ContractRequestRoot {
        fixture_directory: "one_shot",
        schema_definition: "OneShotRequest",
    },
    ContractRequestRoot {
        fixture_directory: "isolation_session_provision",
        schema_definition: "IsolationSessionProvisionRequest",
    },
    ContractRequestRoot {
        fixture_directory: "wslc_provision",
        schema_definition: "WslcProvisionRequest",
    },
    ContractRequestRoot {
        fixture_directory: "start",
        schema_definition: "StartRequest",
    },
    ContractRequestRoot {
        fixture_directory: "exec",
        schema_definition: "ExecRequest",
    },
    ContractRequestRoot {
        fixture_directory: "stop",
        schema_definition: "StopRequest",
    },
    ContractRequestRoot {
        fixture_directory: "deprovision",
        schema_definition: "DeprovisionRequest",
    },
];

const V0_10_ROOTS: &[ContractRequestRoot] = &[
    ContractRequestRoot {
        fixture_directory: "one_shot",
        schema_definition: "OneShotRequest",
    },
    ContractRequestRoot {
        fixture_directory: "windows_sandbox_provision",
        schema_definition: "WindowsSandboxProvisionRequest",
    },
    ContractRequestRoot {
        fixture_directory: "isolation_session_provision",
        schema_definition: "IsolationSessionProvisionRequest",
    },
    ContractRequestRoot {
        fixture_directory: "wslc_provision",
        schema_definition: "WslcProvisionRequest",
    },
    ContractRequestRoot {
        fixture_directory: "start",
        schema_definition: "StartRequest",
    },
    ContractRequestRoot {
        fixture_directory: "exec",
        schema_definition: "ExecRequest",
    },
    ContractRequestRoot {
        fixture_directory: "stop",
        schema_definition: "StopRequest",
    },
    ContractRequestRoot {
        fixture_directory: "deprovision",
        schema_definition: "DeprovisionRequest",
    },
];

/// Metadata for every configuration contract currently registered by this
/// crate.
pub const CONTRACTS: &[ContractDescriptor] = &[
    ContractDescriptor {
        version: ContractVersion::V0_6_0Alpha,
        status: ContractStatus::Published,
        schema_id:
            "https://github.com/microsoft/mxc/schemas/stable/mxc-config.schema.0.6.0-alpha.json",
        schema_path: "schemas/stable/mxc-config.schema.0.6.0-alpha.json",
        typescript_path: None,
        generates_artifacts: false,
        request_roots: NO_GENERATED_ROOTS,
    },
    ContractDescriptor {
        version: ContractVersion::V0_7_0Alpha,
        status: ContractStatus::Published,
        schema_id:
            "https://github.com/microsoft/mxc/schemas/stable/mxc-config.schema.0.7.0-alpha.json",
        schema_path: "schemas/stable/mxc-config.schema.0.7.0-alpha.json",
        typescript_path: None,
        generates_artifacts: false,
        request_roots: NO_GENERATED_ROOTS,
    },
    ContractDescriptor {
        version: ContractVersion::V0_8_0Alpha,
        status: ContractStatus::Published,
        schema_id:
            "https://github.com/microsoft/mxc/schemas/stable/mxc-config.schema.0.8.0-alpha.json",
        schema_path: "schemas/stable/mxc-config.schema.0.8.0-alpha.json",
        typescript_path: None,
        generates_artifacts: false,
        request_roots: NO_GENERATED_ROOTS,
    },
    ContractDescriptor {
        version: ContractVersion::V0_9_0Alpha,
        status: ContractStatus::Published,
        schema_id:
            "https://github.com/microsoft/mxc/schemas/stable/mxc-config.schema.0.9.0-alpha.json",
        schema_path: "schemas/stable/mxc-config.schema.0.9.0-alpha.json",
        typescript_path: Some("sdk/node/src/generated/v0_9_0_alpha/wire.ts"),
        generates_artifacts: true,
        request_roots: V0_9_ROOTS,
    },
    ContractDescriptor {
        version: ContractVersion::V0_10_0Alpha,
        status: ContractStatus::Development,
        schema_id:
            "https://github.com/microsoft/mxc/schemas/dev/mxc-config.schema.0.10.0-alpha.json",
        schema_path: "schemas/dev/mxc-config.schema.0.10.0-alpha.json",
        typescript_path: Some("sdk/node/src/generated/v0_10_0_alpha/wire.ts"),
        generates_artifacts: true,
        request_roots: V0_10_ROOTS,
    },
];

/// Returns the descriptor for a registered contract version.
pub const fn descriptor(version: ContractVersion) -> ContractDescriptor {
    match version {
        ContractVersion::V0_6_0Alpha => CONTRACTS[0],
        ContractVersion::V0_7_0Alpha => CONTRACTS[1],
        ContractVersion::V0_8_0Alpha => CONTRACTS[2],
        ContractVersion::V0_9_0Alpha => CONTRACTS[3],
        ContractVersion::V0_10_0Alpha => CONTRACTS[4],
    }
}

static SUPPORTED_VERSIONS: [ContractVersion; CONTRACTS.len()] = {
    let mut result = [ContractVersion::V0_6_0Alpha; CONTRACTS.len()];
    let mut i = 0;
    while i < CONTRACTS.len() {
        result[i] = CONTRACTS[i].version();
        i += 1;
    }
    result
};

/// Returns all registered contract versions in registry order.
pub fn supported_versions() -> &'static [ContractVersion] {
    &SUPPORTED_VERSIONS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_supported_versions() {
        let versions = supported_versions();
        assert_eq!(versions.len(), 5);
        assert!(versions.contains(&ContractVersion::V0_6_0Alpha));
        assert!(versions.contains(&ContractVersion::V0_7_0Alpha));
        assert!(versions.contains(&ContractVersion::V0_8_0Alpha));
        assert!(versions.contains(&ContractVersion::V0_9_0Alpha));
        assert!(versions.contains(&ContractVersion::V0_10_0Alpha));
    }

    #[test]
    fn test_supported_versions_round_trip() {
        for desc in CONTRACTS {
            let version = desc.version();
            let round_trip_desc = descriptor(version);
            assert_eq!(desc.version(), round_trip_desc.version());
            assert_eq!(desc.is_development(), round_trip_desc.is_development());
            assert_eq!(desc.schema_id(), round_trip_desc.schema_id());
            assert_eq!(desc.schema_path(), round_trip_desc.schema_path());
            assert_eq!(desc.typescript_path(), round_trip_desc.typescript_path());
            assert_eq!(
                desc.generates_artifacts(),
                round_trip_desc.generates_artifacts()
            );
            assert_eq!(desc.request_roots(), round_trip_desc.request_roots());
            assert_eq!(
                version,
                ContractVersion::parse_exact(version.as_str()).unwrap()
            );
        }
    }

    #[test]
    fn development_artifacts_use_exact_version_paths() {
        let descriptor = descriptor(ContractVersion::V0_10_0Alpha);

        assert_eq!(descriptor.status().as_str(), "development");
        assert!(descriptor.schema_id().contains("0.10.0-alpha"));
        assert!(descriptor.schema_path().contains("0.10.0-alpha"));
        assert!(descriptor
            .typescript_path()
            .is_some_and(|path| path.contains("v0_10_0_alpha")));
        assert!(descriptor.generates_artifacts());
        assert!(descriptor
            .request_roots()
            .iter()
            .any(|root| root.fixture_directory() == "wslc_provision"));
    }

    #[test]
    fn legacy_contracts_do_not_advertise_generated_request_roots() {
        for version in [
            ContractVersion::V0_6_0Alpha,
            ContractVersion::V0_7_0Alpha,
            ContractVersion::V0_8_0Alpha,
        ] {
            let descriptor = descriptor(version);
            assert!(!descriptor.generates_artifacts());
            assert!(descriptor.request_roots().is_empty(), "{version:?}");
        }
    }
}
