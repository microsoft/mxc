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

/// Lifecycle metadata for one registered configuration contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContractDescriptor {
    version: ContractVersion,
    status: ContractStatus,
    schema_id: &'static str,
    schema_path: &'static str,
    typescript_path: Option<&'static str>,
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
}

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
    },
    ContractDescriptor {
        version: ContractVersion::V0_7_0Alpha,
        status: ContractStatus::Published,
        schema_id:
            "https://github.com/microsoft/mxc/schemas/stable/mxc-config.schema.0.7.0-alpha.json",
        schema_path: "schemas/stable/mxc-config.schema.0.7.0-alpha.json",
        typescript_path: None,
    },
    ContractDescriptor {
        version: ContractVersion::V0_8_0Alpha,
        status: ContractStatus::Development,
        schema_id:
            "https://github.com/microsoft/mxc/schemas/dev/mxc-config.schema.0.8.0-alpha.json",
        schema_path: "schemas/dev/mxc-config.schema.0.8.0-alpha.json",
        typescript_path: Some("sdk/node/src/generated/v0_8_0_alpha/wire.ts"),
    },
];

/// Returns the descriptor for a registered contract version.
pub const fn descriptor(version: ContractVersion) -> ContractDescriptor {
    match version {
        ContractVersion::V0_6_0Alpha => CONTRACTS[0],
        ContractVersion::V0_7_0Alpha => CONTRACTS[1],
        ContractVersion::V0_8_0Alpha => CONTRACTS[2],
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
        assert_eq!(versions.len(), 3);
        assert!(versions.contains(&ContractVersion::V0_6_0Alpha));
        assert!(versions.contains(&ContractVersion::V0_7_0Alpha));
        assert!(versions.contains(&ContractVersion::V0_8_0Alpha));
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
                version,
                ContractVersion::parse_exact(version.as_str()).unwrap()
            );
        }
    }

    #[test]
    fn development_artifacts_use_exact_version_paths() {
        let descriptor = descriptor(ContractVersion::V0_8_0Alpha);

        assert_eq!(descriptor.status().as_str(), "development");
        assert!(descriptor.schema_id().contains("0.8.0-alpha"));
        assert!(descriptor.schema_path().contains("0.8.0-alpha"));
        assert!(descriptor
            .typescript_path()
            .is_some_and(|path| path.contains("v0_8_0_alpha")));
    }
}
