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

/// Lifecycle metadata for one registered configuration contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContractDescriptor {
    version: ContractVersion,
    status: ContractStatus,
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
}

/// Metadata for every configuration contract currently registered by this
/// crate.
pub const CONTRACTS: &[ContractDescriptor] = &[
    ContractDescriptor {
        version: ContractVersion::V0_6_0Alpha,
        status: ContractStatus::Published,
    },
    ContractDescriptor {
        version: ContractVersion::V0_7_0Alpha,
        status: ContractStatus::Published,
    },
    ContractDescriptor {
        version: ContractVersion::V0_8_0Alpha,
        status: ContractStatus::Development,
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
            assert_eq!(
                version,
                ContractVersion::parse_exact(version.as_str()).unwrap()
            );
        }
    }
}
