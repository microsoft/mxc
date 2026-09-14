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
    /// Returns the stable lowercase spelling used by generated metadata.
    pub const fn as_str(self) -> &'static str {
        match self {
            ContractStatus::Published => "published",
            ContractStatus::Development => "development",
        }
    }
}

/// Lifecycle and freeze metadata for one registered configuration contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContractDescriptor {
    version: ContractVersion,
    status: ContractStatus,
    schema_id: &'static str,
    schema_path: &'static str,
    typescript_path: Option<&'static str>,
    rust_module: &'static str,
    contract_module_path: &'static str,
    adapter_path: &'static str,
    builder_path: &'static str,
    fixture_path: &'static str,
    schema_sha256: Option<&'static str>,
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

    /// Returns the Rust module identifier assigned to this version.
    pub const fn rust_module(&self) -> &'static str {
        self.rust_module
    }

    /// Returns the repository-relative contract module path.
    pub const fn contract_module_path(&self) -> &'static str {
        self.contract_module_path
    }

    /// Returns the repository-relative adapter path.
    pub const fn adapter_path(&self) -> &'static str {
        self.adapter_path
    }

    /// Returns the repository-relative policy-builder path.
    pub const fn builder_path(&self) -> &'static str {
        self.builder_path
    }

    /// Returns the repository-relative contract fixture path.
    pub const fn fixture_path(&self) -> &'static str {
        self.fixture_path
    }

    /// Returns the normalized SHA-256 digest for a published schema.
    pub const fn schema_sha256(&self) -> Option<&'static str> {
        self.schema_sha256
    }
}

/// Metadata for every registered configuration contract.
///
/// This Rust table is the lifecycle source of truth. JSON registry output is
/// generated from it for CI history comparisons and other non-Rust consumers.
pub const CONTRACTS: &[ContractDescriptor] = &[
    ContractDescriptor {
        version: ContractVersion::V0_6_0Alpha,
        status: ContractStatus::Published,
        schema_id:
            "https://github.com/microsoft/mxc/schemas/stable/mxc-config.schema.0.6.0-alpha.json",
        schema_path: "schemas/stable/mxc-config.schema.0.6.0-alpha.json",
        typescript_path: None,
        rust_module: "v0_6_0_alpha",
        contract_module_path: "src/core/mxc_config_contract/src/published/v0_6_0_alpha",
        adapter_path: "src/core/wxc_common/src/config_contract_adapters/v0_6.rs",
        builder_path: "src/core/mxc_engine/src/policy/exact/v0_6.rs",
        fixture_path: "src/core/mxc_config_contract/tests/v0_6_0_alpha",
        schema_sha256: Some("e6b2ef7b7733f5151cc53a676d6ba48dadc7e9137f61aba50ebfaebbb8297dba"),
    },
    ContractDescriptor {
        version: ContractVersion::V0_7_0Alpha,
        status: ContractStatus::Published,
        schema_id:
            "https://github.com/microsoft/mxc/schemas/stable/mxc-config.schema.0.7.0-alpha.json",
        schema_path: "schemas/stable/mxc-config.schema.0.7.0-alpha.json",
        typescript_path: None,
        rust_module: "v0_7_0_alpha",
        contract_module_path: "src/core/mxc_config_contract/src/published/v0_7_0_alpha",
        adapter_path: "src/core/wxc_common/src/config_contract_adapters/v0_7.rs",
        builder_path: "src/core/mxc_engine/src/policy/exact/v0_7.rs",
        fixture_path: "src/core/mxc_config_contract/tests/v0_7_0_alpha",
        schema_sha256: Some("beae8c5785f0591ba295cb4984665d23d8f5a74ece5c392f279da8c26ecc8672"),
    },
    ContractDescriptor {
        version: ContractVersion::V0_8_0Alpha,
        status: ContractStatus::Published,
        schema_id:
            "https://github.com/microsoft/mxc/schemas/stable/mxc-config.schema.0.8.0-alpha.json",
        schema_path: "schemas/stable/mxc-config.schema.0.8.0-alpha.json",
        typescript_path: None,
        rust_module: "v0_8_0_alpha",
        contract_module_path: "src/core/mxc_config_contract/src/published/v0_8_0_alpha",
        adapter_path: "src/core/wxc_common/src/config_contract_adapters/v0_8.rs",
        builder_path: "src/core/mxc_engine/src/policy/exact/v0_8.rs",
        fixture_path: "src/core/mxc_config_contract/tests/v0_8_0_alpha",
        schema_sha256: Some("0bd1e20f117821edd6b232e6b0aebe4c44101ea7ce07415f141ae81567cc0391"),
    },
    ContractDescriptor {
        version: ContractVersion::V0_9_0Alpha,
        status: ContractStatus::Development,
        schema_id:
            "https://github.com/microsoft/mxc/schemas/dev/mxc-config.schema.0.9.0-alpha.json",
        schema_path: "schemas/dev/mxc-config.schema.0.9.0-alpha.json",
        typescript_path: Some("sdk/node/src/generated/v0_9_0_alpha/wire.ts"),
        rust_module: "v0_9_0_alpha",
        contract_module_path: "src/core/mxc_config_contract/src/dev",
        adapter_path: "src/core/wxc_common/src/config_contract_adapters/dev",
        builder_path: "src/core/mxc_engine/src/policy/exact/v0_9.rs",
        fixture_path: "src/core/mxc_config_contract/tests/v0_9_0_alpha",
        schema_sha256: None,
    },
];

/// Returns the descriptor for a registered contract version.
pub const fn descriptor(version: ContractVersion) -> ContractDescriptor {
    match version {
        ContractVersion::V0_6_0Alpha => CONTRACTS[0],
        ContractVersion::V0_7_0Alpha => CONTRACTS[1],
        ContractVersion::V0_8_0Alpha => CONTRACTS[2],
        ContractVersion::V0_9_0Alpha => CONTRACTS[3],
    }
}

static SUPPORTED_VERSIONS: [ContractVersion; CONTRACTS.len()] = {
    let mut result = [ContractVersion::V0_6_0Alpha; CONTRACTS.len()];
    let mut index = 0;
    while index < CONTRACTS.len() {
        result[index] = CONTRACTS[index].version();
        index += 1;
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
    fn supported_versions_round_trip_through_registry() {
        assert_eq!(supported_versions().len(), CONTRACTS.len());
        for registered in CONTRACTS {
            let version = registered.version();
            assert_eq!(*registered, descriptor(version));
            assert_eq!(
                ContractVersion::parse_exact(version.as_str()),
                Some(version)
            );
        }
    }

    #[test]
    fn published_contracts_have_complete_freeze_metadata() {
        for contract in CONTRACTS
            .iter()
            .filter(|contract| contract.status() == ContractStatus::Published)
        {
            assert!(contract.typescript_path().is_none());
            assert!(contract.schema_sha256().is_some());
            assert!(!contract.contract_module_path().is_empty());
            assert!(!contract.adapter_path().is_empty());
            assert!(!contract.builder_path().is_empty());
            assert!(!contract.fixture_path().is_empty());
        }
    }

    #[test]
    fn exactly_one_contract_is_in_development() {
        let development = CONTRACTS
            .iter()
            .filter(|contract| contract.is_development())
            .collect::<Vec<_>>();
        assert_eq!(development.len(), 1);
        assert_eq!(development[0].version(), ContractVersion::V0_9_0Alpha);
        assert!(development[0].schema_sha256().is_none());
        assert!(development[0].typescript_path().is_some());
    }
}
