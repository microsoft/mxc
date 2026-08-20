// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::collections::BTreeMap;

use thiserror::Error;

const RESOURCE_PREFIX: &str = "mxc";
const MAX_HINT_LENGTH: usize = 24;
const TOKEN_BYTES: usize = 16;
const TOKEN_HEX_LENGTH: usize = TOKEN_BYTES * 2;

pub const MANAGED_LABEL: &str = "com.microsoft.mxc.managed";
pub const OWNER_TOKEN_LABEL: &str = "com.microsoft.mxc.owner-token";
pub const RESOURCE_KIND_LABEL: &str = "com.microsoft.mxc.resource-kind";

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ResourceError {
    #[error("ownership token must contain exactly 32 lowercase hexadecimal characters")]
    InvalidOwnershipToken,
    #[error("the operating system random number generator is unavailable")]
    RandomUnavailable,
}

/// Unforgeable per-run ownership token used in names, labels, and recovery.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OwnershipToken(String);

impl OwnershipToken {
    /// Generate a fresh 128-bit ownership token.
    pub fn generate() -> Result<Self, ResourceError> {
        let mut bytes = [0u8; TOKEN_BYTES];
        getrandom::getrandom(&mut bytes).map_err(|_| ResourceError::RandomUnavailable)?;
        Ok(Self(
            bytes.iter().map(|byte| format!("{byte:02x}")).collect(),
        ))
    }

    /// Parse a token persisted by a prior MXC process.
    pub fn parse(value: impl Into<String>) -> Result<Self, ResourceError> {
        let value = value.into();
        if value.len() != TOKEN_HEX_LENGTH
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(ResourceError::InvalidOwnershipToken);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Apple resource type covered by ownership verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceKind {
    Container,
    Network,
}

impl ResourceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Container => "container",
            Self::Network => "network",
        }
    }
}

/// Canonical ownership labels attached to every MXC-created Apple resource.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnershipLabels(BTreeMap<String, String>);

impl OwnershipLabels {
    pub fn new(token: &OwnershipToken, kind: ResourceKind) -> Self {
        Self(BTreeMap::from([
            (MANAGED_LABEL.to_string(), "true".to_string()),
            (OWNER_TOKEN_LABEL.to_string(), token.as_str().to_string()),
            (RESOURCE_KIND_LABEL.to_string(), kind.as_str().to_string()),
        ]))
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.0
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_str()))
    }

    /// Verify labels read back from Apple before a destructive operation.
    pub fn matches(&self, actual: &BTreeMap<String, String>) -> bool {
        self.0
            .iter()
            .all(|(key, expected)| actual.get(key) == Some(expected))
    }
}

/// Collision-resistant Apple resource names for one execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceNames {
    pub container: ContainerName,
    pub network: NetworkName,
}

impl ResourceNames {
    pub fn new(container_hint: &str, token: &OwnershipToken) -> Self {
        let hint = sanitize_hint(container_hint);
        let suffix = &token.as_str()[..12];
        let stem = format!("{RESOURCE_PREFIX}-{hint}-{suffix}");
        Self {
            container: ContainerName(stem.clone()),
            network: NetworkName(format!("{stem}-net")),
        }
    }
}

/// Name accepted only where an Apple container identity is required.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerName(String);

impl ContainerName {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Name accepted only where an Apple network identity is required.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkName(String);

impl NetworkName {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Typed identity for an Apple resource.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResourceName {
    Container(ContainerName),
    Network(NetworkName),
}

impl ResourceName {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Container(name) => name.as_str(),
            Self::Network(name) => name.as_str(),
        }
    }

    pub fn kind(&self) -> ResourceKind {
        match self {
            Self::Container(_) => ResourceKind::Container,
            Self::Network(_) => ResourceKind::Network,
        }
    }
}

/// One named resource plus the ownership proof expected before cleanup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedResource {
    pub name: ResourceName,
    pub labels: OwnershipLabels,
}

impl OwnedResource {
    pub fn container(name: ContainerName, token: &OwnershipToken) -> Self {
        Self {
            name: ResourceName::Container(name),
            labels: OwnershipLabels::new(token, ResourceKind::Container),
        }
    }

    pub fn network(name: NetworkName, token: &OwnershipToken) -> Self {
        Self {
            name: ResourceName::Network(name),
            labels: OwnershipLabels::new(token, ResourceKind::Network),
        }
    }
}

fn sanitize_hint(hint: &str) -> String {
    let mut output = String::with_capacity(MAX_HINT_LENGTH);
    let mut previous_dash = false;
    for character in hint.chars() {
        let normalized = character.to_ascii_lowercase();
        let accepted = normalized.is_ascii_alphanumeric();
        if accepted {
            output.push(normalized);
            previous_dash = false;
        } else if !previous_dash && !output.is_empty() {
            output.push('-');
            previous_dash = true;
        }
        if output.len() == MAX_HINT_LENGTH {
            break;
        }
    }
    while output.ends_with('-') {
        output.pop();
    }
    if output.is_empty() {
        "run".to_string()
    } else {
        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn token() -> OwnershipToken {
        OwnershipToken::parse("0123456789abcdef0123456789abcdef").unwrap()
    }

    #[test]
    fn names_are_sanitized_and_share_a_collision_resistant_suffix() {
        let names = ResourceNames::new(" Build Job / PR #42 ", &token());
        assert_eq!(names.container.as_str(), "mxc-build-job-pr-42-0123456789ab");
        assert_eq!(
            names.network.as_str(),
            "mxc-build-job-pr-42-0123456789ab-net"
        );
    }

    #[test]
    fn ownership_labels_require_every_expected_value() {
        let expected = OwnershipLabels::new(&token(), ResourceKind::Container);
        let mut actual = expected
            .iter()
            .map(|(key, value)| (key.to_string(), value.to_string()))
            .collect::<BTreeMap<_, _>>();
        assert!(expected.matches(&actual));

        actual.insert(OWNER_TOKEN_LABEL.to_string(), "foreign".to_string());
        assert!(!expected.matches(&actual));
    }

    #[test]
    fn token_parser_rejects_weak_or_noncanonical_values() {
        for value in [
            "short",
            "0123456789ABCDEF0123456789ABCDEF",
            "0123456789abcdef0123456789abcdeg",
        ] {
            assert!(OwnershipToken::parse(value).is_err());
        }
    }
}
