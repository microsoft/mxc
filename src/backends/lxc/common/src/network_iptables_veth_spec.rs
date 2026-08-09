//! Spec for the fail-closed contract of `apply_firewall_rules`: when the
//! firewall cannot be scoped to the container, the caller must be told the
//! policy was not applied rather than being handed a chain that filters
//! nothing.
//!
//! Attached to `network_iptables` as a child module via `#[path]`, so it can
//! reach the `#[cfg(test)]` fake-firewall seam.
