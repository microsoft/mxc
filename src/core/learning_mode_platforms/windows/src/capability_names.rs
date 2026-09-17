// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Capability SID → friendly-name resolution.
//!
//! Brokered-capability denials (see [`crate::extractors`]) identify the
//! denied capability by its *capability SID*, not by name. AppContainer
//! capability SIDs live under the well-known `S-1-15-3-…` domain, and there
//! is no OS reverse API — Windows only exposes `DeriveCapabilitySidsFromName`
//! (name → SID). So resolution splits two ways:
//!
//! - A small set of **legacy** capabilities have short, fixed RIDs
//!   (`S-1-15-3-1` == `internetClient`, `S-1-15-3-3` ==
//!   `privateNetworkClientServer`, …). Those are enumerated in
//!   [`WELL_KNOWN`] and resolve to a human-readable name.
//! - Every **modern / custom** capability SID is derived by hashing the
//!   capability's UTF-16 name into four 32-bit RIDs (`S-1-15-3-w-x-y-z`).
//!   That hash is one-way, so we cannot recover the name — we surface the
//!   SID string verbatim, which is still a stable, greppable identifier a
//!   consumer can map back to a policy entry.
//!
//! Only the friendly name is directly consumable when a host regenerates its
//! sandbox policy, because the policy `capabilities` field is name-based
//! (MXC converts names → SIDs at launch, never the reverse). Resolving the
//! well-known network/library capabilities — the ones MXC actually uses — is
//! therefore what makes a capability denial actionable for config
//! regeneration; the SID fallback is a best-effort diagnostic identifier.
//!
//! [`resolve`] is the single entry point: it maps a canonical SID string to
//! the friendly name when known, otherwise echoes the SID unchanged.

/// Legacy AppContainer capability SIDs with well-known short RIDs, paired
/// with the capability name used in sandbox policy.
///
/// The RID is the single sub-authority following the `S-1-15-3-` prefix.
/// Names match the manifest / `SandboxPolicy` capability identifiers so a
/// consumer can feed a resolved denial straight back into policy.
const WELL_KNOWN: &[(u32, &str)] = &[
    (1, "internetClient"),
    (2, "internetClientServer"),
    (3, "privateNetworkClientServer"),
    (4, "picturesLibrary"),
    (5, "videosLibrary"),
    (6, "musicLibrary"),
    (7, "documentsLibrary"),
    (8, "enterpriseAuthentication"),
    (9, "sharedUserCertificates"),
    (10, "removableStorage"),
    (11, "appointments"),
    (12, "contacts"),
];

/// Resolves a capability SID string to a friendly capability name.
///
/// Accepts a canonical SID string (as produced by the TDH SID decoder, e.g.
/// `S-1-15-3-1`). Returns the well-known capability name when the SID is a
/// legacy `S-1-15-3-<rid>` with a recognised RID; otherwise returns the
/// input SID unchanged (custom capability SIDs are one-way hashes and cannot
/// be reversed). A non-SID input is echoed back untouched.
#[must_use]
pub fn resolve(sid: &str) -> String {
    if let Some(rid) = legacy_capability_rid(sid) {
        if let Some((_, name)) = WELL_KNOWN.iter().find(|(r, _)| *r == rid) {
            return (*name).to_string();
        }
    }
    sid.to_string()
}

/// Returns the single RID of a legacy `S-1-15-3-<rid>` capability SID.
///
/// Returns `None` for anything that is not exactly a three-part
/// `S-1-15-3-<rid>` SID (custom capabilities carry four hashed RIDs and are
/// intentionally excluded).
fn legacy_capability_rid(sid: &str) -> Option<u32> {
    let rest = sid.strip_prefix("S-1-15-3-")?;
    // A legacy capability SID has exactly one sub-authority after the domain
    // prefix; hashed custom SIDs have four, so reject anything with a `-`.
    if rest.contains('-') {
        return None;
    }
    rest.parse::<u32>().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_well_known_legacy_capabilities() {
        assert_eq!(resolve("S-1-15-3-1"), "internetClient");
        assert_eq!(resolve("S-1-15-3-3"), "privateNetworkClientServer");
        assert_eq!(resolve("S-1-15-3-12"), "contacts");
    }

    #[test]
    fn unknown_legacy_rid_echoes_sid() {
        assert_eq!(resolve("S-1-15-3-9999"), "S-1-15-3-9999");
    }

    #[test]
    fn custom_hashed_capability_sid_is_not_reversed() {
        // Four hashed RIDs -> one-way, echoed verbatim.
        let custom = "S-1-15-3-1024-1065365936-1281604716-3511738428-1654721687";
        assert_eq!(resolve(custom), custom);
    }

    #[test]
    fn non_capability_sid_is_passed_through() {
        assert_eq!(resolve("S-1-5-18"), "S-1-5-18");
        assert_eq!(resolve("not-a-sid"), "not-a-sid");
    }
}
