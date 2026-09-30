// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Native V1 policy-result layout and bounded conversion into owned diagnostics.

use wxc_common::policy_enforcement::{NativePolicyDetail, NativePolicyResult, PolicyResultCode};

pub(crate) const MAX_DETAILS: usize = 64;
pub(crate) const MAX_RESOURCE_CHARS: usize = 32_768;
#[cfg(test)]
pub(crate) const HAS_ACTIONABLE_DETAILS: u32 = 0x1;
pub(crate) const RESOURCE_COMPLETE: u32 = 0x2;
pub(crate) const BUFFER_TOO_SMALL: u32 = 0x4;
pub(crate) const RESOURCE_UNAVAILABLE: u32 = 0x8;

/// Recognized V1 discriminators; raw fields remain u32 to preserve unknown values.
pub(crate) mod codes {
    pub(crate) mod outcome {
        pub const UNKNOWN: u32 = 0;
        pub const NO_APPLICABLE_POLICY: u32 = 1;
        pub const PASSED: u32 = 2;
        pub const BLOCKED: u32 = 3;
        pub const EVALUATION_FAILED: u32 = 4;
    }
    pub(crate) mod class {
        pub const NONE: u32 = 0;
        pub const NETWORK: u32 = 1;
        pub const FILESYSTEM: u32 = 2;
        pub const ENFORCEMENT_MODE: u32 = 3;
        pub const UI: u32 = 4;
        pub const WIN32K: u32 = 5;
    }
    pub(crate) mod reason {
        pub const NONE: u32 = 0;
        pub const CAPABILITY_NOT_ALLOWED: u32 = 1;
        pub const ACCESS_EXCEEDS_CEILING: u32 = 2;
        pub const DENY_REQUIRED: u32 = 3;
        pub const UI_RESTRICTIONS_REQUIRED: u32 = 4;
        pub const WIN32K_REQUIRED: u32 = 5;
        pub const REQUEST_PATH_LIMIT: u32 = 6;
    }
    pub(crate) mod action {
        pub const NONE: u32 = 0;
        pub const REMOVE_CAPABILITY: u32 = 1;
        pub const RESTRICT_FILESYSTEM_ACCESS: u32 = 2;
        pub const APPLY_UI_RESTRICTIONS: u32 = 3;
        pub const ENABLE_WIN32K_LOCKDOWN: u32 = 4;
        pub const REDUCE_PATH_COUNT: u32 = 5;
    }
    pub(crate) mod resource {
        pub const NONE: u32 = 0;
        pub const PATH: u32 = 1;
        pub const CAPABILITY: u32 = 2;
    }
    pub(crate) mod value {
        pub const NONE: u32 = 0;
        pub const ACCESS: u32 = 1;
        pub const BITMASK: u32 = 2;
        pub const BOOLEAN: u32 = 3;
        pub const PATH_COUNT: u32 = 4;
    }
}

use codes::{action, class, outcome, reason, resource, value};

/// Match PROCESS_SECURITY_ENVIRONMENT_POLICY_DETAIL's frozen V1 array stride.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct RawPolicyDetail {
    pub failure_class: u32,
    pub failure_reason: u32,
    pub required_action: u32,
    pub resource_kind: u32,
    pub value_kind: u32,
    pub flags: u32,
    pub requested_value: u64,
    pub required_value: u64,
    pub resource_offset_chars: u32,
    pub resource_chars_written: u32,
    pub resource_chars_required: u32,
}

/// Match the current PROCESS_SECURITY_ENVIRONMENT_POLICY_RESULT V1 header.
#[repr(C)]
#[derive(Debug)]
pub(crate) struct RawPolicyResult {
    pub size: u32,
    pub version: u32,
    pub details: *mut RawPolicyDetail,
    pub resource_buffer: *mut u16,
    pub details_capacity: u32,
    pub resource_capacity_chars: u32,
    pub outcome: u32,
    pub details_count: u32,
    pub resource_chars_written: u32,
    pub resource_chars_required: u32,
}

fn code(value: u32, names: &[(u32, &str)]) -> PolicyResultCode {
    PolicyResultCode::new(
        value,
        names
            .iter()
            .find_map(|(code, name)| (*code == value).then_some(*name)),
    )
}

impl RawPolicyResult {
    pub fn new(details: &mut [RawPolicyDetail], storage: &mut [u16]) -> Self {
        Self {
            size: std::mem::size_of::<Self>() as u32,
            version: 1,
            details: details.as_mut_ptr(),
            resource_buffer: storage.as_mut_ptr(),
            details_capacity: details.len() as u32,
            resource_capacity_chars: storage.len() as u32,
            outcome: 0,
            details_count: 0,
            resource_chars_written: 0,
            resource_chars_required: 0,
        }
    }

    pub fn to_owned(
        &self,
        details: &[RawPolicyDetail],
        storage: &[u16],
    ) -> (NativePolicyResult, Option<&'static str>) {
        let mut result = NativePolicyResult {
            version: self.version,
            outcome: code(
                self.outcome,
                &[
                    (outcome::UNKNOWN, "unknown"),
                    (outcome::NO_APPLICABLE_POLICY, "noApplicablePolicy"),
                    (outcome::PASSED, "passed"),
                    (outcome::BLOCKED, "blocked"),
                    (outcome::EVALUATION_FAILED, "evaluationFailed"),
                ],
            ),
            details: Vec::new(),
            details_capacity: self.details_capacity,
            details_count: self.details_count,
            resource_capacity_chars: self.resource_capacity_chars,
            resource_chars_written: self.resource_chars_written,
            resource_chars_required: self.resource_chars_required,
        };
        if let Err(error) = self.validate_details(details) {
            return (result, Some(error));
        }
        let pool = self.validate_pool(storage);
        let mut error = pool.as_ref().err().copied();
        if error.is_none()
            && matches!(
                self.outcome,
                outcome::NO_APPLICABLE_POLICY | outcome::PASSED
            )
            && self.details_count != 0
        {
            error = Some("native policy result returned constraints after successful evaluation");
        }
        for detail in &details[..self.details_count as usize] {
            let (owned, invalid) = if pool.is_ok() {
                (*detail).to_owned(&storage[..self.resource_chars_written as usize])
            } else {
                (detail.fixed(), None)
            };
            result.details.push(owned);
            if error.is_none() {
                error = invalid;
            }
        }
        (result, error)
    }

    fn validate_details(&self, details: &[RawPolicyDetail]) -> Result<(), &'static str> {
        if self.size != std::mem::size_of::<Self>() as u32 || self.version != 1 {
            return Err("native policy result changed the V1 header");
        }
        if self.details.cast_const() != details.as_ptr()
            || self.details_capacity as usize != details.len()
            || details.len() > MAX_DETAILS
            || self.details_count as usize > details.len()
        {
            return Err("native policy result changed or exceeded the caller's detail storage");
        }
        Ok(())
    }

    fn validate_pool(&self, storage: &[u16]) -> Result<(), &'static str> {
        if self.resource_buffer.cast_const() != storage.as_ptr()
            || self.resource_capacity_chars as usize != storage.len()
            || storage.len() > MAX_RESOURCE_CHARS
        {
            return Err("native policy result changed the caller's array storage");
        }
        if self.resource_chars_written as usize > storage.len()
            || self.resource_chars_required as usize > MAX_RESOURCE_CHARS
            || self.resource_chars_written > self.resource_chars_required
            || (self.details_count == 0
                && (self.resource_chars_written != 0 || self.resource_chars_required != 0))
        {
            return Err("native policy result has out-of-range array or resource counts");
        }
        Ok(())
    }
}

impl RawPolicyDetail {
    fn fixed(self) -> NativePolicyDetail {
        NativePolicyDetail {
            failure_class: code(
                self.failure_class,
                &[
                    (class::NONE, "none"),
                    (class::NETWORK, "network"),
                    (class::FILESYSTEM, "filesystem"),
                    (class::ENFORCEMENT_MODE, "enforcementMode"),
                    (class::UI, "ui"),
                    (class::WIN32K, "win32k"),
                ],
            ),
            failure_reason: code(
                self.failure_reason,
                &[
                    (reason::NONE, "none"),
                    (reason::CAPABILITY_NOT_ALLOWED, "capabilityNotAllowed"),
                    (reason::ACCESS_EXCEEDS_CEILING, "accessExceedsCeiling"),
                    (reason::DENY_REQUIRED, "denyRequired"),
                    (reason::UI_RESTRICTIONS_REQUIRED, "uiRestrictionsRequired"),
                    (reason::WIN32K_REQUIRED, "win32kRequired"),
                    (reason::REQUEST_PATH_LIMIT, "requestPathLimit"),
                ],
            ),
            required_action: code(
                self.required_action,
                &[
                    (action::NONE, "none"),
                    (action::REMOVE_CAPABILITY, "removeCapability"),
                    (
                        action::RESTRICT_FILESYSTEM_ACCESS,
                        "restrictFilesystemAccess",
                    ),
                    (action::APPLY_UI_RESTRICTIONS, "applyUiRestrictions"),
                    (action::ENABLE_WIN32K_LOCKDOWN, "enableWin32kLockdown"),
                    (action::REDUCE_PATH_COUNT, "reducePathCount"),
                ],
            ),
            resource_kind: code(
                self.resource_kind,
                &[
                    (resource::NONE, "none"),
                    (resource::PATH, "path"),
                    (resource::CAPABILITY, "capability"),
                ],
            ),
            value_kind: code(
                self.value_kind,
                &[
                    (value::NONE, "none"),
                    (value::ACCESS, "access"),
                    (value::BITMASK, "bitmask"),
                    (value::BOOLEAN, "boolean"),
                    (value::PATH_COUNT, "pathCount"),
                ],
            ),
            requested_value: self.requested_value,
            required_value: self.required_value,
            flags: self.flags,
            resource: None,
            resource_offset_chars: self.resource_offset_chars,
            resource_chars_written: self.resource_chars_written,
            resource_chars_required: self.resource_chars_required,
        }
    }

    fn to_owned(self, storage: &[u16]) -> (NativePolicyDetail, Option<&'static str>) {
        let mut result = self.fixed();
        let error = match self.resource_text(storage) {
            Ok(resource) => {
                result.resource = resource;
                None
            }
            Err(message) => Some(message),
        };
        (result, error)
    }

    fn resource_text(&self, storage: &[u16]) -> Result<Option<String>, &'static str> {
        let offset = self.resource_offset_chars as usize;
        let written = self.resource_chars_written as usize;
        let required = self.resource_chars_required as usize;
        if written > storage.len() || required > MAX_RESOURCE_CHARS {
            return Err("native policy result has out-of-range resource counts");
        }
        if self.flags & RESOURCE_COMPLETE == 0 {
            if written != 0 || offset != 0 {
                return Err("native policy result returned incomplete resource text");
            }
            return Ok(None);
        }
        let end = offset
            .checked_add(written)
            .ok_or("native policy resource range overflowed")?;
        let resource = storage
            .get(offset..end)
            .ok_or("native policy resource lies outside the written pool")?;
        if self.flags & (BUFFER_TOO_SMALL | RESOURCE_UNAVAILABLE) != 0
            || self.resource_kind == 0
            || written < 2
            || written != required
            || resource[written - 1] != 0
            || resource[..written - 1].contains(&0)
        {
            return Err("native policy result has inconsistent complete-resource metadata");
        }
        String::from_utf16(&resource[..written - 1])
            .map(Some)
            .map_err(|_| "native policy resource is not valid UTF-16")
    }
}

#[cfg(test)]
mod policy_enforcement_tests {
    use super::*;

    #[test]
    fn native_layout_matches_the_windows_v1_abi() {
        #[cfg(target_pointer_width = "64")]
        {
            assert_eq!(std::mem::size_of::<RawPolicyResult>(), 48);
            assert_eq!(std::mem::offset_of!(RawPolicyResult, resource_buffer), 16);
            assert_eq!(std::mem::offset_of!(RawPolicyResult, details_count), 36);
        }
        #[cfg(target_pointer_width = "32")]
        {
            assert_eq!(std::mem::size_of::<RawPolicyResult>(), 40);
            assert_eq!(std::mem::offset_of!(RawPolicyResult, resource_buffer), 12);
            assert_eq!(std::mem::offset_of!(RawPolicyResult, details_count), 28);
        }
        assert_eq!(std::mem::offset_of!(RawPolicyResult, details), 8);
        assert_eq!(std::mem::size_of::<RawPolicyDetail>(), 56);
        assert_eq!(std::mem::offset_of!(RawPolicyDetail, flags), 20);
        assert_eq!(std::mem::offset_of!(RawPolicyDetail, requested_value), 24);
        assert_eq!(
            std::mem::offset_of!(RawPolicyDetail, resource_offset_chars),
            40
        );
    }

    #[test]
    fn complete_resource_is_copied_without_the_terminator() {
        let mut storage = [b'C' as u16, b':' as u16, b'\\' as u16, 0];
        let raw = RawPolicyDetail {
            resource_kind: 1,
            flags: RESOURCE_COMPLETE | HAS_ACTIONABLE_DETAILS,
            resource_chars_written: 4,
            resource_chars_required: 4,
            ..Default::default()
        };
        let (owned, error) = raw.to_owned(&storage);
        assert_eq!(error, None);
        assert_eq!(owned.resource.as_deref(), Some("C:\\"));
        storage.fill(0);
        assert_eq!(owned.resource.as_deref(), Some("C:\\"));
    }

    #[test]
    fn incomplete_and_invalid_resources_are_never_repair_strings() {
        let mut storage = [0u16; 4];
        let mut raw = RawPolicyDetail {
            resource_kind: 1,
            flags: BUFFER_TOO_SMALL | HAS_ACTIONABLE_DETAILS,
            resource_chars_required: 8,
            ..Default::default()
        };
        let (result, error) = raw.to_owned(&storage);
        assert_eq!(error, None);
        assert_eq!(result.resource, None);
        assert_eq!(result.flags, BUFFER_TOO_SMALL | HAS_ACTIONABLE_DETAILS);
        raw.flags |= RESOURCE_COMPLETE;
        assert!(raw.to_owned(&storage).1.is_some());
        raw.flags = RESOURCE_COMPLETE;
        raw.resource_chars_written = 2;
        raw.resource_chars_required = 2;
        storage[0] = 0xd800;
        assert!(raw.to_owned(&storage).1.is_some());
        raw.resource_chars_written = 5;
        assert!(raw.to_owned(&storage).1.is_some());
    }

    #[test]
    fn future_codes_remain_diagnostic_data() {
        let storage = [0u16; 1];
        let raw = RawPolicyDetail {
            failure_class: 999,
            required_value: u64::MAX,
            ..Default::default()
        };
        let (result, error) = raw.to_owned(&storage);
        assert_eq!(error, None);
        assert_eq!(result.failure_class, PolicyResultCode::new(999, None));
        assert_eq!(result.required_value, u64::MAX);
    }

    #[test]
    fn reviewed_v1_discriminators_decode_without_the_removed_gaps() {
        let cases = [
            (
                4,
                4,
                3,
                2,
                "ui",
                "uiRestrictionsRequired",
                "applyUiRestrictions",
                "bitmask",
            ),
            (
                5,
                5,
                4,
                3,
                "win32k",
                "win32kRequired",
                "enableWin32kLockdown",
                "boolean",
            ),
            (
                2,
                6,
                5,
                4,
                "filesystem",
                "requestPathLimit",
                "reducePathCount",
                "pathCount",
            ),
        ];
        for (class, reason, action, value, class_name, reason_name, action_name, value_name) in
            cases
        {
            let storage = [0u16; 1];
            let raw = RawPolicyDetail {
                failure_class: class,
                failure_reason: reason,
                required_action: action,
                value_kind: value,
                flags: HAS_ACTIONABLE_DETAILS,
                ..Default::default()
            };
            let (owned, error) = raw.to_owned(&storage);
            assert_eq!(error, None);
            assert_eq!(owned.failure_class.name.as_deref(), Some(class_name));
            assert_eq!(owned.failure_reason.name.as_deref(), Some(reason_name));
            assert_eq!(owned.required_action.name.as_deref(), Some(action_name));
            assert_eq!(owned.value_kind.name.as_deref(), Some(value_name));
        }
    }

    #[test]
    fn detail_array_uses_offsets_and_ignores_unwritten_elements() {
        let mut storage: Vec<u16> = "C:\\a\0C:\\b\0".encode_utf16().collect();
        let mut details = [RawPolicyDetail::default(); 3];
        for (index, detail) in details[..2].iter_mut().enumerate() {
            detail.resource_kind = resource::PATH;
            detail.flags = HAS_ACTIONABLE_DETAILS | RESOURCE_COMPLETE;
            detail.resource_offset_chars = (index * 5) as u32;
            detail.resource_chars_written = 5;
            detail.resource_chars_required = 5;
        }
        details[2].resource_offset_chars = u32::MAX;
        let mut raw = RawPolicyResult::new(&mut details, &mut storage);
        raw.outcome = outcome::BLOCKED;
        raw.details_count = 2;
        raw.resource_chars_written = 10;
        raw.resource_chars_required = 10;
        let (owned, error) = raw.to_owned(&details, &storage);
        assert_eq!(error, None);
        assert_eq!(owned.details.len(), 2);
        assert_eq!(owned.details[0].resource.as_deref(), Some("C:\\a"));
        assert_eq!(owned.details[1].resource.as_deref(), Some("C:\\b"));
        storage.fill(0);
        details.fill(RawPolicyDetail::default());
        assert_eq!(owned.details[1].resource.as_deref(), Some("C:\\b"));
    }

    #[test]
    fn short_pool_retains_complete_details_without_using_missing_text() {
        let mut storage = [b'A' as u16, 0];
        let mut details = [
            RawPolicyDetail {
                resource_kind: resource::PATH,
                flags: HAS_ACTIONABLE_DETAILS | BUFFER_TOO_SMALL,
                resource_chars_required: 8,
                ..Default::default()
            },
            RawPolicyDetail {
                resource_kind: resource::CAPABILITY,
                flags: HAS_ACTIONABLE_DETAILS | RESOURCE_COMPLETE,
                resource_chars_written: 2,
                resource_chars_required: 2,
                ..Default::default()
            },
        ];
        let mut raw = RawPolicyResult::new(&mut details, &mut storage);
        raw.outcome = outcome::BLOCKED;
        raw.details_count = 2;
        raw.resource_chars_written = 2;
        raw.resource_chars_required = 10;
        let (owned, error) = raw.to_owned(&details, &storage);
        assert_eq!(error, None);
        assert_eq!(owned.details[0].resource, None);
        assert_eq!(owned.details[0].resource_chars_required, 8);
        assert_eq!(owned.details[1].resource.as_deref(), Some("A"));
        details[1].resource_offset_chars = u32::MAX;
        assert!(raw.to_owned(&details, &storage).1.is_some());
        details[1].resource_offset_chars = 1;
        assert!(raw.to_owned(&details, &storage).1.is_some());
    }

    #[test]
    fn malformed_header_counts_and_changed_storage_are_rejected() {
        let mut details = [RawPolicyDetail::default(); MAX_DETAILS];
        let mut storage = [0u16; 2];
        let mut raw = RawPolicyResult::new(&mut details, &mut storage);
        raw.outcome = outcome::BLOCKED;
        raw.details_count = MAX_DETAILS as u32;
        assert_eq!(
            raw.to_owned(&details, &storage).0.details.len(),
            MAX_DETAILS
        );
        raw.details_count += 1;
        assert!(raw.to_owned(&details, &storage).1.is_some());
        raw.details_count = 1;
        raw.resource_chars_written = 3;
        raw.resource_chars_required = 3;
        assert!(raw.to_owned(&details, &storage).1.is_some());
        raw.resource_chars_written = 0;
        raw.resource_chars_required = MAX_RESOURCE_CHARS as u32 + 1;
        assert!(raw.to_owned(&details, &storage).1.is_some());
        raw.resource_chars_required = 0;
        raw.details = std::ptr::null_mut();
        assert!(raw.to_owned(&details, &storage).1.is_some());
        raw.details = details.as_mut_ptr();
        raw.resource_buffer = std::ptr::null_mut();
        assert!(raw.to_owned(&details, &storage).1.is_some());
        raw.resource_buffer = storage.as_mut_ptr();
        raw.details_capacity -= 1;
        assert!(raw.to_owned(&details, &storage).1.is_some());
    }

    #[test]
    fn no_details_and_zero_capacity_are_valid_but_do_not_imply_success() {
        let mut details = [];
        let mut storage = [];
        let mut raw = RawPolicyResult::new(&mut details, &mut storage);
        for outcome in [
            outcome::BLOCKED,
            outcome::PASSED,
            outcome::NO_APPLICABLE_POLICY,
            999,
        ] {
            raw.outcome = outcome;
            let (owned, error) = raw.to_owned(&details, &storage);
            assert_eq!(error, None);
            assert_eq!(owned.outcome.code, outcome);
            assert!(owned.details.is_empty());
        }
    }

    #[test]
    fn full_pool_and_result_header_invariants_are_checked() {
        let mut storage = vec![b'a' as u16; MAX_RESOURCE_CHARS];
        storage[MAX_RESOURCE_CHARS - 1] = 0;
        let mut details = [RawPolicyDetail {
            resource_kind: resource::PATH,
            flags: HAS_ACTIONABLE_DETAILS | RESOURCE_COMPLETE,
            resource_chars_written: MAX_RESOURCE_CHARS as u32,
            resource_chars_required: MAX_RESOURCE_CHARS as u32,
            ..Default::default()
        }];
        let mut raw = RawPolicyResult::new(&mut details, &mut storage);
        raw.outcome = outcome::BLOCKED;
        raw.details_count = 1;
        raw.resource_chars_written = MAX_RESOURCE_CHARS as u32;
        raw.resource_chars_required = MAX_RESOURCE_CHARS as u32;
        let (owned, error) = raw.to_owned(&details, &storage);
        assert_eq!(error, None);
        assert_eq!(
            owned.details[0].resource.as_ref().unwrap().len(),
            MAX_RESOURCE_CHARS - 1
        );
        raw.version = 2;
        assert!(raw.to_owned(&details, &storage).1.is_some());
        raw.version = 1;
        raw.outcome = outcome::PASSED;
        assert!(raw.to_owned(&details, &storage).1.is_some());
        raw.outcome = outcome::BLOCKED;
        raw.resource_chars_written -= 1;
        assert!(raw.to_owned(&details, &storage).1.is_some());
    }

    #[test]
    fn malformed_pool_keeps_trusted_fixed_details_without_exposing_text() {
        let mut storage = [b'A' as u16, 0];
        let mut details = [
            RawPolicyDetail {
                failure_class: 2,
                required_action: 2,
                resource_kind: resource::PATH,
                flags: HAS_ACTIONABLE_DETAILS | RESOURCE_COMPLETE,
                requested_value: 2,
                required_value: 1,
                resource_chars_written: 2,
                resource_chars_required: 2,
                ..Default::default()
            },
            RawPolicyDetail {
                failure_class: 999,
                required_value: u64::MAX,
                ..Default::default()
            },
        ];
        let mut raw = RawPolicyResult::new(&mut details, &mut storage);
        raw.outcome = outcome::BLOCKED;
        raw.details_count = 2;
        raw.resource_chars_written = 2;
        raw.resource_chars_required = MAX_RESOURCE_CHARS as u32 + 1;
        let (owned, error) = raw.to_owned(&details, &storage);
        assert!(error.is_some());
        assert_eq!(owned.details.len(), 2);
        assert_eq!(owned.details[0].requested_value, 2);
        assert_eq!(owned.details[0].resource, None);
        assert_eq!(owned.details[1].required_value, u64::MAX);
        raw.resource_chars_required = 2;
        raw.outcome = outcome::PASSED;
        let (owned, error) = raw.to_owned(&details, &storage);
        assert!(error.is_some());
        assert_eq!(owned.details.len(), 2);
        assert_eq!(owned.details[0].resource.as_deref(), Some("A"));
    }
}
