// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Bounded native result decoding and recognition of restrictive instructions.

use crate::core_modules::process_security_environment_policy_result::experimental_process_security_environment_policy_result as layout;
use crate::mxc_common::policy_failures::{PolicyFailureDetail, PolicyFailureResult};

pub(crate) use layout::{PolicyDetailT as PolicyDetail, PolicyResultT as PolicyResult};

pub(crate) const POLICY_RESULT_VERSION: u32 = layout::PolicyResultVersion::V1.0;
pub(crate) const MAX_RESULT_BYTES: usize = layout::PolicyResultLimit::MaxResultBytes.0 as usize;
const MAX_DETAILS: usize = layout::PolicyResultLimit::MaxDetails.0 as usize;
const MAX_RESOURCE_CHARS: usize = layout::PolicyResultLimit::MaxResourceChars.0 as usize;
const ACTIONABLE: u32 = layout::PolicyResultFlags::HasActionableDetails.0;
const RESOURCE_COMPLETE: u32 = layout::PolicyResultFlags::ResourceComplete.0;
const RESOURCE_UNAVAILABLE: u32 = layout::PolicyResultFlags::ResourceUnavailable.0;
const KNOWN_FLAGS: u32 = ACTIONABLE | RESOURCE_COMPLETE | RESOURCE_UNAVAILABLE;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) enum MutationHint {
    RemoveCapability(String),
    RestrictPath {
        path: String,
        requested: u64,
        maximum: u64,
    },
    ReducePathCount {
        requested: u64,
        maximum: u64,
    },
}

impl PolicyResult {
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() < 8 || bytes.len() > MAX_RESULT_BYTES {
            return Err("native result has an invalid byte count");
        }
        if !layout::policy_result_buffer_has_identifier(bytes) {
            return Err("native result is not a PSEP FlatBuffer");
        }
        let options = flatbuffers::VerifierOptions {
            max_depth: 16,
            max_tables: 256,
            max_apparent_size: MAX_RESULT_BYTES,
            ..Default::default()
        };
        let result = layout::root_as_policy_result_with_opts(&options, bytes)
            .map_err(|_| "native result is a malformed PSEP FlatBuffer")?;
        if result.version() != POLICY_RESULT_VERSION
            || result.minimum_reader_version() != POLICY_RESULT_VERSION
        {
            return Err("native result does not match the requested V1 contract");
        }
        if result
            .details()
            .is_some_and(|details| details.len() > MAX_DETAILS)
        {
            return Err("native result exceeded the detail limit");
        }
        let mut resource_chars = 0usize;
        if let Some(details) = result.details() {
            for detail in details {
                if let Some(resource) = detail.resource() {
                    resource_chars = resource_chars.saturating_add(resource.len() + 1);
                    if resource_chars > MAX_RESOURCE_CHARS {
                        return Err("native result exceeded the resource limit");
                    }
                    if detail.flags() & RESOURCE_COMPLETE == 0
                        || detail.flags() & RESOURCE_UNAVAILABLE != 0
                    {
                        return Err("native result has inconsistent resource metadata");
                    }
                }
            }
        }
        Ok(result.unpack())
    }

    pub(crate) fn mutation_hints(&self) -> Option<Vec<MutationHint>> {
        let details = self.details.as_deref().unwrap_or_default();
        if self.outcome.0 != 1 || details.is_empty() {
            return None;
        }
        details
            .iter()
            .map(|detail| {
                if detail.flags & ACTIONABLE == 0 || detail.flags & !KNOWN_FLAGS != 0 {
                    return None;
                }
                match (
                    detail.failure_class.0,
                    detail.failure_reason.0,
                    detail.required_action.0,
                    detail.resource_kind.0,
                    detail.value_kind.0,
                ) {
                    (1..=3, 1, 1, 2, 0)
                        if detail.flags == ACTIONABLE | RESOURCE_COMPLETE
                            && detail.requested_value == 0
                            && detail.required_value == 0 =>
                    {
                        Some(MutationHint::RemoveCapability(
                            detail.resource_text().ok()??,
                        ))
                    }
                    (2, 2 | 3, 2, 1, 1)
                        if detail.flags == ACTIONABLE | RESOURCE_COMPLETE
                            && detail.requested_value <= 2
                            && detail.required_value < detail.requested_value
                            && (detail.failure_reason.0 != 3 || detail.required_value == 0) =>
                    {
                        Some(MutationHint::RestrictPath {
                            path: detail.resource_text().ok()??,
                            requested: detail.requested_value,
                            maximum: detail.required_value,
                        })
                    }
                    (2, 4, 3, 0, 2)
                        if detail.flags == ACTIONABLE
                            && detail.requested_value > detail.required_value
                            && detail.resource.is_none() =>
                    {
                        Some(MutationHint::ReducePathCount {
                            requested: detail.requested_value,
                            maximum: detail.required_value,
                        })
                    }
                    _ => None,
                }
            })
            .collect()
    }
}

impl PolicyDetail {
    fn resource_text(&self) -> Result<Option<String>, &'static str> {
        if self.flags & RESOURCE_COMPLETE == 0 {
            return if self.resource.is_some() {
                Err("incomplete resource metadata")
            } else {
                Ok(None)
            };
        }
        let resource = self
            .resource
            .as_deref()
            .ok_or("missing complete resource")?;
        if self.flags & RESOURCE_UNAVAILABLE != 0
            || self.resource_kind.0 == 0
            || resource.is_empty()
            || resource.contains(&0)
        {
            return Err("inconsistent complete-resource metadata");
        }
        String::from_utf16(resource)
            .map(Some)
            .map_err(|_| "invalid UTF-16")
    }
}

impl From<PolicyResult> for PolicyFailureResult {
    fn from(result: PolicyResult) -> Self {
        Self {
            version: result.version,
            minimum_reader_version: result.minimum_reader_version,
            outcome: result.outcome.0,
            details: result
                .details
                .unwrap_or_default()
                .into_iter()
                .map(|detail| PolicyFailureDetail {
                    failure_class: detail.failure_class.0,
                    failure_reason: detail.failure_reason.0,
                    required_action: detail.required_action.0,
                    resource_kind: detail.resource_kind.0,
                    value_kind: detail.value_kind.0,
                    flags: detail.flags,
                    requested_value: detail.requested_value,
                    required_value: detail.required_value,
                    resource: detail.resource,
                })
                .collect(),
        }
    }
}

impl From<&PolicyFailureResult> for PolicyResult {
    fn from(result: &PolicyFailureResult) -> Self {
        Self {
            version: result.version,
            minimum_reader_version: result.minimum_reader_version,
            outcome: layout::PolicyOutcome(result.outcome),
            details: Some(
                result
                    .details
                    .iter()
                    .map(|detail| PolicyDetail {
                        failure_class: layout::FailureClass(detail.failure_class),
                        failure_reason: layout::FailureReason(detail.failure_reason),
                        required_action: layout::RequiredAction(detail.required_action),
                        resource_kind: layout::ResourceKind(detail.resource_kind),
                        value_kind: layout::ValueKind(detail.value_kind),
                        flags: detail.flags,
                        requested_value: detail.requested_value,
                        required_value: detail.required_value,
                        resource: detail.resource.clone(),
                    })
                    .collect(),
            ),
        }
    }
}
