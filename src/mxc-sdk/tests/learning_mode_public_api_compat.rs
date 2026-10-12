// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use mxc_sdk::learning_mode_core::{VerboseLoggingOutcomeReason, VerboseLoggingProvider};

fn provider_name(provider: VerboseLoggingProvider) -> &'static str {
    match provider {
        VerboseLoggingProvider::KernelGeneral => "kernelGeneral",
        VerboseLoggingProvider::PrivacyAuditingPermissiveLearningMode => {
            "privacyAuditingPermissiveLearningMode"
        }
    }
}

fn reason_name(reason: VerboseLoggingOutcomeReason) -> &'static str {
    match reason {
        VerboseLoggingOutcomeReason::Actionable => "actionable",
        VerboseLoggingOutcomeReason::UnsupportedEventSchema => "unsupportedEventSchema",
        VerboseLoggingOutcomeReason::EventPayloadMalformed => "eventPayloadMalformed",
        VerboseLoggingOutcomeReason::DecoderLimitReached => "decoderLimitReached",
        VerboseLoggingOutcomeReason::UnsupportedPropertyEncoding => "unsupportedPropertyEncoding",
        VerboseLoggingOutcomeReason::MissingObjectType => "missingObjectType",
        VerboseLoggingOutcomeReason::MissingObjectName => "missingObjectName",
        VerboseLoggingOutcomeReason::UnsupportedObjectType => "unsupportedObjectType",
        VerboseLoggingOutcomeReason::UnusableResourcePath => "unusableResourcePath",
        VerboseLoggingOutcomeReason::UnresolvedCapability => "unresolvedCapability",
        VerboseLoggingOutcomeReason::ComActivation => "comActivation",
        VerboseLoggingOutcomeReason::ComInterfaceCall => "comInterfaceCall",
        VerboseLoggingOutcomeReason::NotActionable => "notActionable",
    }
}

#[test]
fn existing_verbose_enums_remain_exhaustively_matchable() {
    assert_eq!(
        provider_name(VerboseLoggingProvider::KernelGeneral),
        "kernelGeneral"
    );
    assert_eq!(
        reason_name(VerboseLoggingOutcomeReason::ComInterfaceCall),
        "comInterfaceCall"
    );
}
