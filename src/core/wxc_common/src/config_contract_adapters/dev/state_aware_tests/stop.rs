// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#[test]
fn stop_preserves_common_fields_and_unvalidated_identifier() {
    super::common::assert_no_config_phase("stop");
}
