// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use mxc_config_contract::dev::parse_operation_request;
use mxc_config_contract::published::v0_8_0_alpha::Request as V08Request;

#[test]
fn operation_neutral_config_is_introduced_in_v09() {
    let json = r#"{
        "version":"0.9.0-alpha",
        "containment":"wslc",
        "experimental":{"wslc":{"image":"ubuntu:24.04"}}
    }"#;
    parse_operation_request(json).unwrap();

    let v08_json = json.replace("0.9.0-alpha", "0.8.0-alpha");
    assert!(serde_json::from_str::<V08Request>(&v08_json).is_err());
}

#[test]
fn state_aware_dispatch_fields_are_not_part_of_v09() {
    for field in [r#""phase":"start""#, r#""sandboxId":"wslc:1234abcd""#] {
        let json = format!(r#"{{"version":"0.9.0-alpha",{field}}}"#);
        assert!(parse_operation_request(&json).is_err(), "{json}");
    }
}
