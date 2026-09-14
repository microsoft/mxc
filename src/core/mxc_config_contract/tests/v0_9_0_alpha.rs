// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use mxc_config_contract::published::v0_9_0_alpha::Request;
use std::fs;
use std::path::Path;

#[test]
fn published_v09_fixtures_are_frozen() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("v0_9_0_alpha")
        .join("fixtures");
    for (kind, accepted) in [("valid", true), ("invalid", false)] {
        let directory = root.join(kind);
        let mut paths = fs::read_dir(&directory)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| {
                path.extension()
                    .is_some_and(|extension| extension == "json")
            })
            .collect::<Vec<_>>();
        paths.sort();
        assert!(!paths.is_empty(), "{} is empty", directory.display());
        for path in paths {
            let source = fs::read_to_string(&path).unwrap();
            assert_eq!(
                serde_json::from_str::<Request>(&source).is_ok(),
                accepted,
                "{}",
                path.display()
            );
        }
    }
}

#[test]
fn published_v09_excludes_development_surfaces() {
    for field in [
        r#""phase":"start","sandboxId":"wsb:1234abcd""#,
        r#""containment":"wslc","wslc":{}"#,
        r#""containment":"windows_sandbox","windowsSandbox":{}"#,
        r#""containment":"isolation_session""#,
        r#""test":{}"#,
    ] {
        let source =
            format!(r#"{{"version":"0.9.0-alpha","process":{{"commandLine":"echo"}},{field}}}"#);
        assert!(
            serde_json::from_str::<Request>(&source).is_err(),
            "{source}"
        );
    }
}
