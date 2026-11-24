// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::LxcContainer;
use std::fs;

#[test]
fn valid_maps_report_whether_inside_root_is_shifted() {
    let cases = [
        ("0 100000 65536", true),
        (" \t2\t200000\t3  \r\n\t0  100000  2\t\r\n", true),
        ("0 100000 2\n2 200000 3\n", true),
        ("1 100000 65536\n", false),
        ("0 4294967294 1\n", true),
        ("4294967294 4294967294 1\n", false),
        ("0 1 4294967294\n", true),
        ("000 0001 0001\n", true),
    ];

    for (mapping, expected) in cases {
        assert!(
            LxcContainer::validate_id_map(mapping) == Ok(expected),
            "valid ID map reported the wrong shifted-root state"
        );
    }
}

#[test]
fn malformed_maps_are_rejected_even_after_a_shifted_root_row() {
    let cases = [
        "0 100000 1\nnot a mapping\n",
        "",
        "\n",
        " \t\n",
        "0 100000 1\n\n",
        "0 100000 1\n1 200000\n",
        "0 100000 1\n1 200000 1 extra\n",
        "0 100000 1\n+1 200000 1\n",
        "0 100000 1\n1 +200000 1\n",
        "0 100000 1\n1 200000 +1\n",
        "0 100000 1\n-1 200000 1\n",
        "0 100000 1\n1 \u{ff12}\u{ff10}\u{ff10}\u{ff10}\u{ff10}\u{ff10} 1\n",
        "0 100000 1\n4294967296 200000 1\n",
        "0 100000 1\n1 4294967296 1\n",
        "0 100000 1\n1 200000 4294967296\n",
        "0 100000 1\n1 200000 0\n",
        "0 100000 1\n4294967295 200000 1\n",
        "0 100000 1\n1 4294967295 1\n",
        "0 100000 1\n4294967294 200000 2\n",
        "0 100000 1\n1 4294967294 2\n",
    ];

    for mapping in cases {
        let result = LxcContainer::validate_id_map(mapping);

        assert!(result.is_err(), "malformed ID map was accepted");
    }
}

#[test]
fn outside_zero_is_rejected_in_any_row() {
    let cases = [
        "0 100000 1\n1 0 1\n",
        "0 0 1\n",
        "1 0 1\n",
        "1 0 1\n0 100000 1\n",
    ];

    for mapping in cases {
        let result = LxcContainer::validate_id_map(mapping);

        assert!(result.is_err(), "ID map covering outside zero was accepted");
    }
}

#[test]
fn shifted_inside_root_is_required_for_uid_but_not_gid() {
    let cases = [
        ("0 100000 1\n", "0 200000 1\n", true),
        ("0 100000 1\n", "1 200000 1\n", true),
        ("1 100000 1\n", "0 200000 1\n", false),
    ];

    for (uid_map, gid_map, accepted) in cases {
        let directory = tempfile::tempdir_in(".").expect("create map directory");
        fs::write(directory.path().join("uid_map"), uid_map).expect("write UID map");
        fs::write(directory.path().join("gid_map"), gid_map).expect("write GID map");
        let result = LxcContainer::validate_id_maps(directory.path());

        assert!(
            result.is_ok() == accepted,
            "UID/GID map admission did not match the expected outcome"
        );
    }
}

#[test]
fn invalid_data_in_either_complete_map_is_rejected() {
    for filename in ["gid_map", "uid_map"] {
        for mapping in [
            "0 100000 1\n1 0 1\n",
            "",
            "0 100000 1\ninvalid\n",
            "0 100000 1\n\n",
        ] {
            let directory = tempfile::tempdir_in(".").expect("create map directory");
            for name in ["uid_map", "gid_map"] {
                fs::write(directory.path().join(name), "0 100000 1\n").expect("write valid map");
            }
            fs::write(directory.path().join(filename), mapping).expect("write invalid map");
            let result = LxcContainer::validate_id_maps(directory.path());

            assert!(result.is_err(), "invalid {filename} was accepted");
        }
    }
}

#[test]
fn missing_unreadable_or_invalid_utf8_map_files_are_rejected() {
    for filename in ["uid_map", "gid_map"] {
        for failure in ["missing", "directory", "invalid UTF-8"] {
            let directory = tempfile::tempdir_in(".").expect("create map directory");
            for name in ["uid_map", "gid_map"] {
                fs::write(directory.path().join(name), "0 100000 1\n").expect("write valid map");
            }
            let path = directory.path().join(filename);
            match failure {
                "missing" => fs::remove_file(&path).expect("remove map"),
                "directory" => {
                    fs::remove_file(&path).expect("remove map");
                    fs::create_dir(&path).expect("replace map with unreadable directory");
                }
                "invalid UTF-8" => fs::write(&path, [0xff]).expect("write invalid UTF-8 map"),
                _ => unreachable!(),
            }
            let result = LxcContainer::validate_id_maps(directory.path());

            assert!(
                result.is_err(),
                "{filename} was accepted for the {failure} case"
            );
        }
    }
}
