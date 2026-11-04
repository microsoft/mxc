// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::validate_unprivileged_idmaps;

#[test]
fn split_maps_allow_whitespace_and_independent_uid_and_gid_spaces() {
    let idmaps = "\n  g 8 1008 8  \n u 0 1000 8\n\n g 0 1000 8\n u 8 1008 8\n\n";
    let result = validate_unprivileged_idmaps(idmaps);

    assert!(
        result.is_ok(),
        "valid split UID/GID mappings were rejected: {idmaps:?}: {result:?}"
    );
}

#[test]
fn both_uid_and_gid_mappings_must_cover_container_root() {
    for idmaps in [
        "",
        "u 0 1000 8",
        "g 0 1000 8",
        "u 1 1000 8\ng 0 1000 8",
        "u 0 1000 8\ng 1 1000 8",
    ] {
        assert!(
            validate_unprivileged_idmaps(idmaps).is_err(),
            "accepted a map without both UID and GID container-root coverage: {idmaps:?}"
        );
    }
}

#[test]
fn every_nonempty_line_requires_a_valid_kind_and_three_unsigned_fields() {
    for invalid_line in [
        "x 20 2000 1",
        "u 20 2000",
        "g 20 2000 1 extra",
        "u -1 2000 1",
        "g 20 host 1",
        "u 20 2000 4294967296",
    ] {
        let idmaps = format!("u 0 1000 8\ng 0 1000 8\n{invalid_line}");

        assert!(
            validate_unprivileged_idmaps(&idmaps).is_err(),
            "accepted malformed map text: {idmaps:?}"
        );
    }
}

#[test]
fn host_root_is_rejected_in_any_segment() {
    for host_root_segment in ["u 8 0 1", "g 8 0 1"] {
        let idmaps = format!("u 0 1000 8\ng 0 1000 8\n{host_root_segment}");

        assert!(
            validate_unprivileged_idmaps(&idmaps).is_err(),
            "accepted a segment exposing host root: {idmaps:?}"
        );
    }
}

#[test]
fn segments_require_positive_counts_and_valid_linux_id_ranges() {
    for invalid_segment in [
        "u 8 2000 0",
        "g 8 2000 0",
        "u 4294967295 2000 1",
        "g 8 4294967295 1",
        "u 4294967294 2000 2",
        "g 8 4294967294 2",
    ] {
        let idmaps = format!("u 0 1000 8\ng 0 1000 8\n{invalid_segment}");

        assert!(
            validate_unprivileged_idmaps(&idmaps).is_err(),
            "accepted an empty or out-of-range segment: {idmaps:?}"
        );
    }
}

#[test]
fn exclusive_range_ends_may_equal_the_linux_id_sentinel() {
    for idmaps in [
        "u 0 1 4294967294\ng 0 1 4294967294",
        "u 0 1000 8\ng 0 1000 8\nu 4294967294 4294967294 1\ng 4294967294 4294967294 1",
    ] {
        let result = validate_unprivileged_idmaps(idmaps);

        assert!(
            result.is_ok(),
            "valid ranges ending at the Linux ID sentinel were rejected: {idmaps:?}: {result:?}"
        );
    }
}

#[test]
fn same_kind_segments_cannot_overlap_in_either_id_space() {
    for overlapping_segments in [
        "u 4 2000 8",
        "g 4 2000 8",
        "u 8 1004 8",
        "g 8 1004 8",
        "u 20 2000 8\nu 40 4000 8\nu 16 6000 16",
        "g 16 2000 8\ng 32 4000 8\ng 48 1996 16",
    ] {
        let idmaps = format!("u 0 1000 8\ng 0 1000 8\n{overlapping_segments}");

        assert!(
            validate_unprivileged_idmaps(&idmaps).is_err(),
            "accepted overlapping same-kind segments: {idmaps:?}"
        );
    }
}
