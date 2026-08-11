// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Black-box specification tests for LXC firewall chain-name construction.
//!
//! Written against the published contract only. Nothing here may depend on how
//! `chain_name_for` computes its result.

use lxc_common::network_iptables::{chain_name_for, NetworkIptablesManager, CHAIN_NAME_MAX_LEN};
use std::collections::{HashMap, HashSet};

fn multibyte_inputs() -> Vec<String> {
    vec![
        "日本語のコンテナ名前が非常に長い".to_string(),
        "😀😀😀😀😀😀😀😀😀😀".to_string(),
        // 'e' plus a combining acute accent: the base char is kept, the mark is
        // dropped, and the whole input is multi-byte (defect 3).
        "e\u{0301}e\u{0301}e\u{0301}e\u{0301}e\u{0301}".to_string(),
        "café-münchen-ñoño".to_string(),
        "中文名字".to_string(),
        "あ".repeat(1000),
    ]
}

fn representative_inputs() -> Vec<String> {
    let mut v = multibyte_inputs();
    v.push(String::new());
    for s in [
        "web",
        "a.b",
        "ab",
        "----",
        "____",
        "web-server-1",
        "😀",
        "container-name-that-is-long-1",
    ] {
        v.push(s.to_string());
    }
    v.push("x".repeat(500));
    v
}

fn assert_invariants(input: &str, chain: &str) {
    assert!(!chain.is_empty(), "empty output for input {input:?}");
    assert!(
        chain.is_ascii(),
        "non-ASCII output {chain:?} for input {input:?}"
    );
    assert!(
        chain.len() <= CHAIN_NAME_MAX_LEN,
        "output {chain:?} is {} bytes (> {CHAIN_NAME_MAX_LEN}) for input {input:?}",
        chain.len()
    );
    assert!(
        chain.starts_with("MXC-"),
        "output {chain:?} missing MXC- prefix for input {input:?}"
    );
    for c in chain.chars() {
        assert!(
            c.is_ascii_alphanumeric() || c == '-' || c == '_',
            "output {chain:?} has non-iptables char {c:?} for input {input:?}"
        );
    }
}

// Hand-rolled recognizer for the exact shape the four bash integration scripts
// assert against: `^MXC-([A-Za-z0-9_-]{1,7}-)?[a-z2-7]{16}$`.  Written without a
// regex dependency so the black-box suite stays dependency-free.  The 16-char
// base32 hash is a fixed-width suffix, so the separator (when a slug is present)
// is always the byte immediately before it, which makes the parse unambiguous
// even though `-` is legal inside the slug.
fn matches_documented_shape(chain: &str) -> bool {
    if !chain.is_ascii() {
        return false;
    }
    let Some(rest) = chain.strip_prefix("MXC-") else {
        return false;
    };
    if rest.len() < 16 {
        return false;
    }
    let (head, hash) = rest.split_at(rest.len() - 16);
    let hash_ok = hash.bytes().all(|b| matches!(b, b'a'..=b'z' | b'2'..=b'7'));
    if !hash_ok {
        return false;
    }
    if head.is_empty() {
        // Slug-less form: `MXC-<hash>`.
        return true;
    }
    // Slug form: `MXC-<slug>-<hash>`; strip the mandatory separator, then check
    // the slug is 1..=7 characters drawn from the documented slug alphabet.
    let Some(slug) = head.strip_suffix('-') else {
        return false;
    };
    if slug.is_empty() || slug.len() > 7 {
        return false;
    }
    slug.bytes()
        .all(|b| matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_' | b'-'))
}

#[test]
fn multibyte_names_never_exceed_the_byte_ceiling() {
    for input in multibyte_inputs() {
        let chain = chain_name_for(&input);
        assert!(
            chain.len() <= CHAIN_NAME_MAX_LEN,
            "output {chain:?} is {} bytes (> {CHAIN_NAME_MAX_LEN}) for input {input:?}",
            chain.len()
        );
    }
}

#[test]
fn adversarially_long_input_never_exceeds_the_byte_ceiling() {
    for input in [
        "x".repeat(10_000),
        "a-b_c".repeat(3000),
        "あ".repeat(10_000),
        "😀".repeat(10_000),
    ] {
        let chain = chain_name_for(&input);
        assert!(
            chain.len() <= CHAIN_NAME_MAX_LEN,
            "output {chain:?} is {} bytes (> {CHAIN_NAME_MAX_LEN}) for a {}-byte input",
            chain.len(),
            input.len()
        );
    }
}

#[test]
fn output_is_pure_ascii() {
    for input in multibyte_inputs() {
        let chain = chain_name_for(&input);
        assert!(
            chain.is_ascii(),
            "non-ASCII output {chain:?} for input {input:?}"
        );
    }
}

#[test]
fn output_uses_only_iptables_safe_characters() {
    for input in representative_inputs() {
        let chain = chain_name_for(&input);
        for c in chain.chars() {
            assert!(
                c.is_ascii_alphanumeric() || c == '-' || c == '_',
                "non-iptables char {c:?} in output {chain:?} for input {input:?}"
            );
        }
    }
}

#[test]
fn prefix_is_always_mxc() {
    for input in representative_inputs() {
        let chain = chain_name_for(&input);
        assert!(
            chain.starts_with("MXC-"),
            "missing MXC- prefix in {chain:?} for input {input:?}"
        );
    }
}

#[test]
fn output_is_deterministic() {
    for input in representative_inputs() {
        let first = chain_name_for(&input);
        assert_eq!(
            chain_name_for(&input),
            first,
            "non-deterministic for {input:?}"
        );
        assert_eq!(
            chain_name_for(&input),
            first,
            "non-deterministic for {input:?}"
        );
    }
}

#[test]
fn historical_dot_collision_is_gone() {
    let a = chain_name_for("a.b");
    let b = chain_name_for("ab");
    assert_ne!(a, b, "\"a.b\" and \"ab\" must not collide, both -> {a:?}");
}

#[test]
fn historical_truncation_collision_is_gone() {
    let fifty = "a".repeat(50);
    let fifty_one = "a".repeat(51);
    let a = chain_name_for(&fifty);
    let b = chain_name_for(&fifty_one);
    assert_ne!(
        a, b,
        "\"a\"*50 and \"a\"*51 must not collide, both -> {a:?}"
    );
}

#[test]
fn historical_suffix_collision_is_gone() {
    let a = chain_name_for("container-name-that-is-long-1");
    let b = chain_name_for("container-name-that-is-long-2");
    assert_ne!(
        a, b,
        "long names differing only in the last char must not collide, both -> {a:?}"
    );
}

#[test]
fn names_sharing_first_seven_slug_chars_differ() {
    let a = chain_name_for("abcdefg1");
    let b = chain_name_for("abcdefg2");
    assert!(
        a.starts_with("MXC-abcdefg-"),
        "unexpected slug for \"abcdefg1\": {a:?}"
    );
    assert!(
        b.starts_with("MXC-abcdefg-"),
        "unexpected slug for \"abcdefg2\": {b:?}"
    );
    assert_ne!(
        a, b,
        "names sharing 7 slug chars must differ, both -> {a:?}"
    );
}

#[test]
fn names_differing_only_in_dropped_chars_differ() {
    // '.' and '/' are both dropped, so the slug is "ab" for both; only the hash
    // over the original name can distinguish them.
    let a = chain_name_for("a.b");
    let b = chain_name_for("a/b");
    assert!(
        a.starts_with("MXC-ab-"),
        "unexpected slug for \"a.b\": {a:?}"
    );
    assert!(
        b.starts_with("MXC-ab-"),
        "unexpected slug for \"a/b\": {b:?}"
    );
    assert_ne!(
        a, b,
        "names differing only in a dropped char must differ, both -> {a:?}"
    );
}

#[test]
fn thousands_of_distinct_names_yield_distinct_chains() {
    let mut names: Vec<String> = Vec::new();
    for i in 0..4000 {
        names.push(format!("very-long-shared-container-prefix-{i}"));
    }
    for i in 0..4000 {
        names.push(format!("abcdefg{i}"));
    }
    for i in 0..1000 {
        names.push(format!("drop{i}.tail"));
        names.push(format!("drop{i}/tail"));
    }

    let distinct_inputs: HashSet<&String> = names.iter().collect();
    assert_eq!(
        distinct_inputs.len(),
        names.len(),
        "generator produced duplicate inputs"
    );

    let mut seen: HashMap<String, String> = HashMap::new();
    for name in &names {
        let chain = chain_name_for(name);
        if let Some(prev) = seen.insert(chain.clone(), name.clone()) {
            panic!("collision: {prev:?} and {name:?} both produced {chain:?}");
        }
    }
}

#[test]
fn empty_and_slugless_names_stay_valid_and_distinct() {
    let inputs = [
        "",
        "....",
        "中文名字",
        "----",
        "____",
        "          ",
        "😀😀😀",
    ];
    let mut seen: HashMap<String, &str> = HashMap::new();
    for input in inputs {
        let chain = chain_name_for(input);
        assert_invariants(input, &chain);
        if let Some(prev) = seen.insert(chain.clone(), input) {
            panic!("distinct inputs {prev:?} and {input:?} collided -> {chain:?}");
        }
    }
}

#[test]
fn slugless_output_is_prefix_plus_sixteen_char_base32_hash() {
    // Names with no sluggable chars take the documented `MXC-<hash>` shape: the
    // hash is 16 lowercase RFC 4648 base32 chars, so the whole name is 20 bytes.
    for input in ["", "....", "中文名字", "          ", "😀😀😀"] {
        let chain = chain_name_for(input);
        assert_eq!(
            chain.len(),
            20,
            "slugless name should be 20 bytes: {chain:?} for {input:?}"
        );
        let hash = chain.strip_prefix("MXC-").expect("MXC- prefix");
        assert_eq!(
            hash.len(),
            16,
            "hash should be 16 chars: {chain:?} for {input:?}"
        );
        for c in hash.chars() {
            assert!(
                matches!(c, 'a'..='z' | '2'..='7'),
                "hash char {c:?} not RFC4648 base32 in {chain:?} for {input:?}"
            );
        }
    }
}

#[test]
fn manager_chain_name_matches_free_function() {
    for input in representative_inputs() {
        assert_eq!(
            NetworkIptablesManager::new(&input).chain_name(),
            chain_name_for(&input),
            "manager disagrees with free function for {input:?}"
        );
    }
}

#[test]
fn short_ascii_name_is_recognizable_in_slug() {
    let chain = chain_name_for("web");
    assert!(
        chain.starts_with("MXC-web-"),
        "slug hint missing for \"web\": {chain:?}"
    );
    assert_invariants("web", &chain);
}

#[test]
fn slug_is_capped_at_seven_characters() {
    // Brief: MXC-(4) + slug(<=7) + -(1) + hash(16) = 28 for a 7-char slug.
    let chain = chain_name_for("abcdefghijklmnop");
    assert!(
        chain.starts_with("MXC-abcdefg-"),
        "slug not capped at 7 chars: {chain:?}"
    );
    assert_eq!(
        chain.len(),
        CHAIN_NAME_MAX_LEN,
        "a 7-char slug must yield a {CHAIN_NAME_MAX_LEN}-byte name, got {chain:?}"
    );
}

#[test]
fn names_sharing_a_slug_still_differ() {
    let a = chain_name_for("web-server-1");
    let b = chain_name_for("web-server-2");
    assert!(a.starts_with("MXC-web-"), "slug hint missing: {a:?}");
    assert!(b.starts_with("MXC-web-"), "slug hint missing: {b:?}");
    assert_ne!(a, b, "names sharing a slug must not collide, both -> {a:?}");
}

#[test]
fn hash_region_spans_the_whole_base32_alphabet() {
    // The hash is a deterministic 80-bit value rendered as 16 base32 characters,
    // so a fixed corpus makes this a reproducible assertion rather than a random
    // one.  A few thousand names yield tens of thousands of hash characters, and
    // a full-alphabet encoder is expected to emit each of the 32 symbols well
    // over a thousand times, so every symbol appearing at least once is a
    // near-certainty; a mask that can reach only 16 symbols fails on this same
    // corpus every run.
    const BASE32_ALPHABET: &str = "abcdefghijklmnopqrstuvwxyz234567";
    let alphabet: HashSet<char> = BASE32_ALPHABET.chars().collect();

    // The corpus spans both documented shapes: ASCII names keep a slug
    // (MXC-<slug>-<hash>), while CJK and emoji names drop it (MXC-<hash>).
    let mut names: Vec<String> = Vec::new();
    for i in 0..2000 {
        names.push(format!("web-{i}"));
    }
    for i in 0..500 {
        names.push(format!("infrastructure-service-node-{i}"));
    }
    for i in 0..1500u32 {
        names.push(char::from_u32(0x4E00u32 + i).unwrap().to_string());
    }
    for i in 0..80u32 {
        names.push(char::from_u32(0x1F600u32 + i).unwrap().to_string());
    }

    let distinct: HashSet<&String> = names.iter().collect();
    assert!(
        distinct.len() >= 3000,
        "corpus must contain at least 3000 distinct names, got {}",
        distinct.len()
    );

    let mut seen: HashSet<char> = HashSet::new();
    let mut slugged = 0usize;
    let mut slugless = 0usize;
    for name in &names {
        let chain = chain_name_for(name);
        let chars: Vec<char> = chain.chars().collect();
        assert!(
            chars.len() >= 20,
            "chain {chain:?} too short to hold a 16-char hash for input {name:?}"
        );
        let split = chars.len() - 16;
        let hash: String = chars[split..].iter().collect();
        let prefix: String = chars[..split].iter().collect();

        if prefix == "MXC-" {
            slugless += 1;
        } else {
            slugged += 1;
            // The existing suite width-checked only the slug-less form; pin the
            // same 16-char hash width for the slug form here.
            let after_sep = chain.rsplit('-').next().unwrap();
            assert_eq!(
                after_sep.len(),
                16,
                "slugged hash region must be 16 chars: {chain:?} for input {name:?}"
            );
        }

        for c in hash.chars() {
            assert!(
                alphabet.contains(&c),
                "hash region char {c:?} outside base32 alphabet in {chain:?} for input {name:?}"
            );
            seen.insert(c);
        }
    }

    assert!(
        slugged > 0 && slugless > 0,
        "corpus must exercise both forms; saw {slugged} slugged and {slugless} slug-less"
    );

    let mut missing: Vec<char> = alphabet.difference(&seen).copied().collect();
    missing.sort_unstable();
    let missing_str = missing
        .iter()
        .map(|c| c.to_string())
        .collect::<Vec<_>>()
        .join(" ");
    assert!(
        missing.is_empty(),
        "expected all 32 base32 characters in the hash region, saw {}; missing: {missing_str}",
        seen.len()
    );
}

#[test]
fn every_hash_position_independently_spans_the_full_base32_alphabet() {
    const BASE32_ALPHABET: &str = "abcdefghijklmnopqrstuvwxyz234567";
    let alphabet: HashSet<char> = BASE32_ALPHABET.chars().collect();

    // Both documented shapes are exercised: short and long ASCII names keep a
    // slug (MXC-<slug>-<hash>), while single CJK ideographs and emoji drop it
    // (MXC-<hash>).
    let mut names: Vec<String> = Vec::new();
    for i in 0..16000 {
        names.push(format!("web-{i}"));
    }
    for i in 0..1000 {
        names.push(format!("infrastructure-service-node-{i}"));
    }
    for i in 0..3000u32 {
        names.push(char::from_u32(0x4E00u32 + i).unwrap().to_string());
    }
    for i in 0..80u32 {
        names.push(char::from_u32(0x1F600u32 + i).unwrap().to_string());
    }

    let distinct: HashSet<&String> = names.iter().collect();
    assert!(
        distinct.len() >= 20000,
        "corpus must contain at least 20000 distinct names, got {}",
        distinct.len()
    );

    // With 20000+ names, each of the 16 positions draws ~20000/32 ≈ 625 samples
    // per symbol, so every symbol is expected hundreds of times at every
    // position; a symbol never appearing at some position is a real entropy
    // defect, not sampling noise.  A pooled, whole-region alphabet check cannot
    // see a single position that has silently collapsed toward a constant.
    let mut per_position: Vec<HashSet<char>> = vec![HashSet::new(); 16];
    let mut slugged = 0usize;
    let mut slugless = 0usize;
    for name in &names {
        let chain = chain_name_for(name);
        let chars: Vec<char> = chain.chars().collect();
        assert!(
            chars.len() >= 20,
            "chain {chain:?} too short to hold a 16-char hash for input {name:?}"
        );
        let split = chars.len() - 16;
        if chars[..split].iter().collect::<String>() == "MXC-" {
            slugless += 1;
        } else {
            slugged += 1;
        }
        for (pos, c) in chars[split..].iter().enumerate() {
            assert!(
                alphabet.contains(c),
                "hash char {c:?} at position {pos} outside base32 alphabet in {chain:?} for input {name:?}"
            );
            per_position[pos].insert(*c);
        }
    }

    assert!(
        slugged > 0 && slugless > 0,
        "corpus must exercise both output forms; saw {slugged} slugged and {slugless} slug-less"
    );

    // Report the worst (fewest distinct symbols) position first so a red test
    // names the most severe case immediately.
    let mut failures: Vec<(usize, Vec<char>, Vec<char>)> = Vec::new();
    for (pos, seen) in per_position.iter().enumerate() {
        if seen.len() != 32 {
            let mut present: Vec<char> = seen.iter().copied().collect();
            present.sort_unstable();
            let mut missing: Vec<char> = alphabet.difference(seen).copied().collect();
            missing.sort_unstable();
            failures.push((pos, present, missing));
        }
    }
    failures.sort_by_key(|(_, present, _)| present.len());

    let report = failures
        .iter()
        .map(|(pos, present, missing)| {
            let present_str: String = present.iter().collect();
            let missing_str = missing
                .iter()
                .map(|c| c.to_string())
                .collect::<Vec<_>>()
                .join(" ");
            format!(
                "hash position {pos} carries only {} distinct character(s) (\"{present_str}\"), \
                 so it contributes fewer than 5 bits of entropy; expected all 32, missing: {missing_str}",
                present.len()
            )
        })
        .collect::<Vec<_>>()
        .join("\n");

    assert!(failures.is_empty(), "{report}");
}

// The hash is taken over the *original* container name and SHA-256 is
// byte-exact, so two names that differ only in letter case are distinct inputs
// and must not share a chain -- even when the differing letter lies past the
// 7-char slug, where the slug alone can no longer tell them apart.
#[test]
fn names_differing_only_in_case_receive_distinct_chains() {
    let assert_case_distinct = |a: &str, b: &str| {
        let ca = chain_name_for(a);
        let cb = chain_name_for(b);
        assert_ne!(ca, cb, "{a:?} and {b:?} both map to {ca}");
    };

    // Differs only past the 7-char slug ("contain"): the decisive case, since
    // the slug is identical for both and only the hash can separate them.
    assert_case_distinct("container-A", "container-a");

    // Differs inside the slug.
    assert_case_distinct("Web", "web");

    // Three capitalizations of one name, all mutually distinct.
    assert_case_distinct("MyContainer", "mycontainer");
    assert_case_distinct("MyContainer", "MYCONTAINER");
    assert_case_distinct("mycontainer", "MYCONTAINER");

    // Case difference at the very last character, far past the slug.
    assert_case_distinct("abcdefghijklmnopqrstuvwxyZ", "abcdefghijklmnopqrstuvwxyz");

    // A pair whose only slug characters are the case-varying letters -- the
    // emoji carry nothing sluggable, so the slug is built entirely from what
    // differs by case.
    assert_case_distinct("😀Web😀", "😀web😀");

    // A corpus of 512 names that are pairwise case-variants of one another: a
    // fixed lowercase prefix (slug "contain") followed by nine letters whose
    // case is toggled per bit pattern, so every difference falls past the slug
    // boundary.  Hashing the original name yields 512 distinct chains; hashing a
    // lowercased copy collapses every one of them onto a single chain.
    let mut seen: HashMap<String, String> = HashMap::new();
    for pattern in 0u32..512 {
        let mut name = String::from("container");
        for bit in 0u32..9 {
            let letter = (b'a' + bit as u8) as char;
            if pattern & (1u32 << bit) != 0 {
                name.push(letter.to_ascii_uppercase());
            } else {
                name.push(letter);
            }
        }
        let chain = chain_name_for(&name);
        if let Some(prev) = seen.insert(chain.clone(), name.clone()) {
            panic!("{prev:?} and {name:?} both map to {chain}");
        }
    }
    assert!(
        seen.len() >= 500,
        "expected at least 500 distinct chains from case-variant corpus, got {}",
        seen.len()
    );
}

/// Cross-version stability anchors: known-answer vectors computed independently
/// from the written specification with CPython's `hashlib` and `base64`, never
/// from the crate under test.  They pin the exact `container name -> chain name`
/// mapping so that a future refactor cannot silently change it.
///
/// The operational stakes are concrete.  A container's firewall rules live in a
/// chain whose name is derived here.  If a newer build computed a different name
/// for the same container, teardown would look for a chain that does not exist,
/// the old chain would be orphaned, and its rules would leak -- accumulating
/// stale firewall state that no code path can ever remove.  These anchors exist
/// so that mapping stays byte-for-byte stable across builds and Rust versions.
///
/// Every expected value below was copied verbatim from the Python oracle's
/// output; none was produced by running the implementation.
#[test]
fn known_answer_vectors_pin_the_exact_chain_mapping() {
    let cases = [
        ("webserver", "MXC-webserv-dildp42ed3lx5j3l"),
        ("db", "MXC-db-ppocluljj34yi6bk"),
        (
            "container-name-that-is-long-1",
            "MXC-contain-giziq3v7bty6quci",
        ),
        ("....", "MXC-36ruo2cgzyy236fr"),
        ("\u{4e2d}\u{6587}\u{540d}\u{5b57}", "MXC-47jr3vcteduliieg"),
        ("\u{5bb9}\u{5668}-1", "MXC--1-5k7ay4bkqwi2dacc"),
        ("", "MXC-4oymiquy7qobjgx3"),
        ("a.b.c.d.e.f.g.h", "MXC-abcdefg-cmn37eyc2xbh76ua"),
        ("abcdefghijklmnop", "MXC-abcdefg-6oo2y3f2xjjv4lba"),
        ("web", "MXC-web-jnpfp5xlf5blsa43"),
    ];
    for (input, expected) in cases {
        assert_eq!(
            chain_name_for(input),
            expected,
            "known-answer vector drifted for input {input:?}"
        );
        assert!(
            expected.len() <= CHAIN_NAME_MAX_LEN,
            "vector {expected:?} exceeds the {CHAIN_NAME_MAX_LEN}-byte ceiling"
        );
    }
}

/// Pins the reversal pair to literal digests.  `abcdefg` and `gfedcba` share no
/// property the rest of the suite asserts -- both are 7-char slugs, both are
/// distinct from each other, both are the right length -- because string
/// reversal is a bijection that preserves distinctness, injectivity, length,
/// and alphabet coverage.  A mutant that reverses the container name before
/// hashing therefore survives every property test; only pinning the literal
/// hash over the *original* byte order can distinguish the correct function
/// from the name-reversing mutant.
#[test]
fn reversal_pair_is_pinned_to_literal_digests_to_kill_a_name_reversing_mutation() {
    assert_eq!(chain_name_for("abcdefg"), "MXC-abcdefg-punfiet3eisqf5nx");
    assert_eq!(chain_name_for("gfedcba"), "MXC-gfedcba-3gb4yrzhxoudzuga");
}

/// Pins the case pair to literal digests.  `container-A` and `container-a`
/// share the 7-char slug `contain`, so if the digest were taken over a
/// lowercased name the two would collapse onto one chain -- a real collision
/// between distinct containers.  Pinning both literals proves the hash is taken
/// over the original, case-preserving bytes.
#[test]
fn case_pair_is_pinned_to_literal_digests_to_prove_case_preserving_hashing() {
    assert_eq!(
        chain_name_for("container-A"),
        "MXC-contain-yxnu4zopsc3bor72"
    );
    assert_eq!(
        chain_name_for("container-a"),
        "MXC-contain-tygguspady7fdgsp"
    );
}

// Gap: the contract lists `_` alongside alphanumerics and `-` as a character
// the slug keeps, but no existing test drives an underscore into the slug --
// every known-answer vector and slug assertion uses only letters, digits, and
// `-`.  A mutant that dropped `_` from the slug alphabet would pass the whole
// prior suite.  `a_b_c_d_e` has sluggable characters a, _, b, _, c, _, d in
// order, so the first CHAIN_SLUG_LEN=7 of them are the slug "a_b_c_d".
#[test]
fn slug_keeps_underscores() {
    let input = "a_b_c_d_e";
    let chain = chain_name_for(input);
    assert!(
        chain.starts_with("MXC-a_b_c_d-"),
        "underscores must be kept in the slug for {input:?}: {chain:?}"
    );
    assert_invariants(input, &chain);
}

// Gap: the contract says the slug "keeps" the ASCII characters "in order,
// discarding everything else", and only the hash is documented as lowercased
// (BASE32_LOWER); the shape the integration scripts assert allows `[A-Za-z]` in
// the slug.  So an uppercase ASCII letter must survive verbatim into the slug.
// No prior test pins this -- the case-variance tests are all driven by the hash
// over original bytes, so a mutant that lowercased the slug would pass them.
// `ABCdef` keeps its first six sluggable characters verbatim.
#[test]
fn slug_preserves_ascii_letter_case() {
    let input = "ABCdef";
    let chain = chain_name_for(input);
    assert!(
        chain.starts_with("MXC-ABCdef-"),
        "slug must preserve letter case for {input:?}: {chain:?}"
    );
    assert_invariants(input, &chain);
}

// Gap: the documented slug group is `{1,7}` characters, and the slug-less form
// (`MXC-<hash>`) and the 7-char maximum are both pinned, but the lower boundary
// -- a single sluggable character producing a one-character slug plus separator
// -- is not.  This distinguishes "one sluggable char" from the slug-less path.
#[test]
fn single_sluggable_char_yields_a_one_char_slug() {
    // '.' is dropped, leaving exactly one sluggable character.
    let input = "a...";
    let chain = chain_name_for(input);
    assert!(
        chain.starts_with("MXC-a-"),
        "a single sluggable char must yield a 1-char slug for {input:?}: {chain:?}"
    );
    // MXC-(4) + slug(1) + -(1) + hash(16) = 22 bytes.
    assert_eq!(
        chain.len(),
        22,
        "one-char-slug name should be 22 bytes for {input:?}: {chain:?}"
    );
    assert_invariants(input, &chain);
}

// Gap: four bash integration scripts read the chain name back out of debug logs
// and assert it against the literal shape `^MXC-([A-Za-z0-9_-]{1,7}-)?[a-z2-7]{16}$`,
// so that regex is itself a client-visible contract (unit-testing-what-to-test
// §3: observable behavior is relative to a named client and its goals -- here
// client (c), the scripts).  The prior suite checks fragments of the shape
// separately (prefix, ASCII, safe charset, hash alphabet, length) but never the
// exact composed shape those scripts depend on.  This pins it end to end across
// both documented forms and every character class, including the underscore,
// uppercase, one-char-slug, and slug-less cases the fragment tests miss.
#[test]
fn every_output_matches_the_documented_integration_script_shape() {
    let mut inputs = representative_inputs();
    for extra in ["a_b_c_d_e", "ABCdef", "a...", "Web_Server-1", "_", "-", "A"] {
        inputs.push(extra.to_string());
    }
    for input in &inputs {
        let chain = chain_name_for(input);
        assert!(
            matches_documented_shape(&chain),
            "output {chain:?} does not match ^MXC-([A-Za-z0-9_-]{{1,7}}-)?[a-z2-7]{{16}}$ for input {input:?}"
        );
    }
}
