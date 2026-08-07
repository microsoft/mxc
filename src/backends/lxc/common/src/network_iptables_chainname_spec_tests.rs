//! Spec-derived tests for iptables chain-name derivation and collision
//! resistance.  Written from the documented contract only.
//!
//! Scope note on what these tests can and cannot establish: the derivation
//! compresses an unbounded container-name space into a fixed-width string, so
//! it is collision-*resistant*, NOT injective.  A finite corpus can only show
//! the absence of collisions across the specific near-miss families it
//! contains; it can never establish injectivity over all inputs, and no test
//! here claims to.  These tests focus on: absence of collisions across an
//! adversarial near-miss corpus, the two hard length bounds (netfilter chain
//! 28 chars, `IFNAMSIZ` veth 15 chars), chain-name shape, determinism, and the
//! full-64-bit hash property.

use super::*;
use std::collections::HashMap;
use std::collections::HashSet;

// ── corpus ───────────────────────────────────────────────────────────────────

/// Build the adversarial corpus described in the contract.
///
/// Corpus includes:
/// * The two named adversarial families (shared prefix past truncation point;
///   names that differ only in sanitizer-stripped characters).
/// * Long names (> 12 chars, > 100 chars, 500 chars).
/// * Empty string and single-character names.
/// * All-punctuation names, Unicode names.
/// * Case variants, numeric-only names, names with mixed punctuation.
fn build_corpus() -> Vec<String> {
    let mut names: Vec<String> = Vec::new();

    // Named adversarial family 1 — shared prefix past the truncation point.
    // "web-frontend-1" and "web-frontend-2" are the contract's own examples.
    // Contract clause: "two names that share a prefix past the truncation point
    // would collapse onto one chain".
    for i in 0..50u32 {
        names.push(format!("web-frontend-{}", i));
    }
    for i in 0..50u32 {
        names.push(format!("backend-service-node-{}", i));
    }
    // 12-char prefix variants (right at the truncation boundary)
    for i in 0..20u32 {
        names.push(format!("aaaaabbbbccc-{}", i));
    }

    // Named adversarial family 2 — names differing only in sanitizer-stripped
    // characters.  Contract: "two names that differ only in characters the
    // sanitizer strips ('a.b' / 'ab') would collapse onto one chain".
    names.push("a.b".to_string());
    names.push("ab".to_string());
    names.push("a-b".to_string());
    names.push("a_b".to_string());
    names.push("a..b".to_string());
    names.push("a...b".to_string());
    names.push("a.b.c".to_string());
    names.push("abc".to_string());
    names.push("a-b-c".to_string());
    // More punctuation-only-different pairs
    for c in &[
        '.', '!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '+', '=', '[', ']',
    ] {
        names.push(format!("foo{}bar", c));
    }
    names.push("foobar".to_string());

    // The two names proven to collide under the old 32-bit-truncated hash.
    // Contract: brute force found this pair after 793,379 candidates.
    names.push("web-frontend-017m3b".to_string());
    names.push("web-frontend-01kgar".to_string());

    // Empty string (boundary condition)
    names.push(String::new());

    // Single characters — printable ASCII
    for ch in b'a'..=b'z' {
        names.push((ch as char).to_string());
    }
    for ch in b'0'..=b'9' {
        names.push((ch as char).to_string());
    }

    // All-punctuation (sanitizes to empty)
    names.push("....".to_string());
    names.push("----".to_string());
    names.push("!@#$%^&*()".to_string());

    // Numeric-only names
    for i in 0..30u32 {
        names.push(i.to_string());
    }

    // Long names — 100, 200, 500 characters
    names.push("x".repeat(100));
    names.push("x".repeat(200));
    names.push("x".repeat(500));
    // Long names with trailing numeric suffixes differing only past the
    // truncation point — another shared-prefix family
    for i in 0..30u32 {
        names.push(format!("{}{}", "y".repeat(40), i));
    }

    // Unicode names
    names.push("café".to_string());
    names.push("naïve".to_string());
    names.push("日本語".to_string());
    names.push("中文".to_string());
    names.push("αβγδ".to_string());
    names.push("🦀rust".to_string());
    names.push("container\u{0000}null".to_string()); // embedded NUL

    // Case variants
    names.push("Container".to_string());
    names.push("container".to_string());
    names.push("CONTAINER".to_string());

    // Mixed case + digits
    names.push("MyApp123".to_string());
    names.push("myapp123".to_string());
    names.push("MYAPP123".to_string());

    // Names with whitespace
    names.push("hello world".to_string());
    names.push("hello  world".to_string());
    names.push(" leading".to_string());
    names.push("trailing ".to_string());

    names
}

// ── helper ───────────────────────────────────────────────────────────────────

const HASH_TOKEN_LEN: usize = 11;

/// A base36 token character is `0-9` or lowercase `a-z`.
fn is_base36(c: char) -> bool {
    c.is_ascii_digit() || c.is_ascii_lowercase()
}

/// Regex-free shape check: returns `(sanitized_segment, hash_token)` if the
/// chain matches `"MXC-<body>-<11 base36>"`, or `None` otherwise.
fn parse_chain_shape(chain: &str) -> Option<(&str, &str)> {
    let rest = chain.strip_prefix("MXC-")?;
    // Last (1 + 11) chars must be "-<11 base36>".
    let suffix_len = 1 + HASH_TOKEN_LEN;
    if rest.len() < suffix_len {
        return None;
    }
    let (body, hash_part) = rest.split_at(rest.len() - suffix_len);
    let dash = hash_part.chars().next()?;
    if dash != '-' {
        return None;
    }
    let token = &hash_part[1..];
    if token.len() != HASH_TOKEN_LEN || !token.chars().all(is_base36) {
        return None;
    }
    Some((body, token))
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[test]
fn no_collisions_across_adversarial_near_miss_corpus() {
    // Contract: distinct names should not map to the same chain (collision
    // resistance).  This checks the ABSENCE of collisions across the specific
    // adversarial near-miss families in build_corpus() — shared truncated
    // prefixes and sanitizer-equivalent names.
    //
    // NOT an injectivity proof: the derivation compresses an unbounded name
    // space into a fixed-width string, so collisions exist in principle and
    // injectivity over all inputs is neither established here nor establishable
    // by any finite corpus.  A pass means "no collision among these near-miss
    // names", not "no collision ever".
    let corpus = build_corpus();

    // Blind-spot guard: assert the corpus is large enough that the check is not
    // vacuous.  If this trips, fix build_corpus(), not this assertion.
    assert!(
        corpus.len() >= 200,
        "corpus has only {} names — collision check would be nearly vacuous",
        corpus.len()
    );

    // De-duplicate inputs (unique inputs → unique outputs is what we assert).
    let mut unique_inputs: Vec<String> = corpus.clone();
    unique_inputs.sort();
    unique_inputs.dedup();

    assert!(
        unique_inputs.len() >= 200,
        "corpus has only {} unique names after dedup — collision check may be vacuous",
        unique_inputs.len()
    );

    let mut seen: HashMap<String, String> = HashMap::new(); // chain_name → first input
    for name in &unique_inputs {
        let chain = NetworkIptablesManager::chain_name_for(name);
        if let Some(prior) = seen.get(&chain) {
            panic!(
                "COLLISION: inputs {:?} and {:?} both produced chain {:?}.\n\
                 The derivation must be collision-resistant across near-miss names.",
                prior, name, chain
            );
        }
        seen.insert(chain, name.clone());
    }
}

#[test]
fn large_shared_prefix_sweep_finds_no_chain_collision() {
    // Adversarial sweep: 300,000 names that all share the same 12-char sanitized
    // prefix ("web-frontend"), so ONLY the hash token distinguishes their
    // chains.  Under the old 32-bit-truncated hash a collision in this family
    // was found in 793,379 candidates; the full-64-bit base36 token must survive
    // this sweep with zero collisions.  (Committed size kept modest for speed; a
    // >1,000,000 one-off sweep was run separately and is reported in the PR.)
    const N: u32 = 300_000;
    let mut seen: HashSet<String> = HashSet::with_capacity(N as usize);
    for i in 0..N {
        let name = format!("web-frontend-{}", i);
        let chain = NetworkIptablesManager::chain_name_for(&name);
        assert!(
            seen.insert(chain.clone()),
            "COLLISION at i={i}: name {name:?} produced an already-seen chain {chain:?}"
        );
    }
    assert_eq!(seen.len(), N as usize, "expected {N} distinct chains");
}

#[test]
fn previously_colliding_pair_now_gets_distinct_chains() {
    // Contract's proven collision under the old truncated hash:
    // "web-frontend-017m3b" and "web-frontend-01kgar" both produced
    // "MXC-web-frontend-01-3d4a49a5".  Both sanitize to the same 12-char prefix
    // "web-frontend", so the fix must be carried entirely by the token.
    let a = NetworkIptablesManager::chain_name_for("web-frontend-017m3b");
    let b = NetworkIptablesManager::chain_name_for("web-frontend-01kgar");
    assert_ne!(
        a, b,
        "previously-colliding pair must now differ; both produced {a:?}"
    );
}

#[test]
fn names_differing_only_past_the_truncation_point_get_distinct_chains() {
    // Contract's first named adversarial family.  "web-frontend-1" and
    // "web-frontend-2" are the contract's own examples.
    let a = NetworkIptablesManager::chain_name_for("web-frontend-1");
    let b = NetworkIptablesManager::chain_name_for("web-frontend-2");
    assert_ne!(
        a, b,
        "COLLISION for contract's own example: \
         \"web-frontend-1\" → {:?} and \"web-frontend-2\" → {:?} must differ.\n\
         Contract: \"two names that share a prefix past the truncation point would \
         collapse onto one chain\"",
        a, b
    );
}

#[test]
fn names_differing_only_in_sanitizer_stripped_characters_get_distinct_chains() {
    // Contract's second named adversarial family.  Contract: "two names that
    // differ only in characters the sanitizer strips ('a.b' / 'ab') would
    // collapse onto one chain".
    let a = NetworkIptablesManager::chain_name_for("a.b");
    let b = NetworkIptablesManager::chain_name_for("ab");
    assert_ne!(
        a, b,
        "COLLISION for contract's own example: \
         \"a.b\" → {:?} and \"ab\" → {:?} must differ.\n\
         Contract: \"two names that differ only in characters the sanitizer strips \
         ('a.b' / 'ab') would collapse onto one chain\"",
        a, b
    );
}

#[test]
fn chain_name_never_exceeds_28_characters_over_wide_corpus() {
    // Contract: "The result stays within the netfilter chain-name limit (28 characters)."
    let corpus = build_corpus();

    // Blind-spot guard.
    assert!(
        corpus.len() >= 200,
        "corpus has only {} names — length bound check may be vacuous",
        corpus.len()
    );

    for name in &corpus {
        let chain = NetworkIptablesManager::chain_name_for(name);
        assert!(
            chain.len() <= 28,
            "chain name {:?} (from input {:?}) is {} characters, exceeds the \
             28-character netfilter limit.\n\
             Contract: \"The result stays within the netfilter chain-name limit (28 characters)\"",
            chain,
            name,
            chain.len()
        );
    }
}

#[test]
fn veth_name_never_exceeds_15_characters_over_wide_corpus() {
    // Contract: "The name must fit the kernel IFNAMSIZ limit of 15 characters."
    // The veth name shares the hash token, so this is the binding constraint.
    let corpus = build_corpus();

    assert!(
        corpus.len() >= 200,
        "corpus has only {} names — IFNAMSIZ bound check may be vacuous",
        corpus.len()
    );

    for name in &corpus {
        let veth = NetworkIptablesManager::deterministic_veth_name(name);
        assert!(
            veth.len() <= 15,
            "veth name {:?} (from input {:?}) is {} characters, exceeds the \
             15-character IFNAMSIZ limit.\n\
             Contract: \"must fit the kernel IFNAMSIZ limit of 15 characters\"",
            veth,
            name,
            veth.len()
        );
    }
}

#[test]
fn veth_name_is_exactly_15_characters_fixed_width() {
    // Contract: "mxcv" (4) + 11-char base36 token = 15.  The token is
    // zero-padded to a fixed width, so the veth name is ALWAYS exactly 15
    // characters regardless of input length — including the empty name.
    for name in &["", "a", "hello", "web-frontend-1", &"z".repeat(500)] {
        let veth = NetworkIptablesManager::deterministic_veth_name(name);
        assert_eq!(
            veth.len(),
            15,
            "veth name {:?} (from input {:?}) is {} chars, expected exactly 15",
            veth,
            name,
            veth.len()
        );
        assert!(
            veth.strip_prefix("mxcv")
                .is_some_and(|t| t.len() == HASH_TOKEN_LEN && t.chars().all(is_base36)),
            "veth name {:?} (from input {:?}) is not 'mxcv' + 11 base36 chars",
            veth,
            name
        );
    }
}

#[test]
fn chain_and_veth_share_the_same_hash_token() {
    // Contract: both the chain name and the veth name are derived from the same
    // hash, "so they must be changed together".  The 11-char token appearing in
    // each must be identical for a given name.
    for name in &["", "a", "hello", "web-frontend-1", "a.b", &"q".repeat(200)] {
        let chain = NetworkIptablesManager::chain_name_for(name);
        let veth = NetworkIptablesManager::deterministic_veth_name(name);
        let (_body, chain_token) = parse_chain_shape(&chain)
            .unwrap_or_else(|| panic!("chain {chain:?} from {name:?} has wrong shape"));
        let veth_token = veth.strip_prefix("mxcv").unwrap();
        assert_eq!(
            chain_token, veth_token,
            "chain token {:?} and veth token {:?} differ for input {:?}",
            chain_token, veth_token, name
        );
    }
}

#[test]
fn chain_name_has_required_shape_mxc_prefix_sanitized_body_dash_11base36() {
    // Contract: "\"MXC-\" (4) + up to 12 sanitized characters + \"-\" (1) + 11 base36 digits."
    let long_name = "x".repeat(500);
    let test_cases = vec![
        "hello",
        "web-frontend-1",
        "a.b",
        "ab",
        long_name.as_str(),
        "",
    ];
    for name in test_cases {
        let chain = NetworkIptablesManager::chain_name_for(name);
        let parsed = parse_chain_shape(&chain);
        assert!(
            parsed.is_some(),
            "chain {:?} (from input {:?}) does not match required shape \
             \"MXC-<up-to-12-sanitized>-<11 base36>\".\n\
             Contract: \"'MXC-' (4) + up to 12 sanitized characters + '-' (1) + 11 base36 digits\"",
            chain,
            name
        );
        let (body, _token) = parsed.unwrap();
        assert!(
            body.len() <= 12,
            "sanitized segment {:?} in chain {:?} (input {:?}) is {} chars, exceeds 12.\n\
             Contract: \"up to 12 sanitized characters\"",
            body,
            chain,
            name,
            body.len()
        );
    }
}

#[test]
fn chain_name_starts_with_mxc_prefix() {
    // Contract: "\"MXC-\" (4) + ..."
    for name in &["hello", "world", "", "a.b", &"z".repeat(500)] {
        let chain = NetworkIptablesManager::chain_name_for(name);
        assert!(
            chain.starts_with("MXC-"),
            "chain {:?} (from input {:?}) does not start with \"MXC-\".\n\
             Contract: \"'MXC-' (4) + up to 12 sanitized characters + '-' (1) + 11 base36 digits\"",
            chain,
            name
        );
    }
}

#[test]
fn chain_name_is_deterministic_repeated_calls_return_identical_results() {
    // Contract: "the signal-time force_cleanup rebuilds the manager from the
    // name alone" — requires same name → same chain on every call.
    let long_name = "x".repeat(500);
    let names = vec!["hello", "web-frontend-1", "a.b", "", long_name.as_str()];
    for name in names {
        let first = NetworkIptablesManager::chain_name_for(name);
        for _ in 0..10 {
            let again = NetworkIptablesManager::chain_name_for(name);
            assert_eq!(
                first, again,
                "chain_name_for({:?}) returned different values on repeated calls: \
                 {:?} vs {:?}.\n\
                 Contract: deterministic so force_cleanup can reconstruct the chain from \
                 the name alone",
                name, first, again
            );
        }
    }
}

#[test]
fn cross_process_determinism_exact_string_pins() {
    // Contract: "FNV-1a is used rather than the std hasher because its output
    // must be reproducible across processes and across builds" — the
    // force_cleanup teardown path rebuilds the chain/veth names from the name
    // alone, in a DIFFERENT process, and must land on the byte-identical string.
    //
    // These are exact-string PINS.  They exist so that any change to the hash
    // algorithm, the base36 encoding, the token width, or the sanitized
    // allowance turns into a red test rather than silently breaking
    // cross-process teardown.  If the encoding is changed intentionally, update
    // these literals in the same commit with a comment naming the new scheme.
    assert_eq!(
        NetworkIptablesManager::chain_name_for("hello"),
        "MXC-hello-vyo96lq8v0r",
        "chain name for \"hello\" drifted — cross-process teardown would break"
    );
    assert_eq!(
        NetworkIptablesManager::deterministic_veth_name("hello"),
        "mxcvvyo96lq8v0r",
        "veth name for \"hello\" drifted — cross-process teardown would break"
    );
    assert_eq!(
        NetworkIptablesManager::chain_name_for("my-container_123"),
        "MXC-my-container-txnom6cpxyu",
        "chain name for \"my-container_123\" drifted"
    );
    assert_eq!(
        NetworkIptablesManager::chain_name_for(""),
        "MXC--niihzj4ux45",
        "chain name for \"\" drifted"
    );
}

#[test]
fn name_hash_is_full_64_bit_fnv1a_regression_pin() {
    // Contract: the full 64-bit FNV-1a hash is retained (the previous
    // implementation truncated to the low 32 bits, which caused the collision).
    // FNV-1a 64-bit: offset = 0xcbf29ce484222325, prime = 0x100000001b3.
    //
    // These are regression pins: a change in the hash algorithm across builds
    // turns this test red.  If the algorithm is intentionally changed, update
    // these values with a comment naming the new algorithm.
    assert_eq!(
        NetworkIptablesManager::name_hash("hello"),
        0xa430_d846_80aa_bd0b,
        "name_hash(\"hello\") drifted from the pinned 64-bit FNV-1a value"
    );
    assert_eq!(
        NetworkIptablesManager::name_hash(""),
        0xcbf2_9ce4_8422_2325,
        "name_hash(\"\") must equal the FNV-1a offset basis"
    );
    assert_eq!(
        NetworkIptablesManager::name_hash("a.b"),
        0xe61d_9919_0466_522c,
        "name_hash(\"a.b\") drifted from the pinned 64-bit FNV-1a value"
    );

    // The low 32 bits alone are what USED to be kept.  Guard that we are no
    // longer discarding the high half: "hello"'s full hash must differ from its
    // own low 32 bits, i.e. the high half is non-zero.
    let full = NetworkIptablesManager::name_hash("hello");
    assert_ne!(
        full & 0xffff_ffff,
        full,
        "name_hash appears truncated to 32 bits — the high half is zero"
    );
}

#[test]
fn name_hash_covers_full_unsanitized_name_differs_for_sanitization_equivalent_inputs() {
    // Contract: "A deterministic hash of the full, unsanitized name is folded
    // in ... independent of any caller-side validation."
    //
    // If the hash were computed over the sanitized name, "a.b" and "ab" would
    // produce the same hash.  Verify the hashes differ.
    let h_ab_dot = NetworkIptablesManager::name_hash("a.b");
    let h_ab = NetworkIptablesManager::name_hash("ab");
    assert_ne!(
        h_ab_dot, h_ab,
        "name_hash(\"a.b\") == name_hash(\"ab\") == {:#018x}.\n\
         Contract: hash of the **full, unsanitized** name — if the sanitized name \
         is hashed instead, \"a.b\" and \"ab\" produce the same hash and the \
         collision resistance is lost.",
        h_ab_dot
    );

    // Same check with the contract's long-prefix family.
    let h1 = NetworkIptablesManager::name_hash("web-frontend-1");
    let h2 = NetworkIptablesManager::name_hash("web-frontend-2");
    assert_ne!(
        h1, h2,
        "name_hash(\"web-frontend-1\") == name_hash(\"web-frontend-2\") == {:#018x}.\n\
         Contract: distinct names must hash differently so the chain names are distinct.",
        h1
    );
}

#[test]
fn manager_new_stores_chain_name_matching_chain_name_for() {
    // The struct doc: "Chain name unique to this container (e.g., 'MXC-<container-name>')."
    // new(name) must populate the field consistently with chain_name_for(name).
    let long_name = "x".repeat(500);
    let names = vec!["hello", "web-frontend-1", "a.b", "", long_name.as_str()];
    for name in names {
        let mgr = NetworkIptablesManager::new(name);
        let expected = NetworkIptablesManager::chain_name_for(name);
        assert_eq!(
            mgr.chain_name, expected,
            "NetworkIptablesManager::new({:?}).chain_name = {:?}, \
             expected {:?} (= chain_name_for({:?})).\n\
             Contract: new() populates chain_name via chain_name_for.",
            name, mgr.chain_name, expected, name
        );
    }
}

#[test]
fn chain_name_length_arithmetic_single_char_name_is_17_chars() {
    // Contract breakdown: 4 ("MXC-") + ≤12 + 1 ("-") + 11 = ≤28.
    // The suffix "-<11 base36>" is always 12 chars regardless of name length.
    // A single-character name that is also a valid identifier char gives
    // exactly 4 + 1 + 1 + 11 = 17 chars.
    let chain = NetworkIptablesManager::chain_name_for("a");
    assert_eq!(
        chain.len(),
        17,
        "chain {:?} from input \"a\" is {} chars, expected 4+1+1+11 = 17",
        chain,
        chain.len()
    );
    assert!(
        chain.len() <= 28,
        "chain {:?} from input \"a\" exceeds 28-char limit",
        chain
    );
    // The suffix -<11 base36> must always be present.
    assert!(
        parse_chain_shape(&chain).is_some(),
        "chain {:?} from input \"a\" does not have required shape",
        chain
    );
}
