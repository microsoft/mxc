// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Microsoft Correlation Vector (MS-CV) v2, the correlation primitive that
//! [WIL TraceLogging](https://github.com/microsoft/wil) stamps into the
//! reserved `__TlgCV__` event field.
//!
//! An MS-CV is a lightweight, sortable string identity that threads a single
//! logical operation across process, service, and (here) state-aware lifecycle
//! boundaries. Format (v2): `base "." element ("." element)*` where `base` is
//! 22 base64 characters encoding a random 128-bit value, and each `element` is
//! a decimal `u32`. The whole vector is capped at 127 characters; on overflow
//! the vector is frozen by appending a `!` terminator and is never mutated
//! again.
//!
//! MXC uses three of the spec operators, mirroring the reference implementation
//! [`microsoft/CorrelationVector-Cpp`](https://github.com/microsoft/CorrelationVector-Cpp):
//!
//! - [`seed`] — mint a fresh vector (`base.0`) at the start of a lifecycle
//!   (state-aware `provision`). The base is random, so no `sandbox_id` / UPN or
//!   other caller identity is embedded — the vector is privacy-safe by
//!   construction.
//! - [`spin`] — derive a child vector (`V.<spin>.0`) for a downstream received
//!   flow whose parent cannot atomically increment per child. Each MXC
//!   non-provision phase (`start` / `exec` / `stop` / `deprovision`) is a
//!   separate, stateless `wxc-exec` process that receives the *same* relayed
//!   vector, so a plain [`extend`] would collapse every phase — and every
//!   repeated `exec` — to an identical `V.0`. `spin` mixes a coarse timestamp
//!   and random entropy so each phase/invocation gets a distinct, still-sortable
//!   child.
//! - [`extend`] / [`increment`] — provided for completeness (single incoming
//!   flow, sequential ticks); not currently on MXC's hot path but kept so the
//!   module is a faithful, reusable MS-CV implementation.
//!
//! The operators are total: a *valid* frozen (terminated) input is returned
//! unchanged, and any malformed input — including an ill-formed `!`-terminated
//! value — is replaced by a fresh [`seed`], so telemetry can never panic on, or
//! emit verbatim, a hostile or corrupted relayed value.

use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};

/// Number of base64 characters in a v2 base (128 random bits).
const BASE_LEN: usize = 22;

/// Maximum length of a v2 vector before it must be terminated (spec §-max).
const MAX_LEN: usize = 127;

/// Character appended to freeze a vector that would otherwise overflow [`MAX_LEN`].
const TERMINATOR: char = '!';

/// Default `spin` interval: drop the 24 least-significant bits of the 100ns
/// tick count, so the coarse counter advances ~every 1.67 s (reference default).
const SPIN_INTERVAL_BITS: u32 = 24;

/// Default `spin` entropy: 2 random bytes (16 bits), matching the reference
/// default (`spin_entropy::two`). Combined with the 16-bit coarse counter this
/// yields a single 32-bit `u32` element.
const SPIN_ENTROPY_BYTES: usize = 2;

/// Mint a fresh v2 correlation vector `base.0`.
///
/// `base` is the 22-character base64 encoding of 16 random bytes. Because the
/// input is exactly 128 bits, the final base64 character's low 4 bits are zero,
/// so it is naturally one of `{A, Q, g, w}` — the spec's UUID-interop rule —
/// without any post-hoc masking.
pub fn seed() -> String {
    let random = os_random_bytes::<16>();
    // Only source the clock and fallback nonce on the (unexpected) RNG-failure
    // path — the common success path pays for neither.
    let (now_ticks, nonce) = match random {
        Some(_) => (0, 0),
        None => (now_ticks_100ns(), fallback_nonce()),
    };
    seed_with(random, now_ticks, nonce)
}

/// Source `N` bytes of OS randomness, or `None` if the RNG is unavailable. This
/// is the single seam every operator's randomness flows through, so a test can
/// force the (otherwise unreachable) RNG-failure branch — see
/// [`test_rng::ForceRngFailure`] — that selects the clock+nonce fallback in
/// [`seed`] and [`spin`].
///
/// Design note: the `#[cfg(test)]` hook here (and the [`test_rng`] module) is a
/// deliberate seam, not incidental test-in-prod entanglement. The pure cores
/// [`seed_with`]/[`spin_with`] can already be driven with `None` entropy, but
/// they do NOT cover the *wrapper-level selection* logic — [`seed`]'s
/// `match random { Some => (0, 0), None => (clock, nonce) }` and [`spin`]'s
/// `if entropy.is_none() { fallback_nonce() }`. Forcing this one function to
/// report failure is the only way to exercise those wrapper branches
/// deterministically; the hook compiles out entirely in non-test builds.
fn os_random_bytes<const N: usize>() -> Option<[u8; N]> {
    #[cfg(test)]
    if test_rng::rng_forced_to_fail() {
        return None;
    }
    let mut bytes = [0u8; N];
    getrandom::getrandom(&mut bytes).ok().map(|()| bytes)
}

/// Deterministic core of [`seed`]: build `base.0` from either OS randomness
/// (`Some(bytes)`) or, if the RNG was unavailable (`None`), a fallback derived
/// from `now_ticks` plus `fallback_nonce` so seeding never panics. getrandom
/// should not fail on supported platforms; if it somehow does, a weak fallback
/// is acceptable because this is a correlation token, not a security secret.
/// Split out from [`seed`] so tests can drive both the RNG-success and
/// RNG-failure branches deterministically.
fn seed_with(random: Option<[u8; 16]>, now_ticks: u64, fallback_nonce: u64) -> String {
    let bytes = random.unwrap_or_else(|| {
        // Combine the coarse clock (8 bytes) with a process-wide monotonic nonce
        // (8 bytes) so concurrent fallbacks within the same clock tick still mint
        // distinct bases rather than colliding into one correlation sequence.
        //
        // Endianness note: the nonce is written big-endian here so its
        // fastest-changing (low-order) bits land in the *last* base64 characters,
        // maximising visible variation between consecutive fallback bases. This is
        // deliberately the opposite of `spin_with`, which needs the changing bits
        // *first* (little-endian) because it slices only the leading
        // `SPIN_ENTROPY_BYTES`. Keep the two independent — do not "unify" them.
        let mut bytes = [0u8; 16];
        bytes[..8].copy_from_slice(&now_ticks.to_le_bytes());
        bytes[8..].copy_from_slice(&fallback_nonce.to_be_bytes());
        bytes
    });
    seed_from_bytes(&bytes)
}

/// Process-wide monotonic nonce used only to keep the RNG-failure fallbacks of
/// [`seed`] and [`spin`] distinct across concurrent same-tick calls.
fn fallback_nonce() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    COUNTER.fetch_add(1, Ordering::Relaxed)
}

/// Innermost core: build `base.0` from an explicit 16-byte (128-bit) value.
/// Shared by [`seed_with`] (both its RNG-success and fallback branches) and by
/// tests that need a frozen base.
fn seed_from_bytes(bytes: &[u8; 16]) -> String {
    let base = STANDARD_NO_PAD.encode(bytes);
    debug_assert_eq!(base.len(), BASE_LEN);
    format!("{base}.0")
}

/// Extend an incoming vector for a received flow: `V => V.0`.
///
/// A valid frozen (terminated) input is returned unchanged; any other immutable
/// or malformed input yields a fresh [`seed`]; a would-be overflow freezes the
/// input with a terminator.
pub fn extend(cv: &str) -> String {
    match classify(cv) {
        Class::Frozen => cv.to_string(),
        Class::Invalid => seed(),
        Class::Mutable(m) => terminate_if_oversized(m.full, format!("{}.0", m.full)),
    }
}

/// Increment the rightmost element of a vector: `V.N => V.(N+1)`.
///
/// A valid frozen input is returned unchanged; any other immutable or malformed
/// input yields a fresh [`seed`]. On `u32` overflow the element cannot advance,
/// so the vector is frozen with a terminator (the spec's overflow behaviour);
/// a would-be length overflow likewise freezes it.
pub fn increment(cv: &str) -> String {
    match classify(cv) {
        Class::Frozen => cv.to_string(),
        Class::Invalid => seed(),
        Class::Mutable(m) if m.last == u32::MAX => {
            // Rightmost element is saturated — cannot advance. Freeze so the
            // vector is not silently re-emitted identically and so downstream
            // phases stop trying to mutate it.
            terminate_if_oversized(m.full, format!("{}{TERMINATOR}", m.full))
        }
        Class::Mutable(m) => terminate_if_oversized(m.full, format!("{}.{}", m.prefix, m.last + 1)),
    }
}

/// Derive a child vector for a downstream received flow whose parent cannot
/// atomically increment per child: `V => V.<spin>.0`.
///
/// `<spin>` is a single `u32` built from the low 16 bits of a coarse 100ns tick
/// counter (high half) and 16 bits of random entropy (low half), matching the
/// reference default spin parameters (coarse interval, short periodicity, two
/// entropy bytes). The timestamp keeps sibling spins roughly time-sortable; the
/// entropy keeps concurrent spins distinct.
pub fn spin(cv: &str) -> String {
    // Validate / short-circuit BEFORE sourcing entropy or the clock: a valid
    // frozen or a malformed input never reaches `spin_with`, so we neither waste
    // OS RNG on a pass-through nor double-fetch it on the reseed path (which
    // calls `seed`, itself sourcing randomness + the clock).
    let m = match classify(cv) {
        Class::Frozen => return cv.to_string(),
        Class::Invalid => return seed(),
        Class::Mutable(m) => m,
    };
    let entropy = os_random_bytes::<SPIN_ENTROPY_BYTES>();
    // Only pay for the fallback nonce when the RNG failed.
    let nonce = if entropy.is_none() {
        fallback_nonce()
    } else {
        0
    };
    spin_with(m.full, now_ticks_100ns(), entropy, nonce)
}

/// Deterministic core of [`spin`]: derive `V.<spin>.0` from explicit tick and
/// entropy sources. Split out from [`spin`] so tests can pin the spin element
/// and drive the RNG-failure fallback (`entropy == None`). Assumes `cv` is a
/// valid mutable vector — [`spin`] runs [`classify`] before calling this, so
/// frozen or malformed inputs never reach here.
fn spin_with(
    cv: &str,
    now_ticks: u64,
    entropy: Option<[u8; SPIN_ENTROPY_BYTES]>,
    fallback_nonce: u64,
) -> String {
    // The spin element is a single `u32` (32 bits): the entropy occupies the low
    // `8 * SPIN_ENTROPY_BYTES` bits and the coarse counter the remainder. The
    // math below is width-generic in `SPIN_ENTROPY_BYTES`; the real constraint is
    // that the entropy leave room for the counter *inside* the 32-bit element, so
    // the counter still contributes to the low 32 bits after the shift-and-mix
    // below. That requires strictly fewer than 4 entropy bytes (< 32 bits): at
    // exactly 4 bytes the counter is shifted entirely above bit 32 and dropped by
    // `as u32`, erasing time-sortability. `<< 8` is a logical shift (bits shifted
    // out are simply dropped, no overflow), and `as u32` keeps the low 32 bits.
    const _: () = assert!(SPIN_ENTROPY_BYTES < 4);
    let entropy = entropy.unwrap_or_else(|| {
        // RNG unavailable: derive the entropy bytes from the process-wide nonce
        // so concurrent same-tick sibling spins still get distinct elements.
        //
        // Endianness note: little-endian here (opposite of `seed_with`) because
        // we slice only the leading `SPIN_ENTROPY_BYTES`, and the nonce's
        // fastest-changing bits are its low-order (first, little-endian) bytes.
        let nonce = fallback_nonce.to_le_bytes();
        let mut bytes = [0u8; SPIN_ENTROPY_BYTES];
        bytes.copy_from_slice(&nonce[..SPIN_ENTROPY_BYTES]);
        bytes
    });
    // Coarse counter: high bits of the tick count. Mix the entropy bytes into
    // the low bits, then keep the low 32 bits as a single element.
    let mut value: u64 = now_ticks >> SPIN_INTERVAL_BITS;
    for b in entropy {
        value = (value << 8) | u64::from(b);
    }
    let element = value as u32;

    let spun = format!("{cv}.{element}.0");
    terminate_if_oversized(cv, spun)
}

/// 100-nanosecond ticks since the Unix epoch (the spec's tick unit), saturating
/// to 0 before the epoch. Used only to keep `spin` values loosely time-sortable.
fn now_ticks_100ns() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| (d.as_nanos() / 100) as u64)
        .unwrap_or(0)
}

/// Whether a vector ends with the terminator. This is a purely *syntactic*
/// trailing-`!` check: callers must still confirm [`is_valid_frozen`] before
/// treating a terminated value as a genuine frozen pass-through, since a hostile
/// relayed value can also end in `!` (see [`classify`]).
fn is_immutable(cv: &str) -> bool {
    cv.ends_with(TERMINATOR)
}

/// A validated, mutable v2 vector, split at its rightmost element so operators
/// can advance it without re-parsing (and without an `.unwrap()` resting on an
/// invariant established in a different function). Built only by [`parse_mutable`],
/// so holding one is proof the vector is a valid, mutable MS-CV.
struct MutableCv<'a> {
    /// The whole vector (`base` + every element), the append prefix used by
    /// [`extend`] and [`spin`].
    full: &'a str,
    /// Everything before the rightmost `.` (`base` + interior elements), the
    /// prefix used by [`increment`] when bumping the last element.
    prefix: &'a str,
    /// The already-parsed rightmost element, used by [`increment`].
    last: u32,
}

/// How [`classify`] categorises an incoming vector for the mutating operators
/// ([`extend`], [`increment`], [`spin`]) and the relay planner. This is a
/// **pure** classification — it performs no I/O and no reseeding, so callers that
/// must avoid the RNG (e.g. the state-aware planner deciding spin-vs-reseed
/// without telemetry active) can share the exact same parse as the operators
/// rather than re-implementing validity.
enum Class<'a> {
    /// A *valid* frozen (terminated) vector — pass it through unchanged.
    Frozen,
    /// A valid mutable vector, already split at its rightmost element — advance it.
    Mutable(MutableCv<'a>),
    /// Malformed, out of range, or an ill-formed terminated value — the operator
    /// must reseed (call [`seed`]) so a hostile or corrupt relayed vector can
    /// never reach telemetry via the immutable fast path.
    Invalid,
}

/// Classify `cv` for the mutating operators and the relay planner. Pure: it
/// neither reseeds nor touches the RNG/clock — the `Invalid => seed()` fallback
/// is the caller's responsibility. This lets [`is_relayable`] (used by a planner
/// that must not spin the RNG) and the operators run one and the same parse.
///
/// The immutable check is deliberately gated on [`is_valid_frozen`]: a bare
/// "ends with `!`" test would let an attacker-controlled `correlationVector`
/// (e.g. `"user@contoso.com!"` or a multi-KB string) bypass validation and be
/// emitted verbatim under `__TlgCV__`.
fn classify(cv: &str) -> Class<'_> {
    if is_immutable(cv) {
        return if is_valid_frozen(cv) {
            Class::Frozen
        } else {
            Class::Invalid
        };
    }
    match parse_mutable(cv) {
        Some(m) => Class::Mutable(m),
        None => Class::Invalid,
    }
}

/// If `candidate` exceeds [`MAX_LEN`], freeze the original `cv` with a
/// terminator instead (the spec's overflow behaviour); otherwise return
/// `candidate`. The frozen result is truncated so it still fits within
/// [`MAX_LEN`] rather than emitting a `MAX_LEN + 1`-character value.
fn terminate_if_oversized(cv: &str, candidate: String) -> String {
    if candidate.len() <= MAX_LEN {
        return candidate;
    }
    // Freeze the original `cv` (the overflow came from appending to it). Reserve
    // one byte for the terminator; vectors are ASCII so this is a char boundary.
    let mut keep = (MAX_LEN - TERMINATOR.len_utf8()).min(cv.len());
    // That cut only falls *inside* `cv` when `cv` is already at the cap. In that
    // case back up to the last element boundary so the trailing element is
    // dropped whole: cutting mid-element would either silently falsify a
    // multi-digit value (`.10` -> `.1`) or leave a dangling `.`, and the latter
    // fails `is_valid_frozen` and forces a spurious reseed on the next phase.
    if keep < cv.len() {
        if let Some(dot) = cv[..keep].rfind('.') {
            keep = dot;
        }
    }
    format!("{}{TERMINATOR}", &cv[..keep])
}

/// Whether `cv` is a well-formed *frozen* vector: within the length cap and
/// whose body (everything before the terminator) is a valid mutable vector.
fn is_valid_frozen(cv: &str) -> bool {
    cv.len() <= MAX_LEN && cv.strip_suffix(TERMINATOR).map(is_valid).unwrap_or(false)
}

/// Whether a relayed correlation vector can be built on directly — i.e. it is a
/// valid mutable vector (which [`spin`] advances) or a valid frozen vector
/// (which [`spin`] passes through). Anything else is reseeded. Used by the
/// state-aware planner to decide `Spin` vs `Reseed` without executing the RNG —
/// it runs the same pure [`classify`] the operators do, so planner and operator
/// can never disagree on what "relayable" means.
pub fn is_relayable(cv: &str) -> bool {
    matches!(classify(cv), Class::Frozen | Class::Mutable(_))
}

/// Whether `cv` is a well-formed, mutable v2 vector: a canonical 22-char base64
/// `base` followed by at least one canonical decimal-`u32` element, within the
/// length cap, with no whitespace and no terminator.
fn is_valid(cv: &str) -> bool {
    parse_mutable(cv).is_some()
}

/// Parse `cv` as a valid, mutable v2 vector, returning it split at its rightmost
/// element (see [`MutableCv`]). Returns `None` for anything that is empty, over
/// the length cap, terminated, or not `base "." element ("." element)*` with a
/// canonical base and canonical decimal-`u32` elements. This is the single place
/// the rightmost element is parsed, so operators never re-parse or `.unwrap()`.
fn parse_mutable(cv: &str) -> Option<MutableCv<'_>> {
    if cv.is_empty() || cv.len() > MAX_LEN || is_immutable(cv) {
        return None;
    }
    // Split off the rightmost element; a valid mutable vector always has at least
    // one `.` (a base with no element is invalid).
    let (prefix, last_str) = cv.rsplit_once('.')?;
    // `prefix` is the base plus any interior elements: validate its head as a
    // base and every interior element as canonical.
    let (base, interior) = match prefix.split_once('.') {
        Some((base, interior)) => (base, Some(interior)),
        None => (prefix, None),
    };
    if !is_valid_base(base) {
        return None;
    }
    if let Some(interior) = interior {
        for element in interior.split('.') {
            parse_element(element)?;
        }
    }
    let last = parse_element(last_str)?;
    Some(MutableCv {
        full: cv,
        prefix,
        last,
    })
}

/// Whether `base` is a canonical v2 base: 22 base64 characters whose final
/// character encodes a zero low nibble (`{A, Q, g, w}`) — the spec's
/// UUID-interop rule for a 128-bit no-pad base. [`seed`] always produces such a
/// base, so a relayed base that fails this is not one we minted.
fn is_valid_base(base: &str) -> bool {
    base.len() == BASE_LEN
        && base.bytes().all(is_base64_char)
        && matches!(base.as_bytes()[BASE_LEN - 1], b'A' | b'Q' | b'g' | b'w')
}

/// Parse `element` as a canonical decimal `u32`: non-empty, ASCII digits only,
/// no non-canonical leading zeros (a bare `0` is allowed, `01` is not), and in
/// range. Rejects signed forms (`+1` / `-1`) and other shapes that
/// `u32::from_str` would otherwise accept but that MS-CV never produces. Returns
/// the parsed value so callers get the number without a second parse.
fn parse_element(element: &str) -> Option<u32> {
    if element.is_empty()
        || !element.bytes().all(|b| b.is_ascii_digit())
        // Reject non-canonical leading zeros while still allowing a bare `0`;
        // incrementing one (`01` -> `2`) would silently reshape the vector and
        // break lexical sortability.
        || (element.len() > 1 && element.starts_with('0'))
    {
        return None;
    }
    element.parse::<u32>().ok()
}

/// Standard base64 alphabet membership (`A–Z a–z 0–9 + /`).
fn is_base64_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'+' || b == b'/'
}

/// Test-only seam for the wrapper-level RNG-failure branch. [`os_random_bytes`]
/// consults [`rng_forced_to_fail`] first, so a test can drive the otherwise
/// unreachable "getrandom failed → clock+nonce fallback" selection in [`seed`]
/// and [`spin`] deterministically via the [`ForceRngFailure`] RAII guard. The
/// flag is thread-local, so it only affects the setting test's own thread and
/// never bleeds into other tests running in parallel.
#[cfg(test)]
mod test_rng {
    use std::cell::Cell;

    thread_local! {
        static FORCE_FAIL: Cell<bool> = const { Cell::new(false) };
    }

    pub(super) fn rng_forced_to_fail() -> bool {
        FORCE_FAIL.with(Cell::get)
    }

    /// While alive, forces [`super::os_random_bytes`] to report RNG failure on
    /// this thread. Restores the previous state on drop, so the failure branch is
    /// scoped to the test body even if it panics.
    pub(super) struct ForceRngFailure(bool);

    impl ForceRngFailure {
        pub(super) fn new() -> Self {
            let prev = FORCE_FAIL.with(|f| f.replace(true));
            Self(prev)
        }
    }

    impl Drop for ForceRngFailure {
        fn drop(&mut self) {
            FORCE_FAIL.with(|f| f.set(self.0));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A valid 22-char base whose final character (`A`) satisfies the
    /// UUID-interop rule, usable as a literal in deterministic tests.
    const BASE: &str = "AAAAAAAAAAAAAAAAAAAAAA";

    #[test]
    fn base_literal_is_well_formed() {
        assert_eq!(BASE.len(), BASE_LEN);
        assert!(is_valid(&format!("{BASE}.0")));
    }

    #[test]
    fn seed_is_a_valid_v2_vector() {
        let cv = seed();
        // `base.0`: 22 base64 chars + "." + "0".
        assert_eq!(cv.len(), BASE_LEN + 2);
        assert!(cv.ends_with(".0"));
        let base = cv.split('.').next().unwrap();
        assert_eq!(base.len(), BASE_LEN);
        // 128-bit input => final base char has zero low nibble.
        let last = base.chars().last().unwrap();
        assert!(
            matches!(last, 'A' | 'Q' | 'g' | 'w'),
            "final base char {last} must satisfy the UUID-interop rule"
        );
        assert!(is_valid(&cv));
    }

    #[test]
    fn distinct_seeds_differ() {
        assert_ne!(seed(), seed());
    }

    #[test]
    fn extend_appends_zero_element() {
        assert_eq!(extend(&format!("{BASE}.0")), format!("{BASE}.0.0"));
        assert_eq!(extend(&format!("{BASE}.4")), format!("{BASE}.4.0"));
    }

    #[test]
    fn increment_bumps_last_element() {
        assert_eq!(increment(&format!("{BASE}.0")), format!("{BASE}.1"));
        assert_eq!(increment(&format!("{BASE}.9")), format!("{BASE}.10"));
        assert_eq!(increment(&format!("{BASE}.1.41")), format!("{BASE}.1.42"));
    }

    #[test]
    fn increment_saturates_and_freezes_at_u32_max() {
        // A saturated rightmost element cannot advance, so increment freezes the
        // vector (appends the terminator) rather than re-emitting it unchanged.
        let maxed = format!("{BASE}.{}", u32::MAX);
        let out = increment(&maxed);
        assert_eq!(out, format!("{maxed}{TERMINATOR}"));
        assert!(is_valid_frozen(&out));
    }

    #[test]
    fn spin_adds_a_spin_element_and_zero() {
        let parent = format!("{BASE}.0");
        let spun = spin(&parent);
        assert!(spun.starts_with(&format!("{parent}.")));
        assert!(spun.ends_with(".0"));
        // parent had 2 parts (base, 0); spin adds the spin element and a fresh 0.
        assert_eq!(spun.split('.').count(), 4);
        assert!(is_valid(&spun));
    }

    #[test]
    fn spins_are_distinct() {
        let parent = format!("{BASE}.0");
        // Entropy makes two spins of the same parent differ.
        let a = spin(&parent);
        let b = spin(&parent);
        assert_ne!(a, b);
    }

    #[test]
    fn operators_pass_through_immutable_vectors() {
        let frozen = format!("{BASE}.0{TERMINATOR}");
        assert!(is_valid_frozen(&frozen));
        assert_eq!(extend(&frozen), frozen);
        assert_eq!(increment(&frozen), frozen);
        assert_eq!(spin(&frozen), frozen);
    }

    #[test]
    fn operators_reseed_on_malformed_input() {
        for bad in ["", "not a cv", "short.0", "  .0"] {
            assert!(is_valid(&extend(bad)), "extend({bad:?}) should reseed");
            assert!(is_valid(&spin(bad)), "spin({bad:?}) should reseed");
            assert!(
                is_valid(&increment(bad)),
                "increment({bad:?}) should reseed"
            );
        }
    }

    #[test]
    fn operators_reseed_on_malformed_terminated_input() {
        // A '!'-terminated value that is not a valid frozen vector must NOT pass
        // through the immutable fast path to telemetry — it reseeds instead.
        // Guards against a hostile relayed correlationVector bypassing validation.
        let huge = format!("{}!", "x".repeat(200));
        for bad in ["user@contoso.com!", "!", "not-a-cv!", huge.as_str()] {
            assert!(is_valid(&extend(bad)), "extend({bad:?}) should reseed");
            assert!(
                is_valid(&increment(bad)),
                "increment({bad:?}) should reseed"
            );
            assert!(is_valid(&spin(bad)), "spin({bad:?}) should reseed");
        }
    }

    #[test]
    fn overflow_truncation_stays_a_valid_frozen_vector() {
        // Regression: a valid vector at exactly MAX_LEN whose final element is a
        // single digit. Truncating at a raw byte boundary would drop that digit
        // and leave a dangling '.', producing an invalid frozen body that forces
        // a spurious reseed downstream. Every operator must instead freeze to a
        // valid frozen vector within the cap.
        let cv = max_len_vector_single_digit_tail();
        assert_eq!(cv.len(), MAX_LEN);
        assert!(is_valid(&cv));
        assert!(cv.ends_with(".9"), "tail must be a single digit: {cv:?}");
        for out in [extend(&cv), increment(&cv), spin(&cv)] {
            assert!(out.ends_with(TERMINATOR), "{out:?} must be frozen");
            assert!(out.len() <= MAX_LEN, "{out:?} exceeds MAX_LEN");
            assert!(
                is_valid_frozen(&out),
                "frozen overflow {out:?} must round-trip is_valid_frozen"
            );
        }
    }

    #[test]
    fn is_valid_rejects_bad_shapes() {
        assert!(!is_valid(""));
        assert!(!is_valid(BASE)); // base only, no element
        assert!(!is_valid(&format!("{BASE}.")));
        assert!(!is_valid(&format!("{BASE}.x")));
        assert!(!is_valid("short.0"));
        assert!(!is_valid(&format!("{BASE}.0{TERMINATOR}"))); // terminated
    }

    #[test]
    fn is_valid_rejects_noncanonical_base_final_char() {
        // A 22-char base64 base whose final char does not encode a zero low
        // nibble is not something seed() could have produced.
        let bad_base = "AAAAAAAAAAAAAAAAAAAAAB"; // ends 'B'
        assert_eq!(bad_base.len(), BASE_LEN);
        assert!(!is_valid(&format!("{bad_base}.0")));
        // and an operator reseeds such an input instead of building on it.
        assert!(is_valid(&spin(&format!("{bad_base}.0"))));
    }

    #[test]
    fn is_valid_rejects_signed_and_nondigit_elements() {
        assert!(!is_valid(&format!("{BASE}.+1")));
        assert!(!is_valid(&format!("{BASE}.-1")));
        assert!(!is_valid(&format!("{BASE}.1.+2")));
        assert!(!is_valid(&format!("{BASE}. 1")));
    }

    #[test]
    fn is_valid_rejects_leading_zero_elements() {
        assert!(!is_valid(&format!("{BASE}.01")));
        assert!(!is_valid(&format!("{BASE}.007")));
        assert!(!is_valid(&format!("{BASE}.1.00")));
        // A bare zero element is canonical and must stay valid.
        assert!(is_valid(&format!("{BASE}.0")));
        assert!(is_valid(&format!("{BASE}.10")));
        // A relayed leading-zero vector reseeds instead of being built on.
        assert!(is_valid(&spin(&format!("{BASE}.01"))));
    }

    #[test]
    fn terminate_keeps_frozen_vector_within_cap() {
        // A valid vector at exactly MAX_LEN whose extension overflows must freeze
        // to a value that still fits within MAX_LEN (not MAX_LEN + 1).
        let cv = max_len_vector();
        assert_eq!(cv.len(), MAX_LEN);
        assert!(is_valid(&cv));
        let frozen = extend(&cv);
        assert!(frozen.ends_with(TERMINATOR));
        assert!(frozen.len() <= MAX_LEN, "frozen {frozen:?} exceeds MAX_LEN");
        assert!(is_valid_frozen(&frozen), "frozen {frozen:?} must be valid");
    }

    #[test]
    fn increment_terminates_and_caps_on_length_overflow() {
        // Final element "99" rolls to "100", gaining a char at the cap.
        let cv = max_len_vector();
        assert!(cv.ends_with(".99"));
        let out = increment(&cv);
        assert!(out.ends_with(TERMINATOR));
        assert!(out.len() <= MAX_LEN, "increment {out:?} exceeds MAX_LEN");
        assert!(
            is_valid_frozen(&out),
            "increment {out:?} must be valid frozen"
        );
    }

    #[test]
    fn spin_terminates_and_caps_on_length_overflow() {
        let mut cv = BASE.to_string();
        while cv.len() + 2 <= MAX_LEN {
            cv.push_str(".0");
        }
        // spin appends ".<u32>.0", which must overflow the cap and freeze.
        let out = spin(&cv);
        assert!(out.ends_with(TERMINATOR));
        assert!(out.len() <= MAX_LEN, "spin {out:?} exceeds MAX_LEN");
        assert!(is_valid_frozen(&out), "spin {out:?} must be valid frozen");
    }

    #[test]
    fn seed_from_bytes_is_deterministic() {
        let bytes = [0u8; 16];
        assert_eq!(seed_from_bytes(&bytes), seed_from_bytes(&bytes));
        // All-zero bytes encode to a base of 22 'A' characters.
        assert_eq!(
            seed_from_bytes(&bytes),
            format!("{}.0", "A".repeat(BASE_LEN))
        );
        assert!(is_valid(&seed_from_bytes(&bytes)));
    }

    #[test]
    fn seed_with_covers_rng_and_fallback_branches() {
        // RNG-success branch: uses the provided bytes verbatim, ignoring the
        // clock/nonce fallback inputs.
        let bytes = [0u8; 16];
        assert_eq!(seed_with(Some(bytes), 999, 7), seed_from_bytes(&bytes));
        // RNG-failure branch: deterministic given the fallback ticks + nonce, and
        // still a valid vector so seeding never yields a malformed token.
        let ticks = 0x0123_4567_89ab_cdef;
        let fallback = seed_with(None, ticks, 0);
        assert_eq!(fallback, seed_with(None, ticks, 0));
        assert!(is_valid(&fallback));
        // Different ticks yield a different fallback base.
        assert_ne!(fallback, seed_with(None, 0, 0));
        // Same tick but a different nonce also yields a distinct base, so
        // concurrent same-tick fallbacks do not collide.
        assert_ne!(fallback, seed_with(None, ticks, 1));
    }

    #[test]
    fn spin_with_is_deterministic_given_sources() {
        let parent = format!("{BASE}.0");
        let a = spin_with(&parent, 0x0123_4567_89ab_cdef, Some([0xAB, 0xCD]), 0);
        let b = spin_with(&parent, 0x0123_4567_89ab_cdef, Some([0xAB, 0xCD]), 0);
        assert_eq!(a, b);
        assert!(a.starts_with(&format!("{parent}.")));
        assert!(a.ends_with(".0"));
        assert!(is_valid(&a));
        // Different sources yield a different spin element.
        assert_ne!(a, spin_with(&parent, 0, Some([0x00, 0x01]), 0));
    }

    #[test]
    fn seed_wrapper_takes_fallback_when_rng_forced_to_fail() {
        // Drive the wrapper-level RNG-failure selection (not just the pure core):
        // seed() must still produce a valid vector via the clock+nonce fallback,
        // and successive calls differ because the fallback nonce advances.
        let _guard = test_rng::ForceRngFailure::new();
        let a = seed();
        let b = seed();
        assert!(is_valid(&a), "fallback seed must be valid: {a:?}");
        assert!(is_valid(&b));
        assert_ne!(a, b, "fallback nonce must keep concurrent seeds distinct");
    }

    #[test]
    fn spin_wrapper_takes_fallback_when_rng_forced_to_fail() {
        // Same for spin(): the wrapper's entropy source reports failure, so the
        // nonce-derived fallback entropy must keep sibling spins distinct.
        let _guard = test_rng::ForceRngFailure::new();
        let parent = format!("{BASE}.0");
        let a = spin(&parent);
        let b = spin(&parent);
        assert!(a.starts_with(&format!("{parent}.")), "{a:?}");
        assert!(is_valid(&a));
        assert_ne!(a, b, "fallback nonce must keep concurrent spins distinct");
    }

    #[test]
    fn spin_with_rng_failure_stays_distinct_by_nonce() {
        // When entropy is unavailable (None), the fallback nonce supplies the
        // 16 bits of uniqueness, so concurrent same-tick spins still differ.
        let parent = format!("{BASE}.0");
        let ticks = 0x0123_4567_89ab_cdef;
        let a = spin_with(&parent, ticks, None, 0);
        let b = spin_with(&parent, ticks, None, 0);
        assert_eq!(a, b, "deterministic given the same nonce");
        assert!(is_valid(&a));
        assert_ne!(
            a,
            spin_with(&parent, ticks, None, 1),
            "a different nonce must yield a distinct spin element"
        );
    }

    /// A valid vector of exactly [`MAX_LEN`] characters ending in a `.99`
    /// element (so incrementing or extending it overflows the length cap).
    fn max_len_vector() -> String {
        let mut cv = BASE.to_string(); // 22
        for _ in 0..51 {
            cv.push_str(".9"); // +2 each => 22 + 102 = 124
        }
        cv.push_str(".99"); // +3 => 127
        debug_assert_eq!(cv.len(), MAX_LEN);
        cv
    }

    /// A valid vector of exactly [`MAX_LEN`] characters ending in a single-digit
    /// element (`.9`) — the shape a raw byte-boundary truncation would break by
    /// chopping the final digit and leaving a dangling `.`.
    fn max_len_vector_single_digit_tail() -> String {
        let mut cv = BASE.to_string(); // 22
        cv.push_str(".99"); // +3 => 25 (odd, so the trailing ".9"s land on 127)
        for _ in 0..51 {
            cv.push_str(".9"); // +2 each => 25 + 102 = 127
        }
        debug_assert_eq!(cv.len(), MAX_LEN);
        cv
    }

    /// A valid vector of exactly [`MAX_LEN`] characters ending in a *multi-digit*
    /// element (`.42`). This is the adversarial overflow case: a raw cut at
    /// `MAX_LEN - 1` lands mid-element (`.42` -> `.4`), which is still a
    /// syntactically valid frozen body — so `is_valid_frozen` alone cannot catch
    /// the silent value falsification. Only dropping the whole trailing element
    /// preserves the vector's meaning.
    fn max_len_vector_multi_digit_tail() -> String {
        let mut cv = BASE.to_string(); // 22
        for _ in 0..51 {
            cv.push_str(".9"); // +2 each => 22 + 102 = 124
        }
        cv.push_str(".42"); // +3 => 127
        debug_assert_eq!(cv.len(), MAX_LEN);
        cv
    }

    #[test]
    fn is_relayable_accepts_mutable_and_frozen_rejects_garbage() {
        // A relayed vector is relayable iff spin would build on it (mutable) or
        // pass it through (valid frozen); everything else is reseeded.
        assert!(is_relayable(&format!("{BASE}.0")));
        assert!(is_relayable(&format!("{BASE}.1.2")));
        // A valid frozen vector is relayable (spin passes it through).
        assert!(is_relayable(&format!("{BASE}.0{TERMINATOR}")));
        // Malformed / hostile / empty inputs are not relayable.
        assert!(!is_relayable(""));
        assert!(!is_relayable(BASE)); // base only, no element
        assert!(!is_relayable(&format!("{BASE}.01"))); // leading zero
        assert!(!is_relayable("user@contoso.com!")); // hostile terminated
        assert!(!is_relayable("short.0"));
    }

    #[test]
    fn overflow_drops_whole_multidigit_element_not_just_a_digit() {
        // Regression for the exact-body invariant: at MAX_LEN with a multi-digit
        // tail (`.42`), the operators that overflow (extend, spin) must freeze by
        // dropping the ENTIRE trailing element, not by truncating it to `.4!`.
        // A length+is_valid_frozen check alone would accept the falsified `.4!`
        // body, so assert the precise expected string.
        let cv = max_len_vector_multi_digit_tail();
        assert_eq!(cv.len(), MAX_LEN);
        assert!(is_valid(&cv));
        assert!(cv.ends_with(".42"), "tail must be multi-digit: {cv:?}");
        // Expected frozen body = the vector with its whole rightmost element
        // dropped, plus the terminator.
        let (without_last, last) = cv.rsplit_once('.').unwrap();
        assert_eq!(last, "42");
        let expected = format!("{without_last}{TERMINATOR}");
        for out in [extend(&cv), spin(&cv)] {
            assert_eq!(
                out, expected,
                "overflow must drop the whole `.42` element, not falsify it to `.4{TERMINATOR}`"
            );
            assert!(is_valid_frozen(&out));
            assert!(out.len() <= MAX_LEN);
        }
        // increment(.42 -> .43) stays the same width, so it does NOT overflow and
        // must remain a valid mutable vector (guards against a false "always
        // freezes at cap" assumption).
        let incremented = increment(&cv);
        assert!(incremented.ends_with(".43"), "{incremented:?}");
        assert!(is_valid(&incremented));
    }
}
