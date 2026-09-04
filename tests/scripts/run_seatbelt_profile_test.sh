#!/bin/bash
# Seatbelt generated-profile output (`--debug` / `--log-file`).
#
# The profile is the whole enforcement artifact, so being able to read the
# exact text the kernel was handed is what makes an unexpected denial
# diagnosable. This suite asserts the documented contract: the block appears
# only under --debug, is delimited by stable markers, and is reproduced
# verbatim so it can be pasted straight into `profileOverride` or
# `sandbox-exec -f`.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/seatbelt_common.sh
. "$SCRIPT_DIR/lib/seatbelt_common.sh"

BEGIN="Seatbelt: --- begin generated profile ---"
END="Seatbelt: --- end generated profile ---"

# Everything between the markers, exclusive.
extract() { sed -n "/^${BEGIN}\$/,/^${END}\$/p" <<<"$1" | sed '1d;$d'; }

CFG="$(render seatbelt_basic_hello.json)"

run_config "$CFG"
expect_absent "the profile is not printed without --debug" "$BEGIN"

run_config "$CFG" --debug
expect_marker "--debug prints the begin marker" "$BEGIN"
expect_marker "--debug prints the end marker" "$END"

PROFILE="$(extract "$OUT")"
[ -n "$PROFILE" ] || fail "the marked block is empty" "$OUT"
pass "the markers delimit a non-empty profile"

grep -qF "(version 1)" <<<"$PROFILE" || fail "the profile declares (version 1)" "$PROFILE"
pass "the profile declares (version 1)"

# Default-deny is the property everything else rests on.
grep -qF "(deny default)" <<<"$PROFILE" || fail "the profile is default-deny" "$PROFILE"
pass "the profile is default-deny"

# No log prefixes inside the block, or it would not be pasteable.
if grep -qE '^\[.*\] ' <<<"$PROFILE"; then
    fail "profile lines carry a log prefix and would not be copy-pasteable" "$PROFILE"
fi
pass "profile lines carry no log prefix"

# The strongest available check that the emitted text is a usable profile:
# hand it back to the OS through the documented paste target.
if command -v sandbox-exec >/dev/null 2>&1; then
    echo "$PROFILE" >"$SEATBELT_TMP/p.sb"
    if ! sandbox-exec -f "$SEATBELT_TMP/p.sb" /usr/bin/true >"$SEATBELT_TMP/sb.err" 2>&1; then
        fail "the emitted profile was rejected by sandbox-exec" "$(cat "$SEATBELT_TMP/sb.err")"
    fi
    pass "the emitted profile is accepted verbatim by sandbox-exec"
else
    fail "sandbox-exec is required by this suite"
fi

# A grant named in the config must be visible in the profile it produced.
run_config "$(render seatbelt_fs_baseline_reads.json)" --debug
grep -qF "/bin" <<<"$(extract "$OUT")" || fail "the profile names the baseline read paths" "$OUT"
pass "the profile names the paths it was built from"

# profileOverride replaces generation, so the logged block must be the caller's
# own text -- otherwise --debug would show a profile that was never applied.
run_config "$(render seatbelt_profile_override_marker.json)" --debug
OVERRIDE="$(extract "$OUT")"
grep -qF "MXC_OVERRIDE_SENTINEL" <<<"$OVERRIDE" ||
    fail "profileOverride is echoed verbatim" "$OVERRIDE"
grep -qF "(deny default)" <<<"$OVERRIDE" &&
    fail "the generated profile leaked into a profileOverride run" "$OVERRIDE"
pass "profileOverride is logged verbatim instead of a generated profile"

# --log-file is the alternative sink for callers that cannot take console noise.
LOG="$SEATBELT_TMP/profile.log"
run_config "$CFG" --log-file "$LOG"
expect_absent "--log-file alone does not print the profile to the console" "$BEGIN"
[ -f "$LOG" ] || fail "--log-file produced no file"
grep -qF "$BEGIN" "$LOG" || fail "--log-file captures the profile" "$(cat "$LOG")"
pass "--log-file captures the profile without printing it"

summary "Seatbelt profile output"
