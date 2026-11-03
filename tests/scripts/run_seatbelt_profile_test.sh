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
expect_marker "the run without --debug still executed" "SEATBELT_BASIC_OK"
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

# The cleanup rules are per run, so they must stay out of the copyable block.
grep -qF "com.microsoft.mxc.run." <<<"$PROFILE" &&
    fail "the copyable profile carries this run's cleanup rules" "$PROFILE"
pass "the copyable profile carries no per-run cleanup rules"
RULES="$(sed -n "/^${END}\$/,\$p" <<<"$OUT" | grep -F "com.microsoft.mxc.run." | sed 's/^Seatbelt: *//')"
[ "$(wc -l <<<"$RULES")" -eq 2 ] || fail "this run's two cleanup rules follow the profile" "$OUT"
pass "this run's cleanup rules are printed after the profile"

# JSON config whose profileOverride is the given text.
override_config() {
    local profile
    profile="$(awk 'BEGIN { ORS = "" } { gsub(/\\/, "\\\\"); gsub(/"/, "\\\""); gsub(/\t/, "\\t");
        if (NR > 1) print "\\n"; print }' <<<"$1")"
    printf '{"version":"1.0.0","containment":"seatbelt",
"process":{"commandLine":"echo %s","timeout":10000},
"seatbelt":{"profileOverride":"%s"}}\n' "$2" "$profile" >"$SEATBELT_TMP/override.json"
    echo "$SEATBELT_TMP/override.json"
}

run_config "$(override_config "$PROFILE" PASTED_PROFILE_OK)"
expect_ok "the copied profile runs as a profileOverride" "PASTED_PROFILE_OK"

# Another run's cleanup rules would make that run kill this run's processes.
run_config "$(override_config "$PROFILE"$'\n'"$RULES" COPIED_RULES_RAN)"
[ "$RC" != 0 ] || fail "a profileOverride with another run's cleanup rules was accepted" "$OUT"
expect_marker "copied cleanup rules are refused" "MXC reserves for its process cleanup rules"
expect_absent "the workload never ran with copied cleanup rules" "COPIED_RULES_RAN"

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
expect_marker "the --log-file run still executed" "SEATBELT_BASIC_OK"
expect_absent "--log-file alone does not print the profile to the console" "$BEGIN"
[ -f "$LOG" ] || fail "--log-file produced no file"
grep -qF "$BEGIN" "$LOG" || fail "--log-file captures the profile" "$(cat "$LOG")"
# The rules themselves must reach the file, not just the marker. Asserted by
# content rather than by exact framing: the file sink writes one timestamped
# record per line, so this copy is deliberately not verbatim -- `--debug` is
# the path that promises a copy-pasteable block.
for rule in "(version 1)" "(deny default)"; do
    grep -qF "$rule" "$LOG" ||
        fail "--log-file captures the profile rules (missing '$rule')" "$(cat "$LOG")"
done
pass "--log-file captures the profile rules without printing them"

summary "Seatbelt profile output"
