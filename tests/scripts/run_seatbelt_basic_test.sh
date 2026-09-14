#!/bin/bash
# Seatbelt basic execution: exit codes, stdio, timeout, working directory.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/seatbelt_common.sh
. "$SCRIPT_DIR/lib/seatbelt_common.sh"

run_config "$(render seatbelt_basic_hello.json)"
expect_ok "a basic command runs under the sandbox" "SEATBELT_BASIC_OK"

run_config "$(render seatbelt_basic_exit_code.json)"
[ "$RC" = 42 ] || fail "a non-zero exit code propagates verbatim (got $RC, expected 42)" "$OUT"
pass "a non-zero exit code propagates verbatim"

run_config "$(render seatbelt_basic_stderr.json)"
expect_ok "stdout is captured" "SEATBELT_STDOUT_LINE"
expect_ok "stderr is captured" "SEATBELT_STDERR_LINE"

run_config "$(render seatbelt_basic_timeout.json)"
[ "$RC" != 0 ] || fail "a timeout fails the run" "$OUT"
grep -qF "timed out" <<<"$OUT" || fail "a timeout is reported as such" "$OUT"
pass "a timeout fails the run and is reported as such"
# The workload must have started; a timeout that fired before exec would be a
# different bug wearing the same exit code.
expect_marker "the timed-out workload had actually started" "SEATBELT_TIMEOUT_STARTED"

run_config "$(render seatbelt_basic_workdir.json)"
expect_ok "cwd is honored" "/private/tmp"

run_config "$(render seatbelt_basic_missing_command.json)"
[ "$RC" != 0 ] || fail "a missing executable fails the run" "$OUT"
pass "a missing executable fails the run"

summary "Seatbelt basic"
