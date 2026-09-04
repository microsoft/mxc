#!/bin/bash
# Seatbelt launchMethod "open".
#
# Open mode hands the workload to LaunchServices (`open -n -W -a Terminal`)
# instead of running it as a child, which changes what a test can observe:
#
#   * stdio is Stdio::null, so nothing the workload prints is ever captured.
#     Every observation below is a file written inside a granted path and read
#     back from the host afterwards.
#   * `open -W` waits for Terminal itself to quit, not for the window it just
#     opened, so a run that succeeded still reaches its timeout. Exit codes are
#     therefore deliberately not asserted -- only side effects are.
#
# This suite drives the real GUI, and open mode leaks: `open -n` starts a fresh
# Terminal *application instance* per run, and because the default shellExitAction
# keeps the window after the command exits, Terminal never quits -- so `open -W`
# never returns, MXC kills the waiter at its timeout, and the instance is
# orphaned. Worse, LaunchServices never retires the open-document request, so
# each new instance replays a growing backlog of them.
#
# Every launch here is therefore reaped: run_open_config waits for the workload's
# own sentinel file, then terminates exactly the Terminal instances that appeared
# during the run. Killing them also lets `open -W` return, so mxc-exec-mac exits
# normally and still removes its own temp files.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/seatbelt_common.sh
. "$SCRIPT_DIR/lib/seatbelt_common.sh"

[ -d /System/Applications/Utilities/Terminal.app ] ||
    fail "prerequisite: Terminal.app is required for launchMethod=open" ""
launchctl managername >/dev/null 2>&1 ||
    fail "prerequisite: launchMethod=open needs a GUI login session" ""

# Fixtures live under /private/tmp: a narrow grant on a $TMPDIR path under
# /var/folders cannot be traversed, because its ancestors are not readable.
OPENDIR="$(mktemp -d /private/tmp/mxc-seatbelt-open.XXXXXX)"
BASELINE_TERMS="$SEATBELT_TMP/terms.baseline"
pgrep -x Terminal | sort -u >"$BASELINE_TERMS"

# Reap anything still standing if an assertion aborts the suite mid-run.
reap_strays() {
    local now="$SEATBELT_TMP/terms.stray"
    pgrep -x Terminal | sort -u >"$now" 2>/dev/null || return 0
    local pid
    for pid in $(comm -13 "$BASELINE_TERMS" "$now"); do
        kill "$pid" 2>/dev/null
    done
}
trap 'reap_strays; rm -rf "$OPENDIR" "$SEATBELT_TMP"' EXIT

mkdir -p "$OPENDIR/work" "$OPENDIR/denied"
echo "top secret" > "$OPENDIR/denied/secret.txt"

read_fact() { [ -f "$OPENDIR/$1" ] && cat "$OPENDIR/$1" || echo "<missing>"; }

# Run a config, waiting on the workload's sentinel rather than the timeout:
# `open -W` would otherwise block for the full process.timeout on every run.
run_open_config() {
    local config_path="$1" sentinel="$2"
    shift 2
    local before="$SEATBELT_TMP/terms.before" after="$SEATBELT_TMP/terms.after"
    local outfile="$SEATBELT_TMP/open.out" rcfile="$SEATBELT_TMP/open.rc"

    pgrep -x Terminal | sort -u >"$before"
    rm -f "$OPENDIR/$sentinel" "$outfile" "$rcfile"

    { "$MXC_EXEC_MAC" "$@" "$config_path" >"$outfile" 2>&1; echo $? >"$rcfile"; } &
    local runner=$!

    local i=0
    while [ $i -lt 60 ] && [ ! -f "$OPENDIR/$sentinel" ]; do
        sleep 0.5
        i=$((i + 1))
    done
    sleep 1  # let the workload's remaining writes land

    pgrep -x Terminal | sort -u >"$after"
    local pid
    for pid in $(comm -13 "$before" "$after"); do
        kill "$pid" 2>/dev/null
    done

    wait "$runner" 2>/dev/null
    OUT="$(cat "$outfile" 2>/dev/null)"
    RC="$(cat "$rcfile" 2>/dev/null || echo 1)"
}

# --- the workload actually runs ---------------------------------------------

run_open_config "$(render seatbelt_open_basic.json OUT "$OPENDIR")" marker.txt

[ "$(read_fact marker.txt)" = "OPEN_RAN" ] ||
    fail "open mode runs the configured command" "marker=$(read_fact marker.txt)"
pass "open mode runs the configured command"

[ "$(read_fact env.txt)" = "open_env_ok" ] ||
    fail "open mode exports process.env into the workload" "env=$(read_fact env.txt)"
pass "open mode exports process.env into the workload"

# --- the sandbox profile is still enforced ----------------------------------
#
# Handing the workload to LaunchServices must not become an escape hatch: the
# helper script execs sandbox-exec, so deniedPaths still applies.

run_open_config "$(render seatbelt_open_enforced.json OUT "$OPENDIR")" verdict.txt

[ "$(read_fact verdict.txt)" = "DENIED" ] ||
    fail "open mode still enforces deniedPaths" "verdict=$(read_fact verdict.txt)"
pass "open mode still enforces deniedPaths"

[ -s "$OPENDIR/leak.txt" ] &&
    fail "the denied file must not be readable in open mode" "$(cat "$OPENDIR/leak.txt")"
pass "the denied file's contents never reached the workload"

# --- profile generation is unchanged by the launch method -------------------

run_open_config "$(render seatbelt_open_basic.json OUT "$OPENDIR")" marker.txt --debug
grep -qF "Seatbelt: --- begin generated profile ---" <<<"$OUT" ||
    fail "open mode still logs the generated profile under --debug" "$OUT"
pass "open mode still logs the generated profile under --debug"

# --- working directory -------------------------------------------------------
#
# The backend doc's "Working directory" section promises that process.cwd is
# resolved and exported as PWD, with no carve-out for open mode, so these two
# assertions encode that promise rather than today's behavior.

if [ "$(read_fact pwd.txt)" = "$OPENDIR/work" ]; then
    pass "open mode honors process.cwd"
else
    fail_soft "open mode honors process.cwd" "got=$(read_fact pwd.txt) want=$OPENDIR/work"
fi

if [ "$(read_fact pwdvar.txt)" = "$OPENDIR/work" ]; then
    pass "open mode exports PWD for the resolved cwd"
else
    fail_soft "open mode exports PWD for the resolved cwd" "got=$(read_fact pwdvar.txt)"
fi

# --- the launch must not orphan a Terminal instance (microsoft/mxc#1108) -----
#
# Deliberately unreaped: run_open_config exists to stop this suite leaking, so
# using it here would assert the workaround rather than the behavior. The run
# is left to finish on its own and the surviving instances are counted, then
# cleaned up regardless of the verdict.

TB="$SEATBELT_TMP/orphan.before"
TA="$SEATBELT_TMP/orphan.after"
pgrep -x Terminal | sort -u >"$TB"

RC=0
OUT="$("$MXC_EXEC_MAC" "$(render seatbelt_open_orphan.json OUT "$OPENDIR")" 2>&1)" || RC=$?

# A correctly-behaving launch closes its window, Terminal quits, and `open -W`
# returns; allow a few seconds for that teardown before calling it an orphan.
i=0
while [ $i -lt 5 ]; do
    pgrep -x Terminal | sort -u >"$TA"
    [ -z "$(comm -13 "$TB" "$TA")" ] && break
    sleep 1
    i=$((i + 1))
done
ORPHANS="$(comm -13 "$TB" "$TA" | tr '\n' ' ')"

if [ -z "$ORPHANS" ]; then
    pass "open mode leaves no orphaned Terminal instance"
else
    fail_soft "open mode leaves no orphaned Terminal instance (microsoft/mxc#1108)" \
        "surviving pid(s): $ORPHANS"
    for pid in $ORPHANS; do
        kill "$pid" 2>/dev/null
    done
fi

# The waiter is MXC's own child; it must never outlive the run either.
if pgrep -f "open -n -W -a Terminal" >/dev/null 2>&1; then
    fail_soft "no 'open -n -W' waiter survives the run" "$(pgrep -f 'open -n -W -a Terminal' | tr '\n' ' ')"
else
    pass "no 'open -n -W' waiter survives the run"
fi

# Terminal quitting on its own is what lets `open -W` return, so a run that had
# to be killed by process.timeout is the same defect seen from the other side.
if grep -qi "timed out" <<<"$OUT"; then
    fail_soft "the run completes without hitting process.timeout (microsoft/mxc#1108)" \
        "$(grep -i 'timed out' <<<"$OUT" | head -1)"
else
    pass "the run completes without hitting process.timeout"
fi

summary "Seatbelt launchMethod=open"
