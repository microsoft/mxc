#!/bin/bash
# Bubblewrap teardown test.
#
# Nothing asserted that a run leaves no survivors. The claim that a leak is
# unreachable by construction -- the namespace dies with the process holding
# it -- was untested, and it was FALSE for descendants: `bwrap` forks, so pid 1
# of the sandbox namespace is not the process the executor spawned, and killing
# that handle on timeout left a backgrounded child running after teardown had
# already removed its network enforcement. `--die-with-parent` closes that; this
# test is the regression lock.
#
# Each timed-out run backgrounds a long sleep with a unique duration, which is
# the survivor probe: the sleep far outlasts the 1500ms timeout, so if it is
# still present afterwards it survived teardown. Process counts are compared
# against a pre-run baseline so unrelated `bwrap`/`slirp4netns` processes on a
# developer's machine cannot be mistaken for leaks.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
LXC_EXEC="$REPO_DIR/src/target/release/lxc-exec"

if [ ! -f "$LXC_EXEC" ]; then
    LXC_EXEC="$REPO_DIR/src/target/debug/lxc-exec"
fi

if [ ! -f "$LXC_EXEC" ]; then
    echo "Error: lxc-exec not found. Run build.sh first."
    exit 1
fi

fail() { echo "FAIL: $1"; exit 1; }

count_proc() { pgrep -c -f "$1" 2>/dev/null || true; }

# Runs a config that is expected to time out, then asserts nothing outlived it.
assert_no_survivors() {
    local label="$1"
    local config="$2"
    local sleep_marker="$3"

    echo "Running Bubblewrap teardown test: $label..."

    local bwrap_before slirp_before
    bwrap_before=$(count_proc '^bwrap')
    slirp_before=$(count_proc 'slirp4netns')

    # Output goes to a file rather than `$(...)`: a surviving descendant keeps
    # the pipe's write end open, so command substitution would block for the
    # full sleep duration instead of failing. `timeout` bounds the executor
    # itself, which must exit long before the sleep does.
    local log rc=0
    log=$(mktemp)
    timeout 60 "$LXC_EXEC" --experimental "$REPO_DIR/tests/configs/$config" >"$log" 2>&1 || rc=$?
    local out
    out=$(cat "$log")
    rm -f "$log"

    if [ "$rc" = 124 ]; then
        fail "$label (the executor itself hung and was killed after 60s)"
    fi

    # The run must actually have timed out; otherwise there was never anything
    # to leak and the assertions below are vacuous. A nonzero exit alone is not
    # enough -- any backend error raised after TEARDOWN_STARTED would satisfy
    # the survivor checks trivially -- so pin the timeout diagnostic itself.
    if [ "$rc" = 0 ]; then
        echo "$out"
        fail "$label (the run did not time out, so this proves nothing)"
    fi
    if ! grep -qF "script timed out" <<<"$out"; then
        echo "$out"
        fail "$label (exited $rc for some reason other than the timeout, so this proves nothing)"
    fi
    if ! grep -qF "TEARDOWN_STARTED" <<<"$out"; then
        echo "$out"
        fail "$label (the workload never started, so this proves nothing)"
    fi

    # Teardown is synchronous with the executor exiting, but the kernel reaps
    # asynchronously; give it a moment before declaring a leak.
    sleep 2

    if pgrep -f "$sleep_marker" >/dev/null 2>&1; then
        pgrep -af "$sleep_marker" || true
        # Clean up before failing: the marker uniquely identifies this test's
        # descendant, and leaving it sleeping for ~16 minutes would pollute the
        # host and skew the baseline counts of any later run.
        pkill -f "$sleep_marker" || true
        fail "$label (a backgrounded descendant outlived the sandbox)"
    fi

    local bwrap_after slirp_after
    bwrap_after=$(count_proc '^bwrap')
    slirp_after=$(count_proc 'slirp4netns')

    if [ "$bwrap_after" -gt "$bwrap_before" ]; then
        fail "$label (orphaned bwrap: $bwrap_before before, $bwrap_after after)"
    fi
    if [ "$slirp_after" -gt "$slirp_before" ]; then
        fail "$label (orphaned slirp4netns: $slirp_before before, $slirp_after after)"
    fi

    echo "PASS: $label"
}

assert_no_survivors "a timed-out run leaves no descendant or orphaned bwrap" \
    "bubblewrap_teardown_timeout.json" "sleep 987"

# The private-namespace path additionally stands up slirp4netns, which is the
# other thing that could outlive the run.
if command -v slirp4netns >/dev/null 2>&1; then
    assert_no_survivors "a timed-out private-namespace run leaves no slirp4netns" \
        "bubblewrap_teardown_timeout_netns.json" "sleep 986"
else
    echo "SKIP: slirp4netns not installed; the private-namespace teardown case needs it."
    # 77, not 0: run_bwrap_all_tests.sh must record SKIPPED, not a false PASS,
    # or strict CI cannot tell that the slirp case never ran.
    exit 77
fi

echo "All Bubblewrap teardown tests passed."
