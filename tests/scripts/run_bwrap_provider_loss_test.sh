#!/bin/bash
# Bubblewrap network-provider loss test.
#
# The 0.8 private-namespace modes give the workload a network whose only route
# is slirp4netns. Readiness was checked once at startup and never again, so
# killing slirp mid-run left the sandbox running against a dead network: every
# connection failed with a generic transport error and the run was attributed
# to whatever the workload reported. This test kills slirp under a live
# workload and pins the failure that replaced that silence.
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

if ! command -v slirp4netns >/dev/null 2>&1; then
    echo "SKIP: slirp4netns not installed; this test needs the private-namespace path."
    exit 77
fi

WORKLOAD_MARKER="sleep 985"
LOG=$(mktemp)
RUN_PID=""

cleanup() {
    [ -n "$RUN_PID" ] && kill -9 "$RUN_PID" 2>/dev/null || true
    pkill -f "$WORKLOAD_MARKER" 2>/dev/null || true
    rm -f "$LOG"
}
trap cleanup EXIT

echo "Running Bubblewrap provider-loss test: a slirp4netns killed mid-run fails the run..."

# Every slirp already on this host, so the one this run adds can be told apart
# from a developer's or a concurrent suite's.
before=$(pgrep -x slirp4netns 2>/dev/null | sort || true)

"$LXC_EXEC" --experimental "$REPO_DIR/tests/configs/bubblewrap_provider_loss.json" \
    >"$LOG" 2>&1 &
RUN_PID=$!

# The kill must land while the workload is running, so wait for the workload's
# own marker rather than for the executor to merely have been spawned.
deadline=$((SECONDS + 60))
while ! grep -qF "PROVIDER_LOSS_STARTED" "$LOG" 2>/dev/null; do
    if [ $SECONDS -ge $deadline ]; then
        cat "$LOG"
        fail "the workload never started, so this proves nothing"
    fi
    if ! kill -0 "$RUN_PID" 2>/dev/null; then
        cat "$LOG"
        fail "the run exited before the workload started"
    fi
    sleep 0.1
done

after=$(pgrep -x slirp4netns 2>/dev/null | sort || true)
victim=$(comm -13 <(echo "$before") <(echo "$after") | head -1)

if [ -z "$victim" ]; then
    cat "$LOG"
    fail "no slirp4netns was started for this run, so there is nothing to kill"
fi

kill -9 "$victim" 2>/dev/null || fail "could not kill slirp4netns ($victim)"

rc=0
wait "$RUN_PID" || rc=$?
RUN_PID=""
out=$(cat "$LOG")

if [ "$rc" = 0 ]; then
    echo "$out"
    fail "the run succeeded despite losing the network its workload depended on"
fi
if ! grep -qF "lost its network provider" <<<"$out"; then
    echo "$out"
    fail "exited $rc without naming the lost provider, which is the whole point"
fi

# The sandbox has to actually be gone: reporting the loss while leaving the
# workload running against a dead network would be the same bug with a message.
sleep 2
if pgrep -f "$WORKLOAD_MARKER" >/dev/null 2>&1; then
    pkill -f "$WORKLOAD_MARKER" || true
    fail "the workload outlived the provider whose loss was reported"
fi

echo "PASS: a slirp4netns killed mid-run fails the run"
echo "All Bubblewrap provider-loss tests passed."
