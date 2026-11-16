#!/bin/bash
# Seatbelt process lifetime: nothing the workload starts may outlive the run,
# including a process that leaves MXC's session with setsid().
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/seatbelt_common.sh
. "$SCRIPT_DIR/lib/seatbelt_common.sh"

NODE="$(command -v node)" || fail "node is required by this suite"
NODE="$(realpath "$NODE")"
# Homebrew builds link Homebrew dylibs, so the sandbox needs that whole root.
case "$NODE" in
    /opt/homebrew/*) NODE_ROOT=/opt/homebrew ;;
    /usr/local/Cellar/*) NODE_ROOT=/usr/local ;;
    *) NODE_ROOT="$(dirname "$(dirname "$NODE")")" ;;
esac

TESTDIR="$(mktemp -d /private/tmp/mxc-seatbelt-lifetime.XXXXXX)"
LEAKED=""
cleanup() {
    local pid
    for pid in $LEAKED; do kill -KILL "$pid" 2>/dev/null; done
    rm -rf "$TESTDIR" "$SEATBELT_TMP"
}
trap cleanup EXIT

cat >"$TESTDIR/background_job.sh" <<'EOF'
marker="$1"
/bin/sh -c 'echo started > "$0"; exec /bin/sleep 300' "$marker" </dev/null >/dev/null 2>&1 &
echo "DESCENDANT=$!"
i=0
while [ ! -s "$marker" ] && [ $i -lt 200 ]; do sleep 0.05; i=$((i+1)); done
[ -s "$marker" ] && echo SEATBELT_LIFETIME_STARTED
EOF

cat >"$TESTDIR/detach.js" <<'EOF'
const { spawn } = require('child_process');
const fs = require('fs');
const marker = process.argv[2];
const child = spawn('/bin/sh', ['-c', 'echo started > "$0"; exec /bin/sleep 300', marker], {
  detached: true,
  stdio: 'ignore',
});
child.unref();
console.log(`DESCENDANT=${child.pid}`);
const deadline = Date.now() + 10000;
const timer = setInterval(() => {
  if (fs.existsSync(marker) && fs.statSync(marker).size > 0) {
    console.log('SEATBELT_LIFETIME_STARTED');
    clearInterval(timer);
  } else if (Date.now() > deadline) {
    clearInterval(timer);
    process.exitCode = 97;
  }
}, 50);
EOF

# The process named by KEY=<pid> in the output must be gone shortly after the run.
expect_gone() {
    local name="$1" key="$2" pid
    pid="$(sed -n "s/^$key=\([0-9][0-9]*\)$/\1/p" <<<"$OUT" | head -n 1)"
    [ -n "$pid" ] || fail "[setup] $name: no $key=<pid> in the output" "$OUT"
    for _ in $(seq 1 100); do
        if ! kill -0 "$pid" 2>/dev/null; then
            pass "[lifetime] $name was killed when the run ended"
            return
        fi
        sleep 0.05
    done
    LEAKED="$LEAKED $pid"
    fail_soft "[lifetime] $name outlived the run" "PID $pid was still running 5s after mxc-exec-mac returned"
}

run_config "$(render seatbelt_lifetime_background_job.json TESTDIR "$TESTDIR")"
expect_ok "[setup] background job started inside the sandbox" "SEATBELT_LIFETIME_STARTED"
expect_gone "background job" DESCENDANT

run_config "$(render seatbelt_lifetime_detached_node.json TESTDIR "$TESTDIR" NODE "$NODE" NODE_ROOT "$NODE_ROOT")"
expect_ok "[setup] Node detached child started inside the sandbox" "SEATBELT_LIFETIME_STARTED"
expect_gone "Node detached child" DESCENDANT

summary "Seatbelt process lifetime"
