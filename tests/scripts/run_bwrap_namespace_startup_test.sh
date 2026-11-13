#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
if [ -z "${LXC_EXEC:-}" ]; then
    LXC_EXEC="$REPO_DIR/src/target/release/lxc-exec"
    if [ ! -x "$LXC_EXEC" ]; then
        LXC_EXEC="$REPO_DIR/src/target/debug/lxc-exec"
    fi
fi
if [ ! -x "$LXC_EXEC" ]; then
    echo "Error: lxc-exec not found: $LXC_EXEC"
    exit 1
fi

for tool in bwrap unshare slirp4netns iptables-restore timeout; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "SKIP: $tool is required for namespace startup tests."
        exit 77
    fi
done

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT
mkdir "$WORK_DIR/shim"
export REAL_BWRAP REAL_UNSHARE REAL_RESTORE
REAL_BWRAP="$(command -v bwrap)"
REAL_UNSHARE="$(command -v unshare)"
REAL_RESTORE="$(command -v iptables-restore)"
export PATH="$WORK_DIR/shim:$PATH"

cat >"$WORK_DIR/shim/unshare" <<'SHIM'
#!/bin/sh
if [ "${4:-}" = "--net" ]; then
    echo probe >>"$TEST_LOG"
    echo "test: disposable namespace refused" >&2
    exit 1
fi
if [ "${1:-}" = "--user" ]; then
    echo supervisor >>"$TEST_LOG"
    echo "$$" >"$TEST_PID"
    case "${TEST_FAILURE:-}" in
        refuse) echo "test: supervisor namespace refused" >&2; exit 1 ;;
        timeout) exec sleep 300 ;;
    esac
fi
exec "$REAL_UNSHARE" "$@"
SHIM
cat >"$WORK_DIR/shim/bwrap" <<'SHIM'
#!/bin/sh
if [ "${TEST_FAILURE:-}" = "bwrap" ] && [ "${1:-}" != "--version" ]; then
    echo "test: bwrap network namespace refused" >&2
    exit 1
fi
exec "$REAL_BWRAP" "$@"
SHIM
cat >"$WORK_DIR/shim/iptables-restore" <<'SHIM'
#!/bin/sh
if [ "${TEST_FAILURE:-}" = "rules" ] && [ "${1:-}" != "--version" ]; then
    echo "test: rule installation refused" >&2
    exit 1
fi
exec "$REAL_RESTORE" "$@"
SHIM
chmod +x "$WORK_DIR/shim/unshare" "$WORK_DIR/shim/bwrap" "$WORK_DIR/shim/iptables-restore"

for mode in proxy firewall; do
    proxy=""
    egress="allow"
    if [ "$mode" = proxy ]; then
        egress="deny"
        proxy=', "runtimeConfig": { "networkProxy": "http://127.0.0.1:3128" }'
    fi
    cat >"$WORK_DIR/$mode.json" <<CONFIG
{
  "version": "1.0.0",
  "containerId": "namespace-startup-$mode",
  "containment": "bubblewrap",
  "process": { "commandLine": "echo WORKLOAD_STARTED; readlink /proc/self/ns/net" },
  "network": {
    "egress": { "default": "$egress" },
    "ingress": { "default": "deny", "hostLoopback": "deny" }
  }
  $proxy
}
CONFIG
done

fail() { echo "FAIL: $*" >&2; exit 1; }

run_case() {
    local mode="$1" label="$2" failure="$3"
    shift 3
    local dir="$WORK_DIR/$label"
    mkdir "$dir"
    local rc=0
    TEST_LOG="$dir/unshare.log" TEST_PID="$dir/supervisor.pid" TEST_FAILURE="$failure" \
        timeout 30 "$LXC_EXEC" --experimental "$@" "$WORK_DIR/$mode.json" \
        >"$dir/output" 2>&1 || rc=$?
    echo "$rc" >"$dir/exit"
}

for mode in proxy firewall; do
    run_case "$mode" "$mode-control" ""
    output="$(cat "$WORK_DIR/$mode-control/output")"
    if [ "$(cat "$WORK_DIR/$mode-control/exit")" != 0 ] ||
        ! grep -qF WORKLOAD_STARTED <<<"$output"; then
        fail "$mode launch: $output"
    fi
    sandbox_ns="$(sed -n '/^net:\[/p' <<<"$output" | tail -n 1)"
    if [ -z "$sandbox_ns" ] || [ "$sandbox_ns" = "$(readlink /proc/self/ns/net)" ]; then
        fail "$mode launch did not use a private network namespace: $output"
    fi
    if [ "$(grep -c '^supervisor$' "$WORK_DIR/$mode-control/unshare.log")" != 1 ]; then
        fail "$mode launch did not create exactly one supervisor"
    fi
    if grep -q '^probe$' "$WORK_DIR/$mode-control/unshare.log"; then
        fail "$mode launch allocated a disposable namespace"
    fi

    run_case "$mode" "$mode-dry-run" "" --dry-run
    output="$(cat "$WORK_DIR/$mode-dry-run/output")"
    if [ "$(cat "$WORK_DIR/$mode-dry-run/exit")" = 0 ] ||
        ! grep -qF "host refused" <<<"$output" ||
        grep -qF WORKLOAD_STARTED <<<"$output"; then
        fail "$mode dry run did not report namespace refusal: $output"
    fi
    if ! grep -q '^probe$' "$WORK_DIR/$mode-dry-run/unshare.log"; then
        fail "$mode dry run did not probe namespace availability"
    fi

    for failure in refuse timeout bwrap rules; do
        label="$mode-$failure"
        run_case "$mode" "$label" "$failure"
        output="$(cat "$WORK_DIR/$label/output")"
        rc="$(cat "$WORK_DIR/$label/exit")"
        if [ "$rc" = 0 ] || [ "$rc" = 124 ] ||
            grep -qF WORKLOAD_STARTED <<<"$output"; then
            fail "$label did not fail before the workload (exit $rc): $output"
        fi
        case "$failure" in
            refuse) marker="test: supervisor namespace refused" ;;
            timeout) marker="timed out waiting for user namespace startup" ;;
            bwrap) marker="test: bwrap network namespace refused" ;;
            rules) marker="test: rule installation refused" ;;
        esac
        grep -qF "$marker" <<<"$output" || fail "$label missing diagnostic: $output"
        if [ "$failure" = bwrap ] && ! grep -qF "user.max_net_namespaces" <<<"$output"; then
            fail "$label missing namespace guidance: $output"
        fi
        pid="$(cat "$WORK_DIR/$label/supervisor.pid")"
        if kill -0 "$pid" 2>/dev/null; then
            fail "$label left supervisor $pid running"
        fi
    done
done

mkdir "$WORK_DIR/capability"
capability_output="$(
    TEST_LOG="$WORK_DIR/capability/unshare.log" \
        TEST_PID="$WORK_DIR/capability/supervisor.pid" TEST_FAILURE="" \
        timeout 30 "$LXC_EXEC" --available-backends 2>&1
)"
if ! grep -qF "host refused" <<<"$capability_output" ||
    grep -qF '"proxyEnforcement"' <<<"$capability_output" ||
    ! grep -q '^probe$' "$WORK_DIR/capability/unshare.log"; then
    fail "capability discovery did not report namespace refusal: $capability_output"
fi

for index in 1 2 3 4; do
    run_case firewall "parallel-$index" "" &
    pids[index]=$!
done
parallel_failed=0
for index in 1 2 3 4; do
    if ! wait "${pids[$index]}"; then
        parallel_failed=1
    fi
done
if [ "$parallel_failed" != 0 ]; then
    fail "a parallel test process failed"
fi
for index in 1 2 3 4; do
    dir="$WORK_DIR/parallel-$index"
    if [ "$(cat "$dir/exit")" != 0 ] || ! grep -qF WORKLOAD_STARTED "$dir/output"; then
        fail "parallel launch $index failed: $(cat "$dir/output")"
    fi
    if [ "$(grep -c '^supervisor$' "$dir/unshare.log")" != 1 ] ||
        grep -q '^probe$' "$dir/unshare.log"; then
        fail "parallel launch $index allocated an unexpected namespace"
    fi
done

echo "PASS: Bubblewrap namespace startup and dry-run validation"
