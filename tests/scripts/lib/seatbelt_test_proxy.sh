#!/bin/bash
# Helper to launch/stop the bundled `unix-test-proxy` binary directly (not via
# a config's `builtinTestServer: true`), for tests that need to know the
# OS-assigned port ahead of time so it can be embedded into a dynamically
# generated config (e.g. `network.proxy.localhost` or
# `runtimeConfig.networkProxy`, neither of which has a "launch it for me"
# shorthand the way `builtinTestServer` does).
#
# The sourcing script must set UNIX_TEST_PROXY (see seatbelt_env.sh) before
# calling start_test_proxy.
#
# Bash-3.2 compatible (macOS ships 3.2, no `{FD}` dynamic fd allocation), so
# this uses a fixed fd (9) for the proxy's stdin pipe. Only one test proxy may
# be active per script at a time.

# Starts unix-test-proxy in the background. Any arguments are passed through
# after --ready-file/--bind-address (e.g. --allow-host, --block-host,
# --default-policy). On success sets TEST_PROXY_PID, TEST_PROXY_PORT,
# TEST_PROXY_TMPDIR. Returns non-zero (and prints the proxy's log) if it never
# publishes a ready file.
start_test_proxy() {
    if [ -z "${UNIX_TEST_PROXY:-}" ] || [ ! -f "$UNIX_TEST_PROXY" ]; then
        echo "Error: UNIX_TEST_PROXY not set or not found. Run ./build-mac.sh first." >&2
        return 1
    fi

    local tmpdir
    tmpdir=$(mktemp -d "${TMPDIR:-/tmp}/mxc-seatbelt-proxy.XXXXXX")
    local ready_file="$tmpdir/ready.port"
    local fifo="$tmpdir/stdin.fifo"
    mkfifo "$fifo"

    # Open the fifo read-write on fd 9. This shell process (and the child
    # after fork, which inherits fd 9 as its stdin) then holds a write end of
    # its own read fd open, so the proxy's parent-lifetime EOF watcher never
    # observes a spurious EOF and self-terminates before publishing its ready
    # file. We shut the proxy down explicitly via SIGTERM in stop_test_proxy
    # instead of relying on that mechanism.
    exec 9<>"$fifo"

    "$UNIX_TEST_PROXY" --ready-file "$ready_file" --bind-address 127.0.0.1 "$@" \
        <&9 >"$tmpdir/proxy.log" 2>&1 &
    TEST_PROXY_PID=$!
    TEST_PROXY_TMPDIR="$tmpdir"

    local waited=0
    while [ ! -f "$ready_file" ]; do
        if ! kill -0 "$TEST_PROXY_PID" 2>/dev/null; then
            echo "unix-test-proxy exited before publishing its ready file. Log:" >&2
            cat "$tmpdir/proxy.log" >&2
            exec 9<&-
            rm -rf "$tmpdir"
            return 1
        fi
        sleep 0.1
        waited=$((waited + 1))
        if [ "$waited" -ge 100 ]; then
            echo "Timed out waiting for unix-test-proxy to become ready." >&2
            kill -TERM "$TEST_PROXY_PID" 2>/dev/null || true
            exec 9<&-
            rm -rf "$tmpdir"
            return 1
        fi
    done
    TEST_PROXY_PORT="$(cat "$ready_file")"
}

# Stops the proxy started by start_test_proxy and cleans up its temp dir.
stop_test_proxy() {
    if [ -n "${TEST_PROXY_PID:-}" ] && kill -0 "$TEST_PROXY_PID" 2>/dev/null; then
        kill -TERM "$TEST_PROXY_PID" 2>/dev/null || true
        local waited=0
        while kill -0 "$TEST_PROXY_PID" 2>/dev/null; do
            sleep 0.1
            waited=$((waited + 1))
            if [ "$waited" -ge 30 ]; then
                kill -KILL "$TEST_PROXY_PID" 2>/dev/null || true
                break
            fi
        done
        wait "$TEST_PROXY_PID" 2>/dev/null || true
    fi
    exec 9<&- 2>/dev/null || true
    if [ -n "${TEST_PROXY_TMPDIR:-}" ]; then
        rm -rf "$TEST_PROXY_TMPDIR"
    fi
    unset TEST_PROXY_PID TEST_PROXY_PORT TEST_PROXY_TMPDIR
}
