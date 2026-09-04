#!/bin/bash
# Run every Seatbelt sandbox test.
#
# Unlike the Bubblewrap and LXC harnesses, this one has no skip path. A
# Seatbelt suite is only ever invoked on a macOS host that is supposed to be
# able to execute it, so an absent binary, missing python3 or unreachable
# network anchor means the environment is misconfigured -- not that the test is
# inapplicable. Reporting that as "skipped" is how a gate goes green having
# verified nothing, so exit 77 is treated as a failure here.
#
# The launchMethod=open suite drives LaunchServices, so it needs a GUI login
# session and leaves Terminal windows open behind it.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PASSED=0
FAILED=0
FAILURES=""

check_line_endings() {
    if grep -rPl '\r$' "$SCRIPT_DIR"/run_seatbelt_*.sh "$SCRIPT_DIR"/lib/seatbelt_common.sh >/dev/null 2>&1; then
        echo "ERROR: Shell scripts have Windows line endings (CRLF)."
        echo "Fix with: sed -i '' 's/\r\$//' $SCRIPT_DIR/run_seatbelt_*.sh $SCRIPT_DIR/lib/seatbelt_common.sh"
        exit 1
    fi
}

check_line_endings

if [ "$(uname -s)" != "Darwin" ]; then
    echo "ERROR: the Seatbelt suite requires macOS (found $(uname -s))."
    exit 1
fi

# Several suites assert that the sandbox denies something. Under root, a denial
# can be masked, so a pass would not mean what it says.
if [ "$(id -u)" -eq 0 ]; then
    echo "ERROR: run this suite as an unprivileged user, not root."
    exit 1
fi

run_test() {
    local name="$1"
    local script="$2"
    local rc=0
    echo "=== $name ==="
    bash "$script" || rc=$?
    if [ "$rc" = 0 ]; then
        echo "PASS: $name"
        PASSED=$((PASSED + 1))
    else
        if [ "$rc" = 77 ]; then
            echo "FAIL: $name (prerequisite absent -- this host is expected to provide it)"
        else
            echo "FAIL: $name"
        fi
        FAILED=$((FAILED + 1))
        FAILURES="$FAILURES\n  - $name"
    fi
    echo ""
}

run_test "Seatbelt Basic" "$SCRIPT_DIR/run_seatbelt_basic_test.sh"
run_test "Seatbelt Filesystem" "$SCRIPT_DIR/run_seatbelt_filesystem_test.sh"
run_test "Seatbelt Path Resolution" "$SCRIPT_DIR/run_seatbelt_path_resolution_test.sh"
run_test "Seatbelt UNIX Sockets" "$SCRIPT_DIR/run_seatbelt_unix_socket_test.sh"
run_test "Seatbelt Directional Network" "$SCRIPT_DIR/run_seatbelt_network_test.sh"
run_test "Seatbelt Legacy Network" "$SCRIPT_DIR/run_seatbelt_network_legacy_test.sh"
run_test "Seatbelt Rejections" "$SCRIPT_DIR/run_seatbelt_rejections_test.sh"
run_test "Seatbelt Proxy" "$SCRIPT_DIR/run_seatbelt_proxy_test.sh"
run_test "Seatbelt Environment" "$SCRIPT_DIR/run_seatbelt_environment_test.sh"
run_test "Seatbelt UI" "$SCRIPT_DIR/run_seatbelt_ui_test.sh"
run_test "Seatbelt guiAccess" "$SCRIPT_DIR/run_seatbelt_gui_access_test.sh"
run_test "Seatbelt Options" "$SCRIPT_DIR/run_seatbelt_options_test.sh"
run_test "Seatbelt Profile Output" "$SCRIPT_DIR/run_seatbelt_profile_test.sh"
run_test "Seatbelt Examples" "$SCRIPT_DIR/run_seatbelt_examples_test.sh"
run_test "Seatbelt launchMethod=open" "$SCRIPT_DIR/run_seatbelt_launch_open_test.sh"

echo "================================"
echo "Results: $PASSED passed, $FAILED failed"
if [ $FAILED -gt 0 ]; then
    echo -e "Failures:$FAILURES"
    exit 1
fi
if [ "$PASSED" -eq 0 ]; then
    echo "ERROR: no test executed. Refusing to report success."
    exit 1
fi
