#!/bin/bash
# Run all Bubblewrap sandbox tests
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PASSED=0
FAILED=0
SKIPPED=0
# Skips that strict mode counts. Excludes tests CI deliberately runs elsewhere.
STRICT_SKIPPED=0
FAILURES=""
SKIPS=""

# This suite runs unprivileged, so a root-only test can only ever skip here.
# run_ci_backend_tests.sh invokes those separately under sudo and turns *their*
# skip into a failure, so counting the skip again would make strict mode
# unsatisfiable.
strict_exempt() {
    case "$1" in
    "Bubblewrap Inbound Deny") return 0 ;;
    *) return 1 ;;
    esac
}

# The symlink-alias regression tests, which CI must not lose.
declare -A LAST_LINES=(
    ["Bubblewrap Baseline Aliases"]="Bubblewrap baseline-alias test complete."
    ["Bubblewrap Grant Aliases"]="Bubblewrap grant-alias test complete."
)
declare -A PASSED_TESTS=()

# Check for Windows line endings in test scripts
check_line_endings() {
    if grep -rPl '\r$' "$SCRIPT_DIR"/run_bwrap_*.sh "$SCRIPT_DIR"/run_linux_process_default_test.sh >/dev/null 2>&1; then
        echo "ERROR: Shell scripts have Windows line endings (CRLF)."
        echo "Fix with: sed -i 's/\r\$//' $SCRIPT_DIR/run_bwrap_*.sh $SCRIPT_DIR/run_linux_process_default_test.sh"
        exit 1
    fi
}

check_line_endings

if [ "$(id -u)" -eq 0 ]; then
    echo "ERROR: run this suite as an unprivileged user, not root."
    echo "       Filesystem permission checks must not inherit root access."
    echo "       Root-only tests are run individually, for example:"
    echo "         sudo bash $SCRIPT_DIR/run_bwrap_inbound_deny_test.sh"
    exit 1
fi

run_test() {
    local name="$1"
    local script="$2"
    local rc=0
    echo "=== $name ==="
    if [ -n "${LAST_LINES[$name]:-}" ]; then
        local log
        log=$(mktemp)
        bash "$script" 2>&1 | tee "$log"
        rc=${PIPESTATUS[0]}
        if [ "$rc" = 0 ] && [ "$(tail -n 1 "$log")" != "${LAST_LINES[$name]}" ]; then
            echo "ERROR: $name exited 0 before printing: ${LAST_LINES[$name]}"
            rc=1
        fi
        rm -f "$log"
    else
        bash "$script" || rc=$?
    fi
    # 77 is "prerequisite absent", the same code run_lxc_all_tests.sh uses. It
    # must be neither PASS nor FAIL: reporting a skipped suite as passing is a
    # false green that hides a test which never ran, and reporting it as failing
    # would break every host that legitimately lacks the prerequisite.
    if [ "$rc" = 0 ]; then
        echo "PASS: $name"
        PASSED=$((PASSED + 1))
        PASSED_TESTS["$name"]=1
    elif [ "$rc" = 77 ]; then
        echo "SKIPPED: $name"
        SKIPPED=$((SKIPPED + 1))
        SKIPS="$SKIPS\n  - $name"
        if ! strict_exempt "$name"; then
            STRICT_SKIPPED=$((STRICT_SKIPPED + 1))
        fi
    else
        echo "FAIL: $name"
        FAILED=$((FAILED + 1))
        FAILURES="$FAILURES\n  - $name"
    fi
    echo ""
}

run_test "Basic Bubblewrap" "$SCRIPT_DIR/run_bwrap_basic_test.sh"
run_test "Bubblewrap Workload Capabilities" "$SCRIPT_DIR/run_bwrap_capabilities_test.sh"
run_test "Bubblewrap cwd advisory" "$SCRIPT_DIR/run_bwrap_cwd_advisory_test.sh"
run_test "Bubblewrap Environment" "$SCRIPT_DIR/run_bwrap_environment_test.sh"
run_test "Bubblewrap Filesystem" "$SCRIPT_DIR/run_bwrap_filesystem_test.sh"
run_test "Bubblewrap Read-Only Denial" "$SCRIPT_DIR/run_bwrap_readonly_denial_test.sh"
run_test "Bubblewrap Version Gate" "$SCRIPT_DIR/run_bwrap_version_gate_test.sh"
run_test "Bubblewrap Terminal Isolation" "$SCRIPT_DIR/run_bwrap_terminal_isolation_test.sh"
run_test "Bubblewrap Teardown" "$SCRIPT_DIR/run_bwrap_teardown_test.sh"
run_test "Bubblewrap Provider Loss" "$SCRIPT_DIR/run_bwrap_provider_loss_test.sh"
run_test "Bubblewrap Object Validation" "$SCRIPT_DIR/run_bwrap_filesystem_object_test.sh"
run_test "Bubblewrap Most-Specific Path" "$SCRIPT_DIR/run_bwrap_most_specific_test.sh"
run_test "Bubblewrap Denied Masking" "$SCRIPT_DIR/run_bwrap_denied_masking_test.sh"
run_test "Bubblewrap Baseline Aliases" "$SCRIPT_DIR/run_bwrap_baseline_alias_test.sh"
run_test "Bubblewrap Grant Aliases" "$SCRIPT_DIR/run_bwrap_grant_alias_test.sh"
run_test "Bubblewrap Network Block" "$SCRIPT_DIR/run_bwrap_network_test.sh"
run_test "Bubblewrap Network Proxy" "$SCRIPT_DIR/run_bwrap_network_proxy_test.sh"
run_test "Bubblewrap Namespace Startup" "$SCRIPT_DIR/run_bwrap_namespace_startup_test.sh"
run_test "Bubblewrap Network Firewall" "$SCRIPT_DIR/run_bwrap_firewall_test.sh"
run_test "Bubblewrap Loopback Resolver DNS" "$SCRIPT_DIR/run_bwrap_dns_test.sh"
run_test "Bubblewrap Resolver IPC Isolation" "$SCRIPT_DIR/run_bwrap_resolver_isolation_test.sh"
run_test "Bubblewrap Directional Network" "$SCRIPT_DIR/run_bwrap_directional_test.sh"
run_test "Bubblewrap allowLocalNetwork" "$SCRIPT_DIR/run_bwrap_localnet_test.sh"
run_test "Bubblewrap Inbound Deny" "$SCRIPT_DIR/run_bwrap_inbound_deny_test.sh"
run_test "Linux Process Default" "$SCRIPT_DIR/run_linux_process_default_test.sh"

echo "================================"
echo "Results: $PASSED passed, $FAILED failed, $SKIPPED skipped"
if [ $SKIPPED -gt 0 ]; then
    echo -e "Skipped (prerequisite absent, NOT verified):$SKIPS"
fi
if [ $FAILED -gt 0 ]; then
    echo -e "Failures:$FAILURES"
    exit 1
fi
# Strict mode, for continuous integration. A developer box legitimately lacks
# slirp4netns or outbound access to the external anchors and should be able to
# run what it can, so a skip is only a warning there. On a runner provisioned
# to execute this suite, a skip means a prerequisite silently disappeared, and
# the gate would then go green while testing nothing -- which is how an
# unenforced firewall shipped once already.
if [ "${MXC_BWRAP_TESTS_REQUIRE_EXECUTION:-0}" != "0" ]; then
    if [ "$PASSED" -eq 0 ]; then
        echo "ERROR: strict mode: no test executed. Refusing to report success."
        exit 1
    fi
    if [ "$STRICT_SKIPPED" -gt 0 ]; then
        echo "ERROR: strict mode: $STRICT_SKIPPED test(s) skipped a prerequisite that this"
        echo "environment is supposed to provide. Refusing to report success."
        exit 1
    fi
    for name in "${!LAST_LINES[@]}"; do
        if [ -z "${PASSED_TESTS[$name]:-}" ]; then
            echo "ERROR: strict mode: $name did not run. Refusing to report success."
            exit 1
        fi
    done
fi
