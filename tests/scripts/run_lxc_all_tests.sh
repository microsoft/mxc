#!/bin/bash
# Run all LXC container tests
set -uo pipefail

# LXC tests require root for container management, bind mounts, and iptables
if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: LXC tests require root privileges."
    echo "Run with: sudo $0"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PASSED=0
FAILED=0
SKIPPED=0
DISABLED=0
FAILURES=""
SKIPS=""
DISABLES=""

# Exit status a child test uses to report an honest skip (missing prerequisite
# such as no root, no ip6tables, or an unbuilt binary). Matches the GNU
# Automake convention. A skip must never be counted as a pass.
SKIP_EXIT=77

# Check for Windows line endings in test scripts
check_line_endings() {
    if grep -rPl '\r$' "$SCRIPT_DIR"/run_lxc_*.sh >/dev/null 2>&1; then
        echo "ERROR: Shell scripts have Windows line endings (CRLF)."
        echo "Fix with: sed -i 's/\r\$//' $SCRIPT_DIR/run_lxc_*.sh"
        exit 1
    fi
}

check_line_endings

run_test() {
    local name="$1"
    local script="$2"
    echo "=== $name ==="
    # Do not let a nonzero exit abort the runner; classify it instead.
    set +e
    bash "$script"
    local status=$?
    set -e
    if [ "$status" -eq 0 ]; then
        echo "PASS: $name"
        PASSED=$((PASSED + 1))
    elif [ "$status" -eq "$SKIP_EXIT" ]; then
        echo "SKIP: $name"
        SKIPPED=$((SKIPPED + 1))
        SKIPS="$SKIPS\n  - $name"
    else
        echo "FAIL: $name"
        FAILED=$((FAILED + 1))
        FAILURES="$FAILURES\n  - $name"
    fi
    echo ""
}

# A test that is deliberately not run because it is known-broken, as opposed to
# one whose prerequisite is missing on this host.
#
# This is intentionally NOT the SKIP_EXIT path. A skip means "this host cannot
# run this test", which strict mode below rightly treats as a failure: on a
# provisioned runner a vanished prerequisite means the gate would go green while
# testing nothing. A disabled test is a different claim -- "we know this test is
# broken and have quarantined it" -- so it must not trip strict mode. It is
# counted and reported on its own line so it cannot be quietly forgotten.
disabled_test() {
    local name="$1"
    local reason="$2"
    echo "=== $name ==="
    echo "DISABLED: $name -- $reason"
    DISABLED=$((DISABLED + 1))
    DISABLES="$DISABLES\n  - $name: $reason"
    echo ""
}

run_test "Basic LXC" "$SCRIPT_DIR/run_lxc_basic_test.sh"
run_test "LXC Filesystem" "$SCRIPT_DIR/run_lxc_filesystem_test.sh"
run_test "LXC Object Validation" "$SCRIPT_DIR/run_lxc_object_test.sh"
run_test "LXC Most-Specific Path" "$SCRIPT_DIR/run_lxc_most_specific_test.sh"
run_test "LXC Denied Masking" "$SCRIPT_DIR/run_lxc_denied_masking_test.sh"
run_test "LXC Network" "$SCRIPT_DIR/run_lxc_network_test.sh"
run_test "LXC Network IPv6+CIDR" "$SCRIPT_DIR/run_lxc_network_ipv6_cidr_test.sh"
run_test "LXC Network Invalid CIDR" "$SCRIPT_DIR/run_lxc_network_invalid_cidr_test.sh"
run_test "LXC Network Mixed-Family CIDRs" "$SCRIPT_DIR/run_lxc_network_dualstack_test.sh"
run_test "LXC Network CIDR Boundary" "$SCRIPT_DIR/run_lxc_network_cidr_boundary_test.sh"
run_test "LXC Network Enforcement" "$SCRIPT_DIR/run_lxc_network_enforcement_test.sh"
run_test "LXC Retired Network Contracts" "$SCRIPT_DIR/run_lxc_network_retired_contract_test.sh"
run_test "LXC Network GA Egress" "$SCRIPT_DIR/run_lxc_network_ga_egress_test.sh"
run_test "LXC Network Omitted Network Section" "$SCRIPT_DIR/run_lxc_network_no_network_test.sh"
run_test "LXC Network Extra Interface Isolation" "$SCRIPT_DIR/run_lxc_network_extra_nic_test.sh"
run_test "LXC Network Deny-All Loopback" "$SCRIPT_DIR/run_lxc_network_deny_all_loopback_test.sh"
run_test "LXC Network Deny Precedence" "$SCRIPT_DIR/run_lxc_network_deny_precedence_test.sh"
run_test "LXC Network Proxy Rejection" "$SCRIPT_DIR/run_lxc_network_proxy_rejection_test.sh"
run_test "LXC Network Preserve Policy" "$SCRIPT_DIR/run_lxc_network_preserve_policy_test.sh"
run_test "LXC Network Reuse Tightening" "$SCRIPT_DIR/run_lxc_network_reuse_tighten_test.sh"
run_test "LXC Network Reuse Loosening" "$SCRIPT_DIR/run_lxc_network_reuse_loosen_test.sh"
run_test "LXC Inbound Default-Deny" "$SCRIPT_DIR/run_lxc_inbound_deny_test.sh"
run_test "LXC Inbound Traffic" "$SCRIPT_DIR/run_lxc_inbound_traffic_test.sh"
run_test "LXC Timeout" "$SCRIPT_DIR/run_lxc_timeout_test.sh"
run_test "LXC Env+Cwd" "$SCRIPT_DIR/run_lxc_env_cwd_test.sh"
run_test "LXC Environment" "$SCRIPT_DIR/run_lxc_env_test.sh"

echo "================================"
echo "Results: $PASSED passed, $FAILED failed, $SKIPPED skipped, $DISABLED disabled"
if [ "$SKIPPED" -gt 0 ]; then
    echo -e "Skipped (prerequisite missing, not run):$SKIPS"
fi
if [ "$DISABLED" -gt 0 ]; then
    echo -e "DISABLED (known-broken, quarantined -- must be fixed):$DISABLES"
fi
# A suite that ran nothing must not look green. Make an all-skip (or empty) run
# visibly distinct from a real pass.
if [ "$PASSED" -eq 0 ] && [ "$FAILED" -eq 0 ]; then
    echo "WARNING: no tests actually executed; every test was skipped."
fi
# Strict mode, for continuous integration. A developer box legitimately lacks
# ip6tables or LXC and should be able to run what it can, so a skip is only a
# warning there. On a runner provisioned to execute this suite, a skip means a
# prerequisite silently disappeared, and the gate would then go green while
# testing nothing -- which is the precise way an unenforced firewall shipped.
if [ "${MXC_LXC_TESTS_REQUIRE_EXECUTION:-0}" != "0" ]; then
    if [ "$PASSED" -eq 0 ] && [ "$FAILED" -eq 0 ]; then
        echo "ERROR: strict mode: no test executed. Refusing to report success."
        exit 1
    fi
    if [ "$SKIPPED" -gt 0 ]; then
        echo "ERROR: strict mode: $SKIPPED test(s) skipped a prerequisite that this"
        echo "environment is supposed to provide. Refusing to report success."
        exit 1
    fi
fi
if [ $FAILED -gt 0 ]; then
    echo -e "Failures:$FAILURES"
    exit 1
fi
