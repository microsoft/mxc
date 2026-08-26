#!/usr/bin/env bash
set -euo pipefail

# Dispatches a downloaded Unix artifact to the repository's existing backend
# test suites, keyed by the matrix backend id. Unsupported backends fail
# explicitly rather than reporting a false-success placeholder job.

usage() {
    echo "Usage: $0 <bubblewrap|lxc|microvm|hyperlight|seatbelt> <binary-directory>" >&2
}

if [[ $# -ne 2 ]]; then
    usage
    exit 2
fi

backend="$1"
binary_directory="$(cd "$2" && pwd)"
script_root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_root/../.." && pwd)"
test_script_root="$repo_root/tests/scripts"
release_directory="$repo_root/src/target/release"

case "$backend" in
    microvm)
        # Keep unwired commands explicit so accidental activation fails loudly.
        # Future test script: run_microvm_tests.sh
        echo "The MicroVM CI backend is not wired to an artifact-only Linux test entry point yet." >&2
        exit 2
        ;;
    hyperlight)
        # Keep unwired commands explicit so accidental activation fails loudly.
        # Future test script: run_hyperlight_tests.sh
        echo "The Hyperlight CI backend is not wired to an existing test entry point yet." >&2
        exit 2
        ;;
    bubblewrap)
        # Existing Linux shell tests locate binaries under src/target/release.
        test -x "$binary_directory/lxc-exec"
        test -f "$binary_directory/unix-test-proxy"
        mkdir -p "$release_directory"
        cp -a "$binary_directory/." "$release_directory/"
        chmod +x "$release_directory/lxc-exec" "$release_directory/unix-test-proxy"
        # Strict: a skip on a provisioned runner means a prerequisite vanished,
        # not that the assertion held. Without this the job goes green having
        # verified none of the directional enforcement.
        MXC_BWRAP_TESTS_REQUIRE_EXECUTION=1 bash "$script_root/run_bwrap_all_tests.sh"
        # The inbound chain test needs real host CAP_NET_ADMIN to read the
        # sandbox's network namespace and inject a peer into it, so the non-root
        # suite above can only report it as skipped. Invoking it separately here
        # is what makes that security assertion actually run in CI; it must not
        # be folded into the suite, which asserts the sandbox drops capabilities
        # and therefore cannot itself run as root.
        if ! sudo -n true 2>/dev/null; then
            echo "Bubblewrap CI requires passwordless sudo to run the inbound" \
                 "default-deny test; it cannot be verified unprivileged." >&2
            exit 2
        fi
        # A skip here means a prerequisite is missing on the runner, not that
        # the assertion passed. Translate it into an explicit failure so the
        # inbound guarantee can never be reported as verified without running.
        inbound_status=0
        sudo -n bash "$script_root/run_bwrap_inbound_deny_test.sh" || inbound_status=$?
        if [[ $inbound_status -eq 77 ]]; then
            echo "The Bubblewrap inbound default-deny test skipped for a missing prerequisite;" \
                 "prepare-linux-host.sh should have installed slirp4netns, nsenter, iptables," \
                 "and iproute2. Failing rather than reporting an unverified guarantee." >&2
            exit 1
        fi
        exit "$inbound_status"
        ;;
    lxc)
        test -x "$binary_directory/lxc-exec"
        test -f "$binary_directory/unix-test-proxy"
        mkdir -p "$release_directory"
        cp -a "$binary_directory/." "$release_directory/"
        chmod +x "$release_directory/lxc-exec" "$release_directory/unix-test-proxy"
        # A skip here means a prerequisite disappeared on a runner provisioned
        # to execute this suite, so turn it into a failure rather than a
        # vacuously green gate.
        MXC_LXC_TESTS_REQUIRE_EXECUTION=1 bash "$test_script_root/run_lxc_all_tests.sh"
        ;;
    seatbelt)
        test -x "$binary_directory/mxc-exec-mac"
        test -x "$binary_directory/unix-test-proxy"
        echo "The Seatbelt CI backend is not wired to an existing test entry point yet." >&2
        exit 2
        ;;
    *)
        usage
        exit 2
        ;;
esac
