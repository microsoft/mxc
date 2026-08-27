#!/usr/bin/env bash
set -euo pipefail

# Prepares a macOS host for a backend's artifact-only test suite.
#
# Seatbelt needs nothing installed -- the sandbox is part of the OS -- so this
# currently only takes the host's workload-interpreter inventory. It exists so
# macOS has the same shape as the Windows and Linux preparation scripts, giving
# a future prerequisite an obvious home instead of another workflow-inline step.

usage() {
    echo "Usage: $0 <seatbelt> <binary-directory>" >&2
}

if [[ $# -ne 2 ]]; then
    usage
    exit 2
fi

backend="$1"
binary_directory="$2"

# Runs for every backend: this is host inventory, not a backend prerequisite.
bash "$(dirname "$0")/assert-workload-interpreters.sh"

case "$backend" in
    seatbelt)
        test -f "$binary_directory/mxc-exec-mac"
        ;;
    *)
        usage
        exit 2
        ;;
esac
