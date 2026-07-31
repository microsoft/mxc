#!/usr/bin/env bash
set -euo pipefail

# Dispatches a downloaded Unix artifact to the repository's existing backend
# test suites. Unsupported handlers fail explicitly rather than reporting a
# false-success placeholder job.

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
release_directory="$repo_root/src/target/release"

case "$backend" in
    bubblewrap|lxc)
        ;;
    microvm)
        echo "The MicroVM CI handler is not wired to an artifact-only Linux test entry point yet." >&2
        exit 2
        ;;
    hyperlight)
        echo "The Hyperlight CI handler is not wired to an existing backend test entry point yet." >&2
        exit 2
        ;;
    seatbelt)
        echo "The Seatbelt CI handler is not wired to an existing backend test entry point yet." >&2
        exit 2
        ;;
    *)
        usage
        exit 2
        ;;
esac

# Existing shell tests locate binaries under src/target/release. Recreate that
# layout from the downloaded artifact, including adjacent runtime assets.
test -x "$binary_directory/lxc-exec"
test -f "$binary_directory/unix-test-proxy"
mkdir -p "$release_directory"
cp -a "$binary_directory/." "$release_directory/"
chmod +x "$release_directory/lxc-exec" "$release_directory/unix-test-proxy"

case "$backend" in
    bubblewrap)
        "$script_root/run_bwrap_all_tests.sh"
        ;;
    lxc)
        "$script_root/run_lxc_all_tests.sh"
        ;;
esac
