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

# Verifies the interpreters test suites drive inside the sandbox, following the
# same verify-never-install rule as the rest of host preparation: a missing one
# is an image problem, not something a job can fix mid-run.
#
# The check is suite-agnostic: it describes what a validation host is expected
# to provide, not what any one suite consumes, so a future suite that shells out
# to these programs needs no change here.
assert_workload_interpreters() {
    # name|candidates (tried in order)|required|remedy
    local interpreters=(
        "pwsh|pwsh|false|install PowerShell 7 in the image"
        "git|git|false|install Git in the image"
        "node|node|false|install Node.js in the image"
        "npm|npm|false|install Node.js in the image (npm ships with it)"
        "npx|npx|false|install Node.js in the image (npx ships with it)"
        "python|python3,python|false|install Python in the image"
        "pip|pip3,pip|false|install Python in the image (pip ships with it)"
        "dotnet|dotnet|false|install the .NET SDK in the image"
        "az|az|false|install the Azure CLI in the image"
        "gh|gh|false|install the GitHub CLI in the image"
        "openssl|openssl|false|install OpenSSL in the image"
        # macOS-only
        "brew|brew|false|install Homebrew in the image"
    )

    local missing="" entry name candidates required remedy resolved candidate
    local candidate_list
    for entry in "${interpreters[@]}"; do
        IFS='|' read -r name candidates required remedy <<<"$entry"

        resolved=""
        IFS=',' read -r -a candidate_list <<<"$candidates"
        for candidate in "${candidate_list[@]}"; do
            # python3 before python: on Unix a bare `python` is usually absent,
            # and where it does exist it can still be Python 2.
            if resolved="$(command -v "$candidate" 2>/dev/null)"; then
                break
            fi
            resolved=""
        done

        if [[ -n "$resolved" ]]; then
            echo "Workload interpreter '$name' found at $resolved"
        elif [[ "$required" == "true" ]]; then
            missing="${missing:+$missing; }$name ($remedy)"
        else
            echo "::warning::Workload interpreter '$name' is absent ($remedy)"
        fi
    done

    if [[ -n "$missing" ]]; then
        echo "::error::Workload interpreters missing from this image: $missing"
        exit 1
    fi
}

# Runs for every backend: this is host inventory, not a backend prerequisite.
assert_workload_interpreters

case "$backend" in
    seatbelt)
        test -f "$binary_directory/mxc-exec-mac"
        ;;
    *)
        usage
        exit 2
        ;;
esac
