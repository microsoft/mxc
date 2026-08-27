#!/usr/bin/env bash
set -euo pipefail

# Verifies the interpreters test suites drive inside the sandbox, following the
# same verify-never-install rule as the rest of host preparation: a missing one
# is an image problem, not something a job can fix mid-run.
#
# Shared by prepare-linux-host.sh and prepare-macos-host.sh so the two cannot
# drift. The Windows twin is Assert-WorkloadInterpreters in
# prepare-windows-host.ps1, which stays separate because it has to filter the
# Microsoft Store alias stubs that only exist there.
#
# The check is suite-agnostic: it describes what a validation host is expected
# to provide, not what any one suite consumes, so a future suite that shells out
# to these programs needs no change here.
#
# Written for bash 3.2, which is what macOS still ships -- hence the delimited
# string table rather than associative arrays.

# name|candidates (tried in order)|required|remedy
#
# Nothing is required on Unix today: no Linux or macOS suite drives these
# interpreters yet, so this runs as host inventory and reports absences as
# warnings. Flip a `false` to `true` when a suite starts depending on one --
# that is the whole change.
interpreters=(
    "pwsh|pwsh|false|install PowerShell 7 in the image"
    "git|git|false|install Git in the image"
    "node|node|false|install Node.js in the image"
    "python|python3,python|false|install Python in the image"
)

missing=""
for entry in "${interpreters[@]}"; do
    IFS='|' read -r name candidates required remedy <<<"$entry"

    resolved=""
    IFS=',' read -r -a candidate_list <<<"$candidates"
    for candidate in "${candidate_list[@]}"; do
        # python3 before python: on Unix a bare `python` is usually absent, and
        # where it does exist it can still be Python 2.
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
