#!/bin/bash
# LXC state-aware identifier and adopt-or-create test.
#
# Covers the LXC exception in section 5 of
# docs/state-aware-lifecycle/mxc-state-aware-sandbox-api.md, which is the one
# place a backend is allowed to accept containerId on a state-aware provision
# and the only backend whose sandboxId is not opaque. Four documented
# consequences had no end-to-end coverage: the returned id is lxc:<name>,
# provision adopts an existing container instead of creating one, deprovision
# destroys an adopted container just as readily as a created one, and omitting
# containerId mints a name that adopts nothing.
#
# The adoption path is the one that matters to a caller, because a caller who
# passes the name of a container they already own hands MXC the right to
# destroy it.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"

LXC_EXEC="$REPO_DIR/src/target/release/lxc-exec"
if [ ! -f "$LXC_EXEC" ]; then
    LXC_EXEC="$REPO_DIR/src/target/debug/lxc-exec"
fi

DISTRIBUTION="alpine"
RELEASE="3.23"

SKIP_EXIT=77
skip() {
    echo "SKIP: $1"
    exit "$SKIP_EXIT"
}

[ "$(id -u)" -eq 0 ] || skip "requires root for LXC."
command -v lxc-create >/dev/null 2>&1 || skip "LXC (lxc-create) is not installed."
[ -f "$LXC_EXEC" ] || skip "lxc-exec binary not built; run build.sh first."

WORK_DIR="$(mktemp -d)"
PASSED=0
FAILED=0
CLEANED_UP=0

# Names this test may have brought into existence, by any route: minted by the
# backend, supplied to it, or created here with lxc-create to give provision
# something to adopt. Cleanup destroys the lot directly rather than through
# deprovision, because several assertions below depend on deprovision having
# already run and a second one would report a failure the run has passed.
TRACKED_NAMES=""
track() {
    TRACKED_NAMES="$TRACKED_NAMES $1"
}

cleanup() {
    if [ "$CLEANED_UP" -ne 0 ]; then
        return
    fi
    CLEANED_UP=1
    for name in $TRACKED_NAMES; do
        if lxc-info -n "$name" >/dev/null 2>&1; then
            echo "--- cleanup: destroying $name ---"
            lxc-stop -k -n "$name" >/dev/null 2>&1 || true
            lxc-destroy -f -n "$name" >/dev/null 2>&1 || true
        fi
    done
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT
trap 'cleanup; exit 130' INT
trap 'cleanup; exit 143' TERM

# Emit a provision request carrying $1 as containerId, or no containerId at all
# when $1 is empty, and run it.
provision() {
    local container_id="$1"
    local req="$WORK_DIR/provision.json"

    {
        printf '{\n  "version": "0.8.0-alpha",\n  "phase": "provision",\n  "containment": "lxc"'
        if [ -n "$container_id" ]; then
            printf ',\n  "containerId": "%s"' "$container_id"
        fi
        printf ',\n  "experimental": { "lxc": { "provision": { "distribution": "%s", "release": "%s" } } }' \
            "$DISTRIBUTION" "$RELEASE"
        printf '\n}\n'
    } > "$req"

    "$LXC_EXEC" --experimental "$req"
}

deprovision() {
    local sandbox_id="$1"
    local req="$WORK_DIR/deprovision.json"

    printf '{\n  "version": "0.8.0-alpha",\n  "phase": "deprovision",\n  "sandboxId": "%s"\n}\n' \
        "$sandbox_id" > "$req"

    "$LXC_EXEC" --experimental "$req"
}

# Read one scalar out of a result envelope without jq or python, neither of
# which is guaranteed on an LXC test host.
field() {
    sed -n "s/.*\"$1\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\".*/\1/p" | head -n 1
}

flag() {
    sed -n "s/.*\"$1\"[[:space:]]*:[[:space:]]*\(true\|false\).*/\1/p" | head -n 1
}

check() {
    local name="$1"
    local ok="$2"
    if [ "$ok" = "0" ]; then
        echo "PASS: $name"
        PASSED=$((PASSED + 1))
    else
        echo "FAIL: $name"
        FAILED=$((FAILED + 1))
    fi
}

check_eq() {
    local name="$1"
    local want="$2"
    local got="$3"
    if [ "$want" = "$got" ]; then
        check "$name" 0
    else
        check "$name (want '$want', got '$got')" 1
    fi
}

echo "Running LXC state-aware adopt-or-create test..."

SUPPLIED="mxc-adopt-$$"
track "$SUPPLIED"

# --- create: a supplied name nothing is using ------------------------------
echo "=== provision with a supplied containerId (creates) ==="
OUT="$(provision "$SUPPLIED")"
check "provision with a supplied containerId exits 0" $?
echo "$OUT"

check_eq "sandboxId is lxc:<containerName>" "lxc:$SUPPLIED" "$(printf '%s' "$OUT" | field sandboxId)"
check_eq "metadata reports the container name" "$SUPPLIED" "$(printf '%s' "$OUT" | field containerName)"
check_eq "a name nothing was using reports created" "true" "$(printf '%s' "$OUT" | flag created)"

# --- adopt: the same name, now taken ---------------------------------------
# The container from the previous phase is still there, so this is the adoption
# the caller asked for rather than a second create.
echo "=== provision again with the same containerId (adopts) ==="
OUT="$(provision "$SUPPLIED")"
check "re-provisioning an existing name exits 0" $?
echo "$OUT"

check_eq "adopting returns the same sandboxId" "lxc:$SUPPLIED" "$(printf '%s' "$OUT" | field sandboxId)"
check_eq "an adopted container reports created false" "false" "$(printf '%s' "$OUT" | flag created)"
check_eq "adoption leaves one container, not two" "1" "$(lxc-ls -1 | grep -c "^$SUPPLIED\$")"

echo "=== deprovision ==="
deprovision "lxc:$SUPPLIED" >/dev/null
check "deprovision exits 0" $?
if lxc-info -n "$SUPPLIED" >/dev/null 2>&1; then
    check "deprovision destroys the container" 1
else
    check "deprovision destroys the container" 0
fi

# --- adopt a container MXC never made --------------------------------------
# Section 5 spells out the consequence a caller has to understand: a container
# handed to provision by name is destroyed by deprovision even though MXC did
# not create it, because MXC keeps no state between phases that could tell the
# two apart.
FOREIGN="mxc-foreign-$$"
track "$FOREIGN"
echo "=== provision adopts a container created outside MXC ==="
if ! lxc-create -n "$FOREIGN" -t download -- \
        -d "$DISTRIBUTION" -r "$RELEASE" -a amd64 >/dev/null 2>&1; then
    skip "could not create a container to adopt; no image cache and no network?"
fi

OUT="$(provision "$FOREIGN")"
check "provisioning onto a foreign container exits 0" $?
check_eq "a container MXC did not create reports created false" "false" "$(printf '%s' "$OUT" | flag created)"

deprovision "lxc:$FOREIGN" >/dev/null
check "deprovision of an adopted container exits 0" $?
if lxc-info -n "$FOREIGN" >/dev/null 2>&1; then
    check "deprovision destroys an adopted container it never created" 1
else
    check "deprovision destroys an adopted container it never created" 0
fi

# --- omitting containerId adopts nothing -----------------------------------
echo "=== provision without a containerId (mints) ==="
OUT="$(provision "")"
check "provision without a containerId exits 0" $?
MINTED="$(printf '%s' "$OUT" | field sandboxId)"
track "${MINTED#lxc:}"

case "$MINTED" in
    lxc:mxc-*) check "a minted sandboxId carries the lxc:mxc- form ($MINTED)" 0 ;;
    *)         check "a minted sandboxId carries the lxc:mxc- form ($MINTED)" 1 ;;
esac
check_eq "a minted name is always created, never adopted" "true" "$(printf '%s' "$OUT" | flag created)"

deprovision "$MINTED" >/dev/null
check "deprovision of a minted container exits 0" $?

# --- a containerId LXC cannot name -----------------------------------------
# Rejected before anything is created, so this costs no container.
echo "=== provision with an unusable containerId ==="
OUT="$(provision "not a valid name!" 2>&1)"
case "$OUT" in
    *malformed_request*) check "an unusable containerId is malformed_request" 0 ;;
    *)                   check "an unusable containerId is malformed_request (got: $OUT)" 1 ;;
esac

echo "================================"
echo "Results: $PASSED passed, $FAILED failed"
if [ "$FAILED" -gt 0 ]; then
    exit 1
fi
