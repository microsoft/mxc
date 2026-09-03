#!/bin/bash
# LXC state-aware routing test.
#
# Every refusal here is decided before any backend runs, from the sandbox id
# alone. The contract states what a caller gets for an id that does not parse,
# an id naming a backend this build does not carry, and an id naming a backend
# that has no state-aware lifecycle
# (docs/state-aware-lifecycle/mxc-state-aware-sandbox-api.md:1044-1047).
#
# Nothing here creates a container, so this suite needs neither root nor a
# working LXC installation.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"

LXC_EXEC="$REPO_DIR/src/target/release/lxc-exec"
if [ ! -f "$LXC_EXEC" ]; then
    LXC_EXEC="$REPO_DIR/src/target/debug/lxc-exec"
fi

# Each string is the contract this test holds the binary to. A code that gets
# renamed breaks these rather than silently matching nothing and passing.
MALFORMED_ID='malformed_id'
MALFORMED_REQUEST='malformed_request'
UNSUPPORTED_CONTAINMENT='unsupported_containment'
UNSUPPORTED_PHASE='unsupported_phase'
BACKEND_UNAVAILABLE='backend_unavailable'

SKIP_EXIT=77
skip() {
    echo "SKIP: $1"
    exit "$SKIP_EXIT"
}

[ -f "$LXC_EXEC" ] || skip "lxc-exec binary not built; run build.sh first."

WORK_DIR="$(mktemp -d)"
PASSED=0
FAILED=0

cleanup() {
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT
trap 'cleanup; exit 130' INT
trap 'cleanup; exit 143' TERM

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

# Writes a start request carrying $1 as the sandbox id, or carrying no
# sandboxId at all when $1 is empty.
write_request() {
    local sandbox_id="$1"
    {
        printf '{\n  "version": "0.8.0-alpha",\n  "phase": "start"'
        if [ -n "$sandbox_id" ]; then
            printf ',\n  "sandboxId": "%s"' "$sandbox_id"
        fi
        printf '\n}\n'
    } > "$WORK_DIR/request.json"
}

# A refusal is two observations, and asserting only the exit code would pass on
# any failure at all, including a crash before the id was ever examined.
expect_error_code() {
    local name="$1"
    local expected="$2"
    local sandbox_id="$3"
    shift 3
    local out rc

    write_request "$sandbox_id"
    out="$("$LXC_EXEC" "$@" "$WORK_DIR/request.json" 2>/dev/null)"
    rc=$?

    if [ "$rc" -eq 0 ]; then
        check "$name (exited 0; expected a refusal naming $expected)" 1
        return
    fi
    if printf '%s' "$out" | grep -Eq "\"code\"[[:space:]]*:[[:space:]]*\"$expected\""; then
        check "$name" 0
    else
        check "$name (envelope did not name $expected)" 1
        echo "    got: $out"
    fi
}

echo "Running LXC state-aware routing test..."

echo "=== ids that do not parse ==="
expect_error_code "an id with no prefix separator is refused as $MALFORMED_ID" \
    "$MALFORMED_ID" 'no-colon'
expect_error_code "an id with an empty prefix is refused as $MALFORMED_ID" \
    "$MALFORMED_ID" ':orphan'
expect_error_code "an id with an empty container name is refused as $MALFORMED_ID" \
    "$MALFORMED_ID" 'lxc:' --experimental
expect_error_code "an id with a space in the container name is refused as $MALFORMED_ID" \
    "$MALFORMED_ID" 'lxc:bad name' --experimental
expect_error_code "an id with a punctuation character is refused as $MALFORMED_ID" \
    "$MALFORMED_ID" 'lxc:bad!name' --experimental

# The contract caps the container name at 20 characters. Asserting only the
# rejection would also pass if every name were rejected, which would make the
# five cases above meaningless.
echo "=== container-name length boundary ==="
expect_error_code "a 21-character container name is refused as $MALFORMED_ID" \
    "$MALFORMED_ID" 'lxc:aaaaaaaaaaaaaaaaaaaaa' --experimental

write_request 'lxc:aaaaaaaaaaaaaaaaaaaa'
LEN20_OUT="$("$LXC_EXEC" --experimental "$WORK_DIR/request.json" 2>/dev/null)"
if printf '%s' "$LEN20_OUT" | grep -Eq "\"code\"[[:space:]]*:[[:space:]]*\"$MALFORMED_ID\""; then
    check "a 20-character container name is not refused as $MALFORMED_ID" 1
    echo "    got: $LEN20_OUT"
else
    check "a 20-character container name is not refused as $MALFORMED_ID" 0
fi

echo "=== a missing sandboxId is a malformed request, not a malformed id ==="
expect_error_code "a start request with no sandboxId is refused as $MALFORMED_REQUEST" \
    "$MALFORMED_REQUEST" ''

echo "=== prefixes this build does not serve ==="
expect_error_code "an unregistered prefix is refused as $UNSUPPORTED_CONTAINMENT" \
    "$UNSUPPORTED_CONTAINMENT" 'foo:bar'

# The experimental gate is reached before the backend is asked whether it has a
# state-aware lifecycle, and the two refusals name different codes.
expect_error_code "an experimental backend without the opt-in is refused as $BACKEND_UNAVAILABLE" \
    "$BACKEND_UNAVAILABLE" 'wsb:0a1b2c3d'
expect_error_code "an ephemeral-only backend is refused as $UNSUPPORTED_PHASE" \
    "$UNSUPPORTED_PHASE" 'wsb:0a1b2c3d' --experimental
expect_error_code "a backend absent from this build is refused as $BACKEND_UNAVAILABLE" \
    "$BACKEND_UNAVAILABLE" 'wslc:0a1b2c3d' --experimental
expect_error_code "an lxc lifecycle call without the opt-in is refused as $BACKEND_UNAVAILABLE" \
    "$BACKEND_UNAVAILABLE" 'lxc:mxc-routingtest'

echo "=== the runtime dependency is missing ==="
# §11.7 requires a feature-unavailable test: on a host without the LXC runtime,
# a phase reports backend_unavailable rather than panicking, hanging, or
# blaming the container. A PATH holding coreutils and no lxc-* tools is that
# host.
STRIPPED_BIN="$WORK_DIR/nolxc"
mkdir -p "$STRIPPED_BIN"
for tool in sh bash env cat sed grep printf; do
    resolved="$(command -v "$tool" 2>/dev/null)" && ln -sf "$resolved" "$STRIPPED_BIN/$tool"
done

{
    printf '{\n  "version": "0.8.0-alpha",\n  "phase": "provision",\n'
    printf '  "containment": "lxc",\n  "experimental": {\n    "lxc": {\n'
    printf '      "provision": { "distribution": "alpine", "release": "3.23" }\n'
    printf '    }\n  }\n}\n'
} > "$WORK_DIR/provision.json"

# Without this the case passes whenever the strip failed and LXC was reachable
# all along, which is the one condition it exists to rule out.
if PATH="$STRIPPED_BIN" command -v lxc-info >/dev/null 2>&1; then
    check "the stripped PATH hides the LXC tools" 1
else
    check "the stripped PATH hides the LXC tools" 0

    UNAVAIL_OUT="$(PATH="$STRIPPED_BIN" "$LXC_EXEC" --experimental "$WORK_DIR/provision.json" 2>/dev/null)"
    UNAVAIL_RC=$?
    if [ "$UNAVAIL_RC" -eq 0 ]; then
        check "provision without the LXC runtime is refused as $BACKEND_UNAVAILABLE (exited 0)" 1
    elif printf '%s' "$UNAVAIL_OUT" | grep -Eq "\"code\"[[:space:]]*:[[:space:]]*\"$BACKEND_UNAVAILABLE\""; then
        check "provision without the LXC runtime is refused as $BACKEND_UNAVAILABLE" 0
    else
        check "provision without the LXC runtime is refused as $BACKEND_UNAVAILABLE" 1
        echo "    got: $UNAVAIL_OUT"
    fi
fi

echo "=== stdout carries the envelope and nothing else ==="
# The SDK tells a dispatch failure from a script that exited non-zero by
# parsing stdout whole (§7.3). That rule holds only while MXC keeps its own
# diagnostics on stderr, so anything printed alongside the envelope -- a
# warning, a progress line -- breaks a consumer rather than this test.
write_request 'lxc:bad name'
ENVELOPE_OUT="$("$LXC_EXEC" --experimental "$WORK_DIR/request.json" 2>/dev/null)"
if [ "$(printf '%s' "$ENVELOPE_OUT" | wc -l)" -eq 0 ] &&
    printf '%s' "$ENVELOPE_OUT" | grep -Eq '^\{.*"error".*\}$'; then
    check "a refusal writes one envelope and nothing else to stdout" 0
else
    check "a refusal writes one envelope and nothing else to stdout" 1
    echo "    got: $ENVELOPE_OUT"
fi

# §7.3 reserves operation, nativeCode, and remediation for a failure that
# happened inside a platform API call. An id rejected by the parser never
# reached one, and a consumer reading those fields would be told an API failed
# when none ran.
for diagnostic_field in operation nativeCode remediation; do
    if printf '%s' "$ENVELOPE_OUT" | grep -q "\"$diagnostic_field\""; then
        check "a refusal raised outside any API call omits $diagnostic_field" 1
        echo "    got: $ENVELOPE_OUT"
    else
        check "a refusal raised outside any API call omits $diagnostic_field" 0
    fi
done

echo "================================"
echo "Results: $PASSED passed, $FAILED failed"
if [ "$FAILED" -gt 0 ]; then
    exit 1
fi
