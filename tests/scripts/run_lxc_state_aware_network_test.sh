#!/bin/bash
# LXC state-aware network policy matrix test.
#
# Proves that LXC start requests enforce policy-driven network rules, including
# the inherited default-deny policy when the request omits a network block.
#
# Case 3 proves the default-deny hook reaches a stock provisioned container,
# and reads the host's own iptables state to show the hook was applied rather
# than merely reported.
#
# The start fixtures keep a __SANDBOX_ID__ placeholder because the live LXC
# sandboxId is the container name returned by this test's own provision call.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
CONFIG_DIR="$REPO_DIR/tests/configs"

LXC_EXEC="$REPO_DIR/src/target/release/lxc-exec"
if [ ! -f "$LXC_EXEC" ]; then
    LXC_EXEC="$REPO_DIR/src/target/debug/lxc-exec"
fi

SKIP_EXIT=77
skip() {
    echo "SKIP: $1"
    exit "$SKIP_EXIT"
}

WORK_DIR="$REPO_DIR/tests/.lxc_state_aware_network_test.$$"
SANDBOX_ID=""
SANDBOX_STARTED=0
PASSED=0
FAILED=0
QUARANTINED=0
QUARANTINE_ACTIVE=""
QUARANTINE_NOTES=""
CLEANED_UP=0
FS_FIXTURES_CREATED=0

cleanup() {
    if [ "$CLEANED_UP" -ne 0 ]; then
        return
    fi
    CLEANED_UP=1
    if [ -n "$SANDBOX_ID" ]; then
        if [ "$SANDBOX_STARTED" -ne 0 ]; then
            echo "--- cleanup: stop $SANDBOX_ID ---"
            run_phase stop "$SANDBOX_ID" >/dev/null 2>&1 || true
            SANDBOX_STARTED=0
        fi
        echo "--- cleanup: deprovision $SANDBOX_ID ---"
        run_phase deprovision "$SANDBOX_ID" >/dev/null 2>&1 || true
    fi
    if [ "$FS_FIXTURES_CREATED" -ne 0 ]; then
        rm -rf "$FS_RO_DIR" "$FS_DENIED_DIR"
        FS_FIXTURES_CREATED=0
    fi
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT
trap 'cleanup; exit 130' INT
trap 'cleanup; exit 143' TERM

run_phase() {
    local phase="$1"
    local sandbox_id="${2:-}"
    local extra="${3:-}"
    local req="$WORK_DIR/$phase.json"

    {
        printf '{\n  "phase": "%s"' "$phase"
        if [ "$phase" = "provision" ]; then
            printf ',\n  "containment": "lxc"'
        fi
        if [ -n "$sandbox_id" ]; then
            printf ',\n  "sandboxId": "%s"' "$sandbox_id"
        fi
        if [ -n "$extra" ]; then
            printf ',\n  %s' "$extra"
        fi
        printf '\n}\n'
    } > "$req"

    "$LXC_EXEC" "$req"
}

extract_sandbox_id() {
    sed -n 's/.*"sandboxId"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1
}

check() {
    local name="$1"
    local ok="$2"
    if [ "$ok" = "0" ]; then
        echo "PASS: $name"
        PASSED=$((PASSED + 1))
    elif [ -n "$QUARANTINE_ACTIVE" ]; then
        # The assertion above is preserved byte for byte and still runs; only
        # its tally changes, because it exposes a product gap that predates this
        # change and is out of its scope. This must never read as a pass.
        echo "QUARANTINED (BEHAVIOR NOT VERIFIED): $name"
        echo "    reason: $QUARANTINE_ACTIVE"
        QUARANTINED=$((QUARANTINED + 1))
        QUARANTINE_NOTES="${QUARANTINE_NOTES}  - ${name}
      ${QUARANTINE_ACTIVE}
"
    else
        echo "FAIL: $name"
        FAILED=$((FAILED + 1))
    fi
}

fail_now() {
    echo "FAIL: $1"
    exit 1
}

record_result() {
    local case_no="$1"
    local config="$2"
    local cause="$3"
    local expected="$4"
    local actual="$5"
    local status="$6"
    RESULTS="${RESULTS}${case_no}|${config}|${cause}|${expected}|${actual}|${status}
"
}

CONFIG_NO_NETWORK="$CONFIG_DIR/lxc_state_aware_start_no_network.json"
CONFIG_BLOCK_CAPS="$CONFIG_DIR/lxc_state_aware_start_default_block_capabilities.json"
CONFIG_BLOCK_FIREWALL="$CONFIG_DIR/lxc_state_aware_start_default_block_firewall.json"
CONFIG_ALLOW_CAPS="$CONFIG_DIR/lxc_state_aware_start_default_allow_capabilities.json"
CONFIG_EMPTY_ALLOWED="$CONFIG_DIR/lxc_state_aware_start_empty_allowed_hosts.json"
CONFIG_NONEMPTY_ALLOWED="$CONFIG_DIR/lxc_state_aware_start_nonempty_allowed_hosts_capabilities.json"
CONFIG_PROVISION_NETWORK="$CONFIG_DIR/lxc_state_aware_start_network_at_provision_rejected.json"
CONFIG_PROVISION_FILESYSTEM="$CONFIG_DIR/lxc_state_aware_start_filesystem_at_provision_rejected.json"
CONFIG_BLOCK_BOTH="$CONFIG_DIR/lxc_state_aware_start_default_block_both.json"
CONFIG_ALLOWED_FIREWALL="$CONFIG_DIR/lxc_state_aware_start_allowed_hosts_firewall.json"
CONFIG_BLOCKED_CAPS="$CONFIG_DIR/lxc_state_aware_start_blocked_hosts_capabilities.json"
CONFIG_ALLOW_LOCAL="$CONFIG_DIR/lxc_state_aware_start_allow_local_network.json"
CONFIG_PROXY="$CONFIG_DIR/lxc_state_aware_start_proxy.json"
CONFIG_PROXY_EXTERNAL="$CONFIG_DIR/lxc_state_aware_start_proxy_external.json"
CONFIG_FILESYSTEM_PATHS="$CONFIG_DIR/lxc_state_aware_start_filesystem_paths.json"
RESULTS=""

verify_fixture_contracts() {
    for cfg in "$CONFIG_NO_NETWORK" "$CONFIG_BLOCK_CAPS" "$CONFIG_BLOCK_FIREWALL" \
        "$CONFIG_ALLOW_CAPS" "$CONFIG_EMPTY_ALLOWED" "$CONFIG_NONEMPTY_ALLOWED" \
        "$CONFIG_PROVISION_NETWORK" "$CONFIG_PROVISION_FILESYSTEM" \
        "$CONFIG_BLOCK_BOTH" "$CONFIG_ALLOWED_FIREWALL" "$CONFIG_BLOCKED_CAPS" \
        "$CONFIG_ALLOW_LOCAL" "$CONFIG_PROXY" "$CONFIG_PROXY_EXTERNAL" \
        "$CONFIG_FILESYSTEM_PATHS"; do
        [ -f "$cfg" ] || fail_now "fixture not found: $cfg"
    done

    # Case 8's fixture is guarded here rather than in the block below so the
    # existing seven keep their positional indices.
    grep -q '"phase"[[:space:]]*:[[:space:]]*"provision"' "$CONFIG_PROVISION_FILESYSTEM" \
        || fail_now "fixture drift in $CONFIG_PROVISION_FILESYSTEM: phase must be provision"
    grep -q '"filesystem"' "$CONFIG_PROVISION_FILESYSTEM" \
        || fail_now "fixture drift in $CONFIG_PROVISION_FILESYSTEM: must carry a filesystem block"
    grep -q '"sandboxId"' "$CONFIG_PROVISION_FILESYSTEM" \
        && fail_now "fixture drift in $CONFIG_PROVISION_FILESYSTEM: must not hard-code a sandboxId"

    if command -v python3 >/dev/null 2>&1; then
        python3 - "$CONFIG_NO_NETWORK" "$CONFIG_BLOCK_CAPS" "$CONFIG_BLOCK_FIREWALL" \
            "$CONFIG_ALLOW_CAPS" "$CONFIG_EMPTY_ALLOWED" "$CONFIG_NONEMPTY_ALLOWED" \
            "$CONFIG_PROVISION_NETWORK" <<'PY'
import json
import sys

cases = [json.load(open(path, encoding="utf-8")) for path in sys.argv[1:]]
paths = sys.argv[1:]

def fail(index, message):
    raise SystemExit(f"fixture drift in {paths[index]}: {message}")

if cases[0].get("phase") != "start" or cases[0].get("sandboxId") != "__SANDBOX_ID__" or "network" in cases[0]:
    fail(0, "case 1 must be a start request with no network block")
if cases[1].get("network") != {"defaultPolicy": "block"}:
    fail(1, "case 2 must carry only defaultPolicy=block")
if cases[2].get("network") != {"defaultPolicy": "block", "enforcementMode": "firewall"}:
    fail(2, "case 3 must carry defaultPolicy=block with enforcementMode=firewall")
if cases[3].get("network") != {"defaultPolicy": "allow"}:
    fail(3, "case 4 must carry only defaultPolicy=allow")
if cases[4].get("network") != {"allowedHosts": []}:
    fail(4, "case 5 must carry an empty allowedHosts list and no enforcementMode")
if cases[5].get("network") != {"allowedHosts": ["example.com"]}:
    fail(5, "case 6 must carry one allowedHosts entry and no enforcementMode")
if cases[6].get("phase") != "provision" or cases[6].get("containment") != "lxc":
    fail(6, "case 7 must be an LXC provision request")
if cases[6].get("network") != {"defaultPolicy": "block"}:
    fail(6, "case 7 must carry provision-time network.defaultPolicy=block")
if "sandboxId" in cases[6]:
    fail(6, "case 7 must not hard-code a sandboxId")
PY
        [ $? -eq 0 ] || fail_now "fixture drift in the case 1-7 configs"
    else
        grep -q '"network"' "$CONFIG_NO_NETWORK" && fail_now "fixture drift in $CONFIG_NO_NETWORK: case 1 must have no network block"
        grep -q '"defaultPolicy"[[:space:]]*:[[:space:]]*"block"' "$CONFIG_BLOCK_CAPS" || fail_now "fixture drift in $CONFIG_BLOCK_CAPS: missing defaultPolicy=block"
        grep -q '"enforcementMode"' "$CONFIG_BLOCK_CAPS" && fail_now "fixture drift in $CONFIG_BLOCK_CAPS: enforcementMode must be omitted"
        grep -q '"defaultPolicy"[[:space:]]*:[[:space:]]*"block"' "$CONFIG_BLOCK_FIREWALL" || fail_now "fixture drift in $CONFIG_BLOCK_FIREWALL: missing defaultPolicy=block"
        grep -q '"enforcementMode"[[:space:]]*:[[:space:]]*"firewall"' "$CONFIG_BLOCK_FIREWALL" || fail_now "fixture drift in $CONFIG_BLOCK_FIREWALL: missing enforcementMode=firewall"
        grep -q '"defaultPolicy"[[:space:]]*:[[:space:]]*"allow"' "$CONFIG_ALLOW_CAPS" || fail_now "fixture drift in $CONFIG_ALLOW_CAPS: missing defaultPolicy=allow"
        grep -q '"enforcementMode"' "$CONFIG_ALLOW_CAPS" && fail_now "fixture drift in $CONFIG_ALLOW_CAPS: enforcementMode must be omitted"
        grep -q '"allowedHosts"[[:space:]]*:[[:space:]]*\[\]' "$CONFIG_EMPTY_ALLOWED" || fail_now "fixture drift in $CONFIG_EMPTY_ALLOWED: allowedHosts must be empty"
        grep -q '"allowedHosts"[[:space:]]*:[[:space:]]*\["example.com"\]' "$CONFIG_NONEMPTY_ALLOWED" || fail_now "fixture drift in $CONFIG_NONEMPTY_ALLOWED: allowedHosts must contain example.com"
        grep -q '"phase"[[:space:]]*:[[:space:]]*"provision"' "$CONFIG_PROVISION_NETWORK" || fail_now "fixture drift in $CONFIG_PROVISION_NETWORK: phase must be provision"
        grep -q '"defaultPolicy"[[:space:]]*:[[:space:]]*"block"' "$CONFIG_PROVISION_NETWORK" || fail_now "fixture drift in $CONFIG_PROVISION_NETWORK: missing defaultPolicy=block"
        grep -q '"sandboxId"' "$CONFIG_PROVISION_NETWORK" && fail_now "fixture drift in $CONFIG_PROVISION_NETWORK: must not hard-code sandboxId"
    fi

    # Guarded in its own block so the seven above keep their positional indices.
    # Each of these fixtures isolates one field, and a field that drifts into a
    # neighbouring fixture would let a case pass while pinning nothing.
    if command -v python3 >/dev/null 2>&1; then
        python3 - "$CONFIG_BLOCK_BOTH" "$CONFIG_ALLOWED_FIREWALL" "$CONFIG_BLOCKED_CAPS" \
            "$CONFIG_ALLOW_LOCAL" "$CONFIG_PROXY" "$CONFIG_FILESYSTEM_PATHS" \
            "$CONFIG_PROXY_EXTERNAL" <<'PY'
import json
import sys

paths = sys.argv[1:]
cases = [json.load(open(path, encoding="utf-8")) for path in paths]

def fail(index, message):
    raise SystemExit(f"fixture drift in {paths[index]}: {message}")

for i, case in enumerate(cases):
    if case.get("phase") != "start" or case.get("sandboxId") != "__SANDBOX_ID__":
        fail(i, "must be a start request carrying the sandbox id placeholder")

if cases[0].get("network") != {"defaultPolicy": "block", "enforcementMode": "both"}:
    fail(0, "case 11 must carry defaultPolicy=block with enforcementMode=both")
if cases[1].get("network") != {"allowedHosts": ["example.com"], "enforcementMode": "firewall"}:
    fail(1, "case 12 must carry one allowedHosts entry with enforcementMode=firewall")
if cases[2].get("network") != {"blockedHosts": ["evil.example.com"]}:
    fail(2, "case 13 must carry one blockedHosts entry and no enforcementMode")
if cases[3].get("network", {}).get("allowLocalNetwork") is not True:
    fail(3, "case 14 must request allowLocalNetwork=true")
if cases[4].get("network") != {"proxy": {"builtinTestServer": True}}:
    fail(4, "case 15 must carry exactly the builtin-test-server proxy and nothing else: an "
            "external proxy url, a host list, or an enforcementMode is refused earlier by a "
            "shared parse-time rule, so the case would pass without ever reaching the LXC "
            "start verdict it exists to pin")
if cases[5].get("filesystem") != {
    "readonlyPaths": ["/mxc-e2e-ro"],
    "deniedPaths": ["/mxc-e2e-denied"],
}:
    fail(5, "case 16 must carry exactly the readonly and denied paths the case creates on the host")
if "network" in cases[5]:
    fail(5, "case 16 must carry no network block so it isolates the filesystem fields")
if not cases[6].get("network", {}).get("proxy", {}).get("url"):
    fail(6, "case 15's second half must carry an external proxy url, which is the form a "
            "production config uses")
if cases[6].get("network", {}).get("proxy", {}).get("builtinTestServer"):
    fail(6, "case 15's second half must not be the builtin form; the two halves exist to cover "
            "the two different refusal routes")
PY
        [ $? -eq 0 ] || fail_now "fixture drift in the field-isolation configs"
    fi
    echo "Fixture drift guard passed for all LXC state-aware network configs."
}

make_request_from_config() {
    local config="$1"
    local out="$2"
    sed "s/__SANDBOX_ID__/$SANDBOX_ID/g" "$config" > "$out"
}

expect_error_code() {
    local output="$1"
    local code="$2"
    echo "$output" | grep -Eq '"code"[[:space:]]*:[[:space:]]*"'"$code"'"'
}

start_fresh_sandbox() {
    local label="$1"
    local out rc
    echo "=== provision for $label ==="
    out="$($LXC_EXEC "$CONFIG_DIR/lxc_state_aware_provision.json")"
    rc=$?
    echo "$out"
    if [ "$rc" -ne 0 ]; then
        fail_now "$label: provision failed before the network input could be tested (config: $CONFIG_DIR/lxc_state_aware_provision.json, rc=$rc)."
    fi
    SANDBOX_ID="$(printf '%s' "$out" | extract_sandbox_id)"
    if [ -z "$SANDBOX_ID" ]; then
        fail_now "$label: provision did not return a sandboxId, so the start input cannot be tested."
    fi
    case "$SANDBOX_ID" in
        lxc:mxc-*) ;;
        *) fail_now "$label: provision returned unsafe-looking sandboxId '$SANDBOX_ID'." ;;
    esac
    SANDBOX_STARTED=0
}

finish_current_sandbox() {
    if [ -n "$SANDBOX_ID" ]; then
        if [ "$SANDBOX_STARTED" -ne 0 ]; then
            echo "=== stop $SANDBOX_ID ==="
            run_phase stop "$SANDBOX_ID"
            check "stop after $1 exits 0 for input $2" $?
            SANDBOX_STARTED=0
        fi
        echo "=== deprovision $SANDBOX_ID ==="
        run_phase deprovision "$SANDBOX_ID"
        local deprovision_rc=$?
        check "deprovision after $1 exits 0 for input $2" "$deprovision_rc"
        # Release the ID only once the container is actually gone. Clearing it
        # after a failed deprovision disarms the EXIT trap, so a container this
        # case could not remove leaks into every later case in the matrix.
        if [ "$deprovision_rc" -eq 0 ]; then
            SANDBOX_ID=""
        fi
    fi
}

container_host_veth() {
    local name="$1"
    local peer

    # Ask the container which host ifindex its own link is paired with, then
    # resolve that index on the host.  Nothing here trusts a name MXC chose, so
    # a hook aimed at the wrong interface still fails.
    #
    # `lxc-info` reports a Link: line instead, but it walks lxc.net.N from 0 and
    # stops at the first gap, so it reports nothing at all for a container whose
    # interface is numbered above a hole -- which is exactly the topology case 10
    # builds.  Reading it from the container's own kernel view works whatever the
    # index.
    peer="$(lxc-attach -n "$name" -- ip -o link 2>/dev/null \
        | sed -n 's/.*@if\([0-9][0-9]*\):.*/\1/p' | head -1)"
    [ -n "$peer" ] || return 0
    ip -o link 2>/dev/null \
        | awk -v want="$peer" '{ idx = $1; sub(/:$/, "", idx); if (idx == want) { n = $2; sub(/[@:].*/, "", n); print n; exit } }'
}

renumber_sole_interface() {
    local index="$1"
    local label="$2"
    local name="${SANDBOX_ID#lxc:}"
    local cfg="${LXC_PATH:-/var/lib/lxc}/$name/config"

    # A provisioned container is handed its interface by an include, always at
    # lxc.net.0, so this is the only way to build the one topology that tells
    # "MXC found the interface" apart from "MXC assumed index 0".  Assigning an
    # empty lxc.net clears what the include supplied; the numbered keys then
    # declare the same interface somewhere else.
    [ -f "$cfg" ] || fail_now "$label: no container config at $cfg to renumber."
    {
        echo "lxc.net ="
        echo "lxc.net.$index.type = veth"
        echo "lxc.net.$index.link = lxcbr0"
        echo "lxc.net.$index.flags = up"
    } >> "$cfg"

    echo "=== $label: renumbered sole interface to lxc.net.$index ==="
    echo "    lxc.net      -> $(lxc-info -n "$name" -c lxc.net 2>&1 | tr '\n' ' ')"
    echo "    index 0 type -> $(lxc-info -n "$name" -c lxc.net.0.type 2>&1 | tr '\n' ' ')"
    echo "    index $index type -> $(lxc-info -n "$name" -c "lxc.net.$index.type" 2>&1 | tr '\n' ' ')"

    # Without these the case is vacuous: a renumber that silently failed leaves
    # an ordinary index-0 container, every assertion below still passes, and the
    # test reports success for a topology it never built.
    if lxc-info -n "$name" -c lxc.net.0.type 2>/dev/null | grep -q .; then
        fail_now "$label: renumber did not take -- liblxc still reports an interface at lxc.net.0, so this case would not exercise index independence."
    fi
    if ! lxc-info -n "$name" -c "lxc.net.$index.type" 2>/dev/null | grep -q "veth"; then
        fail_now "$label: renumber did not take -- liblxc reports no veth at lxc.net.$index."
    fi
    if [ "$(lxc-info -n "$name" -c lxc.net 2>/dev/null | grep -c 'veth')" != "1" ]; then
        fail_now "$label: renumber left the container with something other than exactly one interface."
    fi
}

run_start_case() {
    local case_no="$1"
    local config="$2"
    local cause="$3"
    local expected="$4"
    local expect_success="$5"
    local must_exec="$6"
    local clause="$7"
    local assert_default_deny="${8:-}"
    local quarantine="${9:-}"
    local renumber_to="${10:-}"
    local req="$WORK_DIR/case_${case_no}.json"
    local out rc actual status sentinel

    start_fresh_sandbox "case $case_no"
    if [ -n "$renumber_to" ]; then
        renumber_sole_interface "$renumber_to" "case $case_no"
    fi
    make_request_from_config "$config" "$req"
    QUARANTINE_ACTIVE="$quarantine"

    echo "=== case $case_no start: $cause ==="
    out="$($LXC_EXEC "$req" 2>&1)"
    rc=$?
    echo "$out"

    if [ "$expect_success" = "1" ]; then
        if [ "$rc" -eq 0 ]; then
            check "case $case_no start succeeds for input $config -- $clause" 0
            SANDBOX_STARTED=1
            actual="start exited 0"
            status="PASS"
        else
            check "case $case_no start succeeds for input $config -- $clause" 1
            actual="start exited $rc: $(echo "$out" | tr '\n' ' ' | sed 's/|/ /g')"
            status="FAIL"
        fi

        if [ "$must_exec" = "1" ] && [ "$rc" -eq 0 ]; then
            sentinel="MXC_STATE_AWARE_NETWORK_CASE_${case_no}_RAN"
            echo "=== case $case_no exec: prove container is running ==="
            out="$(run_phase exec "$SANDBOX_ID" '"process": { "commandLine": "echo '"$sentinel"'" }' 2>&1)"
            rc=$?
            echo "$out"
            if [ "$rc" -eq 0 ] && echo "$out" | grep -Fq "$sentinel"; then
                check "case $case_no exec observes running container for input $config -- $clause" 0
                actual="$actual; exec printed $sentinel"
            else
                check "case $case_no exec observes running container for input $config -- $clause" 1
                actual="$actual; exec rc=$rc output=$(echo "$out" | tr '\n' ' ' | sed 's/|/ /g')"
                status="FAIL"
            fi
        fi

        if [ "$assert_default_deny" = "1" ] && [ "$rc" -eq 0 ]; then
            local veth chain direct terminal
            # The roadmap asks that the hook be applied, which a zero exit does
            # not show: a run that skipped enforcement and still reported success
            # would look identical here. Read the host instead, and read it
            # through the interface the container actually ended up with rather
            # than a name this test derived, so a hook aimed at the wrong
            # interface cannot pass.
            #
            # The physdev form is the one that decides the case. lxcbr0 is a
            # bridge, and on a bridged veth the plain `-i` rule installs cleanly
            # and never matches, so asserting only that form would accept a
            # container whose traffic walks past the chain untouched.
            veth="$(container_host_veth "${SANDBOX_ID#lxc:}")"
            chain=""
            direct=""
            if [ -n "$veth" ]; then
                chain="$(iptables -S FORWARD 2>/dev/null \
                    | awk -v v="$veth" 'index($0, "--physdev-in " v " -j ") { for (i = 1; i <= NF; i++) if ($i == "-j") { print $(i + 1); exit } }')"
                direct="$(iptables -S FORWARD 2>/dev/null \
                    | awk -v v="$veth" 'index($0, "-i " v " -j ") { for (i = 1; i <= NF; i++) if ($i == "-j") { print $(i + 1); exit } }')"
            fi

            echo "=== case $case_no default-deny: live veth=${veth:-<none>} physdev->${chain:-<none>} direct->${direct:-<none>} ==="
            if [ -n "$veth" ] && [ -n "$chain" ] && [ "$direct" = "$chain" ]; then
                check "case $case_no hooks live veth $veth into $chain on both the physdev and direct paths -- (N1) default-deny outbound" 0
                actual="$actual; FORWARD hooks $veth to $chain on both paths"
            else
                check "case $case_no hooks live veth ${veth:-<none>} into a chain on both the physdev and direct paths -- (N1) default-deny outbound" 1
                actual="$actual; physdev hook=${chain:-<none>} direct hook=${direct:-<none>} for veth ${veth:-<none>}"
                status="FAIL"
            fi

            terminal="$(iptables -S "$chain" 2>/dev/null | tail -1)"
            echo "=== case $case_no terminal rule: ${terminal:-<none>} ==="
            if [ -n "$chain" ] && [ "${terminal##* }" = "DROP" ]; then
                check "case $case_no hooked chain ends in DROP -- (N1) default-deny outbound" 0
                actual="$actual; chain ends in DROP"
            else
                check "case $case_no hooked chain ends in DROP -- (N1) default-deny outbound" 1
                actual="$actual; terminal rule was ${terminal:-<none>}"
                status="FAIL"
            fi
        fi
    else
        if [ "$rc" -ne 0 ] && expect_error_code "$out" "policy_validation"; then
            check "case $case_no start rejects input $config with policy_validation -- $clause" 0
            actual="start exited $rc with policy_validation"
            status="PASS"
        else
            check "case $case_no start rejects input $config with policy_validation -- $clause" 1
            actual="start rc=$rc output=$(echo "$out" | tr '\n' ' ' | sed 's/|/ /g')"
            status="FAIL"
            if [ "$rc" -eq 0 ]; then
                SANDBOX_STARTED=1
            fi
        fi
    fi

    # Clear before teardown so a genuine stop/deprovision failure is still a
    # real failure rather than being absorbed by this case's quarantine.
    if [ -n "$QUARANTINE_ACTIVE" ] && [ "$status" = "FAIL" ]; then
        status="QUARANTINED"
    fi
    QUARANTINE_ACTIVE=""

    finish_current_sandbox "case $case_no" "$config"
    record_result "$case_no" "$config" "$cause" "$expected" "$actual" "$status"
}

run_provision_rejection_case() {
    local case_no="$1"
    local config="$2"
    local cause="$3"
    local clause="$4"
    local expected='rejected with policy_validation'
    local out rc actual status

    echo "=== case $case_no provision rejection: $cause ==="
    out="$($LXC_EXEC "$config" 2>&1)"
    rc=$?
    echo "$out"

    if [ "$rc" -ne 0 ] && expect_error_code "$out" "policy_validation"; then
        check "case $case_no provision rejects input $config with policy_validation -- $clause" 0
        actual="provision exited $rc with policy_validation"
        status="PASS"
    else
        check "case $case_no provision rejects input $config with policy_validation -- $clause" 1
        actual="provision rc=$rc output=$(echo "$out" | tr '\n' ' ' | sed 's/|/ /g')"
        status="FAIL"
        SANDBOX_ID="$(printf '%s' "$out" | extract_sandbox_id)"
        if [ -n "$SANDBOX_ID" ]; then
            case "$SANDBOX_ID" in
                lxc:mxc-*) ;;
                *) fail_now "case $case_no unexpectedly returned unsafe-looking sandboxId '$SANDBOX_ID'; refusing to deprovision it." ;;
            esac
        fi
    fi
    finish_current_sandbox "case $case_no" "$config"
    record_result "$case_no" "$config" "$cause" "$expected" "$actual" "$status"
}

FS_RO_DIR="/mxc-e2e-ro"
FS_DENIED_DIR="/mxc-e2e-denied"
FS_SENTINEL="MXC_E2E_FS_SENTINEL"

# The filesystem lists are the one part of the start policy whose effect is not
# visible in iptables, so this case reads it where it does show: from inside the
# container. Host directories are created first because the parser refuses paths
# that do not exist (roadmap item 8), and each carries a sentinel file so a mount
# that silently did not happen cannot be mistaken for one that did.
run_filesystem_start_case() {
    local case_no="$1"
    local config="$2"
    local cause="$3"
    local clause="$4"
    local expected='start succeeds, the readonly path is readable but not writable, and the denied path is masked'
    local req="$WORK_DIR/case_${case_no}.json"
    local out rc actual status probe

    # These are absolute paths at the host root, so anything already there
    # belongs to something else and deleting it would destroy data this test
    # never created.
    for fixture_dir in "$FS_RO_DIR" "$FS_DENIED_DIR"; do
        if [ -e "$fixture_dir" ]; then
            fail_now "case $case_no found a pre-existing host path '$fixture_dir'; refusing to delete a directory this test did not create.  Remove it by hand if an interrupted run left it behind."
        fi
    done
    mkdir -p "$FS_RO_DIR" "$FS_DENIED_DIR" || fail_now "case $case_no could not create its host fixture directories"
    FS_FIXTURES_CREATED=1
    echo "$FS_SENTINEL" > "$FS_RO_DIR/sentinel"
    echo "$FS_SENTINEL" > "$FS_DENIED_DIR/sentinel"

    start_fresh_sandbox "case $case_no"
    make_request_from_config "$config" "$req"

    echo "=== case $case_no start: $cause ==="
    out="$($LXC_EXEC "$req" 2>&1)"
    rc=$?
    echo "$out"

    if [ "$rc" -eq 0 ]; then
        check "case $case_no start succeeds for input $config -- $clause" 0
        SANDBOX_STARTED=1
        actual="start exited 0"
        status="PASS"
    else
        check "case $case_no start succeeds for input $config -- $clause" 1
        actual="start exited $rc: $(echo "$out" | tr '\n' ' ' | sed 's/|/ /g')"
        status="FAIL"
    fi

    if [ "$rc" -eq 0 ]; then
        echo "=== case $case_no probe: read the mounts from inside the container ==="
        probe="cat $FS_RO_DIR/sentinel 2>/dev/null; touch $FS_RO_DIR/probe 2>/dev/null && echo RO_WRITABLE || echo RO_READONLY; cat $FS_DENIED_DIR/sentinel 2>/dev/null && echo DENIED_VISIBLE || echo DENIED_HIDDEN"
        out="$(run_phase exec "$SANDBOX_ID" '"process": { "commandLine": "'"$probe"'" }' 2>&1)"
        rc=$?
        echo "$out"

        if [ "$rc" -eq 0 ] && echo "$out" | grep -Fq "$FS_SENTINEL"; then
            check "case $case_no readonlyPaths mounts the host directory into the container -- $clause" 0
            actual="$actual; readonly path carries the host sentinel"
        else
            check "case $case_no readonlyPaths mounts the host directory into the container -- $clause" 1
            actual="$actual; readonly path did not carry the host sentinel (exec rc=$rc)"
            status="FAIL"
        fi

        if echo "$out" | grep -Fq "RO_READONLY"; then
            check "case $case_no readonlyPaths is mounted read-only -- $clause" 0
            actual="$actual; readonly path refused a write"
        else
            check "case $case_no readonlyPaths is mounted read-only -- $clause" 1
            actual="$actual; readonly path accepted a write"
            status="FAIL"
        fi

        if echo "$out" | grep -Fq "DENIED_HIDDEN"; then
            check "case $case_no deniedPaths masks the host directory -- $clause" 0
            actual="$actual; denied path is masked"
        else
            check "case $case_no deniedPaths masks the host directory -- $clause" 1
            actual="$actual; denied path still exposed the host sentinel"
            status="FAIL"
        fi
    fi

    finish_current_sandbox "case $case_no" "$config"
    rm -rf "$FS_RO_DIR" "$FS_DENIED_DIR"
    FS_FIXTURES_CREATED=0
    record_result "$case_no" "$config" "$cause" "$expected" "$actual" "$status"
}

LXC_PROXY_REFUSAL='LXC state-aware start does not support network.proxy'

# The proxy field needs its own case because neither wire form reaches the LXC
# verdict by the route the other cases use.
#
# A state-aware start may not carry `containment` -- the backend is fixed at
# provision and later phases route by sandboxId -- so the shared parser applies
# its backend-specific rules under the default backend. An external proxy url is
# refused there, before any LXC code runs. The builtin-test-server form skips
# that rule but is testing-only scaffolding gated centrally for every backend,
# so it needs --allow-testing-features to get past the gate.
#
# Both halves are asserted. The first opens the testing gate and requires LXC's
# own refusal *by its message*, because a case that accepted any non-zero exit
# would pass on the central gate alone and would still pass with LXC's refusal
# deleted. The second sends the production-shaped external form and requires only
# that it is refused -- which layer refuses it is not LXC's contract to state,
# but silently accepting it would leave the container talking past a proxy the
# caller believed was in force.
run_proxy_start_case() {
    local case_no="$1"
    local cause="$2"
    local clause="$3"
    local expected='start is refused, and the builtin form is refused by LXC itself'
    local req="$WORK_DIR/case_${case_no}.json"
    local out rc actual status

    start_fresh_sandbox "case $case_no"
    make_request_from_config "$CONFIG_PROXY" "$req"

    echo "=== case $case_no start: $cause ==="
    out="$($LXC_EXEC --allow-testing-features "$req" 2>&1)"
    rc=$?
    echo "$out"

    if [ "$rc" -ne 0 ] && expect_error_code "$out" "policy_validation" \
        && echo "$out" | grep -Fq "$LXC_PROXY_REFUSAL"; then
        check "case $case_no start refuses the builtin proxy with LXC's own verdict -- $clause" 0
        actual="start exited $rc with LXC's policy_validation refusal"
        status="PASS"
    else
        check "case $case_no start refuses the builtin proxy with LXC's own verdict -- $clause" 1
        actual="start rc=$rc output=$(echo "$out" | tr '\n' ' ' | sed 's/|/ /g')"
        status="FAIL"
        if [ "$rc" -eq 0 ]; then
            SANDBOX_STARTED=1
        fi
    fi

    if [ "$rc" -ne 0 ]; then
        make_request_from_config "$CONFIG_PROXY_EXTERNAL" "$req"
        echo "=== case $case_no start: external proxy url ==="
        out="$($LXC_EXEC "$req" 2>&1)"
        rc=$?
        echo "$out"
        if [ "$rc" -ne 0 ]; then
            check "case $case_no start refuses an external proxy url rather than accepting it -- $clause" 0
            actual="$actual; external url refused"
        else
            check "case $case_no start refuses an external proxy url rather than accepting it -- $clause" 1
            actual="$actual; external url started the container"
            status="FAIL"
            SANDBOX_STARTED=1
        fi
    fi

    finish_current_sandbox "case $case_no" "$CONFIG_PROXY"
    record_result "$case_no" "$CONFIG_PROXY" "$cause" "$expected" "$actual" "$status"
}

print_case_table() {
    echo "| Case | Config file | Cause | Expected effect | Actual result | Status |"
    echo "|---|---|---|---|---|---|"
    printf '%s' "$RESULTS" | while IFS='|' read -r case_no config cause expected actual status; do
        [ -n "$case_no" ] || continue
        echo "| $case_no | $config | $cause | $expected | $actual | $status |"
    done
}

verify_fixture_contracts
mkdir -p "$WORK_DIR" || fail_now "could not create work directory $WORK_DIR"

[ "$(id -u)" -eq 0 ] || skip "LXC state-aware network matrix UNVERIFIED — requires root for LXC."
command -v iptables >/dev/null 2>&1 || skip "LXC state-aware network matrix UNVERIFIED — iptables is not installed."
command -v ip6tables >/dev/null 2>&1 || skip "LXC state-aware network matrix UNVERIFIED — ip6tables is not installed."
command -v lxc-create >/dev/null 2>&1 || skip "LXC state-aware network matrix UNVERIFIED — LXC (lxc-create) is not installed."
[ -f "$LXC_EXEC" ] || skip "LXC state-aware network matrix UNVERIFIED — lxc-exec binary not built; run build.sh first."

echo "Running LXC state-aware network policy matrix test..."

run_start_case "1" "$CONFIG_NO_NETWORK" \
    'no network block at start' \
    'start succeeds, exec proves the container runs, and FORWARD drops by default' \
    "1" "1" \
    'an absent network block inherits deny-by-default and is enforced' \
    "1"

run_start_case "2" "$CONFIG_BLOCK_CAPS" \
    'defaultPolicy=block with enforcementMode omitted at start' \
    'start succeeds, exec proves the container runs, and FORWARD drops by default' \
    "1" "1" \
    'defaultPolicy=block is enforced when enforcementMode is omitted' \
    "1"

#
# This is the direct observable proof of roadmap item 13's "ensure hook is
# always applied": a stock provisioned container carries
# `lxc.include = /usr/share/lxc/config/common.conf`, and the default-deny hook
# has to reach it anyway. The assertion was previously quarantined because
# enumeration read the container's own config file, where an include hides
# whatever it pulls in; it is live now that enumeration asks liblxc, which has
# already resolved the include.
run_start_case "3" "$CONFIG_BLOCK_FIREWALL" \
    'defaultPolicy=block with enforcementMode=firewall at start' \
    'start succeeds, exec proves the container runs, and FORWARD drops by default' \
    "1" "1" \
    'an explicit firewall mode remains accepted, but is not required for enforcement' \
    "1"

run_start_case "4" "$CONFIG_ALLOW_CAPS" \
    'defaultPolicy=allow with enforcementMode omitted at start' \
    'start succeeds' \
    "1" "0" \
    'a permissive default needs no iptables rule and does not require firewall enforcement'

run_start_case "5" "$CONFIG_EMPTY_ALLOWED" \
    'allowedHosts empty list with enforcementMode omitted at start' \
    'start succeeds, exec proves the container runs, and FORWARD drops by default' \
    "1" "1" \
    'an empty list does not relax the inherited default-deny policy' \
    "1"

run_start_case "6" "$CONFIG_NONEMPTY_ALLOWED" \
    'allowedHosts non-empty with enforcementMode omitted at start' \
    'start succeeds, exec proves the container runs, and FORWARD drops by default' \
    "1" "1" \
    'a non-empty allowedHosts policy is enforced when enforcementMode is omitted' \
    "1"

# Clause: roadmap item 13 (N1) asks that default-deny outbound be enforced.  It
# says nothing about how the container numbers its interfaces, and an interface
# at lxc.net.3 is exactly as filterable as one at lxc.net.0 -- enforcement must
# not read the index at all.  This is the only case that separates "MXC enforced
# whichever interface the container has" from "MXC assumed index 0", so it is
# the one that fails if any index assumption is ever reintroduced.
run_start_case "10" "$CONFIG_BLOCK_FIREWALL" \
    'defaultPolicy=block with enforcementMode=firewall on a container whose only interface is at lxc.net.3' \
    'start succeeds, exec proves the container runs, and FORWARD drops by default' \
    "1" "1" \
    '(N1) default-deny outbound does not depend on the interface index' \
    "1" "" "3"

# Clause: the LXC matrix marks network as rejected at provision.
run_provision_rejection_case "7" "$CONFIG_PROVISION_NETWORK" \
    'network.defaultPolicy=block sent at provision' \
    'matrix marks network as rejected at provision'

# Clause: the LXC matrix marks a non-empty filesystem path list as rejected at
# provision.
run_provision_rejection_case "8" "$CONFIG_PROVISION_FILESYSTEM" \
    'filesystem block with a populated path list sent at provision' \
    'matrix marks a non-empty filesystem path list as rejected at provision'

# Clause: roadmap item 13 (N1) names firewall enforcement, and the schema offers
# `both` alongside `firewall`. Case 3 pins `firewall`; nothing pinned `both`, so
# a mode that parsed but enforced nothing would have gone unnoticed. This asserts
# the same host-visible default-deny for it.
run_start_case "11" "$CONFIG_BLOCK_BOTH" \
    'defaultPolicy=block with enforcementMode=both at start' \
    'start succeeds, exec proves the container runs, and FORWARD drops by default' \
    "1" "1" \
    '(N1) default-deny outbound is enforced under enforcementMode=both' \
    "1"

# Case 12 preserves compatibility for callers that explicitly request firewall enforcement.
run_start_case "12" "$CONFIG_ALLOWED_FIREWALL" \
    'allowedHosts non-empty with enforcementMode=firewall at start' \
    'start succeeds, exec proves the container runs, and FORWARD drops by default' \
    "1" "1" \
    '(N3) a non-empty allowedHosts policy remains enforceable with an explicit firewall mode' \
    "1"

run_start_case "13" "$CONFIG_BLOCKED_CAPS" \
    'blockedHosts non-empty with enforcementMode omitted at start' \
    'start succeeds, exec proves the container runs, and FORWARD drops by default' \
    "1" "1" \
    '(N4) a non-empty blockedHosts policy is enforced when enforcementMode is omitted' \
    "1"

# Clause: roadmap item 14 (N2) is explicit -- "reject `hostLoopback: "allow"`
# rather than guessing ports or exposing the container IP." The roadmap records
# `allowLocalNetwork` as "parsed but silently ignored", which is the behavior the
# item asks to replace. A silent ignore and a refusal both exit non-zero on
# nothing, so only asserting the error code separates them.
run_start_case "14" "$CONFIG_ALLOW_LOCAL" \
    'allowLocalNetwork=true at start' \
    'start fails with policy_validation' \
    "0" "0" \
    '(N2) allowLocalNetwork is rejected rather than silently ignored'

# Clause: roadmap item 17 (N5) records the proxy field as one the backend
# ignores, and asks for env-var injection plus egress restriction to the proxy
# port. That work is not in this PR. What is in scope is item 13 (N1)'s posture:
# fail fast rather than silently skip. A start that accepted a proxy it cannot
# enforce would report success while the container talked past it, so it is
# refused until the enforcement item 17 describes exists. See
# run_proxy_start_case for why this case needs both wire forms.
run_proxy_start_case "15" \
    'network.proxy set at start' \
    '(N5) an unenforceable proxy is refused rather than silently ignored'

# Clause: the start phase accepts the filesystem lists it rejects at provision
# (case 8), and D1/D4 ask that readonly be readable-not-writable and that
# denied be masked. Case 8 only pins the provision-time refusal; without this,
# no case shows the lists ever take effect anywhere.
run_filesystem_start_case "16" "$CONFIG_FILESYSTEM_PATHS" \
    'readonlyPaths and deniedPaths sent at start' \
    'the start phase applies the filesystem lists it refuses at provision'

echo "================================"
echo "Results: $PASSED passed, $FAILED failed, $QUARANTINED quarantined"
print_case_table
if [ "$QUARANTINED" -gt 0 ]; then
    echo ""
    echo "!!! $QUARANTINED assertion(s) QUARANTINED -- these behaviors are NOT verified !!!"
    printf '%s' "$QUARANTINE_NOTES"
fi
if [ "$FAILED" -gt 0 ]; then
    exit 1
fi
