#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
LXC_EXEC="${LXC_EXEC:-$REPO_DIR/src/target/release/lxc-exec}"
if [ "$LXC_EXEC" = "$REPO_DIR/src/target/release/lxc-exec" ] && [ ! -f "$LXC_EXEC" ]; then
    LXC_EXEC="$REPO_DIR/src/target/debug/lxc-exec"
fi

fail() {
    echo "FAIL: $1"
    exit 1
}

CONFIG="$REPO_DIR/tests/configs/${1:-lxc_network_cidr_boundary}.json"
BEFORE_FILE="$REPO_DIR/tests/configs/.lxc-cidr-before-$$.json"
LIVE_FILE="$REPO_DIR/tests/configs/.lxc-cidr-live-$$.json"
BEFORE_NFT="$(nft -s list ruleset)"
nft -j list ruleset >"$BEFORE_FILE"
mapfile -t CONFIGS < <(python3 - "$CONFIG" "$$" <<'PY'
import base64, json, sys
config = json.load(open(sys.argv[1]))
assert config["network"]["egress"]["default"] == "deny"
config["containerId"] += "-" + sys.argv[2]
config["process"]["commandLine"] = "true"
for destroy, preserve in ((False, True), (True, False)):
    config["lifecycle"] = {"destroyOnExit": destroy, "preservePolicy": preserve}
    print(base64.b64encode(json.dumps(config).encode()).decode())
PY
)
[ "${#CONFIGS[@]}" = 2 ] || fail "could not prepare the CIDR fixture."

cleanup() {
    "$LXC_EXEC" --config-base64 "${CONFIGS[1]}" >/dev/null 2>&1 || true
    rm -f "$BEFORE_FILE" "$LIVE_FILE"
}
trap cleanup EXIT

OUTPUT=$("$LXC_EXEC" --config-base64 "${CONFIGS[0]}" 2>&1) \
    || fail "the valid CIDR fixture was refused: $OUTPUT"
nft -j list ruleset >"$LIVE_FILE"

python3 - "$CONFIG" "$BEFORE_FILE" "$LIVE_FILE" <<'PY'
import ipaddress, json, pathlib, sys
config = json.load(open(sys.argv[1]))
expected = {
    "lxc_network_cidr_boundary": (
        {"0.0.0.0/0", "::/0", "140.82.112.0/20", "140.82.112.5/32", "2606:50c0::/32"},
        {"198.51.100.42/32", "2001:db8::5/128"}
    ),
    "lxc_network_ipv6_cidr": (
        {"140.82.112.0/20", "2606:50c0::/32", "2606:50c0:8000::153/128"},
        {"10.0.0.0/8", "2001:db8::/32", "fe80::1/128"}
    ),
    "lxc_network_dualstack_cidr": (
        {"127.0.0.1/32", "1.1.1.1/32", "2606:4700:4700::1111/128", "8.8.8.8/32", "2001:4860:4860::8888/128"},
        {"10.0.0.0/8", "2001:db8::/32"}
    )
}[pathlib.Path(sys.argv[1]).stem]
for action, destinations in zip(("allow", "deny"), expected):
    actual = {target["cidr"] for rule in config["network"]["egress"][action] for target in rule["to"]}
    assert actual == destinations, f"{action} destinations drifted in the CIDR fixture"
before = json.load(open(sys.argv[2]))["nftables"]
after = json.load(open(sys.argv[3]))["nftables"]
identifiers = {
    (item["rule"]["family"], item["rule"]["table"], item["rule"]["chain"], item["rule"]["handle"])
    for item in before if "rule" in item
}
rules = [
    item["rule"] for item in after if "rule" in item
    and (item["rule"]["family"], item["rule"]["table"], item["rule"]["chain"], item["rule"]["handle"]) not in identifiers
]
for action, verdict in (("allow", "accept"), ("deny", "drop")):
    for configured in config["network"]["egress"][action]:
        for destination in configured["to"]:
            expected = ipaddress.ip_network(destination["cidr"])
            protocol = "ip" if expected.version == 4 else "ip6"
            found = False
            for rule in rules:
                if {verdict: None} not in rule["expr"]:
                    continue
                for statement in rule["expr"]:
                    match = statement.get("match", {})
                    if match.get("left") != {"payload": {"protocol": protocol, "field": "daddr"}} or match.get("op") != "==":
                        continue
                    value = match["right"]
                    if isinstance(value, dict) and "prefix" in value:
                        value = f"{value['prefix']['addr']}/{value['prefix']['len']}"
                    if ipaddress.ip_network(value) == expected:
                        found = True
            assert found, f"host kernel has no {protocol} destination rule for {expected} -> {verdict}"
PY

"$LXC_EXEC" --config-base64 "${CONFIGS[1]}" || fail "the CIDR fixture could not be destroyed."
[ "$(nft -s list ruleset)" = "$BEFORE_NFT" ] || fail "CIDR fixture cleanup left host rules."
trap - EXIT
rm -f "$BEFORE_FILE" "$LIVE_FILE"
echo "PASS: configured IPv4 and IPv6 destinations and verdicts reached the host kernel."
