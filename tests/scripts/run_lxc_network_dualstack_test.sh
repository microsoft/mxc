#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
TEST_NAME=dualstack

# shellcheck source=lib/lxc_cidr_http_peer.sh
. "$SCRIPT_DIR/lib/lxc_cidr_http_peer.sh"

python3 - "$REPO_DIR/tests/configs/lxc_network_dualstack_cidr.json" \
    "$WORK_DIR" "$CONTAINER" "$HTTP_PROBE_COMMAND" <<'PY'
import json
import pathlib
import shlex
import sys

config = json.loads(pathlib.Path(sys.argv[1]).read_text())
directory = pathlib.Path(sys.argv[2])
egress = config["network"]["egress"]
allowed = ["1.1.1.1", "8.8.8.8", "2606:4700:4700::1111", "2001:4860:4860::8888"]
denied = ["10.0.0.1", "2001:db8::1"]
unlisted = ["198.51.100.1", "2001:db9::1"]
cases = [
    ("control", {"default": "allow"}, [(host, "allowed") for host in allowed + denied + unlisted]),
    ("deny", {**egress, "default": "allow"},
     [(host, "blocked") for host in denied] + [(host, "allowed") for host in unlisted]),
    ("mixed", egress,
     [(host, "allowed") for host in allowed] + [(host, "blocked") for host in denied + unlisted]),
]
for name, policy, probes in cases:
    command = sys.argv[4] + "\n" + "\n".join(
        f"probe_http {shlex.quote(host)} {expected}" for host, expected in probes
    )
    config["containerId"] = sys.argv[3]
    config["process"]["commandLine"] = "sh -c " + shlex.quote(command)
    config["network"]["egress"] = policy
    (directory / f"{name}.json").write_text(json.dumps(config))
(directory / "targets").write_text("\n".join(allowed + denied + unlisted) + "\n")
PY

for case in control deny mixed; do
    run_cidr_http_case "$case"
done

echo "PASS: mixed IPv4/IPv6 CIDRs permit listed HTTP destinations and refuse denied or unlisted destinations."
