#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
TEST_NAME=cidr-boundary

# shellcheck source=lib/lxc_cidr_http_peer.sh
. "$SCRIPT_DIR/lib/lxc_cidr_http_peer.sh"

python3 - "$REPO_DIR/tests/configs/lxc_network_cidr_boundary.json" \
    "$WORK_DIR" "$CONTAINER" "$HTTP_PROBE_COMMAND" <<'PY'
import json
import pathlib
import shlex
import sys

config = json.loads(pathlib.Path(sys.argv[1]).read_text())
directory = pathlib.Path(sys.argv[2])
egress = config["network"]["egress"]
denied = ["198.51.100.42", "2001:db8::5"]
neighbors = ["198.51.100.43", "2001:db8::6"]
cases = [
    ("control", {"default": "allow"}, [(host, "allowed") for host in denied + neighbors]),
    ("boundary", egress,
     [(host, "blocked") for host in denied] + [(host, "allowed") for host in neighbors]),
]
for name, policy, probes in cases:
    command = sys.argv[4] + "\n" + "\n".join(
        f"probe_http {shlex.quote(host)} {expected}" for host, expected in probes
    )
    config["containerId"] = sys.argv[3]
    config["process"]["commandLine"] = "sh -c " + shlex.quote(command)
    config["network"]["egress"] = policy
    (directory / f"{name}.json").write_text(json.dumps(config))
(directory / "targets").write_text("\n".join(denied + neighbors) + "\n")
PY

for case in control boundary; do
    run_cidr_http_case "$case"
done

echo "PASS: /0 permits HTTP while /32 and /128 deny only their exact destinations."
