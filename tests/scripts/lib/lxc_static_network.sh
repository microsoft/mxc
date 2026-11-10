#!/bin/bash

run_with_static_guest_ipv4() (
    config="$1"
    run_config="$REPO_DIR/tests/configs/.lxc-static-network-$BASHPID.json"
    run_log="$REPO_DIR/tests/configs/.lxc-static-network-$BASHPID.log"
    run_pid=""
    : >"$run_log" || exit 1
    trap '
        status=$?
        if [ -n "$run_pid" ]; then
            kill -TERM "$run_pid" 2>/dev/null || true
            wait "$run_pid" 2>/dev/null || true
        fi
        cat "$run_log"
        rm -f "$run_config" "$run_log"
        exit "$status"
    ' EXIT

    # Hold the original probe until host tools have assigned its guest address.
    container="$(python3 - "$config" "$run_config" <<'PY'
import json, shlex, sys
config = json.load(open(sys.argv[1]))
command = config["process"]["commandLine"]
gate = (
    "set -e; rm -f /mxc-static-network-ready; "
    "echo MXC_STATIC_NETWORK_READY; "
    "while [ ! -f /mxc-static-network-ready ]; do sleep 0.1; done; exec "
)
config["process"]["commandLine"] = "sh -c " + shlex.quote(gate + command)
with open(sys.argv[2], "w") as stream:
    json.dump(config, stream)
print(config["containerId"])
PY
)" || exit 1

    "$LXC_EXEC" --debug "$run_config" >"$run_log" 2>&1 &
    run_pid=$!
    for ((attempt = 0; attempt < 600; attempt++)); do
        grep -Fq MXC_STATIC_NETWORK_READY "$run_log" && break
        kill -0 "$run_pid" 2>/dev/null || { echo "FAIL: the probe exited before address setup."; exit 1; }
        sleep 0.5
    done
    grep -Fq MXC_STATIC_NETWORK_READY "$run_log" \
        || { echo "FAIL: the probe never reached address setup."; exit 1; }
    init_pid="$(lxc-info -n "$container" -p -H)" || exit 1

    # Reserve an address in the bridge's subnet without requiring DHCP.
    read -r host_ip guest_cidr < <(
        ip -j -4 address show dev lxcbr0 | python3 -c '
import ipaddress, json, sys
address = json.load(sys.stdin)[0]["addr_info"][0]
network = ipaddress.ip_network(f"{address['\''local'\'']}/{address['\''prefixlen'\'']}", strict=False)
print(address["local"], f"{network.broadcast_address - 2}/{network.prefixlen}")
'
    ) || exit 1

    # Enter init's network namespace using host-installed addressing tools.
    nsenter -t "$init_pid" -n ip -4 address flush dev eth0 || exit 1
    nsenter -t "$init_pid" -n ip address replace "$guest_cidr" dev eth0 || exit 1
    nsenter -t "$init_pid" -n ip link set eth0 up || exit 1
    nsenter -t "$init_pid" -n ip route replace default via "$host_ip" || exit 1
    lxc-attach -n "$container" -- touch /mxc-static-network-ready || exit 1

    if wait "$run_pid"; then
        status=0
    else
        status=$?
    fi
    run_pid=""
    exit "$status"
)
