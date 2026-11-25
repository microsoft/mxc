#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set -euo pipefail
umask 022

if [ "$#" -lt 2 ]; then
    echo "Usage: $0 <output-directory> <command> [arguments...]" >&2
    exit 2
fi

output_directory=$1
shift
mkdir -p "$output_directory"
capture_pid=
sampler_pid=

cleanup()
{
    local status=$?
    trap - EXIT
    if [ -n "$sampler_pid" ]; then
        kill -TERM "$sampler_pid" 2>/dev/null || true
        wait "$sampler_pid" 2>/dev/null || true
    fi
    if [ -n "$capture_pid" ]; then
        if kill -0 "$capture_pid" 2>/dev/null; then
            kill -INT "$capture_pid"
        else
            echo "DHCP packet capture stopped unexpectedly; see $output_directory/tcpdump.log" >&2
            [ "$status" -ne 0 ] || status=1
        fi
        if ! wait "$capture_pid"; then
            echo "DHCP packet capture failed; see $output_directory/tcpdump.log" >&2
            [ "$status" -ne 0 ] || status=1
        fi
    fi
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

snapshot()
{
    echo "=== $(date --iso-8601=ns) ==="
    local file pid argument
    for file in /run/lxc/dnsmasq.pid /etc/default/lxc /etc/lxc/dnsmasq.conf; do
        if [ -f "$file" ]; then
            echo "--- $file ---"
            cat "$file" || echo "Snapshot read failed: $file"
        fi
    done
    if [ -f /run/lxc/dnsmasq.pid ]; then
        pid=$(cat /run/lxc/dnsmasq.pid)
        if [[ "$pid" =~ ^[0-9]+$ ]] && [ -r "/proc/$pid/cmdline" ]; then
            echo "--- dnsmasq PID $pid arguments ---"
            tr '\0' '\n' < "/proc/$pid/cmdline"
            while IFS= read -r argument; do
                case "$argument" in
                    --dhcp-leasefile=*)
                        file=${argument#--dhcp-leasefile=}
                        echo "--- lease file $file ---"
                        cat "$file" || echo "Snapshot read failed: $file"
                        ;;
                esac
            done < <(tr '\0' '\n' < "/proc/$pid/cmdline")
        fi
    fi
    if [ -d /var/lib/mxc-lxc-network/reservations ]; then
        echo "--- published reservations ---"
        find /var/lib/mxc-lxc-network/reservations -maxdepth 1 -type f \
            -exec sh -c 'for file do echo "--- $file ---"; cat "$file"; done' sh {} + ||
            echo "Reservation snapshot changed while reading"
    fi
    if [ -d /var/lib/lxc ]; then
        echo "--- container network configuration ---"
        find /var/lib/lxc -maxdepth 2 -name config -type f \
            -exec grep -HE '^[[:space:]]*lxc\.net\..*\.(hwaddr|ipv4\.address|link)[[:space:]]*=' {} + ||
            echo "No readable matching container network configuration"
    fi
    echo "--- host links, addresses, and neighbors ---"
    ip -j link show
    ip -j address show
    ip -j neighbor show
}

# Bound packet storage to two 5 MB files; include ARP conflict detection.
tcpdump -i lxcbr0 -Z root -s 0 -U -C 5 -W 2 -w "$output_directory/dhcp.pcap" \
    'arp or (udp and (port 67 or port 68))' > "$output_directory/tcpdump.log" 2>&1 &
capture_pid=$!
sleep 1
if ! kill -0 "$capture_pid" 2>/dev/null; then
    echo "DHCP packet capture did not start" >&2
    cat "$output_directory/tcpdump.log" >&2
    exit 1
fi

(
    while :; do
        snapshot
        sleep 1
    done
) > "$output_directory/state.log" 2>&1 &
sampler_pid=$!

printf '%q ' "$@" > "$output_directory/command.txt"
printf '\n' >> "$output_directory/command.txt"
set +e
"$@" 2>&1 | tee "$output_directory/command.log"
statuses=("${PIPESTATUS[@]}")
set -e
if ! kill -0 "$sampler_pid" 2>/dev/null; then
    echo "DHCP state sampler stopped unexpectedly; see $output_directory/state.log" >&2
    exit 1
fi
snapshot >> "$output_directory/state.log" 2>&1
if [ "${statuses[0]}" -ne 0 ]; then
    exit "${statuses[0]}"
fi
exit "${statuses[1]}"
