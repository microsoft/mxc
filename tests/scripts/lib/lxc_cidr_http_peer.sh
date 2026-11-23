#!/bin/bash

LXC_EXEC="$REPO_DIR/src/target/release/lxc-exec"
if [ ! -f "$LXC_EXEC" ]; then
    LXC_EXEC="$REPO_DIR/src/target/debug/lxc-exec"
fi

skip()
{
    echo "SKIP: $1"
    exit 77
}

fail()
{
    echo "FAIL: $1"
    exit 1
}

[ "$(id -u)" -eq 0 ] || skip "requires root for LXC and the local HTTP peer."
for tool in iptables ip6tables lxc-create lxc-info lxc-attach nsenter ip python3 timeout; do
    command -v "$tool" >/dev/null 2>&1 || skip "$tool is not installed."
done
[ -f "$LXC_EXEC" ] || skip "lxc-exec binary not built; run build.sh first."

# shellcheck source=lxc_peer_listener.sh
. "$SCRIPT_DIR/lib/lxc_peer_listener.sh"

WORK_DIR="$REPO_DIR/.lxc-$TEST_NAME-$$"
PEER_NETNS="mxc-$TEST_NAME-$$"
PEER_VETH=cidrpeer0
CONTAINER_VETH=cidrprobe0
CONTAINER="mxc-$TEST_NAME-$$"
LISTENER_PID=""
RUN_PID=""

cleanup_cidr_http_peer()
{
    if [ -n "$RUN_PID" ]; then
        kill -TERM "$RUN_PID" 2>/dev/null || true
        wait "$RUN_PID" 2>/dev/null || true
    fi
    timeout --kill-after=5 30 "$LXC_EXEC" --delete --containername "$CONTAINER" >/dev/null 2>&1 || true
    if [ -n "$LISTENER_PID" ]; then
        kill "$LISTENER_PID" 2>/dev/null || true
        wait "$LISTENER_PID" 2>/dev/null || true
    fi
    ip netns del "$PEER_NETNS" >/dev/null 2>&1 || true
    rm -rf "$WORK_DIR"
}
trap cleanup_cidr_http_peer EXIT

HTTP_PROBE_COMMAND="$(cat <<'SH'
set -eu
command -v wget >/dev/null
until [ -e /cidr-ready ]; do sleep 0.1; done
probe_http()
{
    target="$1"
    expected="$2"
    case "$target" in
        *:*) host="[$target]" ;;
        *) host="$target" ;;
    esac

    # Fetch the peer's response body without using proxy environment variables.
    if body=$(wget -Y off -qO- -T 3 "http://$host:8080/response"); then
        [ "$body" = CIDR_PEER ] || { echo "FAIL: $target returned unexpected HTTP bytes: $body"; exit 1; }
        observed=allowed
    else
        [ -z "$body" ] || { echo "FAIL: $target returned HTTP bytes despite a failed request: $body"; exit 1; }
        observed=blocked
    fi
    [ "$observed" = "$expected" ] || {
        echo "FAIL: $target expected HTTP $expected, got $observed"
        exit 1
    }
}
SH
)"

mkdir "$WORK_DIR"
printf 'CIDR_PEER\n' >"$WORK_DIR/response"
ip netns add "$PEER_NETNS"
ip -n "$PEER_NETNS" link set lo up
ip netns exec "$PEER_NETNS" python3 -m http.server 8080 --bind :: --directory "$WORK_DIR" \
    >"$WORK_DIR/peer.log" 2>&1 &
LISTENER_PID=$!
if ! ip netns exec "$PEER_NETNS" bash -c '. "$1"; await_peer_tcp 127.0.0.1 8080' \
    bash "$SCRIPT_DIR/lib/lxc_peer_listener.sh"; then
    cat "$WORK_DIR/peer.log"
    fail "the local HTTP peer did not accept a connection."
fi

run_cidr_http_case()
{
    local case="$1" init_pid="" candidate deadline status=0 peer_mac container_mac target
    echo "--- $TEST_NAME HTTP traffic: $case ---"
    timeout --kill-after=10 300 "$LXC_EXEC" "$WORK_DIR/$case.json" >"$WORK_DIR/run.log" 2>&1 &
    RUN_PID=$!
    deadline=$((SECONDS + 300))
    while [ "$SECONDS" -lt "$deadline" ]; do
        if ! kill -0 "$RUN_PID" 2>/dev/null; then
            wait "$RUN_PID" || status=$?
            RUN_PID=""
            cat "$WORK_DIR/run.log"
            fail "$case: lxc-exec exited with status $status before a container init PID was available."
        fi
        candidate="$(lxc-info -n "$CONTAINER" -pH 2>/dev/null)" || candidate=""
        if [[ "$candidate" =~ ^[0-9]+$ ]] && [ "$candidate" -gt 0 ]; then
            init_pid="$candidate"
            break
        fi
        sleep 0.2
    done
    if [ -z "$init_pid" ]; then
        cat "$WORK_DIR/run.log"
        fail "$case: no positive container init PID was available within 300 seconds."
    fi

    ip -n "$PEER_NETNS" link add "$PEER_VETH" type veth peer name "$CONTAINER_VETH"
    ip -n "$PEER_NETNS" link set "$CONTAINER_VETH" netns "$init_pid"
    ip -n "$PEER_NETNS" link set "$PEER_VETH" up
    nsenter -t "$init_pid" -n ip link set "$CONTAINER_VETH" up
    nsenter -t "$init_pid" -n ip addr add 198.18.78.1/32 dev "$CONTAINER_VETH"
    nsenter -t "$init_pid" -n ip -6 addr add fd00:78:88::1/128 dev "$CONTAINER_VETH" nodad
    peer_mac="$(ip -n "$PEER_NETNS" -o link show "$PEER_VETH" | sed -n 's/.*link\/ether \([^ ]*\).*/\1/p')"
    container_mac="$(nsenter -t "$init_pid" -n ip -o link show "$CONTAINER_VETH" \
        | sed -n 's/.*link\/ether \([^ ]*\).*/\1/p')"

    # Route HTTP replies directly back to the container's probe interface.
    ip -n "$PEER_NETNS" route add 198.18.78.1/32 dev "$PEER_VETH"
    ip -n "$PEER_NETNS" -6 route add fd00:78:88::1/128 dev "$PEER_VETH"
    ip -n "$PEER_NETNS" -6 neigh add fd00:78:88::1 lladdr "$container_mac" dev "$PEER_VETH" nud permanent

    while IFS= read -r target; do
        if [[ "$target" == *:* ]]; then
            ip -n "$PEER_NETNS" -6 addr add "$target/128" dev "$PEER_VETH" nodad
            nsenter -t "$init_pid" -n ip -6 route add "$target/128" dev "$CONTAINER_VETH" src fd00:78:88::1

            # Keep neighbor discovery from becoming an unrelated default-deny failure.
            nsenter -t "$init_pid" -n ip -6 neigh add "$target" lladdr "$peer_mac" \
                dev "$CONTAINER_VETH" nud permanent
        else
            ip -n "$PEER_NETNS" addr add "$target/32" dev "$PEER_VETH"
            nsenter -t "$init_pid" -n ip route add "$target/32" dev "$CONTAINER_VETH" src 198.18.78.1
        fi
    done <"$WORK_DIR/targets"

    # Release the waiting workload only after every peer address and route is ready.
    lxc-attach -n "$CONTAINER" -- touch /cidr-ready
    wait "$RUN_PID" || status=$?
    RUN_PID=""
    cat "$WORK_DIR/run.log"
    [ "$status" -eq 0 ] || fail "$case: lxc-exec exited with status $status."
}
