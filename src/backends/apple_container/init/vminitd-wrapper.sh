#!/bin/sh
set -eu

log() {
    printf '<6>mxc-init: %s\n' "$*" > /dev/kmsg
}

install_family_policy() {
    command="$1"

    "$command" -w -F
    "$command" -w -X
    "$command" -w -P INPUT DROP
    "$command" -w -P FORWARD DROP
    "$command" -w -P OUTPUT DROP
    "$command" -w -A INPUT -i lo -j ACCEPT
    "$command" -w -A OUTPUT -o lo -j ACCEPT
}

log "installing loopback-only IPv4 and IPv6 policy"
install_family_policy /usr/sbin/iptables
install_family_policy /usr/sbin/ip6tables
log "network policy installed"

exec /sbin/vminitd.real "$@"
