#!/bin/sh
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set -eu
directory=${0%/*}

case "$1" in
    deconfig|nak|leasefail)
        rm -f "$directory/address" "$directory/gateway" "$directory/lease" \
            "$directory/resolv.conf" "$directory/resolv.conf.new"
        ;;

    bound|renew)
        rm -f "$directory/address"
        trap 'rm -f "$directory/address" "$directory/gateway" "$directory/lease" "$directory/resolv.conf" "$directory/resolv.conf.new"' EXIT
        : "${ip:?DHCP omitted the address}" "${mask:?DHCP omitted the subnet mask}" \
            "${router:?DHCP omitted the gateway}" "${lease:?DHCP omitted the lease duration}"
        set -- $router
        test "$#" -gt 0
        printf '%s\n' "$1" > "$directory/gateway"
        printf '%s\n' "$lease" > "$directory/lease"

        {
            for server in ${dns:-}; do
                printf 'nameserver %s\n' "$server"
            done

            if [ -n "${search:-${domain:-}}" ]; then
                printf 'search %s\n' "${search:-$domain}"
            fi
        } > "$directory/resolv.conf.new"
        mv "$directory/resolv.conf.new" "$directory/resolv.conf"
        printf '%s/%s\n' "$ip" "$mask" > "$directory/address"
        trap - EXIT
        ;;
esac
