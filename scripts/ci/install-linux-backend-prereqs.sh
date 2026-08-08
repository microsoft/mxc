#!/usr/bin/env bash
set -euo pipefail

# Installs the host packages a Linux backend needs before its artifact-only
# test suite runs. Distro-aware so the same matrix entry works on Ubuntu,
# Debian, and RHEL images.

usage() {
    echo "Usage: $0 <bubblewrap|lxc|microvm|hyperlight> <binary-directory>" >&2
}

if [[ $# -ne 2 ]]; then
    usage
    exit 2
fi

backend="$1"
binary_directory="$2"

apt_update() {
    # Unrelated third-party repositories on the pool images can fail to
    # refresh; the package install below still decides success.
    if ! sudo apt-get update; then
        echo "WARNING: apt-get update reported repository errors; continuing with available package indexes." >&2
    fi
}

install_epel() {
    local package_manager="$1"
    if ! sudo "$package_manager" install -y epel-release; then
        sudo "$package_manager" install -y \
            https://dl.fedoraproject.org/pub/epel/epel-release-latest-10.noarch.rpm
    fi
}

install_bubblewrap() {
    if command -v bwrap >/dev/null 2>&1; then
        return
    fi
    if command -v apt-get >/dev/null 2>&1; then
        apt_update
        sudo apt-get install -y --no-install-recommends bubblewrap
    elif command -v dnf >/dev/null 2>&1; then
        sudo dnf install -y bubblewrap
    elif command -v yum >/dev/null 2>&1; then
        sudo yum install -y bubblewrap
    elif command -v microdnf >/dev/null 2>&1; then
        sudo microdnf install -y bubblewrap
    else
        echo "No supported package manager found to install bubblewrap." >&2
        exit 1
    fi
}

install_lxc() {
    if command -v lxc-start >/dev/null 2>&1; then
        return
    fi
    if command -v apt-get >/dev/null 2>&1; then
        apt_update
        # Debian dropped lxc-utils; Ubuntu still ships it.
        local packages=(lxc dnsmasq-base iptables bridge-utils)
        if apt-cache show lxc-utils >/dev/null 2>&1; then
            packages+=(lxc-utils)
        fi
        sudo apt-get install -y --no-install-recommends "${packages[@]}"
    elif command -v dnf >/dev/null 2>&1; then
        install_epel dnf
        sudo dnf install -y lxc lxc-templates dnsmasq iptables
    elif command -v yum >/dev/null 2>&1; then
        install_epel yum
        sudo yum install -y lxc lxc-templates dnsmasq iptables
    elif command -v microdnf >/dev/null 2>&1; then
        install_epel microdnf
        sudo microdnf install -y lxc lxc-templates dnsmasq iptables
    else
        echo "No supported package manager found to install LXC." >&2
        exit 1
    fi
}

# Start the LXC bridge and wait until it can actually serve containers.
# A freshly installed lxc-net needs a moment before lxcbr0 has its IPv4 and
# dnsmasq is answering DHCP/DNS. Without this wait a container can boot into a
# bridge that has no lease to give, which surfaces much later as an unrelated
# name-resolution failure inside the guest.
start_lxc_bridge() {
    local bridge="${LXC_BRIDGE:-lxcbr0}"

    if command -v systemctl >/dev/null 2>&1; then
        if systemctl list-unit-files lxc-net.service >/dev/null 2>&1 &&
            systemctl cat lxc-net.service >/dev/null 2>&1; then
            sudo systemctl start lxc-net
        else
            echo "No lxc-net unit on this distribution; skipping bridge startup."
        fi
    fi

    if ! ip link show "$bridge" >/dev/null 2>&1; then
        echo "WARNING: bridge $bridge does not exist; container networking may be unavailable." >&2
        return 0
    fi

    local deadline=$((SECONDS + 30))
    while (( SECONDS < deadline )); do
        if ip -4 addr show "$bridge" 2>/dev/null | grep -q 'inet '; then
            echo "Bridge $bridge is up:"
            ip -4 addr show "$bridge" | sed -n 's/^[[:space:]]*\(inet .*\)$/  \1/p'
            if pgrep -f "dnsmasq.*$bridge" >/dev/null 2>&1; then
                echo "  dnsmasq is serving $bridge"
            else
                echo "  WARNING: no dnsmasq bound to $bridge; DHCP and DNS may fail." >&2
            fi
            return 0
        fi
        sleep 1
    done

    echo "WARNING: $bridge did not receive an IPv4 address within 30s." >&2
    ip addr show "$bridge" || true
}

chmod +x "$binary_directory/lxc-exec"
case "$backend" in
    bubblewrap)
        install_bubblewrap
        command -v bwrap
        if sysctl kernel.apparmor_restrict_unprivileged_userns >/dev/null 2>&1; then
            sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0
        fi
        ;;
    lxc)
        install_lxc
        command -v lxc-start
        sudo -n true
        # Package installs may not activate the AppArmor profile, which
        # lxc-start needs.
        if command -v apparmor_parser >/dev/null 2>&1; then
            sudo apparmor_parser -rT /etc/apparmor.d/lxc* 2>/dev/null || true
        fi
        start_lxc_bridge
        ;;
    microvm)
        for file in nanvixd.elf nanvix_rootfs.img python3.initrd bin/kernel.elf; do
            test -f "$binary_directory/$file"
        done
        ;;
    hyperlight)
        echo "Hyperlight has no artifact-only Linux test prerequisites yet."
        ;;
    *)
        usage
        exit 2
        ;;
esac
