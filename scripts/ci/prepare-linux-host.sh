#!/usr/bin/env bash
set -euo pipefail

# Prepares a Linux host for a backend's artifact-only test suite by installing
# the packages and starting the services it needs. Distro-aware so the same
# matrix entry works on Ubuntu, Debian, and RHEL images.

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

# Red Hat ships no third-party content, so epel-release is not in RHEL's own
# repos; the documented install is the release RPM straight from Fedora. 
install_epel() {
    local package_manager="$1"

    if command -v subscription-manager >/dev/null 2>&1; then
        sudo subscription-manager repos \
            --enable "codeready-builder-for-rhel-10-$(arch)-rpms" ||
            echo "WARNING: could not enable the CRB repository; EPEL packages that depend on it may fail to install." >&2
    fi

    sudo "$package_manager" install -y \
        https://dl.fedoraproject.org/pub/epel/epel-release-latest-10.noarch.rpm
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
            if ! sudo systemctl start lxc-net; then
                echo "WARNING: failed to start lxc-net; container networking may be unavailable." >&2
            fi
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

# Container network policy is programmed as iptables rules reached from
# FORWARD, which only sees bridged traffic when br_netfilter is loaded and
# bridge-nf-call-iptables is enabled. Neither is guaranteed on a fresh image,
# and without them the backend refuses to report success for a policy it
# cannot enforce.
enable_bridge_netfilter() {
    if ! sudo modprobe br_netfilter 2>/dev/null; then
        echo "WARNING: could not load br_netfilter; bridged traffic may bypass iptables." >&2
    fi

    local knob
    for knob in bridge-nf-call-iptables bridge-nf-call-ip6tables; do
        if [[ -e "/proc/sys/net/bridge/$knob" ]]; then
            sudo sysctl -w "net.bridge.$knob=1" >/dev/null ||
                echo "WARNING: could not enable net.bridge.$knob." >&2
        else
            echo "WARNING: /proc/sys/net/bridge/$knob is absent; container network policy cannot be enforced." >&2
        fi
    done
}

# Container-scoped rules hook egress (-i <veth>), so a reply arrives in the
# opposite direction, matches nothing MXC installed, and falls through to the
# host's FORWARD policy. A DROP policy (Docker sets one) therefore breaks
# allowed destinations, and worse, makes the deny cases pass vacuously: a
# container with no working hook at all is equally unreachable. Forwarding by
# default leaves an MXC rule as the only thing that can block traffic.
allow_host_forwarding() {
    local command
    for command in iptables ip6tables; do
        if command -v "$command" >/dev/null 2>&1; then
            sudo "$command" -P FORWARD ACCEPT ||
                echo "WARNING: could not set the $command FORWARD policy to ACCEPT; deny-case tests may pass without enforcing anything." >&2
        fi
    done
}

# Report the host-side state that container networking depends on. Purely
# diagnostic: never fails the job, so a networking problem still surfaces as
# the backend test failure rather than as a prerequisite error.
report_lxc_network_diagnostics() {
    local bridge="${LXC_BRIDGE:-lxcbr0}"

    echo "--- LXC network diagnostics (host) ---"

    echo "net.ipv4.ip_forward: $(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo unknown)"

    echo "bridge-nf-call-iptables: $(cat /proc/sys/net/bridge/bridge-nf-call-iptables 2>/dev/null || echo absent)"

    echo "Bridge $bridge:"
    ip -4 addr show "$bridge" 2>/dev/null | sed 's/^/  /' || echo "  (absent)"

    echo "dnsmasq processes:"
    pgrep -af dnsmasq 2>/dev/null | sed 's/^/  /' || echo "  (none)"

    echo "NAT rules for the bridge subnet:"
    sudo iptables -t nat -S POSTROUTING 2>/dev/null | grep -E '10\.0\.3|MASQUERADE' |
        sed 's/^/  /' || echo "  (none found)"

    # A vacuous pass depends on this policy, so print it verbatim. grep reads
    # the whole ruleset, avoiding the SIGPIPE an early-closing head would send
    # back to iptables under pipefail.
    echo "FORWARD policy (must be ACCEPT, or deny cases prove nothing):"
    sudo iptables -S FORWARD 2>/dev/null | grep '^-P' | sed 's/^/  /' || echo "  (unknown)"
    sudo ip6tables -S FORWARD 2>/dev/null | grep '^-P' | sed 's/^/  /' || echo "  (unknown)"

    echo "FORWARD rules for the bridge:"
    sudo iptables -S FORWARD 2>/dev/null | grep -E "$bridge" | sed 's/^/  /' ||
        echo "  (none found)"

    echo "Host /etc/resolv.conf nameservers:"
    grep '^nameserver' /etc/resolv.conf 2>/dev/null | sed 's/^/  /' || echo "  (none)"

    echo "lxc-net configuration:"
    grep -E '^(USE_LXC_BRIDGE|LXC_ADDR|LXC_NETMASK|LXC_DHCP_RANGE|LXC_DHCP_CONFILE)' \
        /etc/default/lxc-net 2>/dev/null | sed 's/^/  /' || echo "  (no /etc/default/lxc-net)"

    # Prove the host itself can resolve the name the network test uses. If this
    # fails, the container was never going to succeed.
    if command -v getent >/dev/null 2>&1; then
        echo "Host resolution of api.github.com:"
        getent ahostsv4 api.github.com 2>/dev/null | head -n 2 | sed 's/^/  /' ||
            echo "  FAILED - the host cannot resolve it either"
    fi

    # Ask the bridge's own resolver, which is what a container is handed via
    # DHCP. This isolates "dnsmasq is broken" from "the host is fine".
    local bridge_ip
    bridge_ip="$(ip -4 -o addr show "$bridge" 2>/dev/null |
        awk '{print $4}' | cut -d/ -f1 | head -n 1)"
    if [[ -n "$bridge_ip" ]] && command -v nslookup >/dev/null 2>&1; then
        echo "Resolution via bridge resolver ($bridge_ip):"
        nslookup api.github.com "$bridge_ip" 2>&1 | tail -n 4 | sed 's/^/  /' ||
            echo "  FAILED - dnsmasq on $bridge is not answering"
    fi

    echo "--- end diagnostics ---"
}

chmod +x "$binary_directory/lxc-exec"
case "$backend" in
    bubblewrap)
        install_bubblewrap
        command -v bwrap
        # disabled AppArmor restrictions on unprivileged user namespaces, which bubblewrap needs to create a new namespace.
        # should only be used on ephemeral CI runners, not on persistent hosts.
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
        enable_bridge_netfilter
        allow_host_forwarding
        report_lxc_network_diagnostics
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
