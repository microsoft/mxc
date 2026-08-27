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
    if command -v bwrap >/dev/null 2>&1 &&
        command -v slirp4netns >/dev/null 2>&1 &&
        command -v unshare >/dev/null 2>&1 &&
        command -v nsenter >/dev/null 2>&1 &&
        command -v iptables >/dev/null 2>&1 &&

        command -v ip6tables >/dev/null 2>&1 &&
        command -v ip >/dev/null 2>&1; then
        return
    fi
    if command -v apt-get >/dev/null 2>&1; then
        apt_update
        sudo apt-get install -y --no-install-recommends \
            bubblewrap slirp4netns util-linux iptables iproute2
    elif command -v dnf >/dev/null 2>&1; then
        sudo dnf install -y bubblewrap slirp4netns util-linux iptables iproute
    elif command -v yum >/dev/null 2>&1; then
        sudo yum install -y bubblewrap slirp4netns util-linux iptables iproute
    elif command -v microdnf >/dev/null 2>&1; then
        sudo microdnf install -y bubblewrap slirp4netns util-linux iptables iproute
    else
        echo "No supported package manager found to install Bubblewrap prerequisites." >&2
        exit 1
    fi
}

# The ingress chain matches on connection state, which iptables can only
# resolve once nf_conntrack is loaded; without it the whole transaction is
# rejected as "Invalid argument". Loading it here turns a confusing rule
# failure into a prerequisite the host either satisfies or reports.
load_conntrack_module() {
    # Keyed on a conntrack-specific indicator: the net/netfilter directory
    # belongs to the netfilter core (nf_log and friends register there too), so
    # its presence does not imply conntrack. The sysctl covers a loaded module
    # and a built-in; /sys/module covers a kernel that defers the sysctl.
    if [[ -e /proc/sys/net/netfilter/nf_conntrack_max || -d /sys/module/nf_conntrack ]]; then
        return
    fi
    if ! sudo modprobe nf_conntrack 2>/dev/null; then
        echo "WARNING: could not load nf_conntrack; the inbound default-deny test may fail to install its rules." >&2
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

# Outbound container traffic leaves the bridge subnet with a private source
# address, so it needs a MASQUERADE rule to reach anything off-host. lxc-net
# normally installs one, but it skips its firewall setup when it believes
# another manager owns the ruleset, leaving a bridge that hands out leases the
# container cannot use. The symptom is a name-resolution failure inside the
# guest, which reads like a policy problem and is not one.
ensure_bridge_nat() {
    local bridge="${LXC_BRIDGE:-lxcbr0}"
    local subnet

    subnet="$(ip -4 -o addr show "$bridge" 2>/dev/null | awk '{print $4}' | head -n 1)"
    if [[ -z "$subnet" ]]; then
        echo "WARNING: $bridge has no IPv4 subnet; skipping NAT setup." >&2
        return 0
    fi

    # Match on the source subnet rather than the rule text: lxc-net's own rule
    # and ours are equivalent however they are spelled.
    if sudo iptables -t nat -S POSTROUTING 2>/dev/null |
        grep -q -- "-s ${subnet%%/*}"; then
        echo "NAT for $subnet is already present."
        return 0
    fi

    if sudo iptables -t nat -A POSTROUTING -s "$subnet" ! -d "$subnet" -j MASQUERADE; then
        echo "Installed MASQUERADE for $subnet."
    else
        echo "WARNING: could not install MASQUERADE for $subnet; containers will not reach off-host destinations." >&2
    fi
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

# Verifies the interpreters test suites drive inside the sandbox, following the
# same verify-never-install rule as the rest of host preparation: a missing one
# is an image problem, not something a job can fix mid-run.
#
# The check is suite-agnostic: it describes what a validation host is expected
# to provide, not what any one suite consumes, so a future suite that shells out
# to these programs needs no change here.
assert_workload_interpreters() {
    # name|candidates (tried in order)|required|remedy
    local interpreters=(
        "pwsh|pwsh|false|install PowerShell 7 in the image"
        "git|git|false|install Git in the image"
        "node|node|false|install Node.js in the image"
        "npm|npm|false|install Node.js in the image (npm ships with it)"
        "npx|npx|false|install Node.js in the image (npx ships with it)"
        "python|python3,python|false|install Python in the image"
        "pip|pip3,pip|false|install Python in the image (pip ships with it)"
        "dotnet|dotnet|false|install the .NET SDK in the image"
        "az|az|false|install the Azure CLI in the image"
        "gh|gh|false|install the GitHub CLI in the image"
        "openssl|openssl|false|install OpenSSL in the image"
    )

    local missing="" entry name candidates required remedy resolved candidate
    local candidate_list
    for entry in "${interpreters[@]}"; do
        IFS='|' read -r name candidates required remedy <<<"$entry"

        resolved=""
        IFS=',' read -r -a candidate_list <<<"$candidates"
        for candidate in "${candidate_list[@]}"; do
            # python3 before python: on Unix a bare `python` is usually absent,
            # and where it does exist it can still be Python 2.
            if resolved="$(command -v "$candidate" 2>/dev/null)"; then
                break
            fi
            resolved=""
        done

        if [[ -n "$resolved" ]]; then
            echo "Workload interpreter '$name' found at $resolved"
        elif [[ "$required" == "true" ]]; then
            missing="${missing:+$missing; }$name ($remedy)"
        else
            echo "::warning::Workload interpreter '$name' is absent ($remedy)"
        fi
    done

    if [[ -n "$missing" ]]; then
        echo "::error::Workload interpreters missing from this image: $missing"
        exit 1
    fi
}

chmod +x "$binary_directory/lxc-exec"

# Runs for every backend: this is host inventory, not a backend prerequisite.
assert_workload_interpreters

case "$backend" in
    bubblewrap)
        install_bubblewrap
        command -v bwrap
        command -v slirp4netns
        command -v unshare
        command -v nsenter
        command -v iptables
        command -v ip6tables
        command -v ip
        load_conntrack_module
        # The inbound test is invoked through sudo, so prove it is available
        # here rather than midway through the suite.
        sudo -n true
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
        ensure_bridge_nat
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
