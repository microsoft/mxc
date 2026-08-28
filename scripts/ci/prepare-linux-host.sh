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

# Resolves the host's package manager once, so supporting a new distribution
# family is a case in install_packages rather than another branch in every
# installer below.
package_manager=""
resolve_package_manager() {
    if [[ -n "$package_manager" ]]; then
        return 0
    fi

    local candidate
    for candidate in apt-get dnf yum microdnf; do
        if command -v "$candidate" >/dev/null 2>&1; then
            package_manager="$candidate"
            return 0
        fi
    done
    return 1
}

# install_packages <package>...
# Installs from the feeds the host already has configured, and returns the
# package manager's own status so each caller decides what a failure means: a
# missing backend prerequisite is fatal, a missing workload interpreter is not.
install_packages() {
    case "$package_manager" in
        apt-get)
            # sudo resets the environment, so the frontend setting has to be
            # applied on the far side of it rather than exported here.
            sudo env DEBIAN_FRONTEND=noninteractive \
                apt-get install -y --no-install-recommends "$@"
            ;;
        dnf | yum | microdnf)
            sudo "$package_manager" install -y "$@"
            ;;
        *)
            echo "Unsupported package manager: '$package_manager'." >&2
            return 1
            ;;
    esac
}

# Returns 0 when any of the comma-separated candidates is on PATH.
have_command() {
    local candidate
    local IFS=','
    for candidate in $1; do
        if command -v "$candidate" >/dev/null 2>&1; then
            return 0
        fi
    done
    return 1
}

# Red Hat ships no third-party content, so epel-release is not in RHEL's own
# repos; the documented install is the release RPM straight from Fedora. 
install_epel() {
    if command -v subscription-manager >/dev/null 2>&1; then
        sudo subscription-manager repos \
            --enable "codeready-builder-for-rhel-10-$(arch)-rpms" ||
            echo "WARNING: could not enable the CRB repository; EPEL packages that depend on it may fail to install." >&2
    fi

    install_packages \
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

    if ! resolve_package_manager; then
        echo "No supported package manager found to install Bubblewrap prerequisites." >&2
        exit 1
    fi

    local packages=(bubblewrap slirp4netns util-linux iptables)
    if [[ "$package_manager" == "apt-get" ]]; then
        apt_update
        packages+=(iproute2)
    else
        packages+=(iproute)
    fi
    install_packages "${packages[@]}"
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

    if ! resolve_package_manager; then
        echo "No supported package manager found to install LXC." >&2
        exit 1
    fi

    local packages
    if [[ "$package_manager" == "apt-get" ]]; then
        apt_update
        packages=(lxc dnsmasq-base iptables bridge-utils)
        # Debian dropped lxc-utils; Ubuntu still ships it.
        if apt-cache show lxc-utils >/dev/null 2>&1; then
            packages+=(lxc-utils)
        fi
    else
        install_epel
        packages=(lxc lxc-templates dnsmasq iptables)
    fi
    install_packages "${packages[@]}"
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

# PowerShell, the Azure CLI, and the GitHub CLI are in no distribution's own
# repositories, so each comes from its vendor's feed. A feed is added at most
# once and a failure is remembered, so the second tool wanting a broken feed
# does not retry it.
microsoft_feed_state=""
add_microsoft_feed() {
    case "$microsoft_feed_state" in
        added) return 0 ;;
        failed) return 1 ;;
    esac
    microsoft_feed_state="failed"

    local id="" version_id=""
    if [[ -r /etc/os-release ]]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        id="${ID:-}"
        version_id="${VERSION_ID:-}"
    fi
    if [[ -z "$id" || -z "$version_id" ]]; then
        echo "WARNING: could not read the distribution from /etc/os-release; skipping the Microsoft package feed." >&2
        return 1
    fi

    if [[ "$package_manager" == "apt-get" ]]; then
        local package="/tmp/packages-microsoft-prod.deb"
        if ! curl -fsSL \
            "https://packages.microsoft.com/config/${id}/${version_id}/packages-microsoft-prod.deb" \
            -o "$package"; then
            echo "WARNING: no Microsoft package feed published for ${id} ${version_id}." >&2
            return 1
        fi
        if ! sudo dpkg -i "$package"; then
            rm -f "$package"
            echo "WARNING: could not install the Microsoft package feed." >&2
            return 1
        fi
        rm -f "$package"
        apt_update
    else
        # The RPM feed is keyed on the major version alone.
        if ! install_packages \
            "https://packages.microsoft.com/config/rhel/${version_id%%.*}/packages-microsoft-prod.rpm"; then
            echo "WARNING: could not install the Microsoft package feed." >&2
            return 1
        fi
    fi

    microsoft_feed_state="added"
}

add_github_feed() {
    if [[ "$package_manager" == "apt-get" ]]; then
        local keyring="/usr/share/keyrings/githubcli-archive-keyring.gpg"
        if ! curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg |
            sudo dd of="$keyring" status=none; then
            echo "WARNING: could not download the GitHub CLI signing key." >&2
            return 1
        fi
        if ! sudo chmod go+r "$keyring"; then
            echo "WARNING: could not make the GitHub CLI signing key readable." >&2
            return 1
        fi
        if ! echo "deb [arch=$(dpkg --print-architecture) signed-by=$keyring] https://cli.github.com/packages stable main" |
            sudo tee /etc/apt/sources.list.d/github-cli.list >/dev/null; then
            echo "WARNING: could not write the GitHub CLI package source." >&2
            return 1
        fi
        apt_update
        return 0
    fi

    # config-manager is a separate package on some releases and is what adds the
    # feed, so it is requested before it is used.
    install_packages "dnf-command(config-manager)" >/dev/null 2>&1 || true
    if ! sudo "$package_manager" config-manager \
        --add-repo https://cli.github.com/packages/rpm/gh-cli.repo; then
        echo "WARNING: could not add the GitHub CLI package feed." >&2
        return 1
    fi
}

# Installs the workload interpreters the image did not already provide.
#
# Host preparation verifies rather than installs wherever it can, because a
# missing backend prerequisite means the image is wrong for the job. The
# workload interpreters are the exception: they are ordinary developer tools the
# package manager can supply in one transaction, which is cheaper than losing a
# suite's coverage to a tool the image happened not to bake.
#
# Every step here is best effort and none of them fails the job. What the host
# actually ended up with is reported by assert_workload_interpreters below.
install_workload_interpreters() {
    if ! resolve_package_manager; then
        echo "WARNING: no supported package manager on this host; skipping workload interpreter installation." >&2
        return 0
    fi

    # name|command candidates|apt package(s)|rpm package(s)
    # npx has no package of its own; it arrives with npm. pwsh, az, and gh need
    # a vendor feed and are handled separately below.
    local packaged=(
        "git|git|git|git"
        "openssl|openssl|openssl|openssl"
        "node|node|nodejs|nodejs"
        "npm|npm|npm|npm"
        "python|python3,python|python3|python3"
        "pip|pip3,pip|python3-pip|python3-pip"
        "dotnet|dotnet|dotnet-sdk-8.0|dotnet-sdk-8.0"
    )

    local entry name candidates apt_packages rpm_packages
    local wanted=()
    for entry in "${packaged[@]}"; do
        IFS='|' read -r name candidates apt_packages rpm_packages <<<"$entry"
        if have_command "$candidates"; then
            continue
        fi
        # Deliberately unquoted: an entry may name more than one package.
        if [[ "$package_manager" == "apt-get" ]]; then
            wanted+=($apt_packages)
        else
            wanted+=($rpm_packages)
        fi
    done

    local need_pwsh="false" need_az="false" need_gh="false"
    have_command pwsh || need_pwsh="true"
    have_command az || need_az="true"
    have_command gh || need_gh="true"

    if [[ ${#wanted[@]} -eq 0 && "$need_pwsh" == "false" &&
        "$need_az" == "false" && "$need_gh" == "false" ]]; then
        echo "All workload interpreters are already present; nothing to install."
        return 0
    fi

    if [[ "$package_manager" == "apt-get" ]]; then
        apt_update
    fi

    if [[ "$need_pwsh" == "true" || "$need_az" == "true" || "$need_gh" == "true" ]]; then
        # Both feeds are fetched over HTTPS and verified against a signing key,
        # so these have to be present before either can be added.
        install_packages ca-certificates curl gnupg ||
            echo "WARNING: could not install the prerequisites for adding vendor package feeds." >&2
    fi

    if [[ "$need_pwsh" == "true" || "$need_az" == "true" ]]; then
        if add_microsoft_feed; then
            if [[ "$need_pwsh" == "true" ]]; then
                wanted+=(powershell)
            fi
            if [[ "$need_az" == "true" ]]; then
                wanted+=(azure-cli)
            fi
        fi
    fi

    if [[ "$need_gh" == "true" ]] && add_github_feed; then
        wanted+=(gh)
    fi

    if [[ ${#wanted[@]} -eq 0 ]]; then
        return 0
    fi

    echo "Installing workload interpreters: ${wanted[*]}"
    if install_packages "${wanted[@]}"; then
        return 0
    fi

    # A single unavailable package fails the whole transaction, so retry them
    # one at a time rather than leaving the host with none of them.
    echo "WARNING: the combined install failed; retrying each package on its own." >&2
    local package
    for package in "${wanted[@]}"; do
        install_packages "$package" ||
            echo "WARNING: could not install package '$package'." >&2
    done
}

# Verifies the interpreters test suites drive inside the sandbox. This runs
# after install_workload_interpreters and reports what the host ended up with,
# so a tool that could not be installed stays visible instead of silently
# absent.
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

# Run for every backend: this is host inventory, not a backend prerequisite.
install_workload_interpreters
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
