#!/usr/bin/env bash
#
# Installation script for MXC Linux machines (RHEL and compatible).
#
# Installs the sandboxing runtimes, kernel prerequisites and workload
# interpreters an MXC machine is expected to provide, and persists the kernel
# settings so they survive a reboot.
#
# Every step is best effort. Nothing here aborts the run and the script always
# exits 0; what the machine actually ended up with is printed in the summary at
# the end.

set -o pipefail

# Guarantee the exit status regardless of how the script leaves.
trap 'exit 0' EXIT

failures=()
notes=()

step() {
    echo ""
    echo "=== $* ==="
}

ok() {
    echo "OK: $*"
}

note() {
    echo "NOTE: $*"
    notes+=("$*")
}

fail() {
    echo "FAILED: $*"
    failures+=("$*")
}

# Image builders run as root without sudo installed; interactive machines have
# sudo and an unprivileged user. Resolve once and use the same wrapper for
# every privileged call.
if [ "$(id -u)" -eq 0 ]; then
    priv() { "$@"; }
elif command -v sudo >/dev/null 2>&1; then
    priv() { sudo -n "$@"; }
else
    priv() { return 1; }
fi

have() {
    command -v "$1" >/dev/null 2>&1
}

# ---------------------------------------------------------------------------
# Distribution identity
# ---------------------------------------------------------------------------

distro_id=""
distro_version=""
if [ -r /etc/os-release ]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    distro_id="${ID:-}"
    distro_version="${VERSION_ID:-}"
fi
major_version="${distro_version%%.*}"
architecture="$(uname -m 2>/dev/null)"

step "Machine"
echo "Distribution : ${distro_id:-unknown} ${distro_version:-unknown}"
echo "Kernel       : $(uname -r 2>/dev/null)"
echo "Architecture : ${architecture:-unknown}"

package_manager=""
for candidate in dnf yum microdnf; do
    if have "$candidate"; then
        package_manager="$candidate"
        break
    fi
done

if [ -z "$package_manager" ]; then
    fail "no dnf, yum or microdnf on this machine; this script targets RHEL and compatible machines."
    step "Summary"
    echo "Nothing was installed."
    exit 0
fi
echo "Package tool : $package_manager"

if ! priv true 2>/dev/null; then
    fail "cannot obtain root privileges; no packages can be installed."
    step "Summary"
    echo "Nothing was installed."
    exit 0
fi

if [ -z "$major_version" ]; then
    major_version="10"
    note "could not read the release version; assuming ${major_version} for versioned feeds."
fi

# ---------------------------------------------------------------------------
# Package helpers
# ---------------------------------------------------------------------------

# install <package-or-url>...
install() {
    priv "$package_manager" install -y "$@"
}

# install_group <description> <package>...
# Installs as one transaction, then retries individually so a single package
# that is unavailable on this release cannot cost the machine the rest.
install_group() {
    description="$1"
    shift
    [ "$#" -eq 0 ] && return 0

    if install "$@"; then
        ok "$description: $*"
        return 0
    fi

    note "combined install for $description failed; retrying each package on its own."
    for package in "$@"; do
        if install "$package"; then
            ok "$description: $package"
        else
            fail "could not install '$package' ($description)."
        fi
    done
}

# ---------------------------------------------------------------------------
# Repositories
# ---------------------------------------------------------------------------

step "Enabling supplementary repositories"

# Several of the packages below are built against content that only the
# CodeReady Builder repository provides.
if have subscription-manager; then
    if priv subscription-manager repos \
        --enable "codeready-builder-for-rhel-${major_version}-${architecture}-rpms" >/dev/null 2>&1; then
        ok "enabled the CodeReady Builder repository."
    else
        note "could not enable the CodeReady Builder repository; some packages may be unavailable."
    fi
else
    # Rebuilds carry the same content under their own repository name.
    for repo in crb powertools; do
        if priv "$package_manager" config-manager --set-enabled "$repo" >/dev/null 2>&1; then
            ok "enabled the '${repo}' repository."
            break
        fi
    done
fi

# This family ships no third-party content, so the community repository comes
# from its own release package.
if rpm -q epel-release >/dev/null 2>&1; then
    ok "the EPEL repository is already configured."
elif install "https://dl.fedoraproject.org/pub/epel/epel-release-latest-${major_version}.noarch.rpm"; then
    ok "added the EPEL repository."
else
    fail "could not add the EPEL repository; packages that live there will be unavailable."
fi

step "Adding vendor package feeds"

# Carries both PowerShell and the Azure CLI on this family.
if rpm -q packages-microsoft-prod >/dev/null 2>&1; then
    ok "the Microsoft package feed is already configured."
else
    priv rpm --import https://packages.microsoft.com/keys/microsoft.asc >/dev/null 2>&1 ||
        note "could not import the Microsoft signing key; the feed may still supply it."
    # Newer releases are signed with a separate key.
    priv rpm --import https://packages.microsoft.com/keys/microsoft-2025.asc >/dev/null 2>&1 || true

    if install "https://packages.microsoft.com/config/rhel/${major_version}/packages-microsoft-prod.rpm"; then
        ok "added the Microsoft package feed."
    else
        fail "could not add the Microsoft package feed."
    fi
fi

if [ -f /etc/yum.repos.d/gh-cli.repo ]; then
    ok "the GitHub CLI package feed is already configured."
else
    # config-manager is a separate package on some releases and is what adds
    # the feed, so it is requested before it is used.
    install "dnf-command(config-manager)" >/dev/null 2>&1 || true
    if priv "$package_manager" config-manager \
        --add-repo https://cli.github.com/packages/rpm/gh-cli.repo >/dev/null 2>&1; then
        ok "added the GitHub CLI package feed."
    else
        fail "could not add the GitHub CLI package feed."
    fi
fi

# ---------------------------------------------------------------------------
# Sandboxing runtimes
# ---------------------------------------------------------------------------

step "Installing unprivileged sandboxing prerequisites"
install_group "unprivileged sandboxing" \
    bubblewrap slirp4netns util-linux iproute iptables

# The packet-filter command moved into a separate package on newer releases.
if have iptables; then
    ok "the packet filter command is present."
else
    install_group "the packet filter" iptables-nft
fi

step "Installing container prerequisites"
install_group "containers" lxc lxc-templates dnsmasq

# ---------------------------------------------------------------------------
# Workload interpreters
# ---------------------------------------------------------------------------

step "Installing workload interpreters"
install_group "interpreters" \
    git openssl nodejs npm python3 python3-pip

# Named separately so an unavailable release does not take the rest with it.
install_group "the .NET SDK" dotnet-sdk-8.0
install_group "PowerShell" powershell
install_group "the Azure CLI" azure-cli
install_group "the GitHub CLI" gh

# ---------------------------------------------------------------------------
# Kernel configuration
# ---------------------------------------------------------------------------

# Written to disk rather than only applied live, so the machine comes back the
# same way after a reboot.
persist_module() {
    module="$1"
    if echo "$module" | priv tee "/etc/modules-load.d/mxc-${module}.conf" >/dev/null; then
        ok "${module} will load at boot."
    else
        fail "could not configure ${module} to load at boot."
    fi
    priv modprobe "$module" 2>/dev/null ||
        note "could not load ${module} now; it may be built in or unavailable until reboot."
}

step "Configuring kernel modules"
# Connection-state matching in the packet filter needs conntrack present.
persist_module nf_conntrack
# Bridged traffic is only visible to the packet filter with this loaded.
persist_module br_netfilter

step "Configuring kernel settings"
sysctl_file="/etc/sysctl.d/99-mxc.conf"
sysctl_lines=""

# Unprivileged user namespaces are what unprivileged sandboxing is built on.
if [ -e /proc/sys/user/max_user_namespaces ]; then
    sysctl_lines="${sysctl_lines}user.max_user_namespaces = 28633
"
fi
# Bridged traffic must traverse the packet filter for container network policy
# to apply to it.
sysctl_lines="${sysctl_lines}net.bridge.bridge-nf-call-iptables = 1
net.bridge.bridge-nf-call-ip6tables = 1
net.ipv4.ip_forward = 1
"

if printf '%s' "$sysctl_lines" | priv tee "$sysctl_file" >/dev/null; then
    ok "wrote ${sysctl_file}."
else
    fail "could not write ${sysctl_file}."
fi

if priv sysctl --system >/dev/null 2>&1; then
    ok "applied the kernel settings."
else
    note "could not apply the kernel settings now; they will take effect after a reboot."
fi

# ---------------------------------------------------------------------------
# Container bridge
# ---------------------------------------------------------------------------

step "Configuring the container bridge"
if have systemctl; then
    for unit in lxc-net lxc; do
        if priv systemctl enable "$unit" >/dev/null 2>&1; then
            ok "'${unit}' will start at boot."
        else
            note "could not enable '${unit}'."
        fi
    done
    if priv systemctl restart lxc-net >/dev/null 2>&1; then
        ok "started the container bridge."
    else
        note "could not start the container bridge; it should come up on the next boot."
    fi
else
    note "no systemctl on this machine; skipping the bridge service."
fi

# The default container profile is not created by the package install on every
# release, and container startup needs one.
if [ ! -f /etc/lxc/default.conf ] && [ -d /etc/lxc ]; then
    if printf 'lxc.net.0.type = veth\nlxc.net.0.link = lxcbr0\nlxc.net.0.flags = up\n' |
        priv tee /etc/lxc/default.conf >/dev/null; then
        ok "wrote the default container profile."
    else
        note "could not write the default container profile."
    fi
fi

# ---------------------------------------------------------------------------
# Inventory
# ---------------------------------------------------------------------------

step "Inventory"

# name|candidates tried in order
inventory="bwrap|bwrap
slirp4netns|slirp4netns
unshare|unshare
nsenter|nsenter
ip|ip
iptables|iptables
ip6tables|ip6tables
lxc-start|lxc-start
git|git
openssl|openssl
node|node,nodejs
npm|npm
npx|npx
python|python3,python
pip|pip3,pip
dotnet|dotnet
pwsh|pwsh
az|az
gh|gh"

absent=""
while IFS='|' read -r name candidates; do
    [ -z "$name" ] && continue
    resolved=""
    old_ifs="$IFS"
    IFS=','
    for candidate in $candidates; do
        if resolved="$(command -v "$candidate" 2>/dev/null)"; then
            break
        fi
        resolved=""
    done
    IFS="$old_ifs"

    if [ -n "$resolved" ]; then
        printf '  %-14s %s\n' "$name" "$resolved"
    else
        printf '  %-14s ABSENT\n' "$name"
        absent="${absent:+$absent }$name"
    fi
done <<EOF
$inventory
EOF

# ---------------------------------------------------------------------------
# Cleanup and summary
# ---------------------------------------------------------------------------

step "Cleaning up"
priv "$package_manager" clean all >/dev/null 2>&1 && ok "cleared the package cache."

step "Summary"
if [ -n "$absent" ]; then
    echo "Absent after installation: $absent"
else
    echo "Every expected program is present."
fi

if [ "${#notes[@]}" -gt 0 ]; then
    echo ""
    echo "Notes:"
    for entry in "${notes[@]}"; do
        echo "  - $entry"
    done
fi

if [ "${#failures[@]}" -gt 0 ]; then
    echo ""
    echo "Failures:"
    for entry in "${failures[@]}"; do
        echo "  - $entry"
    done
else
    echo ""
    echo "No failures."
fi

echo ""
echo "Setup finished."
exit 0
