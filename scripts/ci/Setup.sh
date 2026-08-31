#!/usr/bin/env bash
#
# Installation script for MXC Linux machines (Debian / Ubuntu).
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

export DEBIAN_FRONTEND=noninteractive

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
distro_codename=""
if [ -r /etc/os-release ]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    distro_id="${ID:-}"
    distro_version="${VERSION_ID:-}"
    distro_codename="${VERSION_CODENAME:-}"
fi
if [ -z "$distro_codename" ] && have lsb_release; then
    distro_codename="$(lsb_release -cs 2>/dev/null)"
fi

step "Machine"
echo "Distribution : ${distro_id:-unknown} ${distro_version:-} (${distro_codename:-unknown codename})"
echo "Kernel       : $(uname -r 2>/dev/null)"
echo "Architecture : $(uname -m 2>/dev/null)"

if ! have apt-get; then
    fail "apt-get is not available; this script targets Debian and Ubuntu machines."
    step "Summary"
    echo "Nothing was installed."
    exit 0
fi

if ! priv true 2>/dev/null; then
    fail "cannot obtain root privileges; no packages can be installed."
    step "Summary"
    echo "Nothing was installed."
    exit 0
fi

# ---------------------------------------------------------------------------
# Package helpers
# ---------------------------------------------------------------------------

apt_refresh() {
    # A broken third-party feed makes the whole refresh non-zero; the installs
    # that follow still decide success against whatever indexes did update.
    if priv apt-get update; then
        return 0
    fi
    note "apt-get update reported repository errors; continuing with the available package indexes."
    return 0
}

# install <package>...
install() {
    priv env DEBIAN_FRONTEND=noninteractive \
        apt-get install -y --no-install-recommends "$@"
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

# available <package>
available() {
    apt-cache show "$1" >/dev/null 2>&1
}

step "Refreshing package indexes"
apt_refresh

step "Installing feed prerequisites"
install_group "feed prerequisites" ca-certificates curl gnupg apt-transport-https

# ---------------------------------------------------------------------------
# Vendor package feeds
# ---------------------------------------------------------------------------

# Carries PowerShell on this family. It does not carry the Azure CLI, which is
# published separately below.
add_microsoft_prod_feed() {
    if [ -f /etc/apt/sources.list.d/microsoft-prod.list ] ||
        [ -f /etc/apt/sources.list.d/microsoft-prod.sources ]; then
        ok "the Microsoft package feed is already configured."
        return 0
    fi

    if [ -z "$distro_id" ] || [ -z "$distro_version" ]; then
        fail "could not read the distribution; skipping the Microsoft package feed."
        return 1
    fi

    package="/tmp/packages-microsoft-prod.deb"
    if ! curl -fsSL \
        "https://packages.microsoft.com/config/${distro_id}/${distro_version}/packages-microsoft-prod.deb" \
        -o "$package"; then
        fail "no Microsoft package feed is published for ${distro_id} ${distro_version}."
        return 1
    fi

    if ! priv dpkg -i "$package"; then
        rm -f "$package"
        fail "could not install the Microsoft package feed."
        return 1
    fi

    rm -f "$package"
    apt_refresh
    ok "added the Microsoft package feed."
}

# The Azure CLI has a repository of its own, keyed by distribution codename
# rather than version. It lags new releases, so the codename this machine
# reports may not be published yet.
add_azure_cli_feed() {
    if [ -f /etc/apt/sources.list.d/azure-cli.list ] ||
        [ -f /etc/apt/sources.list.d/azure-cli.sources ]; then
        ok "the Azure CLI package feed is already configured."
        return 0
    fi

    if [ -z "$distro_codename" ]; then
        fail "could not read the distribution codename; skipping the Azure CLI feed."
        return 1
    fi

    candidates="$distro_codename"
    case "$distro_id" in
        debian) [ "$distro_codename" = "bookworm" ] || candidates="$candidates bookworm" ;;
        ubuntu) [ "$distro_codename" = "noble" ] || candidates="$candidates noble" ;;
    esac

    # Probe before writing. An unpublished suite in a source list makes every
    # later refresh fail, which would cost this machine the packages that were
    # otherwise going to install.
    suite=""
    for candidate in $candidates; do
        if curl -fsL --head -o /dev/null \
            "https://packages.microsoft.com/repos/azure-cli/dists/${candidate}/Release"; then
            suite="$candidate"
            break
        fi
        echo "The Azure CLI feed publishes no '$candidate' suite."
    done

    if [ -z "$suite" ]; then
        fail "the Azure CLI feed publishes no suite usable on '${distro_codename}'."
        return 1
    fi
    if [ "$suite" != "$distro_codename" ]; then
        note "the Azure CLI feed has no '${distro_codename}' suite; using '${suite}'."
    fi

    keyring="/etc/apt/keyrings/microsoft.gpg"
    if ! priv install -d -m 0755 /etc/apt/keyrings; then
        fail "could not create the apt keyring directory."
        return 1
    fi
    if ! curl -fsSL https://packages.microsoft.com/keys/microsoft.asc |
        gpg --dearmor | priv dd of="$keyring" status=none; then
        fail "could not install the Microsoft signing key."
        return 1
    fi
    priv chmod go+r "$keyring"

    if ! echo "deb [arch=$(dpkg --print-architecture) signed-by=${keyring}] https://packages.microsoft.com/repos/azure-cli/ ${suite} main" |
        priv tee /etc/apt/sources.list.d/azure-cli.list >/dev/null; then
        fail "could not write the Azure CLI package source."
        return 1
    fi

    apt_refresh
    ok "added the Azure CLI package feed (${suite})."
}

add_github_cli_feed() {
    if [ -f /etc/apt/sources.list.d/github-cli.list ]; then
        ok "the GitHub CLI package feed is already configured."
        return 0
    fi

    keyring="/usr/share/keyrings/githubcli-archive-keyring.gpg"
    if ! curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg |
        priv dd of="$keyring" status=none; then
        fail "could not download the GitHub CLI signing key."
        return 1
    fi
    priv chmod go+r "$keyring"

    if ! echo "deb [arch=$(dpkg --print-architecture) signed-by=${keyring}] https://cli.github.com/packages stable main" |
        priv tee /etc/apt/sources.list.d/github-cli.list >/dev/null; then
        fail "could not write the GitHub CLI package source."
        return 1
    fi

    apt_refresh
    ok "added the GitHub CLI package feed."
}

step "Adding vendor package feeds"
add_microsoft_prod_feed
add_azure_cli_feed
add_github_cli_feed

# ---------------------------------------------------------------------------
# Sandboxing runtimes
# ---------------------------------------------------------------------------

step "Installing unprivileged sandboxing prerequisites"
install_group "unprivileged sandboxing" \
    bubblewrap slirp4netns util-linux iproute2 iptables

step "Installing container prerequisites"
container_packages="lxc dnsmasq-base bridge-utils iptables"
# Debian folded the tools into the lxc package; Ubuntu still ships them apart.
if available lxc-utils; then
    container_packages="$container_packages lxc-utils"
fi
if available lxc-templates; then
    container_packages="$container_packages lxc-templates"
fi
# shellcheck disable=SC2086
install_group "containers" $container_packages

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
# Recent releases restrict them by default.
if [ -e /proc/sys/kernel/apparmor_restrict_unprivileged_userns ]; then
    sysctl_lines="${sysctl_lines}kernel.apparmor_restrict_unprivileged_userns = 0
"
fi
if [ -e /proc/sys/kernel/unprivileged_userns_clone ]; then
    sysctl_lines="${sysctl_lines}kernel.unprivileged_userns_clone = 1
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
# Debian ships the bridge disabled; Ubuntu enables it.
if [ -f /etc/default/lxc-net ]; then
    if priv sed -i 's/^\s*#\?\s*USE_LXC_BRIDGE\s*=.*/USE_LXC_BRIDGE="true"/' /etc/default/lxc-net &&
        grep -q 'USE_LXC_BRIDGE="true"' /etc/default/lxc-net; then
        ok "enabled the container bridge in /etc/default/lxc-net."
    else
        note "could not confirm the bridge setting in /etc/default/lxc-net."
    fi
else
    note "/etc/default/lxc-net is absent; leaving the bridge at its packaged default."
fi

if have systemctl; then
    if priv systemctl enable lxc-net >/dev/null 2>&1; then
        ok "the container bridge will start at boot."
    else
        note "could not enable the container bridge service."
    fi
    if priv systemctl restart lxc-net >/dev/null 2>&1; then
        ok "started the container bridge."
    else
        note "could not start the container bridge; it should come up on the next boot."
    fi
else
    note "no systemctl on this machine; skipping the bridge service."
fi

# Package installs do not always activate the confinement profiles the
# container tooling relies on.
if have apparmor_parser && [ -d /etc/apparmor.d ]; then
    if priv apparmor_parser -rT /etc/apparmor.d/lxc* 2>/dev/null; then
        ok "reloaded the container confinement profiles."
    else
        note "could not reload the container confinement profiles."
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
priv apt-get clean >/dev/null 2>&1 && ok "cleared the package cache."

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
