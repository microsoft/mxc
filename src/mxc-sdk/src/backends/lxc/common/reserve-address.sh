#!/bin/sh
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set -eu
umask 077
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH

action=$1
config=$(readlink -m -- "$2")
identity=$(printf '%s' "$config" | sha256sum)
identity=${identity%% *}
state=/var/lib/mxc-lxc-network
reservations=$state/reservations
reservation=$reservations/$identity

if [ "$action" = release ] && [ ! -e "$reservation" ] && [ ! -L "$reservation" ]; then
    exit 0
fi

fail()
{
    echo "$*" >&2
    exit 1
}

case "$config" in
    *'
'*) fail "LXC reservation config paths must not contain a newline" ;;
esac

protect_directory()
{
    test ! -L "$1" || fail "LXC reservation directory is a symbolic link: $1"
    if [ ! -e "$1" ]; then
        mkdir -p "$1"
    fi
    test -d "$1" && test ! -L "$1" && test "$(stat -c %u "$1")" = 0 ||
        fail "LXC reservation directory must be owned by root: $1"
    mode=$(stat -c %a "$1")
    test "$((0$mode & 0022))" -eq 0 ||
        fail "LXC reservation directory must not be writable by other users: $1"
    chmod 755 "$1"
}

test "$(id -u)" = 0 || fail "LXC address reservation requires root"
protect_directory "$state"
test ! -L "$state/lock" || fail "LXC reservation lock must not be a symbolic link"
exec 9>"$state/lock"
flock -x -w 30 9 || fail "Timed out waiting for the LXC address reservation lock"
protect_directory "$reservations"

USE_LXC_BRIDGE=true
LXC_BRIDGE=lxcbr0
LXC_DHCP_CONFILE=
distrosysconfdir=/etc/default
varrun=/run/lxc
defaults=/etc/default/lxc
test -r "$defaults" || fail "Cannot read local lxc-net settings in $defaults"
. "$defaults"
test "$USE_LXC_BRIDGE" = true || fail "The local lxc-net bridge is disabled"
server_config=${LXC_DHCP_CONFILE:-/dev/null}
case "$LXC_DHCP_CONFILE" in
    ''|/dev/null) LXC_DHCP_CONFILE=/etc/lxc/dnsmasq.conf ;;
esac
case "$LXC_DHCP_CONFILE" in
    /*) ;;
    *) fail "LXC_DHCP_CONFILE must be an absolute path" ;;
esac
if [ -e "$LXC_DHCP_CONFILE" ] || [ -L "$LXC_DHCP_CONFILE" ]; then
    test -f "$LXC_DHCP_CONFILE" && test -r "$LXC_DHCP_CONFILE" &&
        test ! -L "$LXC_DHCP_CONFILE" &&
        test "$(stat -c %u "$LXC_DHCP_CONFILE")" = 0 ||
        fail "The local lxc-net dnsmasq config must be readable and owned by root"
    mode=$(stat -c %a "$LXC_DHCP_CONFILE")
    test "$((0$mode & 0022))" -eq 0 ||
        fail "The local lxc-net dnsmasq config must not be writable by other users"
else
    test "$server_config" = /dev/null ||
        fail "The configured local lxc-net dnsmasq file does not exist"
fi

server_pid()
{
    pid=$(cat /run/lxc/dnsmasq.pid) || fail "Cannot read the local lxc-net dnsmasq PID"
    case "$pid" in
        ''|*[!0-9]*) fail "Invalid local lxc-net dnsmasq PID" ;;
    esac
    test "$pid" -gt 1 || fail "Invalid local lxc-net dnsmasq PID"
    executable=$(readlink "/proc/$pid/exe") || fail "Cannot inspect local lxc-net dnsmasq"
    test "${executable##*/}" = dnsmasq || fail "The lxc-net PID does not identify dnsmasq"
    arguments=$(tr '\000' '\n' < "/proc/$pid/cmdline")
    for expected in "--interface=$LXC_BRIDGE" "--conf-file=$server_config" \
        "--pid-file=/run/lxc/dnsmasq.pid"; do
        printf '%s\n' "$arguments" | grep -Fxq -- "$expected" ||
            fail "The local dnsmasq process does not have $expected"
    done
    printf '%s\n' "$pid"
}

server=$(server_pid)
directive="dhcp-hostsfile=$reservations"
if [ "$action" = release ]; then
    grep -Fxq "$directive" "$LXC_DHCP_CONFILE" ||
        fail "Local lxc-net no longer reads the LXC reservation directory"
    rm -- "$reservation"
    server=$(server_pid)
    kill -HUP "$server" || fail "Failed to reload local lxc-net reservations"
    exit 0
fi
test "$action" = reserve || fail "Unknown LXC address operation: $action"
directory=$3
bridge=$4
mac=$(printf '%s' "$5" | tr '[:upper:]' '[:lower:]')
test "$bridge" = "$LXC_BRIDGE" ||
    fail "The container bridge must be the managed local lxc-net bridge: $LXC_BRIDGE"
printf '%s\n' "$mac" | grep -Eq '^([0-9a-f]{2}:){5}[0-9a-f]{2}$' ||
    fail "LXC address reservation requires a concrete hardware address"
first_octet=${mac%%:*}
test "$((0x$first_octet & 1))" -eq 0 && test "$mac" != 00:00:00:00:00:00 ||
    fail "LXC address reservation requires a unicast hardware address"
busybox --list | grep -Fxq udhcpc ||
    fail "Networked LXC requires BusyBox with udhcpc; install busybox-static on Debian/Ubuntu"

veth_host=
veth_peer=mxp$$
owner=$identity-$$
marking=false
backup=
stage=
record_stage=
defaults_backup=
defaults_stage=
created_config=
initialization_state=pre_restart

cleanup()
{
    status=$?
    trap - EXIT
    trap '' HUP INT TERM
    if [ -n "$veth_host" ] && [ -e "/sys/class/net/$veth_host" ]; then
        if [ "$(cat "/sys/class/net/$veth_host/ifalias")" = "$owner" ] ||
            { [ "$marking" = true ] &&
                [ -z "$(cat "/sys/class/net/$veth_host/ifalias")" ] &&
                [ -e "/sys/class/net/$veth_peer" ] &&
                [ "$(cat "/sys/class/net/$veth_host/iflink")" = \
                    "$(cat "/sys/class/net/$veth_peer/ifindex")" ] &&
                [ "$(cat "/sys/class/net/$veth_peer/iflink")" = \
                    "$(cat "/sys/class/net/$veth_host/ifindex")" ]; }; then
            ip link delete dev "$veth_host" || { [ "$status" -ne 0 ] || status=1; }
        else
            echo "Cannot remove an LXC acquisition interface with a different owner" >&2
            [ "$status" -ne 0 ] || status=1
        fi
    fi
    rollback_ok=true
    if [ "$initialization_state" != committed ]; then
        if [ -n "$backup" ] && ! cp -p -- "$backup" "$LXC_DHCP_CONFILE"; then
            echo "Failed to restore local lxc-net dnsmasq config; backup retained at $backup" >&2
            rollback_ok=false
        fi
        if [ -n "$defaults_backup" ] && ! cp -p -- "$defaults_backup" "$defaults"; then
            echo "Failed to restore local lxc-net defaults; backup retained at $defaults_backup" >&2
            rollback_ok=false
        fi
        if [ -n "$created_config" ] && ! rm -f -- "$created_config"; then
            echo "Failed to remove newly created local lxc-net dnsmasq config: $created_config" >&2
            rollback_ok=false
        fi
        if [ "$initialization_state" = restart_pending ]; then
            if [ "$rollback_ok" != true ]; then
                echo "Cannot recover local lxc-net because configuration restoration failed" >&2
            elif ! timeout --signal=TERM --kill-after=2 30 systemctl restart lxc-net; then
                echo "Failed to recover local lxc-net after restoring its configuration" >&2
                rollback_ok=false
            elif ! server=$(server_pid); then
                echo "Recovered local lxc-net dnsmasq did not match its original configuration" >&2
                rollback_ok=false
            fi
        fi
    fi
    if [ "$rollback_ok" = true ]; then
        for pending in "$backup" "$defaults_backup"; do
            if [ -n "$pending" ]; then
                rm -f -- "$pending" || { [ "$status" -ne 0 ] || status=1; }
            fi
        done
    elif [ "$status" -eq 0 ]; then
        status=1
    fi
    for pending in "$stage" "$record_stage" "$defaults_stage"; do
        if [ -n "$pending" ]; then
            rm -f -- "$pending" || { [ "$status" -ne 0 ] || status=1; }
        fi
    done
    exit "$status"
}

trap cleanup EXIT
trap 'exit 1' HUP INT TERM

if [ "$server_config" != "$LXC_DHCP_CONFILE" ] ||
    ! grep -Fxq "$directive" "$LXC_DHCP_CONFILE"; then
    if [ -e "$LXC_DHCP_CONFILE" ]; then
        test -w "$LXC_DHCP_CONFILE" || fail "Cannot update local lxc-net dnsmasq config"
    fi
    stage_path=$LXC_DHCP_CONFILE.mxc-$$
    backup_path=$LXC_DHCP_CONFILE.mxc-backup-$$
    test ! -e "$stage_path" && test ! -L "$stage_path" &&
        test ! -e "$backup_path" && test ! -L "$backup_path" ||
        fail "LXC dnsmasq config staging path already exists"
    stage=$stage_path
    if [ -e "$LXC_DHCP_CONFILE" ]; then
        cp -p -- "$LXC_DHCP_CONFILE" "$stage"
    else
        : > "$stage"
        chmod 644 "$stage"
    fi
    if ! grep -Fxq "$directive" "$stage"; then
        printf '\n%s\n' "$directive" >> "$stage"
    fi
    dnsmasq --test --conf-file="$stage" ||
        fail "The local lxc-net dnsmasq config did not pass validation"
    if [ "$server_config" != "$LXC_DHCP_CONFILE" ]; then
        test -f "$defaults" && test ! -L "$defaults" &&
            test "$(stat -c %u "$defaults")" = 0 ||
            fail "The local lxc-net defaults must be a regular file owned by root"
        mode=$(stat -c %a "$defaults")
        test "$((0$mode & 0022))" -eq 0 ||
            fail "The local lxc-net defaults must not be writable by other users"
        defaults_stage_path=$defaults.mxc-$$
        defaults_backup_path=$defaults.mxc-backup-$$
        test ! -e "$defaults_stage_path" && test ! -L "$defaults_stage_path" &&
            test ! -e "$defaults_backup_path" && test ! -L "$defaults_backup_path" ||
            fail "LXC defaults staging path already exists"
        defaults_stage=$defaults_stage_path
        cp -p -- "$defaults" "$defaults_stage"
        printf '\nLXC_DHCP_CONFILE=/etc/lxc/dnsmasq.conf\n' >> "$defaults_stage"
        sh -n "$defaults_stage" || fail "The local lxc-net defaults did not pass validation"
    fi
    if [ -e "$LXC_DHCP_CONFILE" ]; then
        cp -p -- "$LXC_DHCP_CONFILE" "$backup_path"
        backup=$backup_path
    else
        created_config=$LXC_DHCP_CONFILE
    fi
    mv -f -- "$stage" "$LXC_DHCP_CONFILE"
    stage=
    if [ -n "$defaults_stage" ]; then
        cp -p -- "$defaults" "$defaults_backup_path"
        defaults_backup=$defaults_backup_path
        mv -f -- "$defaults_stage" "$defaults"
        defaults_stage=
    fi

    initialization_state=restart_pending

    # Main dnsmasq configuration is not reloaded by SIGHUP.
    timeout --signal=TERM --kill-after=2 30 systemctl restart lxc-net ||
        fail "Failed to enable the LXC reservation directory in local lxc-net"
    server=$(
        server_config=$LXC_DHCP_CONFILE
        server_pid
    )
    initialization_state=committed
    server_config=$LXC_DHCP_CONFILE
    if [ -n "$backup" ]; then
        rm -f -- "$backup"
    fi
    if [ -n "$defaults_backup" ]; then
        rm -f -- "$defaults_backup"
    fi
    backup=
    defaults_backup=
    created_config=
fi

for existing in "$reservations"/*; do
    test -f "$existing" || continue
    test ! -L "$existing" || continue
    name=${existing##*/}
    test "${#name}" -eq 64 || continue
    case "$name" in
        *[!0-9a-f]*) continue ;;
    esac
    IFS= read -r saved_owner < "$existing" || continue
    case "$saved_owner" in
        '# owner='*)
            owner_config=${saved_owner#\# owner=}
            saved_identity=$(printf '%s' "$owner_config" | sha256sum)
            saved_identity=${saved_identity%% *}
            test "$saved_identity" = "$name" || continue
            if [ ! -e "$owner_config" ]; then
                rm -- "$existing"
                continue
            fi
            ;;
        *) continue ;;
    esac
    test "$existing" != "$reservation" || continue
    if grep -Fiq "$mac," "$existing"; then
        fail "The LXC hardware address already belongs to another container reservation"
    fi
done
if [ -e "$reservation" ] || [ -L "$reservation" ]; then
    test -f "$reservation" && test ! -L "$reservation" ||
        fail "LXC reservation path is not a regular file"
    IFS= read -r saved_owner < "$reservation"
    test "$saved_owner" = "# owner=$config" ||
        fail "LXC reservation path belongs to a different owner"
fi
server=$(server_pid)
kill -HUP "$server" || fail "Failed to reload local lxc-net reservations after cleanup"

test ! -e "/sys/class/net/mxh$$" && test ! -e "/sys/class/net/$veth_peer" ||
    fail "LXC acquisition interface name is already in use"
veth_host=mxh$$
marking=true
ip link add name "$veth_host" type veth peer name "$veth_peer"
ip link set dev "$veth_host" alias "$owner"
test "$(cat "/sys/class/net/$veth_host/ifalias")" = "$owner" ||
    fail "Cannot verify ownership of the LXC acquisition interface"
marking=false
for device in "$veth_host" "$veth_peer"; do
    if [ -e "/proc/sys/net/ipv6/conf/$device/disable_ipv6" ]; then
        printf '1\n' > "/proc/sys/net/ipv6/conf/$device/disable_ipv6"
    fi
done
ip link set dev "$veth_host" master "$bridge"
ip link set dev "$veth_peer" address "$mac"
ip link set dev "$veth_host" up
ip link set dev "$veth_peer" up

acquire()
{
    # Leave the finite lease active while the reservation is being installed.
    if ! timeout --signal=TERM --kill-after=2 15 busybox udhcpc \
        -i "$veth_peer" -f -q -n -t 3 -T 2 -a -B -O search \
        -s "$directory/dhcp-event.sh" > "$directory/client.log" 2>&1 ||
        ! test -s "$directory/address"; then
        cat "$directory/client.log" >&2
        fail "Failed to acquire an LXC address from local lxc-net"
    fi
}

acquire
address=$(cat "$directory/address")
ip=${address%/*}
case "$ip" in
    ''|*[!0-9.]*) fail "DHCP returned an invalid IPv4 address" ;;
esac
for existing in "$reservations"/*; do
    test -f "$existing" || continue
    test "$existing" != "$reservation" || continue
    if grep -Fq ",$ip," "$existing"; then
        fail "The acquired LXC address already belongs to another container reservation"
    fi
done
lease=$(cat "$directory/lease")
case "$lease" in
    ''|*[!0-9]*) fail "DHCP did not return a finite positive lease duration" ;;
esac
test "$lease" -gt 0 && test "$lease" -lt 4294967295 ||
    fail "DHCP did not return a finite positive lease duration"
duration=300
if [ "$lease" = "$duration" ]; then
    duration=301
fi
record=$mac,$ip,$duration
dnsmasq --test --conf-file=/dev/null --dhcp-host="$record" ||
    fail "The LXC address reservation did not pass validation"

record_path=$state/.reservation-$$
test ! -e "$record_path" && test ! -L "$record_path" ||
    fail "LXC reservation staging path already exists"
record_stage=$record_path
printf '# owner=%s\n%s\n' "$config" "$record" > "$record_stage"
chmod 644 "$record_stage"
mv -f -- "$record_stage" "$reservation"
record_stage=
server=$(server_pid)
kill -HUP "$server" || fail "Failed to reload local lxc-net reservations"

for attempt in 1 2 3; do
    acquire
    if [ "$(cat "$directory/address")" = "$address" ] &&
        [ "$(cat "$directory/lease")" = "$duration" ]; then
        test "$server" = "$(server_pid)" ||
            fail "Local lxc-net restarted while activating the LXC reservation"
        exit 0
    fi
    sleep 0.1
done
fail "Local lxc-net did not activate the LXC address reservation"
