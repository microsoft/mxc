#!/bin/bash
# Seatbelt seatbelt.deniedPathNames and seatbelt.deniedUnixSocketPaths.
#
# Every run uses the generated profile with broad grants: two separate
# read-write roots and open network. Each denial is paired with a control in the
# same run, so a sandbox that failed to start cannot pass as a denial. The host
# root's name is full of regex metacharacters, so a rule that interpolated it
# unescaped would silently match nothing.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/seatbelt_common.sh
. "$SCRIPT_DIR/lib/seatbelt_common.sh"

require_python3_probe

TESTDIR="$(mktemp -d /private/tmp/mxc-seatbelt-names.XXXXXX)"
LISTENER_PID=""
trap 'kill $LISTENER_PID 2>/dev/null; rm -rf "$TESTDIR" "$SEATBELT_TMP"' EXIT

ROOT="$TESTDIR/"'host (1) [x]+{y}$^.*?'
OTHER="$TESTDIR/other"
mkdir -p "$ROOT/.ssh" "$ROOT/a/b/.SSH" "$ROOT/a/.config/gh" "$ROOT/sub" "$ROOT/x.ssh" \
    "$ROOT/xssh" "$ROOT/plain" "$ROOT/b" "$ROOT/renamable" "$ROOT/branch/nested/.ssh" \
    "$ROOT/run" "$OTHER"
for secret in .ssh/id a/b/.SSH/id a/.config/gh/hosts.yml "sub/a+b(1).key" \
    branch/nested/.ssh/sentinel; do
    echo PATH_NAMES_SECRET >"$ROOT/$secret"
done
for readable in a/.config/other.txt x.ssh/id xssh/id sub/aab1xkey plain/data.txt; do
    echo PATH_NAMES_READABLE >"$ROOT/$readable"
done
ln -s "$ROOT/.ssh" "$ROOT/link-into"
ln -s ../plain "$ROOT/b/.ssh"

render_names() { render "$1" TESTDIR "$TESTDIR" ROOT "$ROOT"; }

run_config "$(render_names seatbelt_path_names_reads.json)" --experimental
expect_ok "the name probe ran" "PATH_NAMES_PROBE_DONE"
expect_marker "a denied name is unreadable" "TOP=DENIED"
expect_marker "a denied name matches at depth and in any ASCII case" "DEEP_CASE=DENIED"
expect_marker "a multi-component name is denied" "MULTI=DENIED"
expect_marker "regex metacharacters in a name are literal" "SPECIAL_NAME=DENIED"
expect_marker "a symlink that resolves into a denied name is denied" "LINK_INTO=DENIED"
expect_marker "a symlink carrying a denied name blocks access through it" "LINK_NAMED=DENIED"
expect_marker "a sibling of a multi-component match stays readable" "SIBLING=READ"
expect_marker "a name only matches whole components" "BOUNDARY=READ"
expect_marker "a '.' in a name does not match any character" "DOT_DECOY=READ"
expect_marker "metacharacters in a name do not act as regex syntax" "SPECIAL_DECOY=READ"
expect_marker "the target of a denied-name symlink stays readable under its own name" "TARGET=READ"

run_config "$(render_names seatbelt_path_names_renames.json)" --experimental
expect_ok "the rename probe ran" "PATH_NAMES_PROBE_DONE"
expect_marker "unrelated renames still work" "UNRELATED=MOVED"
expect_marker "a leading component of a multi-component name cannot be renamed" "PREFIX=REFUSED"
expect_absent "renaming the leading component exposes nothing" "PREFIX_TARGET=READ"
expect_marker "a denied name cannot be renamed" "MATCH=REFUSED"
expect_marker "a directory holding a match can move to another writable root" "CROSS_ROOT=MOVED"
expect_marker "the moved match is still denied in the other root" "CROSS_ROOT_MATCH=DENIED"
[ -f "$ROOT/a/.config/gh/hosts.yml" ] || fail "the pinned .config directory was moved"
[ -f "$OTHER/moved/.ssh/sentinel" ] || fail "the cross-root move did not happen on the host"
pass "the host tree matches what the sandbox reported"

# A name created after launch: the probe signals that it is running, the host
# then creates the name, and only afterwards does the probe try to read it.
LATE_OUT="$SEATBELT_TMP/late.out"
"$MXC_EXEC_MAC" --experimental "$(render_names seatbelt_path_names_late.json)" >"$LATE_OUT" 2>&1 &
late_pid=$!
for _ in $(seq 1 100); do
    [ -e "$ROOT/late-started" ] && break
    sleep 0.1
done
[ -e "$ROOT/late-started" ] || fail "the late-creation probe never started" "$(cat "$LATE_OUT")"
mkdir -p "$ROOT/late/.ssh"
echo PATH_NAMES_SECRET >"$ROOT/late/.ssh/id"
touch "$ROOT/late-ready"
RC=0
wait "$late_pid" || RC=$?
OUT="$(cat "$LATE_OUT")"
expect_ok "the late-creation probe saw the host create the name" "LATE_READY"
expect_marker "a name created after launch is denied" "LATE=DENIED"

/usr/bin/python3 -c $'import socket, sys\ns = socket.socket(socket.AF_UNIX)\ns.bind(sys.argv[1])\ns.listen(8)\nwhile True:\n    s.accept()[0].close()' \
    "$ROOT/run/host.sock" &
LISTENER_PID=$!
for _ in $(seq 1 50); do
    [ -S "$ROOT/run/host.sock" ] && break
    sleep 0.1
done
[ -S "$ROOT/run/host.sock" ] || fail "the host listener did not start"

run_config "$(render_names seatbelt_unix_socket_denied_paths.json)" --experimental
expect_ok "the socket probe ran" "PATH_NAMES_PROBE_DONE"
expect_marker "a host socket under a denied socket path is unreachable" "HOST_SOCKET=REFUSED"
expect_marker "the workload cannot bind under a denied socket path" "HOST_FOLDER_IPC=REFUSED"
expect_marker "private scratch IPC keeps working" "SCRATCH_IPC=IPC_OK"
expect_marker "file writes under a denied socket path still work" "HOST_FOLDER_FILE_WRITE=OK"
# Documented limitation: the rule matches the socket's path, not its inode, so
# a writable socket moved out of the denied path becomes reachable.
expect_marker "a socket moved out of a denied socket path is reachable" "MOVED_SOCKET=CONNECTED"

expect_rejected "path exclusions require --experimental" \
    "seatbelt_reject_path_names_without_experimental.json" \
    "require --experimental" "PATH_NAMES_SHOULD_NOT_RUN"
expect_rejected "a glob-looking name is refused" \
    "seatbelt_reject_path_name_glob.json" \
    "is not supported" "PATH_NAMES_SHOULD_NOT_RUN" --experimental
expect_rejected "path exclusions cannot be combined with profileOverride" \
    "seatbelt_reject_path_exclusions_with_profile_override.json" \
    "profileOverride cannot be combined" "PATH_NAMES_SHOULD_NOT_RUN" --experimental

summary "Seatbelt path exclusions"
