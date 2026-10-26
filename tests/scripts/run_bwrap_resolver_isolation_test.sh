#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
LXC_EXEC="${LXC_EXEC:-$REPO_DIR/src/target/release/lxc-exec}"
if [ ! -f "$LXC_EXEC" ]; then
    echo "FAIL: lxc-exec not found at $LXC_EXEC; set LXC_EXEC to the built executable."
    exit 1
fi

for tool in bwrap unshare python3 mount timeout; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "FAIL: $tool is required for resolver isolation coverage."
        exit 1
    fi
done
if ! command -v slirp4netns >/dev/null 2>&1; then
    echo "SKIP: slirp4netns is required for the filtered and proxy-only cases."
    exit 77
fi

# Replace host paths only inside a private mount namespace.
if [ "${MXC_RESOLVER_ISOLATION_INNER:-0}" != "1" ]; then
    if ! unshare -Urm true >/dev/null 2>&1; then
        echo "SKIP: unprivileged user and mount namespaces are unavailable."
        exit 77
    fi
    exec unshare -Urm env MXC_RESOLVER_ISOLATION_INNER=1 \
        LXC_EXEC="$LXC_EXEC" bash "$0"
fi

WORK_DIR="$(mktemp -d)"
PEER_PID=""
ETC_MOUNTED=0
RUN_MOUNTED=0
VAR_MOUNTED=0
MNT_MOUNTED=0
cleanup() {
    if [ -n "$PEER_PID" ]; then
        kill "$PEER_PID" 2>/dev/null || true
        wait "$PEER_PID" 2>/dev/null || true
    fi
    if [ "$ETC_MOUNTED" = 1 ]; then umount /etc; fi
    if [ "$RUN_MOUNTED" = 1 ]; then umount /run; fi
    if [ "$VAR_MOUNTED" = 1 ]; then umount /var; fi
    if [ "$MNT_MOUNTED" = 1 ]; then umount /mnt; fi
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT

mkdir -p "$WORK_DIR/etc" "$WORK_DIR/run" "$WORK_DIR/scratch" "$WORK_DIR/var" \
    "$WORK_DIR/bin" "$WORK_DIR/mnt/wsl"
for file in passwd group hosts ld.so.cache protocols services; do
    if [ -f "/etc/$file" ]; then cp "/etc/$file" "$WORK_DIR/etc/$file"; fi
done
if [ -d /etc/alternatives ]; then cp -RP /etc/alternatives "$WORK_DIR/etc/"; fi
printf 'passwd: files\ngroup: files\nhosts: resolve [!UNAVAIL=return] files dns\n' \
    >"$WORK_DIR/etc/nsswitch.conf"
ln -s /run/systemd/resolve/stub-resolv.conf "$WORK_DIR/etc/resolv.conf"
mount --bind "$WORK_DIR/etc" /etc
ETC_MOUNTED=1
mount --bind "$WORK_DIR/run" /run
RUN_MOUNTED=1
ln -s /run "$WORK_DIR/var/run"
mount --bind "$WORK_DIR/var" /var
VAR_MOUNTED=1

mkdir -p /run/systemd/resolve /run/NetworkManager /run/resolvconf/sub
for file in /run/systemd/resolve/stub-resolv.conf \
    /run/NetworkManager/resolv.conf /run/resolvconf/resolv.conf; do
    printf 'nameserver 192.0.2.53\nsearch mxc-test.invalid\n' >"$file"
done
ln -s /run/NetworkManager/resolv.conf /run/systemd/resolve/alias.conf
ln -s /run/resolvconf /run/systemd/resolve/linked
ln -s /run/resolvconf/sub /run/systemd/resolve/nested-link
for root in /run/systemd/resolve /run/resolvconf; do
    printf 'READ_ONLY\n' >"$root/readonly-sibling.conf"
    printf 'WRITABLE\n' >"$root/writable-sibling.conf"
    mkdir -p "$root/writable-child" "$root/blocked/subtree"
    printf 'HIDDEN\n' >"$root/blocked/subtree/secret"
done

# Serve private stand-ins for host IPC, with a control connection before each run.
python3 - "$WORK_DIR" >"$WORK_DIR/peer.log" 2>&1 <<'PY' &
import pathlib
import selectors
import socket
import sys

work = pathlib.Path(sys.argv[1])
paths = [
    "/run/systemd/resolve/io.systemd.Resolve",
    "/run/NetworkManager/mxc-test.sock",
    "/run/resolvconf/mxc-test.sock",
]
with selectors.DefaultSelector() as selector:
    for path in paths:
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(path)
        server.listen()
        selector.register(server, selectors.EVENT_READ)
    (work / "peer.ready").touch()
    while True:
        for key, _ in selector.select():
            connection, _ = key.fileobj.accept()
            with connection:
                connection.sendall(b"HOST_RESOLVER")
PY
PEER_PID=$!
for _ in $(seq 1 100); do
    [ -f "$WORK_DIR/peer.ready" ] && break
    if ! kill -0 "$PEER_PID" 2>/dev/null; then
        cat "$WORK_DIR/peer.log"
        echo "FAIL: resolver IPC fixture exited before becoming ready."
        exit 1
    fi
    sleep 0.1
done
if [ ! -f "$WORK_DIR/peer.ready" ]; then
    cat "$WORK_DIR/peer.log"
    echo "FAIL: resolver IPC fixture did not become ready."
    exit 1
fi

python3 - "$WORK_DIR" <<'PY'
import json
import pathlib
import shlex
import shutil
import sys

work = pathlib.Path(sys.argv[1])
script = """
import errno
import pathlib
import socket
for path in ['/run/systemd/resolve/io.systemd.Resolve',
             '/run/NetworkManager/mxc-test.sock', '/run/resolvconf/mxc-test.sock']:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(2)
        try:
            client.connect(path)
        except OSError as error:
            allowed = {errno.ENOENT, errno.ENOTDIR}
            if MASK_SOCKET and path.endswith('/io.systemd.Resolve'):
                allowed.update({errno.ECONNREFUSED, errno.EACCES})
            if error.errno not in allowed:
                raise
        else:
            raise SystemExit('FAIL: sandbox reached host resolver IPC at ' + path)
resolver = pathlib.Path('/etc/resolv.conf')
if DENIED:
    try:
        contents = resolver.read_bytes()
    except (FileNotFoundError, PermissionError, NotADirectoryError):
        pass
    else:
        if contents:
            raise SystemExit('FAIL: resolver file bypassed deniedPaths')
    if list(pathlib.Path(SCRATCH).glob('mxc-bwrap-resolver-*')):
        raise SystemExit('FAIL: denied resolver was copied into granted scratch storage')
    if pathlib.Path('/var/lib/resolvconf/resolv.conf').exists():
        raise SystemExit('FAIL: resolver alias escaped the denied original path')
else:
    if resolver.read_text() != 'nameserver NAMESERVER\\nsearch mxc-test.invalid\\n':
        raise SystemExit('FAIL: resolver contents changed')
    try:
        with resolver.open('ab'):
            pass
    except OSError as error:
        if WRITABLE or error.errno not in (errno.EROFS, errno.EACCES):
            raise
    else:
        if not WRITABLE:
            raise SystemExit('FAIL: resolver snapshot is writable')
socket.getaddrinfo('localhost', 80)
EXTRA_CHECKS
print('RESOLVER_ISOLATION_OK')
"""
for mode in ("deny", "allow", "filtered", "proxy", "pinned", "denied-directory",
             "denied-file", "denied-with-scratch", "readonly-file", "ungranted-target",
             "custom-resolver", "readwrite-file", "denied-ancestor", "ancestor-with-grant",
             "invalid-resolver", "staging-swap", "sibling-denial", "sibling-grants",
             "alias-readonly", "alias-readwrite", "alias-siblings"):
    denied = mode.startswith("denied-") or mode in ("ungranted-target", "invalid-resolver")
    nameserver = "10.0.2.3" if mode == "pinned" else "192.0.2.53"
    workload = (
        script.replace("DENIED", str(denied)).replace("NAMESERVER", nameserver)
              .replace("SCRATCH", repr(str(work / "scratch")))
              .replace("WRITABLE", str(mode in ("readwrite-file", "alias-readwrite")))
              .replace("MASK_SOCKET", str(mode == "sibling-denial"))
    )
    config = {
        "version": "0.9.0-alpha",
        "containerId": "Resolver-Isolation-" + mode,
        "containment": "bubblewrap",
        "network": {"egress": {"default": "allow" if mode in ("allow", "pinned") else "deny"}},
    }
    if mode == "filtered":
        config["network"]["egress"]["allow"] = [{"to": [{"cidr": "192.0.2.0/24"}]}]
    if mode == "proxy":
        config["runtimeConfig"] = {"networkProxy": "http://127.0.0.1:9"}
    if mode.startswith("denied-"):
        path = "/run/systemd/resolve"
        if mode == "denied-file":
            path += "/stub-resolv.conf"
        config["filesystem"] = {"deniedPaths": [path]}
        if mode == "denied-with-scratch":
            config["filesystem"]["readwritePaths"] = [str(work / "scratch")]
    if mode == "readonly-file":
        config["filesystem"] = {"readonlyPaths": ["/run/systemd/resolve/stub-resolv.conf"]}
    if mode == "custom-resolver":
        config["filesystem"] = {"readonlyPaths": [str(work / "private.conf")]}
    if mode == "readwrite-file":
        config["filesystem"] = {"readwritePaths": ["/run/systemd/resolve/stub-resolv.conf"]}
    if mode == "denied-ancestor":
        config["filesystem"] = {"deniedPaths": ["/run"]}
    if mode == "ancestor-with-grant":
        config["filesystem"] = {
            "deniedPaths": ["/run"],
            "readonlyPaths": ["/run/resolvconf/resolv.conf"],
        }
    if mode == "staging-swap":
        config["filesystem"] = {"readwritePaths": [str(work / "scratch")]}
    extra = ""
    if mode == "sibling-denial":
        config["filesystem"] = {"deniedPaths": [
            "/run/systemd/resolve/io.systemd.Resolve",
            "/run/systemd/resolve/blocked/subtree",
        ]}
        extra = "assert not pathlib.Path('/run/systemd/resolve/blocked/subtree/secret').exists()"
    if mode in ("alias-readonly", "alias-readwrite"):
        key = "readonlyPaths" if mode == "alias-readonly" else "readwritePaths"
        config["filesystem"] = {key: ["/run/resolvconf/resolv.conf"]}
    if mode in ("sibling-grants", "alias-siblings"):
        root = "/run/resolvconf" if mode == "alias-siblings" else "/run/systemd/resolve"
        config["filesystem"] = {
            "readonlyPaths": [root + "/readonly-sibling.conf"],
            "readwritePaths": [root + "/writable-sibling.conf", root + "/writable-child"],
        }
        extra = f"""
root = pathlib.Path({root!r})
readonly = root / 'readonly-sibling.conf'
assert readonly.read_text() == 'READ_ONLY\\n'
try:
    readonly.write_text('NOT_ALLOWED')
except OSError as error:
    if error.errno not in (errno.EROFS, errno.EACCES):
        raise
else:
    raise SystemExit('FAIL: readonly sibling accepted a write')
for path in (root / 'writable-sibling.conf', root / 'writable-child' / 'new-file'):
    path.write_text('UPDATED')
    assert path.read_text() == 'UPDATED'
"""
    config["process"] = {
        "commandLine": "python3 -c " + shlex.quote(workload.replace("EXTRA_CHECKS", extra))
    }
    (work / (mode + ".json")).write_text(json.dumps(config))

wrapper = work / "bin/bwrap"
wrapper.write_text(f"""#!{sys.executable}
import os
from pathlib import Path
import sys
if '--version' not in sys.argv:
    for value in sys.argv[1:]:
        if value.startswith(os.environ['TMPDIR'] + '/mxc-bwrap-resolver-'):
            os.unlink(value)
            os.symlink({str(work / 'ungranted-sentinel')!r}, value)
    if '--file' in sys.argv:
        fd = int(sys.argv[sys.argv.index('--file') + 1])
        try:
            os.write(fd, b'POISONED_RESOLVER')
        except PermissionError:
            Path({str(work / 'sealed-descriptor')!r}).touch()
        else:
            raise SystemExit('FAIL: resolver descriptor is not sealed')
os.execv({shutil.which('bwrap')!r}, ['bwrap'] + sys.argv[1:])
""")
wrapper.chmod(0o755)
(work / "ungranted-sentinel").write_text("UNGRANTED_FILE_SENTINEL\n")
PY

run_case() {
    local mode="$1" output
    python3 - <<'PY'
import socket
for path in ["/run/systemd/resolve/io.systemd.Resolve",
             "/run/NetworkManager/mxc-test.sock", "/run/resolvconf/mxc-test.sock"]:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(2)
        client.connect(path)
        if client.recv(64) != b"HOST_RESOLVER":
            raise SystemExit("FAIL: host resolver IPC control did not answer")
PY
    if ! output="$(TMPDIR="$WORK_DIR/scratch" timeout 60 \
        "$LXC_EXEC" --experimental "$WORK_DIR/$mode.json" 2>&1)"; then
        echo "$output"
        echo "FAIL: resolver isolation in $mode mode."
        exit 1
    fi
    if ! grep -qF RESOLVER_ISOLATION_OK <<<"$output"; then
        echo "$output"
        echo "FAIL: resolver isolation workload did not complete in $mode mode."
        exit 1
    fi
    if compgen -G "$WORK_DIR/scratch/mxc-bwrap-resolver-*" >/dev/null; then
        echo "FAIL: resolver snapshot was not removed after $mode completed."
        exit 1
    fi
    if [ "$mode" = invalid-resolver ] &&
        ! grep -qF 'not a regular resolver file' <<<"$output"; then
        echo "$output"
        echo "FAIL: nonregular resolver was not reported."
        exit 1
    fi
    echo "PASS: resolver isolation and filesystem policy in $mode mode."
}

for mode in deny allow filtered proxy denied-directory denied-file denied-with-scratch \
    readonly-file readwrite-file sibling-denial sibling-grants; do
    run_case "$mode"
done
for target in ../run/NetworkManager/resolv.conf /var/run/resolvconf/resolv.conf \
    /run/systemd/resolve/alias.conf /run/systemd/resolve/linked/resolv.conf \
    /run/resolvconf/sub/../resolv.conf \
    /run/systemd/resolve/nested-link/../resolv.conf; do
    ln -sfn "$target" /etc/resolv.conf
    run_case deny
    printf 'nameserver 127.0.0.53\nsearch mxc-test.invalid\n' >"$(readlink -f /etc/resolv.conf)"
    run_case pinned
    printf 'nameserver 192.0.2.53\nsearch mxc-test.invalid\n' >"$(readlink -f /etc/resolv.conf)"
done

printf 'nameserver 192.0.2.53\nsearch mxc-test.invalid\n' >"$WORK_DIR/private.conf"
ln -sfn "$WORK_DIR/private.conf" /etc/resolv.conf
run_case ungranted-target
run_case custom-resolver

rm /run/NetworkManager/resolv.conf
ln -s "$WORK_DIR/private.conf" /run/NetworkManager/resolv.conf
ln -sfn /run/NetworkManager/resolv.conf /etc/resolv.conf
run_case custom-resolver

mv "$WORK_DIR/run/resolvconf" "$WORK_DIR/resolver-state"
ln -s "$WORK_DIR/resolver-state" /run/resolvconf
ln -sfn /run/resolvconf/resolv.conf /etc/resolv.conf
run_case deny
run_case allow

rm /run/resolvconf
mkdir -p /var/lib
mv "$WORK_DIR/resolver-state" "$WORK_DIR/var/lib/resolvconf"
ln -s /var/lib/resolvconf /run/resolvconf
run_case alias-readonly
run_case alias-readwrite
run_case alias-siblings
run_case denied-ancestor
run_case ancestor-with-grant

ln -sfn /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf
PATH="$WORK_DIR/bin:$PATH" run_case staging-swap
if [ ! -f "$WORK_DIR/sealed-descriptor" ]; then
    echo "FAIL: the resolver was not supplied through a sealed descriptor."
    exit 1
fi

mkfifo /run/systemd/resolve/fifo.conf
ln -sfn /run/systemd/resolve/fifo.conf /etc/resolv.conf
run_case invalid-resolver

# Keep the executor reachable when the private /mnt replaces WSL drive mounts.
cp "$LXC_EXEC" "$WORK_DIR/lxc-exec"
chmod u+x "$WORK_DIR/lxc-exec"
LXC_EXEC="$WORK_DIR/lxc-exec"
mount --bind "$WORK_DIR/mnt" /mnt
MNT_MOUNTED=1
printf 'nameserver 192.0.2.53\nsearch mxc-test.invalid\n' >/mnt/wsl/resolv.conf
ln -sfn /mnt/wsl/resolv.conf /etc/resolv.conf
run_case deny
