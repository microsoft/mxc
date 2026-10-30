#!/bin/bash
# Kata Containers backend tests.
#
# Runs create-and-run requests through lxc-exec on every configured
# hypervisor, then the in-process streaming and lifecycle suite
# (streaming_kata) if its prebuilt binary or a Rust toolchain is available.
#
# Needs root, /dev/kvm, a Kata runtime-rs install, and root filesystems:
#   MXC_KATA_ROOT               Kata install prefix (or the shim on PATH)
#   MXC_KATA_TEST_ROOTFS        directory holding a root filesystem with /bin/sh
#   MXC_KATA_TEST_ROOTFS_IMAGE  ext4 image of it; required for firecracker
#   MXC_KATA_TEST_HYPERVISORS   subset of qemu,clh,dragonball,firecracker
#   MXC_KATA_CONFIG_<NAME>      use this Kata configuration for a hypervisor
#
# A missing prerequisite exits 77 (skip). With MXC_KATA_TESTS_REQUIRE_EXECUTION
# set it is a failure instead, so a provisioned runner cannot go green without
# running anything.
set -uo pipefail

SKIP_EXIT=77
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
HYPERVISORS="${MXC_KATA_TEST_HYPERVISORS:-qemu,clh,dragonball,firecracker}"

not_ready() {
    if [ "${MXC_KATA_TESTS_REQUIRE_EXECUTION:-0}" != "0" ]; then
        echo "ERROR: strict mode: $1"
        exit 1
    fi
    echo "SKIPPED: $1"
    exit "$SKIP_EXIT"
}

[ "$(id -u)" -eq 0 ] || not_ready "the Kata backend needs root"
[ -e /dev/kvm ] || not_ready "/dev/kvm is missing; the Kata backend needs hardware virtualization"
if [ -n "${MXC_KATA_ROOT:-}" ]; then
    SHIM="$MXC_KATA_ROOT/runtime-rs/bin/containerd-shim-kata-v2"
    [ -x "$SHIM" ] || SHIM="$MXC_KATA_ROOT/bin/containerd-shim-kata-v2"
    [ -x "$SHIM" ] || not_ready "no containerd-shim-kata-v2 under MXC_KATA_ROOT=$MXC_KATA_ROOT"
else
    command -v containerd-shim-kata-v2 >/dev/null 2>&1 \
        || not_ready "containerd-shim-kata-v2 was not found; set MXC_KATA_ROOT"
fi
[ -n "${MXC_KATA_TEST_ROOTFS:-}" ] && [ -d "$MXC_KATA_TEST_ROOTFS" ] \
    || not_ready "MXC_KATA_TEST_ROOTFS must name a root filesystem directory"

LXC_EXEC="$REPO_DIR/src/target/release/lxc-exec"
[ -f "$LXC_EXEC" ] || LXC_EXEC="$REPO_DIR/src/target/debug/lxc-exec"
if [ ! -f "$LXC_EXEC" ]; then
    echo "Error: lxc-exec not found. Run build.sh first."
    exit 1
fi

WORK="$(mktemp -d /run/mxc-kata-suite.XXXXXX)"
export MXC_KATA_STATE_DIR="$WORK/state"
HOST_KERNEL="$(uname -r)"
PASSED=0
FAILED=0
FAILURES=""
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

fail() {
    echo "FAIL: $1"
    FAILED=$((FAILED + 1))
    FAILURES="$FAILURES\n  - $1"
}
pass() {
    echo "PASS: $1"
    PASSED=$((PASSED + 1))
}

# What a sandbox may not leave behind: directories, mounts, namespaces, VM and
# shim processes, and loop devices.
assert_clean() {
    local label="$1" problems=""
    if [ -n "$(ls -A "$MXC_KATA_STATE_DIR" 2>/dev/null)" ]; then
        problems="$problems state-dir:$(ls -A "$MXC_KATA_STATE_DIR" | tr '\n' ' ')"
    fi
    if grep -q "$WORK\|/mxc-kata-" /proc/self/mountinfo; then
        problems="$problems mounts"
    fi
    # No -q: SIGPIPE plus pipefail hides a match.
    if ps -eo stat=,cmd= | awk '$1 !~ /^Z/' | grep '[m]xc-kata-' >/dev/null; then
        problems="$problems processes"
    fi
    local backing
    for backing in /sys/block/loop*/loop/backing_file; do
        [ -e "$backing" ] || continue
        if grep -q "$WORK" "$backing" 2>/dev/null; then
            problems="$problems loop-device"
        fi
    done
    if [ -n "$problems" ]; then
        fail "$label left behind:$problems"
        return 1
    fi
    return 0
}

rootfs_for() {
    if [ "$1" = firecracker ]; then
        echo "${MXC_KATA_TEST_ROOTFS_IMAGE:-}"
    else
        echo "$MXC_KATA_TEST_ROOTFS"
    fi
}

# write_config <file> <hypervisor> <command> [extra top-level JSON members] [rootfs]
# Commands in this suite contain no double quotes or backslashes. An extra that
# names "process" replaces the default process member.
write_config() {
    local file="$1" hypervisor="$2" command="$3" extra="${4:-}"
    local rootfs="${5:-$(rootfs_for "$hypervisor")}"
    local members=('"version": "1.1.0-alpha"' '"containment": "kata"'
        '"kata": {"rootfs": "'"$rootfs"'", "hypervisor": "'"$hypervisor"'"}')
    [ -n "$extra" ] && members+=("$extra")
    case "$extra" in
        *'"process"'*) ;;
        *) members+=('"process": {"commandLine": "'"$command"'"}') ;;
    esac
    (IFS=,; echo "{${members[*]}}") >"$file"
}

# run_kata <name> <hypervisor> <command> [extra JSON] [rootfs]
# Leaves stdout in $OUT, stderr in $ERR, and the exit status in $STATUS.
run_kata() {
    local name="$1" hypervisor="$2"
    OUT="$WORK/$name.out"
    ERR="$WORK/$name.err"
    write_config "$WORK/$name.json" "$hypervisor" "$3" "${4:-}" "${5:-}"
    "$LXC_EXEC" --experimental "$WORK/$name.json" >"$OUT" 2>"$ERR"
    STATUS=$?
}

test_hypervisor() {
    local h="$1"
    echo "=== $h ==="
    if [ "$h" = firecracker ] && [ ! -f "$(rootfs_for "$h")" ]; then
        not_ready "MXC_KATA_TEST_ROOTFS_IMAGE must name an ext4 image for firecracker"
    fi

    # Exit code, stdout and stderr relay, and the guest kernel.
    run_kata basic "$h" 'uname -r; echo err-line >&2; exit 3'
    if [ "$STATUS" -eq 3 ] \
        && [ -n "$(head -n 1 "$OUT")" ] \
        && [ "$(head -n 1 "$OUT")" != "$HOST_KERNEL" ] \
        && grep -q 'err-line' "$ERR"; then
        pass "$h basic: exit code, streams, guest kernel $(head -n 1 "$OUT")"
    else
        fail "$h basic (status $STATUS): $(cat "$OUT") / $(cat "$ERR")"
    fi
    assert_clean "$h basic" || true

    # Deny-all network: loopback only, whether omitted or spelled out.
    run_kata network "$h" 'ls /sys/class/net' \
        '"network": {"egress": {"default": "deny"}, "ingress": {"default": "deny", "hostLoopback": "deny"}}'
    if [ "$STATUS" -eq 0 ] && [ "$(cat "$OUT")" = "lo" ]; then
        pass "$h network: deny-all leaves only loopback"
    else
        fail "$h network (status $STATUS): $(cat "$OUT") / $(cat "$ERR")"
    fi
    assert_clean "$h network" || true

    # Filesystem policy.
    if [ "$h" = firecracker ]; then
        run_kata filesystem "$h" 'echo passwd-bytes=$(cat /etc/passwd | wc -c)' \
            '"filesystem": {"deniedPaths": ["/etc/passwd"]}'
        if [ "$STATUS" -eq 0 ] && [ "$(cat "$OUT")" = "passwd-bytes=0" ]; then
            pass "$h filesystem: a denied guest file reads as empty"
        else
            fail "$h filesystem (status $STATUS): $(cat "$OUT") / $(cat "$ERR")"
        fi
    else
        local host="$WORK/fs-$h"
        mkdir -p "$host/ro" "$host/rw/private"
        echo from-host >"$host/ro/readable.txt"
        echo classified >"$host/rw/private/secret.txt"
        echo classified >"$host/rw/token.txt"
        run_kata filesystem "$h" \
            "cat $host/ro/readable.txt; (echo changed > $host/ro/readable.txt) 2>/dev/null && echo ro-write=allowed || echo ro-write=denied; echo from-guest > $host/rw/created.txt && echo rw-write=allowed; echo private-entries=\$(ls $host/rw/private | wc -l); echo token-bytes=\$(cat $host/rw/token.txt | wc -c)" \
            "\"filesystem\": {\"readonlyPaths\": [\"$host/ro\"], \"readwritePaths\": [\"$host/rw\"], \"deniedPaths\": [\"$host/rw/private\", \"$host/rw/token.txt\"]}"
        expected="from-host
ro-write=denied
rw-write=allowed
private-entries=0
token-bytes=0"
        if [ "$STATUS" -eq 0 ] && [ "$(cat "$OUT")" = "$expected" ] \
            && [ "$(cat "$host/ro/readable.txt")" = "from-host" ] \
            && [ "$(cat "$host/rw/created.txt")" = "from-guest" ] \
            && [ "$(cat "$host/rw/token.txt")" = "classified" ]; then
            pass "$h filesystem: read-only, read-write, and denied paths"
        else
            fail "$h filesystem (status $STATUS): $(cat "$OUT") / $(cat "$ERR")"
        fi
    fi
    assert_clean "$h filesystem" || true

    # Timeout: the workload is killed, the run reports it, and the VM goes.
    local started
    started="$(date +%s)"
    run_kata timeout "$h" 'echo started; sleep 600' '"process": {"commandLine": "echo started; sleep 600", "timeout": 3000}'
    local elapsed=$(($(date +%s) - started))
    if [ "$STATUS" -ne 0 ] && grep -qi 'timed out' "$OUT" "$ERR" && [ "$elapsed" -lt 90 ]; then
        pass "$h timeout: killed and reported after ${elapsed}s"
    else
        fail "$h timeout (status $STATUS, ${elapsed}s): $(cat "$OUT") / $(cat "$ERR")"
    fi
    assert_clean "$h timeout" || true

    # Input the workload never reads must not stall the run, even when it fills
    # the stdin FIFO.
    write_config "$WORK/stdin.json" "$h" 'echo done'
    OUT="$WORK/stdin.out"
    ERR="$WORK/stdin.err"
    started="$(date +%s)"
    head -c 4194304 /dev/zero | timeout 150 "$LXC_EXEC" --experimental "$WORK/stdin.json" >"$OUT" 2>"$ERR"
    STATUS=${PIPESTATUS[1]}
    elapsed=$(($(date +%s) - started))
    if [ "$STATUS" -eq 0 ] && [ "$(cat "$OUT")" = "done" ]; then
        pass "$h stdin: unread input did not stall the run (${elapsed}s)"
    else
        fail "$h stdin (status $STATUS, ${elapsed}s): $(cat "$OUT") / $(cat "$ERR")"
    fi
    assert_clean "$h stdin" || true
}

# Requests the backend must refuse before it creates a VM.
run_kata rejected-network qemu 'true' '"network": {"egress": {"default": "allow"}}'
if [ "$STATUS" -ne 0 ] && grep -q 'cannot enforce' "$ERR" "$OUT"; then
    pass "network allow is rejected"
else
    fail "network allow was not rejected (status $STATUS): $(cat "$OUT") / $(cat "$ERR")"
fi
run_kata rejected-firecracker firecracker 'true' '' "$MXC_KATA_TEST_ROOTFS"
if [ "$STATUS" -ne 0 ] && grep -q 'ext4 image' "$ERR" "$OUT"; then
    pass "a firecracker rootfs directory is rejected"
else
    fail "a firecracker rootfs directory was not rejected (status $STATUS): $(cat "$OUT") / $(cat "$ERR")"
fi
assert_clean "rejections" || true

IFS=',' read -ra LIST <<<"$HYPERVISORS"
for hypervisor in "${LIST[@]}"; do
    test_hypervisor "$hypervisor"
done

# The in-process suite: streaming, kill, drop, and the container lifecycle.
STREAMING_TEST="$REPO_DIR/src/target/release/streaming_kata"
echo "=== streaming_kata ==="
if [ -x "$STREAMING_TEST" ]; then
    if env -u MXC_KATA_STATE_DIR "$STREAMING_TEST" --test-threads=1 --nocapture; then
        pass "streaming_kata"
    else
        fail "streaming_kata"
    fi
elif command -v cargo >/dev/null 2>&1; then
    if (cd "$REPO_DIR/src" && env -u MXC_KATA_STATE_DIR cargo test -p mxc-sdk --test streaming_kata -- --test-threads=1 --nocapture); then
        pass "streaming_kata"
    else
        fail "streaming_kata"
    fi
else
    fail "streaming_kata: neither a prebuilt $STREAMING_TEST nor cargo is available"
fi

echo "================================"
echo "Results: $PASSED passed, $FAILED failed"
if [ "$PASSED" -eq 0 ] && [ "$FAILED" -eq 0 ]; then
    echo "WARNING: no tests actually executed."
    [ "${MXC_KATA_TESTS_REQUIRE_EXECUTION:-0}" != "0" ] && exit 1
fi
if [ "$FAILED" -gt 0 ]; then
    echo -e "Failures:$FAILURES"
    exit 1
fi
