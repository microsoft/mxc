#!/bin/bash
# Bubblewrap baseline-alias masking test.
#
# On a merged-/usr host /bin is a symlink to usr/bin, so /bin/cat and
# /usr/bin/cat are one file. A path denied under either spelling of a
# symlinked system directory must be hidden under both.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
LXC_EXEC="$REPO_DIR/src/target/release/lxc-exec"

if [ ! -f "$LXC_EXEC" ]; then
    LXC_EXEC="$REPO_DIR/src/target/debug/lxc-exec"
fi

if [ ! -f "$LXC_EXEC" ]; then
    echo "Error: lxc-exec not found. Run build.sh first."
    exit 1
fi

fail() { echo "FAIL: $1"; exit 1; }

if [ ! -L /bin ] || [ ! -L /lib ] || [ "$(readlink -f /bin)" != /usr/bin ] \
    || [ "$(readlink -f /lib)" != /usr/lib ]; then
    echo "SKIP: /bin and /lib are not symlinks into /usr on this host, so there are no aliases to test."
    exit 77
fi

TOOL=
for candidate in cat sed tar gzip; do
    if [ -f "/usr/bin/$candidate" ] && [ ! -L "/usr/bin/$candidate" ]; then
        TOOL="$candidate"
        break
    fi
done
if [ -z "$TOOL" ]; then
    echo "SKIP: /usr/bin has no standalone cat, sed, tar, or gzip to deny."
    exit 77
fi

# Paths no probe may deny: the probe shell, the libraries it loads, and every
# path already chosen.
SHELL_PATH=$(readlink -f /bin/sh)
EXCLUDED=$(
    echo "$SHELL_PATH"
    ldd "$SHELL_PATH" 2>/dev/null | grep -o '/[^ ]*' | xargs -r readlink -f || true
)
EXCLUDED+=$'\n'"/usr/bin/$TOOL"

# Print a sandbox shell test that succeeds while directory $1 lists an entry.
lists() { printf 'set -- %s/*; [ -e "$1" ] || [ -L "$1" ]' "$1"; }

deniable_file() { [ -f "$1" ] && [ ! -L "$1" ] && [ -s "$1" ] && [ -r "$1" ]; }
deniable_dir() { [ -d "$1" ] && [ ! -L "$1" ] && [ -r "$1" ] && [ -x "$1" ] && eval "$(lists "$1")"; }

# Print the name of the first entry of directory $1 that passes test $2, needs
# no quoting, and is not excluded.
pick() {
    local path
    for path in "$1"/*; do
        case "${path##*/}" in *[!A-Za-z0-9._+-]*) continue ;; esac
        grep -qF "$path" <<<"$EXCLUDED" && continue
        if "$2" "$path"; then
            echo "${path##*/}"
            return 0
        fi
    done
    return 1
}

PROBES=
OPEN=()
DENIED=()

# Probe marker $1, printing _OPEN while sandbox test $2 succeeds and _BLOCKED
# otherwise; $3 is the state expected once the chosen paths are denied.
probe() {
    PROBES+="if $2; then echo ${1}_OPEN; else echo ${1}_BLOCKED; fi; "
    OPEN+=("${1}_OPEN")
    DENIED+=("${1}_$3")
}

probe TOOL "/usr/bin/$TOOL --version >/dev/null 2>&1" BLOCKED
probe TOOL_ALIAS "/bin/$TOOL --version >/dev/null 2>&1" BLOCKED
DENY_REAL=("/usr/bin/$TOOL")
DENY_ALIAS=("/bin/$TOOL")

for alias in /bin /sbin /lib /lib32 /lib64 /libx32 /usr/sbin /usr/lib64; do
    [ -L "$alias" ] || continue
    real=$(readlink -f "$alias")
    case "$real" in
    /usr/bin | /usr/sbin | /usr/lib | /usr/lib32 | /usr/lib64 | /usr/libx32) ;;
    *)
        echo "NOTE: $alias -> $real is not a merged-/usr directory; not testing it."
        continue
        ;;
    esac
    id=${alias//\//_}
    file=$(pick "$real" deniable_file) || file=
    dir=$(pick "$real" deniable_dir) || dir=
    echo "Testing $alias -> $real with file '${file:-none}' and directory '${dir:-none}'."

    # The alias must still reach its directory, so a BLOCKED below is the mask.
    probe "LISTED$id" "$(lists "$alias")" OPEN
    if [ -n "$file" ]; then
        EXCLUDED+=$'\n'"$real/$file"
        probe "FILE$id" "[ -s $real/$file ]" BLOCKED
        probe "FILE_ALIAS$id" "[ -s $alias/$file ]" BLOCKED
        DENY_REAL+=("$real/$file")
        DENY_ALIAS+=("$alias/$file")
    fi
    if [ -n "$dir" ]; then
        EXCLUDED+=$'\n'"$real/$dir/"
        probe "DIR$id" "$(lists "$real/$dir")" BLOCKED
        probe "DIR_ALIAS$id" "$(lists "$alias/$dir")" BLOCKED
        DENY_REAL+=("$real/$dir")
        DENY_ALIAS+=("$alias/$dir")
    fi
    if [ "$alias" = /lib ] && { [ -z "$file" ] || [ -z "$dir" ]; }; then
        fail "found no file and directory under /usr/lib that are safe to deny."
    fi
done

json() {
    local text=${1//\\/\\\\}
    printf '"%s"' "${text//\"/\\\"}"
}

json_array() {
    local items= item
    for item in "$@"; do items+="${items:+,}$(json "$item")"; done
    printf '[%s]' "$items"
}

# Run the probes with the JSON deniedPaths $1 and require each marker after it.
expect() {
    local denied="$1" config output marker
    shift
    config=$(printf '{"version":"1.0.0","containment":"bubblewrap","process":{"commandLine":%s,"timeout":30000},"filesystem":{"deniedPaths":%s}}' \
        "$(json "$PROBES")" "$denied")
    echo "Running Bubblewrap baseline-alias test: deniedPaths $denied..."
    if ! output=$("$LXC_EXEC" --experimental --config-base64 "$(printf '%s' "$config" | base64 -w0)" 2>&1); then
        echo "$output"
        fail "the sandbox did not start with deniedPaths $denied."
    fi
    echo "$output"
    for marker in "$@"; do
        grep -qFx "$marker" <<<"$output" || fail "deniedPaths $denied: expected $marker."
    done
    echo "PASS: deniedPaths $denied"
}

# Without a denial every probe must see access, so a later BLOCKED is the
# policy's doing.
expect '[]' "${OPEN[@]}"
expect "$(json_array "${DENY_REAL[@]}")" "${DENIED[@]}"
expect "$(json_array "${DENY_ALIAS[@]}")" "${DENIED[@]}"

# Show lxc-exec a root whose /bin is a symlink loop.
echo "Running Bubblewrap baseline-alias test: unresolvable /bin..."
links=()
for link in /sbin /lib /lib32 /lib64 /libx32; do
    if [ -L "$link" ]; then
        links+=(--symlink "$(readlink "$link")" "$link")
    fi
done
config='{"version":"1.0.0","containment":"bubblewrap","process":{"commandLine":"echo LOOP_RAN"}}'
rc=0
output=$(bwrap --unshare-pid --ro-bind /usr /usr --ro-bind /etc /etc "${links[@]}" \
    --symlink bin /bin --dev /dev --proc /proc --tmpfs /tmp \
    --ro-bind "$LXC_EXEC" "$LXC_EXEC" -- \
    "$LXC_EXEC" --experimental --config-base64 "$(printf '%s' "$config" | base64 -w0)" 2>&1) || rc=$?
if [ "$rc" -eq 0 ] || grep -qF LOOP_RAN <<<"$output" \
    || ! grep -qF "could not resolve the host's /bin" <<<"$output"; then
    echo "$output"
    fail "an unresolvable /bin did not stop the launch (exit $rc)."
fi
echo "PASS: an unresolvable /bin stops the launch."

echo "Bubblewrap baseline-alias test complete."