#!/bin/bash
# Bubblewrap grant-alias test: a readwritePaths or readonlyPaths entry named
# through a symlink must keep the rules inside it under every spelling, and the
# caller's spelling must still reach it.
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

ROOTS=()
cleanup() { if [ "${#ROOTS[@]}" -gt 0 ]; then rm -rf "${ROOTS[@]}"; fi; }
trap cleanup EXIT

json() {
    local text=${1//\\/\\\\}
    printf '"%s"' "${text//\"/\\\"}"
}

make_root() {
    ROOT=$(cd "$(mktemp -d "$1/.mxc_bwrap_grant_alias_XXXXXX")" && pwd -P)
    ROOTS+=("$ROOT")
    mkdir -p "$ROOT/real/sub" "$ROOT/real/protected"
    echo SECRET_CONTENT >"$ROOT/real/secret.txt"
    echo SECRET_CONTENT >"$ROOT/real/sub/secret.txt"
    echo HOOK_CONTENT >"$ROOT/real/protected/hook"
    echo OTHER_CONTENT >"$ROOT/other.txt"
    ln -s "$ROOT/real" "$ROOT/alias"
    ln -s alias "$ROOT/chain"
    ln -s real/protected/hook "$ROOT/hook-link"
}

PROBES=
MARKERS=()

# Probe marker $1, printing _OPEN while sandbox command $2 succeeds and
# _BLOCKED otherwise; $3 is the state required.
probe() {
    PROBES+="if $2; then echo ${1}_OPEN; else echo ${1}_BLOCKED; fi; "
    MARKERS+=("${1}_$3")
}

# Print a sandbox command that succeeds while file $1 holds the line $2.
holds() { printf "grep -qx %s '%s' 2>/dev/null" "$2" "$1"; }

# Print a sandbox command that succeeds when $2 can be written to file $1.
accepts() { printf "(echo %s >'%s') 2>/dev/null" "$2" "$1"; }

# Print a sandbox command that succeeds while file $1 holds the bytes whose
# cksum output is $2.
same_bytes() { printf "[ \"\$( (cksum <'%s') 2>/dev/null)\" = '%s' ]" "$1" "$2"; }

# Print each file the probe commands load: sh, grep, and cksum as found on the
# sandbox's PATH, and the loader and libraries each of them links.
probe_files() {
    local PATH=/usr/sbin:/usr/bin:/sbin:/bin tool path
    for tool in sh grep cksum; do
        path=$(command -v "$tool") || continue
        readlink -f "$path"
        ldd "$path" 2>/dev/null | grep -o '/[^ ]*' | xargs -r readlink -f || true
    done
}

probes_load_from() {
    local path
    while IFS= read -r path; do
        case "$path" in "$1"/*) return 0 ;; esac
    done <<<"$PROBE_FILES"
    return 1
}

# Print a directory directly under /usr/lib that the probe commands load
# nothing from, followed by the names of two small readable files in it.
pick_shared_dir() {
    local dir path files
    for dir in /usr/lib/*; do
        case "${dir##*/}" in *[!A-Za-z0-9._+-]*) continue ;; esac
        if [ ! -d "$dir" ] || [ -L "$dir" ] || [ ! -r "$dir" ] || [ ! -x "$dir" ] \
            || probes_load_from "$dir"; then
            continue
        fi
        files=()
        for path in "$dir"/*; do
            case "${path##*/}" in *[!A-Za-z0-9._+-]*) continue ;; esac
            if [ -f "$path" ] && [ ! -L "$path" ] && [ -r "$path" ] && [ -s "$path" ] \
                && [ "$(stat -c %s "$path")" -le 1048576 ]; then
                files+=("${path##*/}")
            fi
            if [ "${#files[@]}" -eq 2 ]; then
                echo "$dir ${files[*]}"
                return 0
            fi
        done
    done
    return 1
}

# Probe the granted file and its sibling in SHARED_DIR under both /lib and
# /usr/lib; $1 and $2 are the states required for each.
shared_probes() {
    local spelling id
    for spelling in /lib /usr/lib; do
        id=${spelling//\//_}
        probe "GRANTED$id" "$(same_bytes "$spelling/$SHARED_NAME/$GRANTED" "$GRANTED_SUM")" "$1"
        probe "SIBLING$id" "$(same_bytes "$spelling/$SHARED_NAME/$SIBLING" "$SIBLING_SUM")" "$2"
    done
}

run() {
    local name="$1" filesystem="$2" cwd="$3" process config marker
    shift 3
    process=$(printf '"commandLine":%s,"timeout":30000' "$(json "$PROBES")")
    if [ -n "$cwd" ]; then
        process+=",\"cwd\":$(json "$cwd")"
    fi
    config=$(printf '{"version":"1.0.0","containment":"bubblewrap","process":{%s},"filesystem":%s}' \
        "$process" "$filesystem")
    echo "Running Bubblewrap grant-alias test: $name..."
    if ! OUTPUT=$("$@" "$LXC_EXEC" --experimental --config-base64 "$(printf '%s' "$config" | base64 -w0)" 2>&1); then
        echo "$OUTPUT"
        fail "$name: the sandbox did not start."
    fi
    echo "$OUTPUT"
    for marker in "${MARKERS[@]}"; do
        grep -qFx "$marker" <<<"$OUTPUT" || fail "$name: expected $marker."
    done
    echo "PASS: $name"
    PROBES=
    MARKERS=()
}

refused() {
    local grant=$1 expected=$2 config output
    config=$(printf '{"version":"1.0.0","containment":"bubblewrap","process":{"commandLine":"echo GRANT_WORKLOAD_RAN"},"filesystem":{"readwritePaths":[%s]}}' \
        "$(json "$grant")")
    echo "Running Bubblewrap grant-alias test: unresolvable grant $grant..."
    if output=$("$LXC_EXEC" --experimental --config-base64 "$(printf '%s' "$config" | base64 -w0)" 2>&1); then
        echo "$output"
        fail "the sandbox started with the unresolvable grant $grant."
    fi
    echo "$output"
    if grep -qF GRANT_WORKLOAD_RAN <<<"$output"; then
        fail "the workload ran with the unresolvable grant $grant."
    fi
    grep -qF "$expected" <<<"$output" || fail "the refusal of $grant does not say: $expected"
    echo "PASS: unresolvable grant $grant"
}

host_holds() {
    [ "$(cat "$1" 2>/dev/null)" = "$2" ] || fail "host file $1 does not hold $2."
}

# /tmp is a private tmpfs in the sandbox, while the home directory has no
# covering mount, so the links are recreated in two kinds of location.
for parent in /tmp "$(cd "$HOME" && pwd -P)"; do
    make_root "$parent"
    R=$ROOT
    echo "Testing links under $R."

    probe READ_REAL "$(holds "$R/real/secret.txt" SECRET_CONTENT)" BLOCKED
    probe READ_ALIAS "$(holds "$R/alias/secret.txt" SECRET_CONTENT)" BLOCKED
    probe WRITE_ALIAS "$(accepts "$R/alias/secret.txt" MODIFIED_THROUGH_ALIAS)" BLOCKED
    probe WRITE_SIBLING "$(accepts "$R/alias/written.txt" WRITTEN_THROUGH_ALIAS)" OPEN
    probe CWD_IS_REAL "[ \"\$(pwd -P)\" = '$R/real' ]" OPEN
    probe WRITE_CWD "$(accepts cwd.txt WRITTEN_IN_CWD)" OPEN
    run "denied real path inside an aliased grant" \
        "{\"readwritePaths\":[$(json "$R/alias")],\"deniedPaths\":[$(json "$R/real/secret.txt")]}" \
        "$R/alias"
    host_holds "$R/real/secret.txt" SECRET_CONTENT
    host_holds "$R/real/written.txt" WRITTEN_THROUGH_ALIAS
    host_holds "$R/real/cwd.txt" WRITTEN_IN_CWD

    probe RO_REAL "$(accepts "$R/real/protected/hook" MODIFIED)" BLOCKED
    probe RO_ALIAS "$(accepts "$R/alias/protected/hook" MODIFIED_THROUGH_ALIAS)" BLOCKED
    probe RO_READ "$(holds "$R/alias/protected/hook" HOOK_CONTENT)" OPEN
    probe FILE_LINK_READ "$(holds "$R/hook-link" HOOK_CONTENT)" OPEN
    probe FILE_LINK_WRITE "$(accepts "$R/hook-link" MODIFIED_THROUGH_LINK)" BLOCKED
    run "read-only path inside an aliased grant" \
        "{\"readwritePaths\":[$(json "$R/alias")],\"readonlyPaths\":[$(json "$R/real/protected"),$(json "$R/hook-link")]}" \
        ""
    host_holds "$R/real/protected/hook" HOOK_CONTENT

    probe READ_ALIAS "$(holds "$R/alias/secret.txt" SECRET_CONTENT)" BLOCKED
    probe READ_REAL "$(holds "$R/real/secret.txt" SECRET_CONTENT)" BLOCKED
    probe WRITE_ALIAS "$(accepts "$R/alias/secret.txt" MODIFIED_THROUGH_ALIAS)" BLOCKED
    run "denied alias path inside an aliased grant" \
        "{\"readwritePaths\":[$(json "$R/alias")],\"deniedPaths\":[$(json "$R/alias/secret.txt")]}" \
        ""
    host_holds "$R/real/secret.txt" SECRET_CONTENT

    probe READ_CHAIN "$(holds "$R/chain/sub/secret.txt" SECRET_CONTENT)" BLOCKED
    probe READ_ALIAS "$(holds "$R/alias/sub/secret.txt" SECRET_CONTENT)" BLOCKED
    probe WRITE_CHAIN "$(accepts "$R/chain/sub/written.txt" WRITTEN_THROUGH_CHAIN)" OPEN
    run "denied path below a chain of links" \
        "{\"readwritePaths\":[$(json "$R/chain/sub")],\"deniedPaths\":[$(json "$R/real/sub/secret.txt")]}" \
        ""
    host_holds "$R/real/sub/secret.txt" SECRET_CONTENT
    host_holds "$R/real/sub/written.txt" WRITTEN_THROUGH_CHAIN

    probe READ_ALIAS "$(holds "$R/alias/secret.txt" SECRET_CONTENT)" BLOCKED
    probe WRITE_ALIAS "$(accepts "$R/alias/secret.txt" MODIFIED_THROUGH_ALIAS)" BLOCKED
    probe WRITE_SIBLING "$(accepts "$R/alias/visible.txt" WRITTEN_THROUGH_VISIBLE_LINK)" OPEN
    run "aliased grant whose link is inside another grant" \
        "{\"readwritePaths\":[$(json "$R"),$(json "$R/alias")],\"deniedPaths\":[$(json "$R/real/secret.txt")]}" \
        ""
    host_holds "$R/real/secret.txt" SECRET_CONTENT
    host_holds "$R/real/visible.txt" WRITTEN_THROUGH_VISIBLE_LINK
    [ "$(readlink "$R/alias")" = "$R/real" ] || fail "the host link $R/alias changed."

    probe OTHER "$(holds "$R/other.txt" OTHER_CONTENT)" BLOCKED
    probe WRITE_ALIAS "$(accepts "$R/alias/inside.txt" WRITTEN_INSIDE_MASK)" OPEN
    probe READ_REAL "$(holds "$R/real/secret.txt" SECRET_CONTENT)" OPEN
    run "aliased grant inside a denied directory" \
        "{\"readwritePaths\":[$(json "$R/alias")],\"deniedPaths\":[$(json "$R")]}" \
        ""
    host_holds "$R/real/inside.txt" WRITTEN_INSIDE_MASK

    mkdir -p "$R/work/sub/shared" "$R/work/shared"
    echo DECOY_CONTENT >"$R/work/sub/shared/m"
    echo SECRET_CONTENT >"$R/work/shared/m"
    echo VISIBLE_CONTENT >"$R/work/shared/ok"
    probe RELATIVE_GRANT "$(holds "$R/work/shared/ok" VISIBLE_CONTENT)" OPEN
    probe RELATIVE_DENIAL "$(holds "$R/work/shared/m" SECRET_CONTENT)" BLOCKED
    probe DECOY "$(holds "$R/work/sub/shared/m" DECOY_CONTENT)" BLOCKED
    run "relative paths from the directory lxc-exec starts in" \
        '{"readonlyPaths":["../shared"],"deniedPaths":["../shared/m"]}' \
        "" env -C "$R/work/sub"

    probe RELATIVE_DENIAL "$(holds "$R/work/shared/m" SECRET_CONTENT)" BLOCKED
    probe DECOY "$(holds "$R/work/sub/shared/m" DECOY_CONTENT)" OPEN
    run "relative denial inside an absolute grant" \
        "{\"readwritePaths\":[$(json "$R/work")],\"deniedPaths\":[\"../shared/m\"]}" \
        "" env -C "$R/work/sub"
done

ln -s "$R/missing" "$R/dangling"
ln -s loop "$R/loop"
refused "$R/dangling" "readwritePaths entry '$R/dangling' could not be resolved"
refused "$R/loop" "'$R/loop'"

if [ -L /lib ] && [ "$(readlink -f /lib)" = /usr/lib ]; then
    # A non-root test cannot create files under /usr/lib, so it borrows an
    # existing directory there.
    PROBE_FILES=$(probe_files)
    shared=$(pick_shared_dir) \
        || fail "found no directory under /usr/lib with two small readable files that is safe to deny."
    read -r SHARED_DIR GRANTED SIBLING <<<"$shared"
    SHARED_NAME=${SHARED_DIR#/usr/lib/}
    GRANTED_SUM=$(cksum <"$SHARED_DIR/$GRANTED")
    SIBLING_SUM=$(cksum <"$SHARED_DIR/$SIBLING")
    echo "Testing a grant through /lib in $SHARED_DIR: granting $GRANTED, hiding $SIBLING."

    shared_probes OPEN OPEN
    run "file granted through /lib with nothing denied" \
        "{\"readonlyPaths\":[$(json "/lib/$SHARED_NAME/$GRANTED")]}" ""
    for denied in "/lib/$SHARED_NAME" "$SHARED_DIR"; do
        shared_probes OPEN BLOCKED
        run "file granted through /lib inside denied $denied" \
            "{\"readonlyPaths\":[$(json "/lib/$SHARED_NAME/$GRANTED")],\"deniedPaths\":[$(json "$denied")]}" \
            ""
    done
else
    echo "NOTE: /lib is not a symlink to /usr/lib on this host; not testing grants through it."
fi

# An outer sandbox whose /tmp is a symlink to var/tmp, as some hosts have.
VAR_TMP=$(cd "$(mktemp -d "$(cd "$HOME" && pwd -P)/.mxc_bwrap_grant_alias_XXXXXX")" && pwd -P)
ROOTS+=("$VAR_TMP")
mkdir "$VAR_TMP/project"
echo SECRET_CONTENT >"$VAR_TMP/project/secret.txt"
OUTER=(bwrap --unshare-pid --die-with-parent --ro-bind /usr /usr --ro-bind /etc /etc
    --ro-bind "$LXC_EXEC" "$LXC_EXEC" --bind "$VAR_TMP" /var/tmp --symlink var/tmp /tmp
    --dev /dev --proc /proc)
for entry in /bin /sbin /lib /lib32 /lib64 /libx32; do
    if [ -L "$entry" ]; then
        OUTER+=(--symlink "$(readlink "$entry")" "$entry")
    elif [ -d "$entry" ]; then
        OUTER+=(--ro-bind "$entry" "$entry")
    fi
done
OUTER+=(--)
if ! "${OUTER[@]}" bwrap --ro-bind / / true >/dev/null 2>&1; then
    echo "SKIP: this host cannot run bwrap inside bwrap, so the symlinked /tmp cases did not run."
    exit 77
fi

probe CWD_IS_REAL "[ \"\$(pwd -P)\" = /var/tmp/project ]" OPEN
probe WRITE_TMP "$(accepts /tmp/project/written.txt WRITTEN_THROUGH_TMP)" OPEN
probe READ_TMP "$(holds /tmp/project/secret.txt SECRET_CONTENT)" BLOCKED
probe READ_VAR_TMP "$(holds /var/tmp/project/secret.txt SECRET_CONTENT)" BLOCKED
run "grant and cwd below a symlinked /tmp" \
    '{"readwritePaths":["/tmp/project"],"deniedPaths":["/tmp/project/secret.txt"]}' \
    /tmp/project "${OUTER[@]}"
host_holds "$VAR_TMP/project/written.txt" WRITTEN_THROUGH_TMP
host_holds "$VAR_TMP/project/secret.txt" SECRET_CONTENT

probe WRITE_VAR_TMP "$(accepts /var/tmp/whole.txt WRITTEN_TO_VAR_TMP)" OPEN
run "grant of a symlinked /tmp itself" '{"readwritePaths":["/tmp"]}' "" "${OUTER[@]}"
if ! grep -qF "named through the symlink /tmp, which cannot be recreated" <<<"$OUTPUT" \
    || ! grep -qF "Use /var/tmp instead." <<<"$OUTPUT"; then
    fail "granting a symlinked /tmp did not warn that /tmp is unavailable in the sandbox."
fi
host_holds "$VAR_TMP/whole.txt" WRITTEN_TO_VAR_TMP

echo "Bubblewrap grant-alias test complete."
