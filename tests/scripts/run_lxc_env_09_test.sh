#!/bin/bash
# LXC process environment, schema 0.9.
#
# `lxc-exec` always passes `--clear-env`, so the host environment never reaches
# the container. Schema 0.9 adds a default block on top of the small baseline
# `lxc-attach` injects, and gives `process.env` a four-state contract; this
# asserts all four. `run_lxc_env_cwd_test.sh` covers the pre-0.9 plumbing.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
CONFIG_DIR="$REPO_DIR/tests/configs"
LXC_EXEC="$REPO_DIR/src/target/release/lxc-exec"

if [ ! -f "$LXC_EXEC" ]; then
    LXC_EXEC="$REPO_DIR/src/target/debug/lxc-exec"
fi

if [ ! -f "$LXC_EXEC" ]; then
    echo "Error: lxc-exec not found. Run build.sh first."
    exit 1
fi

PASS_COUNT=0
OUT=""
RC=0

fail() {
    echo "FAIL: $1"
    [ $# -gt 1 ] && echo "--- output ---" && echo "$2" && echo "--------------"
    exit 1
}

pass() {
    echo "PASS: $1"
    PASS_COUNT=$((PASS_COUNT + 1))
}

run_config() {
    RC=0
    OUT=$("$LXC_EXEC" "$CONFIG_DIR/$1" 2>&1) || RC=$?
}

expect_ok() {
    local label="$1" marker="$2"
    [ "$RC" = 0 ] || fail "$label (exit $RC, expected 0)" "$OUT"
    grep -qF "$marker" <<<"$OUT" || fail "$label (missing '$marker')" "$OUT"
    pass "$label"
}

expect_absent() {
    local label="$1" marker="$2"
    ! grep -qF "$marker" <<<"$OUT" || fail "$label (unexpected '$marker')" "$OUT"
    pass "$label"
}

DEFAULT_PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

# Exported here rather than set by a config: `--clear-env` is unconditional, so
# it must hold for a request that never mentions the variable.
export MXC_LEAK_PROBE="LXC_HOST_ENV_LEAKED"

# PATH is only ever asserted absent-or-default where the container's own
# baseline cannot fabricate the answer. `lxc-attach` injects its own baseline
# PATH into every process it attaches -- and that baseline is byte-for-byte
# DEFAULT_PATH -- so the container always reports one whether or not MXC
# supplied it. HOME and TERM are not injected, so they are what witnesses the
# default block. The one PATH claim that IS provable is replacement: liblxc
# applies MXC's `--set-var` entries last, via `putenv`, so a supplied PATH must
# appear verbatim with no trace of the baseline (asserted below). That
# `resolved_env` is exactly empty is asserted directly by
# `an_explicitly_empty_env_stays_empty` / `a_supplied_env_is_used_verbatim` in
# `lxc_runner.rs`, which reads the env MXC builds instead of the container's.

run_config lxc_env_09_default_block.json
expect_ok "an omitted env gets the default PATH" "PATH=[$DEFAULT_PATH]"
expect_ok "an omitted env gets HOME" "HOME=[/tmp]"
expect_ok "an omitted env gets TERM" "TERM=[xterm-256color]"
expect_ok "a host environment variable does not leak in" "LEAK=[]"
expect_absent "the host value itself does not appear" "LXC_HOST_ENV_LEAKED"

# No `process.cwd` resolves no directory, so no HOME -- a policy grant can bind
# a host path over the container's /tmp, and a reused container keeps its own.
run_config lxc_env_09_no_cwd.json
expect_ok "an unresolved working directory leaves HOME unset" "HOME=[]"
expect_ok "the rest of the default block still applies" "PATH=[$DEFAULT_PATH]"
expect_ok "an unset HOME is not the host's" "LEAK=[]"

# Unlike bwrap and Seatbelt, an empty env is not a wholly empty environment:
# `lxc-attach` injects its own baseline under everything MXC supplies. What
# 0.9 guarantees is that MXC adds nothing on top of it.
run_config lxc_env_09_empty.json
expect_ok "an empty env runs" "ENV_PROBE_DONE"
expect_ok "an empty env suppresses the default HOME" "HOME=[]"
expect_ok "an empty env suppresses the default TERM" "TERM=[]"
expect_ok "an empty env inherits nothing from the host" "LEAK=[]"

run_config lxc_env_09_verbatim.json
expect_ok "a supplied env is honored" "FOO=[bar]"
expect_ok "a supplied env adds no default HOME" "HOME=[]"
expect_ok "a supplied env adds no default TERM" "TERM=[]"
# A supplied PATH replaces the `lxc-attach` baseline outright rather than being
# appended to it, so neither the baseline nor any fragment of it survives.
expect_ok "a supplied PATH is used verbatim" "PATH=[/mxc-probe/bin:/usr/bin:/bin]"
expect_absent "a supplied PATH is not appended to the baseline" "PATH=[$DEFAULT_PATH"

run_config lxc_env_09_inherit.json
expect_ok "inheritDefaultEnv keeps the default PATH" "PATH=[$DEFAULT_PATH]"
expect_ok "inheritDefaultEnv keeps the default HOME" "HOME=[/tmp]"
expect_ok "inheritDefaultEnv adds the caller's variable" "FOO=[bar]"
expect_ok "a caller entry overrides the same-named default" "TERM=[vt100]"

echo "All $PASS_COUNT LXC environment assertions passed."
