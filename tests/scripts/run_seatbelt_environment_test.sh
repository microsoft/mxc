#!/bin/bash
# Seatbelt process environment.
#
# The headline guarantee is that the host environment is never inherited: it is
# what stops a cloud credential or API token in the operator's shell from
# reaching untrusted code. It is unconditional, so it is asserted with a probe
# variable exported by this script rather than by any config.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/seatbelt_common.sh
. "$SCRIPT_DIR/lib/seatbelt_common.sh"

export MXC_LEAK_PROBE="SEATBELT_HOST_ENV_LEAKED"

run_config "$(render seatbelt_env_no_inherit.json)"
expect_ok "the sandbox runs with a cleared environment" "ENV_PROBE_DONE"
expect_absent "a host environment variable does not leak in" "SEATBELT_HOST_ENV_LEAKED"
expect_marker "the probe variable is empty inside the sandbox" "LEAK=[]"

run_config "$(render seatbelt_env_default_path.json)"
expect_ok "PATH defaults to the documented value" "PATH=[/usr/bin:/bin:/usr/sbin:/sbin]"

run_config "$(render seatbelt_env_home_unset.json)"
expect_ok "HOME is unset unless passed" "HOME=[]"
# The doc says `~` expands to an empty string; sh actually yields "/" with HOME
# unset. Either way it is not a usable home directory, which is the point.
grep -qF "TILDE=[$HOME]" <<<"$OUT" && fail "the host HOME leaked through ~ expansion" "$OUT"
pass "~ does not expand to the host home directory"

run_config "$(render seatbelt_env_custom.json)"
expect_ok "process.env supplies a variable" "MYVAR=[hello]"
expect_ok "process.env overrides the default PATH" "PATH=[/custom/bin:/usr/bin:/bin]"
expect_ok "process.env can supply HOME" "HOME=[/private/tmp]"

# Schema 0.9 gave `process.env` a four-state contract against a default block
# of PATH + HOME + TERM. The assertions above pin the pre-0.9 behavior, which
# stays as it was.
#
# The cases below that supply no PATH assert HOME rather than PATH or TERM.
# macOS `/bin/sh` assigns its own PATH (`/usr/gnu/bin:/usr/local/bin:...`) and
# its own `TERM=dumb` when it starts without them, so neither reports what MXC
# passed. HOME is not fabricated, so it is what witnesses the default block --
# and the leak probe distinguishes a fabricated value from an inherited one.
# Where a case must still show the default block was not added, it asserts the
# block's own TERM value is absent, which no shell fabricates.
# That `resolved_env` is exactly empty is asserted directly by
# `an_explicitly_empty_env_stays_empty` / `a_supplied_env_is_used_verbatim` in
# `default_env.rs`, which reads the env MXC builds instead of the child's.

run_config "$(render seatbelt_env_09_default_block.json)"
expect_ok "0.9: an omitted env gets the default PATH" "PATH=[/usr/bin:/bin:/usr/sbin:/sbin]"
expect_ok "0.9: an omitted env gets HOME" "HOME=[/private/tmp]"
expect_ok "0.9: an omitted env gets TERM" "TERM=[xterm-256color]"
expect_marker "0.9: a host environment variable does not leak in" "LEAK=[]"
expect_absent "0.9: the host value itself does not appear" "SEATBELT_HOST_ENV_LEAKED"

# No `process.cwd` and no policy path resolves no directory, so no HOME.
run_config "$(render seatbelt_env_09_no_cwd.json)"
expect_ok "0.9: an unresolved working directory leaves HOME unset" "HOME=[]"
expect_ok "0.9: the rest of the default block still applies" "PATH=[/usr/bin:/bin:/usr/sbin:/sbin]"
expect_marker "0.9: an unset HOME is not the host's" "LEAK=[]"

run_config "$(render seatbelt_env_09_empty.json)"
expect_ok "0.9: an empty env runs" "ENV_PROBE_DONE"
expect_ok "0.9: an empty env suppresses HOME" "HOME=[]"
expect_absent "0.9: an empty env adds no default TERM" "TERM=[xterm-256color]"
expect_marker "0.9: an empty env inherits nothing from the host" "LEAK=[]"

run_config "$(render seatbelt_env_09_verbatim.json)"
expect_ok "0.9: a supplied env is honored" "FOO=[bar]"
expect_ok "0.9: a supplied env adds no default HOME" "HOME=[]"
expect_absent "0.9: a supplied env adds no default TERM" "TERM=[xterm-256color]"
expect_marker "0.9: a supplied env inherits nothing from the host" "LEAK=[]"
# A supplied PATH replaces the default block's PATH outright rather than being
# merged with it, so no fragment of the default survives.
expect_ok "0.9: a supplied PATH is used verbatim" "PATH=[/mxc-probe/bin:/usr/bin:/bin]"
expect_absent "0.9: a supplied PATH is not merged with the default" "PATH=[/usr/bin:/bin:/usr/sbin:/sbin"

run_config "$(render seatbelt_env_09_inherit.json)"
expect_ok "0.9: inheritDefaultEnv keeps the default PATH" "PATH=[/usr/bin:/bin:/usr/sbin:/sbin]"
expect_ok "0.9: inheritDefaultEnv keeps the default HOME" "HOME=[/private/tmp]"
expect_ok "0.9: inheritDefaultEnv adds the caller's variable" "FOO=[bar]"
expect_ok "0.9: a caller entry overrides the same-named default" "TERM=[vt100]"

summary "Seatbelt environment"
