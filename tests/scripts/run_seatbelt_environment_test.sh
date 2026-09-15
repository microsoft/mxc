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

run_config "$(render seatbelt_env_09_default_block.json)"
expect_ok "0.9: an omitted env gets the default PATH" "PATH=[/usr/bin:/bin:/usr/sbin:/sbin]"
expect_ok "0.9: an omitted env gets HOME" "HOME=[/tmp]"
expect_ok "0.9: an omitted env gets TERM" "TERM=[xterm-256color]"

run_config "$(render seatbelt_env_09_empty.json)"
expect_ok "0.9: an empty env runs" "ENV_PROBE_DONE"
expect_ok "0.9: an empty env suppresses the default PATH" "PATH=[]"
expect_ok "0.9: an empty env suppresses HOME" "HOME=[]"
expect_ok "0.9: an empty env suppresses TERM" "TERM=[]"

run_config "$(render seatbelt_env_09_verbatim.json)"
expect_ok "0.9: a supplied env is honored" "FOO=[bar]"
expect_ok "0.9: a supplied env is verbatim, with no implicit PATH" "PATH=[]"

run_config "$(render seatbelt_env_09_inherit.json)"
expect_ok "0.9: inheritDefaultEnv keeps the default PATH" "PATH=[/usr/bin:/bin:/usr/sbin:/sbin]"
expect_ok "0.9: inheritDefaultEnv keeps the default HOME" "HOME=[/tmp]"
expect_ok "0.9: inheritDefaultEnv adds the caller's variable" "FOO=[bar]"
expect_ok "0.9: a caller entry overrides the same-named default" "TERM=[dumb]"

summary "Seatbelt environment"
