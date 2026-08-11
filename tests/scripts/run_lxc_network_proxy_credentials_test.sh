#!/bin/bash
# LXC credentialed-proxy rejection test.
#
# Proves, from the outside, that a proxy URL carrying inline credentials is
# refused rather than handed to `lxc-attach`, and that refusing it does not
# itself print the secret.
#
# Cause  : tests/configs/lxc_network_proxy_credentials_rejected.json — an
#          otherwise valid LXC request whose network.proxy.url embeds
#          `alice:hunter2`.
# Effect : lxc-exec exits non-zero, names the credential rule, and neither the
#          password nor the username appears anywhere in its output. The
#          container's command line is never reached.
#
# Why the secret matters more than the exit code: LXC passes the proxy URL to
# `lxc-attach` as `--set-var`, and process arguments are world-readable through
# /proc/<pid>/cmdline. A rejection that echoed the URL back verbatim would leak
# the same secret it just refused to accept, so the redaction is asserted as
# its own observable.
#
# Unlike the other LXC network tests, this one needs no root, no LXC, no
# bridge, and no network: the rule is enforced while the configuration is
# parsed, before any container is created. Only the built binary is required,
# so this runs on any Linux host and is skipped only when the binary is absent.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
CONFIG="$REPO_DIR/tests/configs/lxc_network_proxy_credentials_rejected.json"

# Drift guard: these mirror the fixture. A fixture edited to drop the
# credentials would make every assertion below vacuous -- the run would exit
# non-zero for some unrelated reason, or succeed -- so the fixture is checked
# against them first.
#
# Do not run this script under `set -x`. Tracing prints every expansion,
# including these two values and the captured output, which defeats the
# withholding below. The workflow does not enable it.
EXPECTED_USERNAME="alice"
EXPECTED_PASSWORD="hunter2"
EXPECTED_PROXY_URL="http://alice:hunter2@10.0.3.1:3128"

fail() {
    echo "FAIL: $*"
    exit 1
}

# ---------------------------------------------------------------------------
# Always-run assertions: the fixture must exist and still carry the credentials
# this test is about.
# ---------------------------------------------------------------------------
[ -f "$CONFIG" ] || fail "fixture not found: $CONFIG"

read_json_field() {
    # $1 = dotted path under the JSON root (python) ; prints the value.
    local path="$1"
    if command -v python3 >/dev/null 2>&1; then
        python3 - "$CONFIG" "$path" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1]))
cur = doc
for key in sys.argv[2].split("."):
    cur = cur[key]
print(cur)
PY
    else
        # Fallback for hosts without python3: grep the leaf key. Works because
        # the fixture keeps these on one line with simple string values.
        local leaf="${path##*.}"
        grep -o "\"$leaf\"[[:space:]]*:[[:space:]]*\"[^\"]*\"" "$CONFIG" \
            | head -1 | sed 's/.*:[[:space:]]*"\([^"]*\)".*/\1/'
    fi
}

actual_url="$(read_json_field network.proxy.url)"
if [ "$actual_url" != "$EXPECTED_PROXY_URL" ]; then
    # Naming either URL here would publish the password on exactly the failure
    # that says this fixture can no longer be trusted, so the mismatch is
    # described rather than quoted.
    if echo "$actual_url" | grep -qF "@"; then
        drift_detail="it still carries userinfo, but not the pair this test asserts"
    else
        drift_detail="it carries no userinfo at all, so every assertion below would be vacuous"
    fi
    fail "fixture proxy.url changed; both values withheld because they carry credentials -- $drift_detail"
fi
echo "Fixture drift guard passed (proxy.url carries inline credentials)."

# ---------------------------------------------------------------------------
# Conditional assertion: the live rejection. Only the binary is a prerequisite.
# ---------------------------------------------------------------------------
SKIP_EXIT=77

skip_live() {
    echo "SKIP: credentialed-proxy rejection UNVERIFIED — $*"
    echo "      (fixture drift guard still ran and passed)"
    exit "$SKIP_EXIT"
}

LXC_EXEC="$REPO_DIR/src/target/release/lxc-exec"
[ -f "$LXC_EXEC" ] || LXC_EXEC="$REPO_DIR/src/target/debug/lxc-exec"
[ -f "$LXC_EXEC" ] || skip_live "lxc-exec not built (run build.sh first)"

# Which binary, and how old. `release` is preferred, so a stale one left over
# from before this rule existed is picked ahead of a freshly built `debug` --
# and it fails exactly as a genuine regression would, because a binary without
# the rule really does accept the URL. Naming the artifact turns that hour of
# hunting a phantom regression into one line.
echo "Using $LXC_EXEC (built $(date -r "$LXC_EXEC" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo 'unknown'))."

OUT="$("$LXC_EXEC" "$CONFIG" 2>&1)"
STATUS=$?

# Publishing the capture helps diagnose every failure except the one this test
# exists to catch. On that one the capture *is* the secret, so echoing it first
# would publish the password to the CI log before the assertion below could
# fail the run -- the test would leak what it is guarding. Withhold it in that
# case; the assertions still name what went wrong.
if echo "$OUT" | grep -qF "$EXPECTED_PASSWORD" || echo "$OUT" | grep -qF "$EXPECTED_USERNAME"; then
    echo "--- lxc-exec output WITHHELD: it contains a credential ---"
else
    echo "--- lxc-exec output ---"
    echo "$OUT"
    echo "-----------------------"
fi

# The request must be refused. A zero exit means the credentialed URL was
# accepted, which is the whole defect.
[ "$STATUS" -ne 0 ] \
    || fail "lxc-exec accepted a proxy URL carrying credentials (exit 0). If this is
      unexpected, check that $LXC_EXEC is current -- a binary built before this
      rule existed fails here in exactly the same way as a regression."

# Refused for the right reason, not by coincidence. Without this, a fixture
# broken in some unrelated way would still pass the exit-code check.
echo "$OUT" | grep -qi "must not carry credentials" \
    || fail "rejected, but not for carrying credentials"

# The rejection must not become the leak it is rejecting.
if echo "$OUT" | grep -qF "$EXPECTED_PASSWORD"; then
    fail "the proxy password appeared in lxc-exec output"
fi
if echo "$OUT" | grep -qF "$EXPECTED_USERNAME"; then
    fail "the proxy username appeared in lxc-exec output"
fi

# The redacted host must survive, or the message names no URL at all and gives
# the operator nothing to act on.
echo "$OUT" | grep -qF "10.0.3.1:3128" \
    || fail "the rejection redacted the host as well as the credentials"

# The process must never have started.
if echo "$OUT" | grep -qF "THIS_MUST_NEVER_RUN"; then
    fail "the container command ran despite the rejected proxy URL"
fi

echo "PASS: credentialed proxy URL refused, secret not echoed, command never ran."
