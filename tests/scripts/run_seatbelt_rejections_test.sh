#!/bin/bash
# Seatbelt policy rejections.
#
# Every case here is a config MXC must refuse rather than approximate, per the
# "What gets rejected" table in docs/backends/seatbelt/seatbelt-backend.md. Each asserts
# both that the run failed and that the workload never started: a policy that
# is "enforced" by the command failing afterwards is not enforcement.
#
# Rejections resolve during validation, so this suite needs no network, no
# fixtures and no privilege.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/seatbelt_common.sh
. "$SCRIPT_DIR/lib/seatbelt_common.sh"

S="REJECT_SHOULD_NOT_RUN"

# --- Network: no per-host / per-CIDR filtering primitive exists -------------

expect_rejected "non-empty egress.allow rules are refused" \
    "seatbelt_reject_egress_allow_rules.json" \
    "network.egress allow/deny rules are not supported" "$S"

expect_rejected "non-empty egress.deny rules are refused" \
    "seatbelt_reject_egress_deny_rules.json" \
    "network.egress allow/deny rules are not supported" "$S"

# --- Network: the inbound half of hostLoopback is not expressible -----------

expect_rejected "hostLoopback=allow under ingress.default=deny is refused" \
    "seatbelt_reject_hostloopback_mismatch.json" \
    "cannot enforce network.ingress.hostLoopback" "$S"

# --- Proxy ------------------------------------------------------------------

# Outbound is already open, so the proxy would enforce nothing and traffic
# could bypass it silently.
expect_rejected "a runtime proxy under egress.default=allow is refused" \
    "seatbelt_reject_proxy_with_egress_allow.json" \
    "requires network.egress.default='deny'" "$S"

expect_rejected "a non-loopback runtime proxy endpoint is refused" \
    "seatbelt_reject_proxy_remote_host.json" \
    "must use localhost, 127.0.0.1, or [::1]" "$S"

# Documented as rejected because peer identity pinning is unsupported. In
# practice the shared multi-backend guard fires first, since processContainer
# is another backend's section -- refused either way, but not for the reason
# the Seatbelt doc gives.
expect_rejected "processContainer.network.allowedProxyPeer is refused" \
    "seatbelt_reject_allowed_proxy_peer.json" \
    "Multiple containment backends configured" "$S"

# --- GUI --------------------------------------------------------------------

# The GUI rules are only emitted when UI is enabled, so accepting this would
# drop the request without a word.
expect_rejected "guiAccess=true with ui.disable=true is refused" \
    "seatbelt_reject_gui_with_ui_disabled.json" \
    "guiAccess=true cannot be combined with ui.disable=true" "$S"

expect_rejected "guiAccess=true with no ui section is refused" \
    "seatbelt_reject_gui_without_ui_section.json" \
    "guiAccess=true cannot be combined with ui.disable=true" "$S"

summary "Seatbelt rejections"
