#!/bin/bash
# Seatbelt captureDenials (learning mode) and the mxc-exec-mac --audit shortcut.
#
# Each mode is checked against the workload's own result as well as the
# report, so a report that lists the read cannot hide a mode that stopped
# changing enforcement.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/seatbelt_common.sh
. "$SCRIPT_DIR/lib/seatbelt_common.sh"

[ -x /usr/bin/python3 ] || fail "/usr/bin/python3 is required to read the reports"

# Under /private/tmp so the logged path matches what we assert on (/tmp is a
# symlink). No config grants this directory, so the read is a default deny.
TESTDIR="$(mktemp -d /private/tmp/mxc-seatbelt-capture.XXXXXX)"
LISTENER_PID=""
cleanup_capture() {
    if [ -n "$LISTENER_PID" ]; then
        kill "$LISTENER_PID" 2>/dev/null || true
        wait "$LISTENER_PID" 2>/dev/null || true
    fi
    rm -rf "$TESTDIR" "$SEATBELT_TMP"
}
trap cleanup_capture EXIT
mkdir -p "$TESTDIR/ungranted" "$TESTDIR/denied" "$TESTDIR/out"
echo "CAPTURE_SECRET_CONTENT" >"$TESTDIR/ungranted/secret.txt"
echo "CAPTURE_DENIED_CONTENT" >"$TESTDIR/denied/secret.txt"
chmod -R a+rX "$TESTDIR"
SECRET="$TESTDIR/ungranted/secret.txt"

# Report path from the pointer line mxc-exec-mac prints on stderr.
REPORT=""
read_pointer() {
    local label="$1" line
    line="$(grep -m1 '^{"type":"captureDenials"' <<<"$OUT")" ||
        fail "$label (no captureDenials pointer line)" "$OUT"
    REPORT="$(/usr/bin/python3 -c 'import json,sys; print(json.loads(sys.argv[1])["outputPath"])' "$line")" ||
        fail "$label (unreadable pointer line)" "$OUT"
    [ -f "$REPORT" ] || fail "$label (report $REPORT was not written)" "$OUT"
    pass "$label"
}

# Assert the report lists RESOURCE with the given type and access.
expect_listed() {
    local label="$1" type="$2" resource="$3" access="$4"
    /usr/bin/python3 - "$REPORT" "$type" "$resource" "$access" <<'EOF' ||
import json, sys
path, rtype, resource, access = sys.argv[1:]
doc = json.load(open(path))
sys.exit(0 if any(
    d["resourceType"] == rtype and d["resource"] == resource and d["accessType"] == access
    for d in doc["denials"]) else 1)
EOF
        fail "$label (no $type/$access entry for $resource)" "$(cat "$REPORT")"
    pass "$label"
}

# --- block mode (the default) -----------------------------------------------

run_config "$(render seatbelt_capture_denials_block.json TESTDIR "$TESTDIR" OUTPUT "$TESTDIR/out/denials.json")"
expect_ok "block mode still enforces the policy" "CAPTURE_READ_BLOCKED"
expect_absent "block mode does not leak the file" "CAPTURE_SECRET_CONTENT"
expect_marker "block mode preserves unterminated workload stderr" "CAPTURE_STDERR_UNTERMINATED"
read_pointer "block mode separates the report pointer from unterminated stderr"
expect_listed "block mode lists the denied read" file "$SECRET" read

case "$REPORT" in
    "$TESTDIR/out/denials."*.json) pass "the report name gets a per-run identifier" ;;
    *) fail "the report was not written next to outputPath with a run identifier: $REPORT" ;;
esac

VERBOSE="${REPORT%.json}.verbose.json"
[ -f "$VERBOSE" ] || fail "the verbose report was not written: $VERBOSE"
/usr/bin/python3 - "$VERBOSE" <<'EOF' || fail "the verbose report is not a v6 seatbelt document" "$(head -c 2000 "$VERBOSE")"
import json, sys
doc = json.load(open(sys.argv[1]))
assert doc["version"] == 6
assert doc["signatures"]
assert all(s["signature"]["provider"] == "seatbelt" for s in doc["signatures"])
EOF
pass "the verbose report is a v6 seatbelt document"

# --- allow mode --------------------------------------------------------------

run_config "$(render seatbelt_capture_denials_allow.json TESTDIR "$TESTDIR" OUTPUT "$TESTDIR/out/denials.json")"
expect_ok "allow mode lets the default-denied read through" "CAPTURE_SECRET_CONTENT"
expect_ok "allow mode still blocks an explicitly denied read" "CAPTURE_EXPLICIT_READ_BLOCKED"
expect_absent "allow mode does not leak an explicitly denied file" "CAPTURE_DENIED_CONTENT"
expect_marker "allow mode warns that the policy was not enforced" "ran the workload without enforcing"
read_pointer "allow mode writes a report"
expect_listed "allow mode still lists the read" file "$SECRET" read
expect_listed "allow mode lists the explicitly denied read" file "$TESTDIR/denied/secret.txt" read

# --- repeated captures with an extensionless outputPath ----------------------

PREVIOUS_REPORT=""
for run in 1 2; do
    run_config "$(render seatbelt_capture_denials_block.json TESTDIR "$TESTDIR" OUTPUT "$TESTDIR/out/extensionless")"
    expect_ok "extensionless capture $run still enforces the policy" "CAPTURE_READ_BLOCKED"
    read_pointer "extensionless capture $run writes a report"
    expect_listed "extensionless capture $run lists the denied read" file "$SECRET" read
    case "$REPORT" in
        "$TESTDIR/out/extensionless."*.json) ;;
        *) fail "extensionless capture did not get a per-run JSON name: $REPORT" ;;
    esac
    [ -f "${REPORT%.json}.verbose.json" ] || fail "extensionless capture has no verbose report: $REPORT"
    if [ -n "$PREVIOUS_REPORT" ]; then
        [ "$REPORT" != "$PREVIOUS_REPORT" ] || fail "repeated captures reused a report path: $REPORT"
        [ -f "$PREVIOUS_REPORT" ] && [ -f "${PREVIOUS_REPORT%.json}.verbose.json" ] ||
            fail "repeated capture removed the previous report pair"
    fi
    PREVIOUS_REPORT="$REPORT"
done
pass "repeated extensionless captures keep distinct report pairs"

# --- --audit -----------------------------------------------------------------

run_config "$(render seatbelt_capture_denials_audit.json TESTDIR "$TESTDIR")" --audit
expect_ok "--audit runs the workload in allow mode" "CAPTURE_SECRET_CONTENT"
read_pointer "--audit writes a report"
expect_listed "--audit lists the read" file "$SECRET" read
rm -f "$REPORT" "${REPORT%.json}.verbose.json"

# --- timeout plus report-write failure --------------------------------------

mkdir "$TESTDIR/timeout-out"
run_config "$(render seatbelt_capture_denials_timeout.json TESTDIR "$TESTDIR")"
[ "$RC" != 0 ] || fail "timeout plus capture failure must fail" "$OUT"
expect_marker "the workload removed the report directory before timing out" "CAPTURE_OUTPUT_REMOVED"
expect_absent "a failed capture does not emit a success pointer" '"type":"captureDenials"'
ERROR_LINE="$(grep -m1 '^{"error":' <<<"$OUT")" || fail "timeout has no error envelope" "$OUT"
/usr/bin/python3 - "$ERROR_LINE" "$TESTDIR/timeout-out" <<'EOF' || fail "timeout lost the capture-write diagnostic" "$OUT"
import json, sys
error = json.loads(sys.argv[1])["error"]
assert error["code"] == "backend_error"
assert "script timed out after 1000ms" in error["message"]
assert "captureDenials teardown also failed:" in error["message"]
assert "failed to create temporary actionable output file" in error["message"]
assert sys.argv[2] in error["message"]
EOF
pass "timeout preserves the capture-write diagnostic in the CLI error"

# --- allow-mode host-loopback policy and proxy exception ---------------------

require_python3_probe
/usr/bin/python3 -c '
import socket, time
listeners = [socket.socket(), socket.socket()]
for listener in listeners:
    listener.bind(("127.0.0.1", 0))
    listener.listen(16)
print(*(listener.getsockname()[1] for listener in listeners), flush=True)
time.sleep(600)
' >"$TESTDIR/ports" &
LISTENER_PID=$!
for _ in $(seq 1 50); do
    if [ -s "$TESTDIR/ports" ]; then
        read -r PORT PROXY_PORT <"$TESTDIR/ports"
        break
    fi
    kill -0 "$LISTENER_PID" 2>/dev/null || fail "capture network listeners exited"
    sleep 0.1
done
[ -n "${PORT:-}" ] && [ -n "${PROXY_PORT:-}" ] || fail "capture network listeners did not publish their ports"
/usr/bin/python3 - "$PORT" "$PROXY_PORT" <<'EOF' || fail "host cannot reach the capture network listeners"
import socket, sys
for port in sys.argv[1:]:
    socket.create_connection(("127.0.0.1", int(port)), timeout=2).close()
EOF
pass "both host loopback listeners are reachable before capture"

for scenario in deny allow proxy; do
    config="$(render seatbelt_capture_denials_network.json PORT "$PORT" PROXY_PORT "$PROXY_PORT" OUTPUT "$TESTDIR/out/network.json")"
    /usr/bin/python3 - "$config" "$scenario" "$PROXY_PORT" <<'EOF' || fail "could not prepare network capture config"
import json, sys
path, scenario, port = sys.argv[1:]
with open(path) as source:
    config = json.load(source)
if scenario == "allow":
    config["network"]["ingress"]["hostLoopback"] = "allow"
elif scenario == "proxy":
    config["runtimeConfig"] = {"networkProxy": f"http://127.0.0.1:{port}"}
with open(path, "w") as output:
    json.dump(config, output)
EOF
    run_config "$config"
    case "$scenario" in
        deny)
            expect_ok "allow mode enforces hostLoopback=deny" "LOOPBACK_BLOCKED"
            expect_marker "hostLoopback=deny blocks the second host port" "PROXY_BLOCKED"
            ;;
        allow)
            expect_ok "allow mode preserves an explicit host-loopback grant" "LOOPBACK_OK"
            expect_marker "the loopback grant reaches both host ports" "PROXY_OK"
            ;;
        proxy)
            expect_ok "allow mode keeps non-proxy host ports blocked" "LOOPBACK_BLOCKED"
            expect_marker "the configured proxy port remains reachable" "PROXY_OK"
            ;;
    esac
    read_pointer "$scenario loopback capture writes a report"
    /usr/bin/python3 - "$REPORT" "$scenario" "$PORT" "$PROXY_PORT" <<'EOF' || fail "$scenario loopback report misclassifies blocked or granted connections" "$(cat "$REPORT")"
import json, sys
path, scenario, host_port, proxy_port = sys.argv[1:]
with open(path) as source:
    denials = json.load(source)["denials"]
for port, blocked in [(host_port, scenario != "allow"), (proxy_port, scenario == "deny")]:
    listed = any(d["resourceType"] == "network"
                 and d["resource"] == f"network-outbound:remote:*:{port}" for d in denials)
    assert listed == blocked, (port, blocked, denials)
EOF
    pass "$scenario loopback capture reports denied connections, not explicit grants"
done

# --- UI denials under guiAccess ---------------------------------------------

# ui.clipboard=none must survive the guiAccess blanket Mach grant, and the
# report must attribute the blocked pasteboard to UI rather than "other".
for scenario in allow:all block:none allow:none; do
    mode="${scenario%:*}"
    clipboard="${scenario#*:}"
    config="$(render seatbelt_capture_denials_gui_clipboard_none.json OUTPUT "$TESTDIR/out/clipboard.json")"
    /usr/bin/python3 - "$config" "$mode" "$clipboard" <<'EOF' || fail "could not prepare clipboard capture config"
import json, sys
path, mode, clipboard = sys.argv[1:]
with open(path) as source:
    config = json.load(source)
config["seatbelt"]["captureDenials"]["mode"] = mode
config["ui"]["clipboard"] = clipboard
with open(path, "w") as output:
    json.dump(config, output)
EOF
    run_config "$config"
    if [ "$clipboard" = all ]; then
        expect_ok "allow mode permits the pasteboard when granted under guiAccess" "CLIPBOARD_OK"
        read_pointer "the allowed pasteboard control writes a report"
        continue
    fi
    expect_ok "$mode mode keeps the pasteboard blocked under guiAccess" "CLIPBOARD_BLOCKED"
    read_pointer "$mode mode with guiAccess writes a report"
    /usr/bin/python3 - "$REPORT" <<'EOF' || fail "$mode mode pasteboard denial is not reported as ui" "$(cat "$REPORT")"
import json, sys
doc = json.load(open(sys.argv[1]))
assert any(d["resourceType"] == "ui" and "com.apple.pasteboard" in d["resource"]
           for d in doc["denials"])
EOF
    pass "$mode mode pasteboard denial is reported as ui"
done

# --- a real GUI app: which Mach services and IOKit drivers it needs ----------

# A minimal AppKit app (JavaScript for Automation) that opens a window. Only
# services every Mac has, VMs included, are asserted; the reports list more.
mkdir -p "$TESTDIR/app"
cat >"$TESTDIR/app/window.js" <<'EOF'
ObjC.import('AppKit');
var app = $.NSApplication.sharedApplication;
app.setActivationPolicy($.NSApplicationActivationPolicyAccessory);
var w = $.NSWindow.alloc.initWithContentRectStyleMaskBackingDefer(
    $.NSMakeRect(0, 0, 200, 100), $.NSWindowStyleMaskTitled, $.NSBackingStoreBuffered, false);
w.orderFrontRegardless;
w.display;
$.NSRunLoop.currentRunLoop.runUntilDate($.NSDate.dateWithTimeIntervalSinceNow(0.5));
console.log(w.windowNumber > 0 ? "GUI_WINDOW_OK" : "GUI_WINDOW_FAILED");
w.close;
EOF
chmod -R a+rX "$TESTDIR/app"

GUI_MACH="mach-lookup:com.apple.CARenderServer"
GUI_IOKIT="iokit-open-user-client:IOSurfaceRootUserClient"

# Assert the verbose report shows guiAccess's blanket grant serving OP TARGET.
expect_granted() {
    local label="$1" op="$2" target="$3"
    /usr/bin/python3 - "${REPORT%.json}.verbose.json" "$op" "$target" <<'EOF' ||
import json, sys
path, op, target = sys.argv[1:]
doc = json.load(open(path))
sys.exit(0 if any(
    s["signature"]["eventName"] == op
    and dict(s["signature"]["properties"]).get("target") == target
    and dict(s["signature"]["properties"]).get("decision") == "allowGrant"
    for s in doc["signatures"]) else 1)
EOF
        fail "$label (no allowGrant $op $target in the verbose report)" "$(head -c 4000 "${REPORT%.json}.verbose.json")"
    pass "$label"
}

# Without guiAccess, ui.disable=false still reaches WindowServer, but drawing
# the window needs services only guiAccess grants. The report names them.
run_config "$(render seatbelt_capture_denials_gui_app_no_gui_access.json TESTDIR "$TESTDIR" OUTPUT "$TESTDIR/out/gui_off.json")"
expect_marker_any "the GUI app ran without guiAccess" "GUI_WINDOW_OK" "GUI_WINDOW_FAILED"
read_pointer "the GUI app run without guiAccess writes a report"
expect_listed "without guiAccess the Core Animation lookup is reported blocked" other "$GUI_MACH" unknown
expect_listed "without guiAccess the IOSurface driver is reported blocked" other "$GUI_IOKIT" unknown

# With guiAccess the same requests succeed and are reported as grant uses,
# not as denials.
run_config "$(render seatbelt_capture_denials_gui_app.json TESTDIR "$TESTDIR" OUTPUT "$TESTDIR/out/gui_on.json")"
expect_ok "the GUI app ran with guiAccess" "GUI_WINDOW_OK"
read_pointer "the GUI app run with guiAccess writes a report"
expect_granted "guiAccess reports the Core Animation lookup it served" mach-lookup com.apple.CARenderServer
expect_granted "guiAccess reports the IOSurface driver it opened" iokit-open-user-client IOSurfaceRootUserClient
for resource in "$GUI_MACH" "$GUI_IOKIT"; do
    grep -qF "\"$resource\"" "$REPORT" && fail "a granted request is listed as denied: $resource" "$(cat "$REPORT")"
done
pass "granted requests are not listed as denials"

# --- rejections --------------------------------------------------------------

expect_rejected "captureDenials cannot be combined with profileOverride" \
    seatbelt_capture_denials_profile_override.json "cannot be combined with seatbelt.profileOverride" \
    "CAPTURE_OVERRIDE_RAN"
expect_rejected "--audit refuses a config that already sets captureDenials" \
    seatbelt_capture_denials_block.json "cannot be combined with seatbelt.captureDenials" "CAPTURE_READ" --audit

summary "Seatbelt captureDenials"
