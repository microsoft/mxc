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
# Unfinished background mxc-exec-mac runs.
BACKGROUND_PIDS=""
# Kills a workload shell and its children without relying on process groups.
# Stopping the shell first keeps it from starting new children.
kill_workload() {
    kill -STOP "$1" 2>/dev/null || return 0
    pkill -KILL -P "$1" 2>/dev/null
    kill -KILL "$1" 2>/dev/null
    return 0
}
cleanup_capture() {
    local pid
    # Workloads outlive a killed mxc-exec-mac and its timeout, so stop them first.
    for pid in $(pgrep -f "$TESTDIR/ungranted/"); do
        kill_workload "$pid"
    done
    for pid in $LISTENER_PID $BACKGROUND_PIDS; do
        kill "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    done
    rm -rf "$TESTDIR" "$SEATBELT_TMP"
}
trap cleanup_capture EXIT
mkdir -p "$TESTDIR/ungranted" "$TESTDIR/denied" "$TESTDIR/out" "$TESTDIR/gate"
echo "CAPTURE_SECRET_CONTENT" >"$TESTDIR/ungranted/secret.txt"
echo "CAPTURE_DENIED_CONTENT" >"$TESTDIR/denied/secret.txt"
for name in overlap_a overlap_b drain killed watchdog; do
    echo "CAPTURE_SENTINEL_CONTENT" >"$TESTDIR/ungranted/$name.txt"
    echo "CAPTURE_SENTINEL_CONTENT" >"$TESTDIR/ungranted/$name-after.txt"
done
chmod -R a+rX "$TESTDIR"
SECRET="$TESTDIR/ungranted/secret.txt"

# Report path from the pointer line mxc-exec-mac prints on stderr.
REPORT=""
POINTER=""
read_pointer() {
    local label="$1"
    POINTER="$(grep -m1 '^{"type":"captureDenials"' <<<"$OUT")" ||
        fail "$label (no captureDenials pointer line)" "$OUT"
    REPORT="$(pointer_field outputPath)" || fail "$label (unreadable pointer line)" "$OUT"
    [ -f "$REPORT" ] || fail "$label (report $REPORT was not written)" "$OUT"
    pass "$label"
}

pointer_field() {
    /usr/bin/python3 -c 'import json,sys; print(json.loads(sys.argv[1])[sys.argv[2]])' "$POINTER" "$1"
}

# Render the sentinel workload to its own file so several can run at once.
# It reads NAME.txt, waits for open_gate NAME, then reads NAME-after.txt.
SENTINEL_CONFIG=""
render_sentinel() {
    local name="$1" output="$2" rendered
    rendered="$(render seatbelt_capture_denials_sentinel.json TESTDIR "$TESTDIR" NAME "$name" OUTPUT "$output")"
    SENTINEL_CONFIG="$TESTDIR/$name.json"
    cp "$rendered" "$SENTINEL_CONFIG" 2>/dev/null || fail "config was not rendered: $rendered"
}

BG_PID=""
start_background() {
    local config="$1" output="$2"
    "$MXC_EXEC_MAC" "$config" >"$output" 2>&1 &
    BG_PID=$!
    BACKGROUND_PIDS="$BACKGROUND_PIDS $BG_PID"
}

finish_background() {
    local pid="$1" output="$2"
    RC=0
    wait "$pid" 2>/dev/null || RC=$?
    BACKGROUND_PIDS="${BACKGROUND_PIDS/ $pid/}"
    OUT="$(cat "$output")"
}

open_gate() {
    local name
    for name in "$@"; do touch "$TESTDIR/gate/$name"; done
}

# Wait until background run MXC has a ready collector and its sentinel
# workload NAME is running. Sets COLLECTOR to the `log stream` PID,
# WATCHDOG to its parent shell's PID, and WORKLOAD to the workload shell's PID.
COLLECTOR=""
WATCHDOG=""
WORKLOAD=""
wait_for_collector() {
    local label="$1" mxc="$2" name="$3" output="$4" shell
    COLLECTOR=""
    for _ in $(seq 1 150); do
        for shell in $(pgrep -P "$mxc" -f '/usr/bin/log stream'); do
            COLLECTOR="$(pgrep -P "$shell" -f '/usr/bin/log stream')"
            WATCHDOG="$shell"
        done
        WORKLOAD="$(pgrep -P "$mxc" -f "ungranted/$name")"
        [ -n "$COLLECTOR" ] && [ -n "$WORKLOAD" ] && return
        kill -0 "$mxc" 2>/dev/null || fail "$label (mxc-exec-mac exited early)" "$(cat "$output")"
        sleep 0.1
    done
    fail "$label (no running collector and workload after 15s)" "$(cat "$output")"
}

# `log stream` can take a moment to see its closed pipe after a kill.
expect_collector_gone() {
    local label="$1" pid="$2"
    for _ in $(seq 1 50); do
        kill -0 "$pid" 2>/dev/null || { pass "$label"; return; }
        sleep 0.1
    done
    ps -o pid,ppid,stat,command -p "$pid"
    kill -KILL "$pid" 2>/dev/null || true
    fail "$label (log stream $pid is still running)"
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

# --- block mode with deniedPaths ---------------------------------------------

config="$(render seatbelt_capture_denials_allow.json TESTDIR "$TESTDIR" OUTPUT "$TESTDIR/out/denials.json")"
edit_config "$config" 'config["seatbelt"]["captureDenials"]["mode"] = "block"'
run_config "$config"
expect_ok "block mode blocks the default-denied read" "CAPTURE_READ_BLOCKED"
expect_marker "block mode blocks an explicitly denied read" "CAPTURE_EXPLICIT_READ_BLOCKED"
expect_absent "block mode does not leak an explicitly denied file" "CAPTURE_DENIED_CONTENT"
read_pointer "block mode with deniedPaths writes a report"
expect_listed "block mode lists the default-denied read" file "$SECRET" read
expect_listed "block mode lists the explicitly denied read" file "$TESTDIR/denied/secret.txt" read

# --- retainEtl keeps the raw log stream ---------------------------------------

config="$(render seatbelt_capture_denials_block.json TESTDIR "$TESTDIR" OUTPUT "$TESTDIR/out/denials.json")"
edit_config "$config" 'config["seatbelt"]["captureDenials"]["retainEtl"] = True'
run_config "$config"
expect_ok "retainEtl still enforces the policy" "CAPTURE_READ_BLOCKED"
read_pointer "retainEtl writes a report"
TRACE="${REPORT%.json}.seatbelt.log"
[ "$(pointer_field etlPath)" = "$TRACE" ] || fail "the pointer's etlPath does not name $TRACE" "$POINTER"
[ -f "$TRACE" ] || fail "the trace was not written: $TRACE"
pass "retainEtl writes the trace next to the report and names it in etlPath"
[ "$(stat -f %Lp "$TRACE")" = 600 ] || fail "the trace is readable by other users: $(stat -f %Sp "$TRACE")"
pass "the trace is readable only by its owner, like the reports"
# Raw `log` JSON escapes "/" as "\/", so match the file name alone.
grep -qF "secret.txt" "$TRACE" || fail "the trace does not contain the denied read" "$(head -c 2000 "$TRACE")"
pass "the trace contains the raw denial"

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

config="$(render seatbelt_capture_denials_v1_0.json TESTDIR "$TESTDIR" OUTPUT unused)"
edit_config "$config" 'del config["seatbelt"]'
run_config "$config" --audit
expect_ok "--audit accepts a published 1.0.0 config" "CAPTURE_READ_OK"
read_pointer "--audit writes a report for a 1.0.0 config"
expect_listed "--audit lists the read from a 1.0.0 config" file "$SECRET" read
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

for scenario in deny allow proxy block; do
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
elif scenario == "block":
    config["seatbelt"]["captureDenials"]["mode"] = "block"
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
        block)
            expect_ok "block mode blocks the network connection" "LOOPBACK_BLOCKED"
            expect_marker "block mode blocks the second host port" "PROXY_BLOCKED"
            ;;
    esac
    read_pointer "$scenario loopback capture writes a report"
    /usr/bin/python3 - "$REPORT" "$scenario" "$PORT" "$PROXY_PORT" <<'EOF' || fail "$scenario loopback report misclassifies blocked or granted connections" "$(cat "$REPORT")"
import json, sys
path, scenario, host_port, proxy_port = sys.argv[1:]
with open(path) as source:
    denials = json.load(source)["denials"]
for port, blocked in [(host_port, scenario != "allow"), (proxy_port, scenario in ("deny", "block"))]:
    listed = any(d["resourceType"] == "network"
                 and d["resource"] == f"network-outbound:remote:*:{port}" for d in denials)
    assert listed == blocked, (port, blocked, denials)
EOF
    pass "$scenario loopback capture reports denied connections, not explicit grants"
done

# --- repeated denials ---------------------------------------------------------

# 11,000 denials of ~1 KB paths (10 files read 1,100 times each), then one new
# denial. Repeats are counted as they arrive, so even more repeats than the
# 10,000-denial limit may not push out the late denial or mark the report
# truncated.
LONGDIR="$TESTDIR/ungranted/$(/usr/bin/python3 -c 'print("/".join(["d" * 200] * 4))')"
mkdir -p "$LONGDIR"
for name in f0 f1 f2 f3 f4 f5 f6 f7 f8 f9 late; do echo x >"$LONGDIR/$name"; done
chmod -R a+rX "$TESTDIR/ungranted"
run_config "$(render seatbelt_capture_denials_repeats.json LONGDIR "$LONGDIR" OUTPUT "$TESTDIR/out/repeats.json")"
expect_ok "a run with heavy repeated denials completes" "CAPTURE_REPEAT_LOOP_DONE"
read_pointer "a run with heavy repeated denials writes a report"
[ "$(pointer_field deniedResourcesTruncated)" = False ] ||
    fail "repeated denials marked the report truncated" "$POINTER"
pass "repeated denials don't mark the report truncated"
expect_listed "a repeated denial is listed" file "$LONGDIR/f9" read
expect_listed "a denial after heavy repeats is still listed" file "$LONGDIR/late" read
/usr/bin/python3 - "${REPORT%.json}.verbose.json" <<'EOF' || fail "repeated denials were not all counted" "$(head -c 2000 "${REPORT%.json}.verbose.json")"
import json, sys
summary = json.load(open(sys.argv[1]))["summary"]
assert not summary["processedEventsTruncated"], summary
assert summary["totalOccurrences"] > 10000, summary
EOF
pass "repeated denials are counted past the 10,000-denial limit"
rm -f "$REPORT" "${REPORT%.json}.verbose.json"

# --- different-denial limit ---------------------------------------------------

# 15,000 different denials; the margin covers reports `log stream` drops under
# load. The report keeps the first 10,000, and the run still finishes cleanly.
MANYDIR="$TESTDIR/ungranted/many"
mkdir -p "$MANYDIR"
/usr/bin/python3 - "$MANYDIR" <<'EOF' || fail "could not create the limit test files"
import os, sys
for i in range(15000):
    open(os.path.join(sys.argv[1], str(i)), "w").close()
EOF
chmod -R a+rX "$MANYDIR"
# The workload waits for open_gate many, so this run's collector can be found.
start_background "$(render seatbelt_capture_denials_unique_limit.json TESTDIR "$TESTDIR" \
    MANYDIR "$MANYDIR" COUNT 15000 OUTPUT "$TESTDIR/out/limit.json")" "$TESTDIR/limit.out"
wait_for_collector "the different-denial limit run starts" "$BG_PID" many "$TESTDIR/limit.out"
open_gate many
finish_background "$BG_PID" "$TESTDIR/limit.out"
expect_ok "a run past the different-denial limit completes" "CAPTURE_UNIQUE_LOOP_DONE"
read_pointer "a run past the different-denial limit writes a report"
[ "$(pointer_field deniedResourcesTruncated)" = True ] ||
    fail "a report at the different-denial limit is not marked truncated" "$POINTER"
pass "a report at the different-denial limit is marked truncated"
/usr/bin/python3 - "$REPORT" "${REPORT%.json}.verbose.json" <<'EOF' || fail "the different-denial limit was not applied" "$POINTER"
import json, sys
report, verbose = (json.load(open(path)) for path in sys.argv[1:])
assert len(report["denials"]) == 10000, len(report["denials"])
assert verbose["summary"]["actionableLimitReached"], verbose["summary"]
EOF
pass "the report stops at 10,000 different denials"
expect_collector_gone "a run past the different-denial limit stops its log stream" "$COLLECTOR"
rm -rf "$MANYDIR" "$REPORT" "${REPORT%.json}.verbose.json"

# --- overlapping runs with the same outputPath ---------------------------------

# Each run reads its after-gate file once both collectors are running, so
# a collector not filtered to its own run would list the other run's reads.
render_sentinel overlap_a "$TESTDIR/out/overlap.json"
CONFIG_A="$SENTINEL_CONFIG"
render_sentinel overlap_b "$TESTDIR/out/overlap.json"
CONFIG_B="$SENTINEL_CONFIG"
start_background "$CONFIG_A" "$TESTDIR/overlap_a.out"
PID_A="$BG_PID"
wait_for_collector "overlapping run A starts" "$PID_A" overlap_a "$TESTDIR/overlap_a.out"
COLLECTOR_A="$COLLECTOR"
start_background "$CONFIG_B" "$TESTDIR/overlap_b.out"
PID_B="$BG_PID"
wait_for_collector "overlapping run B starts" "$PID_B" overlap_b "$TESTDIR/overlap_b.out"
COLLECTOR_B="$COLLECTOR"
open_gate overlap_a overlap_b

finish_background "$PID_A" "$TESTDIR/overlap_a.out"
expect_ok "overlapping run A enforces the policy" "CAPTURE_SENTINEL_BLOCKED"
read_pointer "overlapping run A writes a report"
REPORT_A="$REPORT"
expect_listed "overlapping run A lists its own read" file "$TESTDIR/ungranted/overlap_a-after.txt" read
finish_background "$PID_B" "$TESTDIR/overlap_b.out"
expect_ok "overlapping run B enforces the policy" "CAPTURE_SENTINEL_BLOCKED"
read_pointer "overlapping run B writes a report"
REPORT_B="$REPORT"
expect_listed "overlapping run B lists its own read" file "$TESTDIR/ungranted/overlap_b-after.txt" read

[ "$REPORT_A" != "$REPORT_B" ] || fail "overlapping runs wrote the same report: $REPORT_A"
! grep -qF "ungranted/overlap_b" "$REPORT_A" || fail "run A's report lists run B's read" "$(cat "$REPORT_A")"
! grep -qF "ungranted/overlap_a" "$REPORT_B" || fail "run B's report lists run A's read" "$(cat "$REPORT_B")"
pass "each overlapping report excludes the other run's read"
expect_collector_gone "overlapping run A's log stream stopped" "$COLLECTOR_A"
expect_collector_gone "overlapping run B's log stream stopped" "$COLLECTOR_B"

# --- incomplete drain ----------------------------------------------------------

# A stopped `log stream` never shows the end marker, so MXC cannot confirm
# that it received every event.
render_sentinel drain "$TESTDIR/out/drain.json"
start_background "$SENTINEL_CONFIG" "$TESTDIR/drain.out"
wait_for_collector "the drain run starts" "$BG_PID" drain "$TESTDIR/drain.out"
kill -STOP "$COLLECTOR"
open_gate drain
finish_background "$BG_PID" "$TESTDIR/drain.out"
expect_ok "a run whose log stream stalls still completes" "CAPTURE_SENTINEL_BLOCKED"
expect_marker "the CLI warns that the report may be incomplete" \
    '{"warning":{"message":"Seatbelt captureDenials could not confirm that all sandbox log events were received'
read_pointer "a stalled log stream still produces a report"
[ "$(pointer_field deniedResourcesTruncated)" = True ] ||
    fail "an undrained report is not marked truncated" "$POINTER"
pass "an undrained report is marked truncated"
expect_collector_gone "the stalled log stream was stopped" "$COLLECTOR"

# --- mxc-exec-mac killed mid-run -----------------------------------------------

render_sentinel killed "$TESTDIR/out/killed.json"
start_background "$SENTINEL_CONFIG" "$TESTDIR/killed.out"
wait_for_collector "the run to kill starts" "$BG_PID" killed "$TESTDIR/killed.out"
# The workload outlives a killed MXC; clean it up here.
kill -KILL "$BG_PID"
finish_background "$BG_PID" "$TESTDIR/killed.out"
expect_collector_gone "killing mxc-exec-mac stops its log stream" "$COLLECTOR"
kill_workload "$WORKLOAD"

# --- collector's watchdog shell killed mid-run ---------------------------------

# `log stream` keeps running without its parent shell. MXC must still stop it
# rather than wait forever for its output to close.
render_sentinel watchdog "$TESTDIR/out/watchdog.json"
start_background "$SENTINEL_CONFIG" "$TESTDIR/watchdog.out"
wait_for_collector "the watchdog run starts" "$BG_PID" watchdog "$TESTDIR/watchdog.out"
kill -KILL "$WATCHDOG"
open_gate watchdog
for _ in $(seq 1 300); do
    kill -0 "$BG_PID" 2>/dev/null || break
    sleep 0.1
done
if kill -0 "$BG_PID" 2>/dev/null; then
    kill -KILL "$COLLECTOR" 2>/dev/null
    fail "mxc-exec-mac hung after its log stream lost its watchdog shell" "$(cat "$TESTDIR/watchdog.out")"
fi
finish_background "$BG_PID" "$TESTDIR/watchdog.out"
expect_ok "a run whose watchdog shell was killed completes" "CAPTURE_SENTINEL_BLOCKED"
! grep -qF "could not confirm that all sandbox log events" <<<"$OUT" ||
    fail "a run whose watchdog shell was killed did not drain its log stream" "$OUT"
read_pointer "a run whose watchdog shell was killed writes a report"
[ "$(pointer_field deniedResourcesTruncated)" = False ] ||
    fail "a run whose watchdog shell was killed is marked truncated" "$POINTER"
expect_listed "the report lists the read made after the watchdog died" file "$TESTDIR/ungranted/watchdog-after.txt" read
expect_collector_gone "the orphaned log stream was stopped" "$COLLECTOR"

# --- UI denials under guiAccess ---------------------------------------------

# ui.clipboard=none must survive the guiAccess blanket Mach grant, and the
# report must attribute the blocked pasteboard to UI rather than "other".
# Allow mode enforces only a written setting: an omitted ui.clipboard lets the
# pasteboard through and still reports it, despite guiAccess's grant.
for scenario in allow:all block:none allow:none allow:omitted; do
    mode="${scenario%:*}"
    clipboard="${scenario#*:}"
    config="$(render seatbelt_capture_denials_gui_clipboard_none.json OUTPUT "$TESTDIR/out/clipboard.json")"
    /usr/bin/python3 - "$config" "$mode" "$clipboard" <<'EOF' || fail "could not prepare clipboard capture config"
import json, sys
path, mode, clipboard = sys.argv[1:]
with open(path) as source:
    config = json.load(source)
config["seatbelt"]["captureDenials"]["mode"] = mode
if clipboard == "omitted":
    del config["ui"]["clipboard"]
else:
    config["ui"]["clipboard"] = clipboard
with open(path, "w") as output:
    json.dump(config, output)
EOF
    run_config "$config"
    case "$clipboard" in
        all)
            expect_ok "allow mode permits the pasteboard when granted under guiAccess" "CLIPBOARD_OK"
            read_pointer "the allowed pasteboard control writes a report"
            continue
            ;;
        omitted)
            expect_ok "allow mode permits the pasteboard when ui.clipboard is omitted" "CLIPBOARD_OK"
            ;;
        *)
            expect_ok "$mode mode keeps the pasteboard blocked under guiAccess" "CLIPBOARD_BLOCKED"
            ;;
    esac
    read_pointer "$mode mode with clipboard $clipboard writes a report"
    /usr/bin/python3 - "$REPORT" <<'EOF' || fail "$mode mode with clipboard $clipboard: pasteboard is not reported as ui" "$(cat "$REPORT")"
import json, sys
doc = json.load(open(sys.argv[1]))
assert any(d["resourceType"] == "ui" and "com.apple.pasteboard" in d["resource"]
           for d in doc["denials"])
EOF
    pass "$mode mode with clipboard $clipboard reports the pasteboard as ui"
done

# Same for keychainAccess. HOME must be set or Security.framework fails for an
# unrelated reason.
for keychain in omitted false; do
    config="$(render seatbelt_capture_denials_gui_keychain.json HOME "$HOME" OUTPUT "$TESTDIR/out/keychain.json")"
    [ "$keychain" = false ] && edit_config "$config" 'config["seatbelt"]["keychainAccess"] = False'
    run_config "$config"
    if [ "$keychain" = omitted ]; then
        expect_ok "allow mode permits the Keychain when keychainAccess is omitted" "KEYCHAIN_OK"
    else
        expect_ok "allow mode keeps the Keychain blocked with keychainAccess=false" "KEYCHAIN_BLOCKED"
    fi
    read_pointer "allow mode with keychainAccess $keychain writes a report"
    /usr/bin/python3 - "$REPORT" <<'EOF' || fail "allow mode with keychainAccess $keychain does not report the Keychain" "$(cat "$REPORT")"
import json, sys
doc = json.load(open(sys.argv[1]))
assert any(d["resource"].startswith(("mach-lookup:com.apple.securityd", "mach-lookup:com.apple.SecurityServer"))
           for d in doc["denials"])
EOF
    pass "allow mode with keychainAccess $keychain reports the Keychain"
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

# In allow mode, empty custom lists don't block the app; the report names what
# the lists need to grant.
run_config "$(render seatbelt_capture_denials_gui_app_custom_allow.json TESTDIR "$TESTDIR" OUTPUT "$TESTDIR/out/gui_custom.json")"
expect_ok "allow mode runs the GUI app despite empty custom lists" "GUI_WINDOW_OK"
read_pointer "the allow-mode custom-list run writes a report"
expect_listed "allow mode lists the Core Animation lookup to grant" other "$GUI_MACH" unknown
expect_listed "allow mode lists the IOSurface driver to grant" other "$GUI_IOKIT" unknown
expect_listed "allow mode lists the shared memory to grant" other \
    "ipc-posix-shm-read-data:apple.shm.notification_center" read

# --- rejections --------------------------------------------------------------

expect_rejected "captureDenials cannot be combined with profileOverride" \
    seatbelt_capture_denials_profile_override.json "cannot be combined with seatbelt.profileOverride" \
    "CAPTURE_OVERRIDE_RAN"
expect_rejected "--audit refuses a config that already sets captureDenials" \
    seatbelt_capture_denials_block.json "cannot be combined with seatbelt.captureDenials" "CAPTURE_READ" --audit
expect_rejected "a 1.0.0 config cannot set captureDenials" \
    seatbelt_capture_denials_v1_0.json 'unknown field `captureDenials`' "CAPTURE_READ"

summary "Seatbelt captureDenials"
