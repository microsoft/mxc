#!/bin/bash
# TEMPORARY diagnostic for #1725: how long Seatbelt reports take to appear in
# `log show`. Prints measurements only and always exits 0.
set -uo pipefail

LABEL="$(date +%T)"
echo "host: $(sw_vers -productVersion) ($(uname -m)) ${LABEL}"
/usr/bin/python3 - <<'EOF'
import json, os, subprocess, tempfile, time, uuid

POLL_LIMIT = 60.0

def profile(tag, directory):
    return ('(version 1)(allow default)(deny file-write* (with message "%s") (subpath "%s"))'
            % (tag, directory))

def show(tag, window):
    started = time.monotonic()
    out = subprocess.run(
        ["/usr/bin/log", "show", "--style", "ndjson", "--last", window, "--predicate",
         'sender == "Sandbox" AND eventMessage CONTAINS "%s"' % tag],
        capture_output=True, text=True).stdout
    messages = [json.loads(l).get("eventMessage", "") for l in out.splitlines()
                if '"eventMessage"' in l]
    return messages, time.monotonic() - started

def scenario(name, workload_code):
    tag = "mxcdiag-" + uuid.uuid4().hex[:12]
    directory = tempfile.mkdtemp(prefix="mxcdiag.", dir="/private/var/tmp")
    stream = subprocess.Popen(
        ["/usr/bin/log", "stream", "--style", "ndjson", "--predicate",
         'sender == "Sandbox" AND eventMessage CONTAINS "%s"' % tag],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    time.sleep(2)
    run_started = time.monotonic()
    subprocess.run(["/usr/bin/sandbox-exec", "-p", profile(tag, directory),
                    "/usr/bin/python3", "-c", workload_code, directory],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["/usr/bin/sandbox-exec", "-p", profile(tag, directory),
                    "/usr/bin/touch", directory + "/marker-done"],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    marker_at = time.monotonic()
    seen_after = None
    polls = 0
    show_times = []
    while time.monotonic() - marker_at < POLL_LIMIT:
        messages, took = show(tag, "300s")
        polls += 1
        show_times.append(took)
        if any("marker-done" in m for m in messages):
            seen_after = time.monotonic() - marker_at
            break
        time.sleep(0.25)
    wide, _ = show(tag, "300s")
    narrow, _ = show(tag, "%ds" % (int(time.monotonic() - run_started) + 2))
    time.sleep(1)
    stream.terminate()
    streamed = sum('"eventMessage"' in l for l in stream.communicate()[0].splitlines())
    seen = "%.2fs" % seen_after if seen_after is not None else "NEVER within %ds" % POLL_LIMIT
    print("%-22s marker in log show after %s (%d polls, show took max %.2fs); "
          "reports: show(300s)=%d show(MXC window)=%d stream=%d"
          % (name, seen, polls, max(show_times), len(wide), len(narrow), streamed), flush=True)
    subprocess.run(["rm", "-rf", directory])

single = "import sys; open(sys.argv[1] + '/one', 'w')"
repeats = ("import sys\nfor i in range(11000):\n    try: open('%s/f%d' % (sys.argv[1], i % 10), 'w')\n"
           "    except OSError: pass")
unique = ("import sys\nfor i in range(15000):\n    try: open('%s/u%d' % (sys.argv[1], i), 'w')\n"
          "    except OSError: pass")
for i in range(5):
    scenario("single denial #%d" % (i + 1), single)
scenario("11k repeated denials", repeats)
scenario("15k unique denials", unique)
scenario("single after floods", single)
EOF
exit 0
