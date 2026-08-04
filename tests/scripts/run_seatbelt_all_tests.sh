#!/bin/bash
# Artifact-only macOS Seatbelt executor tests.
set -uo pipefail

if [[ $# -ne 1 ]]; then
    echo "Usage: $0 <binary-directory>" >&2
    exit 2
fi

BINARY_DIRECTORY="$(cd "$1" && pwd)"
MXC_EXEC="$BINARY_DIRECTORY/mxc-exec-mac"
UNIX_TEST_PROXY="$BINARY_DIRECTORY/unix-test-proxy"

if [[ ! -x "$MXC_EXEC" ]]; then
    echo "Error: executable mxc-exec-mac not found in $BINARY_DIRECTORY" >&2
    exit 1
fi
if [[ ! -x "$UNIX_TEST_PROXY" ]]; then
    echo "Error: executable unix-test-proxy not found in $BINARY_DIRECTORY" >&2
    exit 1
fi
for command_name in curl python3; do
    if ! command -v "$command_name" >/dev/null; then
        echo "Error: required command not found: $command_name" >&2
        exit 1
    fi
done

TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/mxc-seatbelt-tests.XXXXXX")"
PASSED=0
FAILED=0
FAILURES=""
INFO_PASSED=0
INFO_FAILED=0
INFO_FAILURES=""
SERVER_PID=""

cleanup() {
    if [[ -n "$SERVER_PID" ]]; then
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
    rm -rf "$TEST_ROOT"
}
trap cleanup EXIT

run_test() {
    local name="$1"
    local function_name="$2"
    echo "=== $name ==="
    if "$function_name"; then
        echo "PASS: $name"
        PASSED=$((PASSED + 1))
    else
        echo "FAIL: $name"
        FAILED=$((FAILED + 1))
        FAILURES="${FAILURES}\n  - ${name}"
    fi
    echo ""
}

run_info_test() {
    local name="$1"
    local function_name="$2"
    echo "=== $name (INFORMATION ONLY) ==="
    if "$function_name"; then
        echo "INFO-PASS: $name"
        INFO_PASSED=$((INFO_PASSED + 1))
    else
        echo "INFO-FAIL: $name"
        INFO_FAILED=$((INFO_FAILED + 1))
        INFO_FAILURES="${INFO_FAILURES}\n  - ${name}"
    fi
    echo ""
}

seed_host_clipboard() {
    python3 - "$1" <<'PYTHON'
import subprocess
import sys

token = sys.argv[1].encode()
subprocess.run(["/usr/bin/pbcopy"], input=token, timeout=5, check=True)
result = subprocess.run(
    ["/usr/bin/pbpaste"],
    capture_output=True,
    timeout=5,
    check=True,
)
sys.exit(0 if result.stdout == token else 1)
PYTHON
}

host_clipboard_matches() {
    python3 - "$1" <<'PYTHON'
import subprocess
import sys

result = subprocess.run(
    ["/usr/bin/pbpaste"],
    capture_output=True,
    timeout=5,
    check=True,
)
sys.exit(0 if result.stdout == sys.argv[1].encode() else 1)
PYTHON
}

test_execution() {
    local config="$TEST_ROOT/execution.json"
    cat >"$config" <<'JSON'
{
  "version": "0.7.0-alpha",
  "containerId": "ci-seatbelt-execution",
  "containment": "seatbelt",
  "process": { "commandLine": "printf 'SEATBELT_EXEC_OK\\n'" }
}
JSON

    local output
    output=$("$MXC_EXEC" "$config" 2>&1) || {
        echo "$output"
        return 1
    }
    grep -q "SEATBELT_EXEC_OK" <<<"$output"
}

test_exit_code() {
    local config="$TEST_ROOT/exit-code.json"
    cat >"$config" <<'JSON'
{
  "version": "0.7.0-alpha",
  "containerId": "ci-seatbelt-exit-code",
  "containment": "seatbelt",
  "process": { "commandLine": "exit 7" }
}
JSON

    local output status
    if output=$("$MXC_EXEC" "$config" 2>&1); then
        echo "Expected exit code 7, got 0"
        return 1
    else
        status=$?
    fi
    if [[ $status -ne 7 ]]; then
        echo "$output"
        echo "Expected exit code 7, got $status"
        return 1
    fi
}

test_filesystem_policy() {
    local allowed="$TEST_ROOT/allowed"
    local denied="$TEST_ROOT/denied"
    local config="$TEST_ROOT/filesystem.json"
    mkdir -p "$allowed" "$denied"
    printf 'host secret\n' >"$denied/secret.txt"

    cat >"$config" <<JSON
{
  "version": "0.7.0-alpha",
  "containerId": "ci-seatbelt-filesystem",
  "containment": "seatbelt",
  "process": {
    "commandLine": "set -e; printf 'sandbox write\\\\n' > '$allowed/output.txt'; if cat '$denied/secret.txt' >/dev/null 2>&1; then echo DENIED_PATH_LEAK; exit 1; fi; echo FILESYSTEM_OK"
  },
  "filesystem": {
    "readwritePaths": ["$allowed"],
    "deniedPaths": ["$denied"]
  }
}
JSON

    local output
    output=$("$MXC_EXEC" "$config" 2>&1) || {
        echo "$output"
        return 1
    }
    grep -q "FILESYSTEM_OK" <<<"$output" &&
        ! grep -q "DENIED_PATH_LEAK" <<<"$output" &&
        grep -q "sandbox write" "$allowed/output.txt"
}

test_environment_policy() {
    local config="$TEST_ROOT/environment.json"
    cat >"$config" <<'JSON'
{
  "version": "0.7.0-alpha",
  "containerId": "ci-seatbelt-environment",
  "containment": "seatbelt",
  "process": {
    "commandLine": "printf 'HOST=[%s] CONFIG=[%s]\\n' \"$MXC_HOST_MARKER\" \"$MXC_CONFIG_MARKER\"",
    "env": ["MXC_CONFIG_MARKER=from_config"]
  }
}
JSON

    local output
    output=$(MXC_HOST_MARKER=must_not_leak "$MXC_EXEC" "$config" 2>&1) || {
        echo "$output"
        return 1
    }
    grep -q "HOST=\[\] CONFIG=\[from_config\]" <<<"$output" &&
        ! grep -q "must_not_leak" <<<"$output"
}

test_timeout() {
    local config="$TEST_ROOT/timeout.json"
    cat >"$config" <<'JSON'
{
  "version": "0.7.0-alpha",
  "containerId": "ci-seatbelt-timeout",
  "containment": "seatbelt",
  "process": {
    "commandLine": "echo TIMEOUT_STARTED; /bin/sleep 10; echo TIMEOUT_LEAK",
    "timeout": 1000
  }
}
JSON

    local output status start elapsed
    start=$SECONDS
    if output=$("$MXC_EXEC" "$config" 2>&1); then
        echo "$output"
        echo "Expected timed-out execution to fail"
        return 1
    else
        status=$?
    fi
    elapsed=$((SECONDS - start))
    if [[ $status -eq 0 || $elapsed -ge 8 ]]; then
        echo "$output"
        echo "Timeout did not terminate promptly (status=$status elapsed=${elapsed}s)"
        return 1
    fi
    grep -q "TIMEOUT_STARTED" <<<"$output" &&
        ! grep -q "TIMEOUT_LEAK" <<<"$output"
}

start_host_server() {
    local server_script="$TEST_ROOT/server.py"
    local port_file="$TEST_ROOT/server.port"
    cat >"$server_script" <<'PYTHON'
import http.server
import socketserver
import sys

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"HOST_SERVER_OK\n"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format, *_args):
        pass

with socketserver.TCPServer(("127.0.0.1", 0), Handler) as server:
    with open(sys.argv[1], "w", encoding="utf-8") as port_file:
        port_file.write(str(server.server_address[1]))
    server.serve_forever()
PYTHON

    python3 "$server_script" "$port_file" >"$TEST_ROOT/server.log" 2>&1 &
    SERVER_PID=$!
    for _ in {1..50}; do
        [[ -s "$port_file" ]] && break
        sleep 0.1
    done
    [[ -s "$port_file" ]] || {
        cat "$TEST_ROOT/server.log"
        return 1
    }
    HOST_SERVER_PORT="$(cat "$port_file")"
    curl --fail --silent --max-time 2 "http://127.0.0.1:$HOST_SERVER_PORT" |
        grep -q "HOST_SERVER_OK"
}

test_network_default_deny() {
    start_host_server || return 1

    local config="$TEST_ROOT/network-deny.json"
    cat >"$config" <<JSON
{
  "version": "0.7.0-alpha",
  "containerId": "ci-seatbelt-network-deny",
  "containment": "seatbelt",
  "process": {
    "commandLine": "if curl --fail --silent --max-time 2 http://127.0.0.1:$HOST_SERVER_PORT >/dev/null 2>&1; then echo NETWORK_LEAK; exit 1; else echo NETWORK_BLOCKED; fi"
  },
  "network": { "defaultPolicy": "block" }
}
JSON

    local output
    output=$("$MXC_EXEC" "$config" 2>&1) || {
        echo "$output"
        return 1
    }
    grep -q "NETWORK_BLOCKED" <<<"$output" &&
        ! grep -q "NETWORK_LEAK" <<<"$output"
}

test_builtin_proxy_startup() {
    local config="$TEST_ROOT/proxy.json"
    cat >"$config" <<'JSON'
{
  "version": "0.7.0-alpha",
  "containerId": "ci-seatbelt-proxy",
  "containment": "seatbelt",
  "process": {
    "commandLine": "printf 'HTTP_PROXY=%s HTTPS_PROXY=%s\\n' \"$HTTP_PROXY\" \"$HTTPS_PROXY\""
  },
  "network": {
    "defaultPolicy": "block",
    "proxy": { "builtinTestServer": true }
  }
}
JSON

    local output
    output=$("$MXC_EXEC" --experimental --allow-testing-features "$config" 2>&1) || {
        echo "$output"
        return 1
    }
    grep -Eq "HTTP_PROXY=http://127\.0\.0\.1:[0-9]+ HTTPS_PROXY=http://127\.0\.0\.1:[0-9]+" \
        <<<"$output"
}

test_clipboard_allow() {
    local token="mxc_seatbelt_clipboard_$$_${RANDOM}"
    local allow_config="$TEST_ROOT/clipboard-allow.json"

    cat >"$allow_config" <<JSON
{
  "version": "0.7.0-alpha",
  "containerId": "ci-seatbelt-clipboard-allow",
  "containment": "seatbelt",
  "process": {
    "commandLine": "printf '$token' | /usr/bin/pbcopy && /usr/bin/pbpaste",
    "timeout": 10000
  },
  "ui": {
    "disable": false,
    "clipboard": "all"
  }
}
JSON

    local output
    output=$("$MXC_EXEC" "$allow_config" 2>&1) || {
        echo "$output"
        echo "Clipboard allow probe failed"
        return 1
    }
    if ! grep -q "$token" <<<"$output"; then
        echo "$output"
        echo "Clipboard allow probe did not return its token"
        return 1
    fi
}

test_clipboard_deny() {
    local token="mxc_seatbelt_clipboard_deny_$$_${RANDOM}"
    local deny_config="$TEST_ROOT/clipboard-deny.json"
    if ! seed_host_clipboard "$token"; then
        echo "Host clipboard read/write baseline failed"
        return 1
    fi

    cat >"$deny_config" <<'JSON'
{
  "version": "0.7.0-alpha",
  "containerId": "ci-seatbelt-clipboard-deny",
  "containment": "seatbelt",
  "process": {
    "commandLine": "copy_status=0; printf 'clipboard_denied_probe' | /usr/bin/pbcopy >/dev/null 2>&1 || copy_status=$?; read_status=0; /usr/bin/pbpaste >/dev/null 2>&1 || read_status=$?; leaked=0; if [ $copy_status -eq 0 ]; then echo CLIPBOARD_WRITE_LEAK; leaked=1; fi; if [ $read_status -eq 0 ]; then echo CLIPBOARD_READ_LEAK; leaked=1; fi; if [ $leaked -eq 0 ]; then echo CLIPBOARD_DENIED; else exit 1; fi",
    "timeout": 10000
  },
  "ui": {
    "disable": false,
    "clipboard": "none"
  }
}
JSON

    local output
    output=$("$MXC_EXEC" "$deny_config" 2>&1) || {
        echo "$output"
        echo "Clipboard deny probe failed"
        return 1
    }
    if ! grep -q "CLIPBOARD_DENIED" <<<"$output" ||
        grep -Eq "CLIPBOARD_WRITE_LEAK|CLIPBOARD_READ_LEAK" <<<"$output"; then
        return 1
    fi
    if ! host_clipboard_matches "$token"; then
        echo "Host clipboard changed during denied sandbox probe"
        return 1
    fi
}

test_gui_session() {
    local config="$TEST_ROOT/gui.json"
    cat >"$config" <<'JSON'
{
  "version": "0.7.0-alpha",
  "containerId": "ci-seatbelt-gui",
  "containment": "seatbelt",
  "process": {
    "commandLine": "/usr/bin/osascript -e 'tell application \"Finder\" to get name' && echo GUI_SESSION_OK",
    "timeout": 10000
  },
  "ui": {
    "disable": false,
    "clipboard": "all"
  },
  "seatbelt": {
    "guiAccess": true
  }
}
JSON

    local output
    output=$("$MXC_EXEC" "$config" 2>&1) || {
        echo "$output"
        echo "GUI session probe failed"
        return 1
    }
    grep -q "GUI_SESSION_OK" <<<"$output"
}

test_public_internet_allow() {
    local config="$TEST_ROOT/public-internet.json"
    cat >"$config" <<'JSON'
{
  "version": "0.7.0-alpha",
  "containerId": "ci-seatbelt-public-internet",
  "containment": "seatbelt",
  "process": {
    "commandLine": "curl --fail --silent --show-error --max-time 10 https://example.com >/dev/null && echo PUBLIC_INTERNET_OK",
    "timeout": 15000
  },
  "network": {
    "defaultPolicy": "allow"
  }
}
JSON

    local output
    output=$("$MXC_EXEC" "$config" 2>&1) || {
        echo "$output"
        echo "Public internet probe failed"
        return 1
    }
    grep -q "PUBLIC_INTERNET_OK" <<<"$output"
}

test_proxy_traffic_filtering() {
    local control_config="$TEST_ROOT/proxy-filtering-control.json"
    local config="$TEST_ROOT/proxy-filtering.json"
    if ! curl --noproxy '*' --fail --silent --max-time 10 \
        https://example.com >/dev/null; then
        echo "Host direct-egress baseline failed"
        return 1
    fi

    cat >"$control_config" <<'JSON'
{
  "version": "0.7.0-alpha",
  "containerId": "ci-seatbelt-proxy-filtering-control",
  "containment": "seatbelt",
  "process": {
    "commandLine": "curl --fail --silent --show-error --max-time 10 https://example.com >/dev/null && echo PROXY_CONTROL_OK",
    "timeout": 15000
  },
  "network": {
    "defaultPolicy": "allow",
    "proxy": {
      "builtinTestServer": true
    }
  }
}
JSON

    local output
    output=$("$MXC_EXEC" --experimental --allow-testing-features "$control_config" 2>&1) || {
        echo "$output"
        echo "Unfiltered proxy control failed"
        return 1
    }
    if ! grep -q "PROXY_CONTROL_OK" <<<"$output"; then
        echo "$output"
        echo "Unfiltered proxy control did not reach the negative-test target"
        return 1
    fi

    cat >"$config" <<'JSON'
{
  "version": "0.7.0-alpha",
  "containerId": "ci-seatbelt-proxy-filtering",
  "containment": "seatbelt",
  "process": {
    "commandLine": "set -e; curl --fail --silent --show-error --max-time 10 https://api.github.com/zen >/dev/null; echo PROXY_ALLOWED; if curl --fail --silent --max-time 5 https://example.com >/dev/null 2>&1; then echo PROXY_FILTER_LEAK; exit 1; else echo PROXY_FILTERED; fi; if curl --noproxy '*' --fail --silent --max-time 5 https://example.com >/dev/null 2>&1; then echo PROXY_DIRECT_BYPASS_OBSERVED; else echo PROXY_DIRECT_BLOCKED_OBSERVED; fi",
    "timeout": 30000
  },
  "network": {
    "defaultPolicy": "block",
    "proxy": {
      "builtinTestServer": true
    },
    "allowedHosts": [
      "api.github.com"
    ]
  }
}
JSON

    output=$("$MXC_EXEC" --experimental --allow-testing-features "$config" 2>&1) || {
        echo "$output"
        echo "Proxy traffic filtering probe failed"
        return 1
    }
    if grep -q "PROXY_DIRECT_BYPASS_OBSERVED" <<<"$output"; then
        echo "INFO: direct traffic bypassed the cooperative proxy, as Seatbelt currently permits"
    elif grep -q "PROXY_DIRECT_BLOCKED_OBSERVED" <<<"$output"; then
        echo "INFO: direct traffic was blocked independently of the cooperative proxy"
    else
        echo "$output"
        echo "Direct traffic observation was missing"
        return 1
    fi
    grep -q "PROXY_ALLOWED" <<<"$output" &&
        grep -q "PROXY_FILTERED" <<<"$output" &&
        ! grep -q "PROXY_FILTER_LEAK" <<<"$output"
}

run_test "Seatbelt execution" test_execution
run_test "Seatbelt exit code" test_exit_code
run_test "Seatbelt filesystem policy" test_filesystem_policy
run_test "Seatbelt environment policy" test_environment_policy
run_test "Seatbelt timeout" test_timeout
run_test "Seatbelt network default deny" test_network_default_deny
run_test "Seatbelt builtin proxy startup" test_builtin_proxy_startup

run_info_test "Seatbelt clipboard allow" test_clipboard_allow
run_info_test "Seatbelt clipboard deny" test_clipboard_deny
run_info_test "Seatbelt GUI session" test_gui_session
run_info_test "Seatbelt public internet allow" test_public_internet_allow
run_info_test "Seatbelt full proxy traffic filtering" test_proxy_traffic_filtering

echo "================================"
echo "Results: $PASSED passed, $FAILED failed"
echo "Information only: $INFO_PASSED passed, $INFO_FAILED failed"
if [[ $INFO_FAILED -gt 0 ]]; then
    echo -e "Informational failures (non-blocking):$INFO_FAILURES"
fi
if [[ $FAILED -gt 0 ]]; then
    echo -e "Failures:$FAILURES"
    exit 1
fi
