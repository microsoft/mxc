"""Comprehensive resource denial test script for MXC sandbox.

Exercises supported resource types (file, network) inside a sandbox
to trigger denial detection. Each section uses try/except so all denials are
captured even if earlier ones fail.

Output is formatted to match the SDK's denial regex patterns in denied-resources.ts.
"""

import os
import sys
import tempfile

# ---------------------------------------------------------------------------
# File access tests
# ---------------------------------------------------------------------------

file_denied = False


def test_file_access():
    global file_denied

    # Test 1: Write to MXC_TEST_TARGET_DIR (matches python_permission_error)
    # Use a path that's NOT in the readwrite policy (user's home dir, not temp)
    target_dir = os.environ.get("MXC_TEST_TARGET_DIR", os.path.join(os.path.expanduser("~"), "mxc_all_resources_test"))
    target_file = os.path.join(target_dir, "mxc_all_resources_test.txt")

    print(f"[file] Attempting to write: {target_file}")
    try:
        with open(target_file, "w") as f:
            f.write("test\n")
        print(f"[file] SUCCESS: wrote {target_file}")
    except PermissionError as e:
        # Print in traceback format to match pattern: PermissionError: [WinError 5] ...
        print(f"[file] DENIED: PermissionError: {e}")
        file_denied = True
    except OSError as e:
        print(f"[file] DENIED: OSError: {e}")
        file_denied = True

    # Test 2: Read a protected system file (matches python_permission_error)
    system_file = r"C:\Windows\System32\config\SAM"
    print(f"[file] Attempting to read: {system_file}")
    try:
        with open(system_file, "r") as f:
            f.read(1)
        print(f"[file] SUCCESS: read {system_file}")
    except PermissionError as e:
        # PermissionError: [WinError 5] Access is denied: 'C:\Windows\System32\config\SAM'
        print(f"[file] DENIED: PermissionError: {e}")
        file_denied = True
    except OSError as e:
        print(f"[file] DENIED: OSError: {e}")
        file_denied = True


# ---------------------------------------------------------------------------
# Network access tests
# ---------------------------------------------------------------------------

network_denied = False


def test_network_access():
    global network_denied

    import urllib.request
    import urllib.error
    import socket

    # Test 1: HTTPS connection to httpbin.org
    target_url = "https://httpbin.org/get"
    target_host_1 = "httpbin.org"
    print(f"[network] Attempting to connect to: {target_url}")
    try:
        req = urllib.request.urlopen(target_url, timeout=5)
        req.close()
        print(f"[network] SUCCESS: connected to {target_url}")
    except urllib.error.URLError as e:
        reason = str(e.reason) if hasattr(e, "reason") else str(e)
        if "getaddrinfo" in reason.lower() or "name or service not known" in reason.lower():
            print(f"[network] DENIED: getaddrinfo ENOTFOUND {target_host_1}")
        else:
            print(f"[network] DENIED: Connection refused: {target_host_1}:443")
        network_denied = True
    except socket.timeout:
        print(f"[network] DENIED: Connection refused: {target_host_1}:443")
        network_denied = True
    except OSError as e:
        print(f"[network] DENIED: Connection refused: {target_host_1}:443")
        network_denied = True

    # Test 2: HTTP connection to pypi.org
    target_host_2 = "pypi.org"
    target_port = 443
    print(f"[network] Attempting raw socket to: {target_host_2}:{target_port}")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((target_host_2, target_port))
        sock.close()
        print(f"[network] SUCCESS: raw socket to {target_host_2}:{target_port}")
    except (ConnectionRefusedError, socket.timeout, OSError) as e:
        print(f"[network] DENIED: Connection refused: {target_host_2}:{target_port}")
        network_denied = True


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    print("=" * 60)
    print("  MXC All-Resource Denial Test")
    print("=" * 60)
    print()

    test_file_access()
    print()
    test_network_access()
    print()

    # Summary
    print("=" * 60)
    print("  SUMMARY")
    print("=" * 60)
    results = {
        "file": file_denied,
        "network": network_denied,
    }

    denied_count = 0
    for resource_type, was_denied in results.items():
        status = "DENIED" if was_denied else "ALLOWED"
        symbol = "✗" if was_denied else "✓"
        print(f"  {symbol} {resource_type:12s}: {status}")
        if was_denied:
            denied_count += 1

    print()
    print(f"  Total denied: {denied_count}/{len(results)} resource types")
    print("=" * 60)

    # Exit with code 1 if any access was denied
    if denied_count > 0:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
