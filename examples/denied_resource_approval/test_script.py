"""Test script that deliberately triggers a PermissionError.

When executed inside a sandboxed container WITHOUT readwrite access to the
target directory, this script fails with a PermissionError — which the
denied_resource_approval example then detects, presents to the user for
approval, and re-runs after updating the policy.
"""

import os
import tempfile

# Attempt to write a file in a restricted location.
# The target path is passed via the MXC_TEST_TARGET_DIR environment variable.
# If not set, defaults to the system TEMP directory (which is typically denied
# inside an AppContainer).
target_dir = os.environ.get("MXC_TEST_TARGET_DIR", tempfile.gettempdir())
target_file = os.path.join(target_dir, "mxc_approval_demo.txt")

print(f"[test_script] Attempting to write: {target_file}")

with open(target_file, "w") as f:
    f.write("Hello from MXC sandbox!\n")

print(f"[test_script] Successfully wrote: {target_file}")
