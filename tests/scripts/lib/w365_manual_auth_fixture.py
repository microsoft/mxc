# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Test-only replacement, staged by test_w365_command_manual.ps1."""

import argparse
import json
import os
from pathlib import Path
import sys
import time

parser = argparse.ArgumentParser()
parser.add_argument("--tenant-id", required=True)
parser.add_argument("--client-id", required=True)
parser.add_argument("--login-hint")
parser.add_argument("--expected-user-object-id")
parser.add_argument("--force-sign-in", action="store_true")
parser.add_argument("--silent-only", action="store_true")
args = parser.parse_args()
assert not any(key.startswith(("W365A_", "MXC_W365_TEST_")) for key in os.environ)
with Path(os.environ["W365_MANUAL_FIXTURE_LOG"]).open("a") as log:
    log.write(json.dumps({"operation": "auth", "force": args.force_sign_in, "silent": args.silent_only}) + "\n")
if os.environ["W365_MANUAL_FIXTURE_SCENARIO"] == "auth_failure":
    print("SYNTHETIC_SECRET", file=sys.stderr)
    print("W365_AUTH_ERROR:synthetic_failure", file=sys.stderr)
    raise SystemExit(2)
print(json.dumps({
    "accessToken": "synthetic-private-computer-token",
    "userObjectId": "33333333-3333-3333-3333-333333333333",
    "expiresOn": int(time.time()) + 3600,
}))
