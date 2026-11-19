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
parser.add_argument("--resource", choices=("service", "graph"), default="service")
parser.add_argument("--resource-id", default="274133f7-12bb-4bfb-ae3b-bd446b7e8a75")
parser.add_argument("--graph-environment", choices=("public", "canary"), default="public")
args = parser.parse_args()
assert not any(key.startswith(("W365A_", "MXC_W365_TEST_")) for key in os.environ)
with Path(os.environ["W365_MANUAL_FIXTURE_LOG"]).open("a") as log:
    log.write(json.dumps({"operation": "auth", "force": args.force_sign_in, "silent": args.silent_only,
                          "resource": args.resource, "resourceId": args.resource_id,
                          "graphEnvironment": args.graph_environment, "clientId": args.client_id}) + "\n")
scenario = os.environ["W365_MANUAL_FIXTURE_SCENARIO"]
if scenario == "auth_failure" or (scenario == "graph_auth_failure" and args.resource == "graph"):
    print("SYNTHETIC_SECRET", file=sys.stderr)
    print("W365_AUTH_ERROR:synthetic_failure", file=sys.stderr)
    raise SystemExit(2)
owner = "33333333-3333-3333-3333-333333333333"
if scenario == "graph_wrong_owner" and args.resource == "graph":
    owner = "55555555-5555-5555-5555-555555555555"
elif scenario == "dp_wrong_owner" and args.resource_id == "66666666-6666-6666-6666-666666666666":
    owner = "55555555-5555-5555-5555-555555555555"
service_token = {
    "90ecec28-f5a6-42b3-9bde-dae1ca98f8b5": "synthetic-private-production-token",
    "66666666-6666-6666-6666-666666666666": "synthetic-private-dp-token",
}.get(args.resource_id, "synthetic-private-computer-token")
print(json.dumps({
    "accessToken": "synthetic-private-graph-token" if args.resource == "graph" else service_token,
    "userObjectId": owner,
    "expiresOn": int(time.time()) + 3600,
}))
