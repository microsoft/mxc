#!/usr/bin/env python3
"""crates.io release helper for the `mxc-sdk` crate closure, ESRP edition.

Per review feedback on PR #647 (Brandon Bonaby), MXC publishes to crates.io
through the **ESRP Release** system -- the Microsoft OSS publishing pipeline --
under the official `microsoft-oss-releases` crates.io account. ESRP takes a
pre-built `.crate` file and publishes it server-side, so this repository never
handles a `CARGO_REGISTRY_TOKEN`. See:
https://eng.ms/docs/microsoft-security/identity/trust-and-security-services/tss-release-distribute/tss-release-esrp-parent/oss-publishing/releasing-open-source/cratesio

ESRP publishes via the crates.io API, which -- unlike `cargo publish` -- does
NOT enforce dependency order and offers no bulk sorting. Ordering is therefore
our responsibility: the closure is released leaf-first (every crate after all of
its first-party dependencies), one ESRP task per crate, and each crate is
confirmed present on the crates.io index before its dependents publish.

Subcommands
-----------
package       Run `cargo package` for every crate in the closure (leaf-first),
              copy the resulting <name>-<version>.crate files into an output
              directory, and write release-order.json. Runs in the official
              build; the output is published as the `mxc-crates-package`
              pipeline artifact. This is the only subcommand that needs cargo.

verify-order  Assert that a caller-supplied ordered crate-name list (the
              pipeline's compile-time `crateOrder`) exactly matches the order in
              a release-order.json, so the YAML ESRP loop can never silently
              drift from what was packaged.

stage         Copy exactly one crate's `.crate` file (looked up in
              release-order.json) into a clean folder for a single ESRP task.

wait          Poll the crates.io sparse index until <crate>@<version> is
              visible, so the next (dependent) crate only publishes once this
              one is resolvable. Runs after each ESRP publish.

`cargo package --no-verify` tars a crate's source without compiling it, so a
non-leaf crate packages fine even though its first-party dependencies are not on
crates.io yet -- there is nothing to resolve or build at package time.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request

# Leaf-first release order. Every crate appears after all of its first-party
# dependencies, so each ESRP publish's dependencies already exist on crates.io.
#
# !!! KNOWN-INCOMPLETE PLACEHOLDER -- DO NOT enable `publishCrates` trusting this
# list as-is. !!!
# This is an OUTDATED 10-crate closure. A later refactor inserted the `mxc_engine`
# hub crate ("shared by the public SDK and the executor binaries") between mxc-sdk
# and the backends, so the true `--all-features` first-party closure of mxc-sdk is
# now 17 crates (adds mxc_engine, windows_sandbox_common, isolation_session_common,
# isolation_session_bindings, wslc_common, hyperlight_common, nanvix_runner).
# Before the closure can actually publish, three things must be resolved (tracked
# in the session plan / PR #647 discussion):
#   1. 7 path deps in src/Cargo.toml [workspace.dependencies] lack a `version`
#      (add `version = "0.7.0"` to match their 8 siblings).
#   2. `isolation_session_bindings` is `publish = false` (a Windows WinRT bindings
#      crate) -- it must be made publishable or dropped from mxc_engine's published
#      manifest, since crates.io validates even optional/feature-gated deps.
#   3. This list + the pipeline's `crateOrder` parameter must be reconciled to the
#      final closure and OSPO OSS-release setup / crate-name reservation completed.
# Until then the pipeline ships with `publishCrates=false` (default) and the
# `verify-order` guard fails safely if `crateOrder` and this list disagree.
#
# Leaf-first rationale for the crates currently listed:
#   mxc-sdk -> wxc_common (all targets)
#           -> appcontainer_common (windows) -> sandbox_spec
#           -> bwrap_common (linux) -> lxc_common -> mxc_pty
#           -> seatbelt_common (macos)
#   wxc_common -> mxc_telemetry, nanvix_common
# nanvix_common is optional (pulled only by wxc_common's off-by-default `microvm`
# feature), but cargo requires EVERY dependency in a published manifest --
# optional, feature-gated ones included -- to carry a version and exist on
# crates.io, so wxc_common cannot publish unless nanvix_common does too.
CRATES: list[str] = [
    "mxc_telemetry",
    "nanvix_common",
    "mxc_pty",
    "sandbox_spec",
    "wxc_common",
    "lxc_common",
    "seatbelt_common",
    "appcontainer_common",
    "bwrap_common",
    "mxc-sdk",
]

CRATES_IO_SPARSE_INDEX = "https://index.crates.io"
PROPAGATION_TIMEOUT = 300  # seconds to wait for a publish to appear in the index
PROPAGATION_POLL = 5       # seconds between index polls


def _sparse_index_path(name: str) -> str:
    """Path the crates.io sparse index uses to locate a crate."""
    name = name.lower()
    if len(name) == 1:
        return f"1/{name}"
    if len(name) == 2:
        return f"2/{name}"
    if len(name) == 3:
        return f"3/{name[0]}/{name}"
    return f"{name[:2]}/{name[2:4]}/{name}"


def _published_versions(crate: str) -> set[str]:
    """Return the versions of `crate` already on crates.io (empty set if none)."""
    url = f"{CRATES_IO_SPARSE_INDEX}/{_sparse_index_path(crate)}"
    with urllib.request.urlopen(url, timeout=30) as response:
        body = response.read().decode("utf-8")
    versions: set[str] = set()
    for line in body.splitlines():
        line = line.strip()
        if line:
            versions.add(json.loads(line)["vers"])
    return versions


def _cargo_metadata(manifest_path: str) -> dict:
    result = subprocess.run(
        ["cargo", "metadata", "--no-deps", "--format-version", "1",
         "--manifest-path", manifest_path],
        check=True, capture_output=True, text=True,
    )
    return json.loads(result.stdout)


def _run(args: list[str], cwd: str | None = None) -> int:
    print("+ " + " ".join(args), flush=True)
    return subprocess.run(args, cwd=cwd).returncode


def _load_order(order_file: str) -> list[dict]:
    with open(order_file, encoding="utf-8") as fh:
        return json.load(fh)["crates"]


# ---------------------------------------------------------------------------
# package
# ---------------------------------------------------------------------------
def cmd_package(args: argparse.Namespace) -> int:
    metadata = _cargo_metadata(args.manifest_path)
    versions = {pkg["name"]: pkg["version"] for pkg in metadata["packages"]}
    target_dir = metadata["target_directory"]
    package_dir = os.path.join(target_dir, "package")

    missing = [c for c in CRATES if c not in versions]
    if missing:
        print("Crates not found in workspace metadata: " + ", ".join(missing))
        return 1

    out_dir = os.path.abspath(args.out_dir)
    os.makedirs(out_dir, exist_ok=True)

    print(f"=== cargo package: {len(CRATES)} crates (leaf-first) ===")
    for crate in CRATES:
        print(f"  {crate} {versions[crate]}")
    print(flush=True)

    manifest = os.path.abspath(args.manifest_path)
    ordered: list[dict] = []
    for crate in CRATES:
        version = versions[crate]
        # --no-verify: source-only tar, no compile against unpublished deps.
        # --allow-dirty: CI setup (e.g. appending the internal feed to
        # .cargo/config.toml) leaves the tree in a state cargo calls dirty.
        rc = _run(["cargo", "package", "-p", crate, "--no-verify", "--allow-dirty",
                   "--manifest-path", manifest])
        if rc != 0:
            print(f"FAIL  cargo package {crate} {version} (exit {rc})")
            return 1

        crate_file = f"{crate}-{version}.crate"
        src = os.path.join(package_dir, crate_file)
        if not os.path.isfile(src):
            print(f"FAIL  expected {src} was not produced by cargo package")
            return 1
        shutil.copy2(src, os.path.join(out_dir, crate_file))
        ordered.append({"name": crate, "version": version, "file": crate_file})
        print(f"OK    packaged {crate_file}", flush=True)

    order_path = os.path.join(out_dir, "release-order.json")
    with open(order_path, "w", encoding="utf-8") as fh:
        json.dump({"crates": ordered}, fh, indent=2)
    print(f"\nWrote {order_path}")
    print(f"=== packaged {len(ordered)} crates into {out_dir} ===")
    return 0


# ---------------------------------------------------------------------------
# verify-order
# ---------------------------------------------------------------------------
def cmd_verify_order(args: argparse.Namespace) -> int:
    packaged = [c["name"] for c in _load_order(args.order_file)]
    expected = json.loads(args.expected)
    if packaged != expected:
        print("Crate order mismatch between the pipeline `crateOrder` parameter "
              "and the packaged release-order.json.")
        print(f"  pipeline crateOrder : {expected}")
        print(f"  release-order.json  : {packaged}")
        print("Update the `crateOrder` parameter in 1ES.Release.yml to match "
              "the CRATES list in crates_release.py.")
        return 1
    print(f"Crate order verified ({len(packaged)} crates, leaf-first).")
    return 0


# ---------------------------------------------------------------------------
# stage
# ---------------------------------------------------------------------------
def cmd_stage(args: argparse.Namespace) -> int:
    entry = next((c for c in _load_order(args.order_file) if c["name"] == args.crate), None)
    if entry is None:
        print(f"Crate {args.crate!r} not found in {args.order_file}")
        return 1

    out_dir = os.path.abspath(args.out_dir)
    if os.path.isdir(out_dir):
        shutil.rmtree(out_dir)
    os.makedirs(out_dir, exist_ok=True)

    src = os.path.join(os.path.dirname(os.path.abspath(args.order_file)), entry["file"])
    if not os.path.isfile(src):
        print(f"Crate file not found: {src}")
        return 1
    shutil.copy2(src, os.path.join(out_dir, entry["file"]))
    print(f"Staged {entry['file']} ({args.crate} {entry['version']}) into {out_dir} for ESRP.")
    return 0


# ---------------------------------------------------------------------------
# wait
# ---------------------------------------------------------------------------
def cmd_wait(args: argparse.Namespace) -> int:
    entry = next((c for c in _load_order(args.order_file) if c["name"] == args.crate), None)
    if entry is None:
        print(f"Crate {args.crate!r} not found in {args.order_file}")
        return 1
    crate, version = entry["name"], entry["version"]

    deadline = time.monotonic() + args.timeout
    while time.monotonic() < deadline:
        try:
            if version in _published_versions(crate):
                print(f"OK    {crate} {version} is live on the crates.io index.")
                return 0
        except urllib.error.HTTPError as error:
            if error.code != 404:  # 404 == not indexed yet; keep polling
                print(f"WARN  crates.io index HTTP {error.code} for {crate}; retrying")
        except (urllib.error.URLError, TimeoutError) as error:
            print(f"WARN  crates.io index unreachable for {crate}: {error}; retrying")
        time.sleep(args.poll)

    # ESRP ran with waitforreleasecompletion:true, so the publish itself already
    # completed; only index propagation is unconfirmed. Warn (don't fail the
    # release) and let the next crate proceed.
    print(f"##vso[task.logissue type=warning]{crate} {version} not confirmed on the "
          f"crates.io index within {args.timeout}s; continuing (ESRP reported the "
          f"publish complete).")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    p_pkg = sub.add_parser("package", help="cargo package the closure leaf-first")
    p_pkg.add_argument("--manifest-path", default="src/Cargo.toml")
    p_pkg.add_argument("--out-dir", required=True)
    p_pkg.set_defaults(func=cmd_package)

    p_ord = sub.add_parser("verify-order", help="assert crateOrder matches the package")
    p_ord.add_argument("--order-file", required=True)
    p_ord.add_argument("--expected", required=True,
                       help="JSON array of crate names in the expected order")
    p_ord.set_defaults(func=cmd_verify_order)

    p_stg = sub.add_parser("stage", help="copy one crate's .crate into a clean folder")
    p_stg.add_argument("--order-file", required=True)
    p_stg.add_argument("--crate", required=True)
    p_stg.add_argument("--out-dir", required=True)
    p_stg.set_defaults(func=cmd_stage)

    p_wait = sub.add_parser("wait", help="poll the crates.io index for a crate version")
    p_wait.add_argument("--order-file", required=True)
    p_wait.add_argument("--crate", required=True)
    p_wait.add_argument("--timeout", type=int, default=PROPAGATION_TIMEOUT)
    p_wait.add_argument("--poll", type=int, default=PROPAGATION_POLL)
    p_wait.set_defaults(func=cmd_wait)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
