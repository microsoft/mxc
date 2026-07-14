#!/usr/bin/env python3
"""Publish the mxc-sdk crate and its first-party dependency closure to crates.io.

The release pipeline (`.azure-pipelines/1ES.Crate.Release.yml`) runs this from
the repository root. Crates are published leaf-first so that, by the time a
crate is uploaded, every first-party dependency it names already exists on
crates.io. Between real publishes the script waits for the sparse index to
reflect the new version, so the next crate can resolve it.

Idempotent: a crate whose exact version is already on crates.io is skipped, so a
re-run after a partial failure only publishes what is still missing.

`--dry-run` runs `cargo package --list` for every crate: it validates each
manifest (rejecting, for example, a path dependency with no version, exactly as
publish would) and prints the packaged file set, without contacting crates.io's
publish endpoint and without requiring first-party dependencies to be published
yet. It never needs CARGO_REGISTRY_TOKEN.

A real publish reads CARGO_REGISTRY_TOKEN from the environment (injected by the
pipeline from the MXC-CratesIo-Publish variable group). The token never lives in
the repository.

`--no-verify` is intentional: the pipeline has already built and tested the
workspace, and a verify build would try to compile a crate against its
just-published dependencies before the crates.io index has propagated them.
Publishing is source-only, so there is nothing to compile here.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request

# Leaf-first publish order. Every crate appears after all of its first-party
# dependencies, so each upload's dependencies already exist on crates.io.
# Derived from the mxc-sdk dependency closure:
#   mxc-sdk -> wxc_common (all targets)
#           -> appcontainer_common (windows) -> sandbox_spec
#           -> bwrap_common (linux) -> lxc_common -> mxc_pty
#           -> seatbelt_common (macos)
#   wxc_common -> mxc_telemetry, nanvix_common
# nanvix_common is optional (pulled only by wxc_common's off-by-default
# `microvm` feature), but cargo requires EVERY dependency in a published
# manifest -- optional, feature-gated ones included -- to carry a version and
# exist on crates.io. wxc_common therefore cannot be published unless
# nanvix_common is too. It is a leaf (serde/serde_json only).
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
    try:
        with urllib.request.urlopen(url, timeout=30) as response:
            body = response.read().decode("utf-8")
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return set()  # this crate name has never been published
        raise
    versions: set[str] = set()
    for line in body.splitlines():
        line = line.strip()
        if line:
            versions.add(json.loads(line)["vers"])
    return versions


def _workspace_versions(manifest_path: str) -> dict[str, str]:
    """Map every workspace package name to its version via `cargo metadata`."""
    result = subprocess.run(
        ["cargo", "metadata", "--no-deps", "--format-version", "1",
         "--manifest-path", manifest_path],
        check=True, capture_output=True, text=True,
    )
    metadata = json.loads(result.stdout)
    return {pkg["name"]: pkg["version"] for pkg in metadata["packages"]}


def _run_cargo(args: list[str]) -> int:
    print("+ " + " ".join(args), flush=True)
    return subprocess.run(args).returncode


def _wait_for_index(crate: str, version: str) -> bool:
    deadline = time.monotonic() + PROPAGATION_TIMEOUT
    while time.monotonic() < deadline:
        if version in _published_versions(crate):
            return True
        time.sleep(PROPAGATION_POLL)
    return False


def _publish_one(crate: str, version: str, manifest_path: str, dry_run: bool) -> bool:
    if version in _published_versions(crate):
        print(f"SKIP  {crate} {version} - already on crates.io")
        return True

    if dry_run:
        # `cargo package --list` validates the manifest (it rejects a path dep
        # that lacks a version, exactly as publish does) and prints the packaged
        # file set, WITHOUT resolving first-party deps against the crates.io
        # index. `cargo publish --dry-run` cannot be used for a whole-closure
        # preview: it resolves dependencies against the live index, so every
        # non-leaf crate would fail until its first-party deps are actually
        # published. --allow-dirty keeps the preview frictionless if CI leaves
        # the tree in a state cargo considers dirty; the real publish never
        # allows it.
        rc = _run_cargo(
            ["cargo", "package", "-p", crate, "--no-verify", "--allow-dirty",
             "--manifest-path", manifest_path, "--list"]
        )
        ok = rc == 0
        print(f"{'OK   ' if ok else 'FAIL '} dry-run {crate} {version}")
        return ok

    rc = _run_cargo(
        ["cargo", "publish", "-p", crate, "--no-verify",
         "--manifest-path", manifest_path]
    )
    if rc != 0:
        print(f"FAIL  publish {crate} {version} (cargo exit {rc})")
        return False
    if not _wait_for_index(crate, version):
        print(f"FAIL  {crate} {version} did not appear in the crates.io index "
              f"within {PROPAGATION_TIMEOUT}s")
        return False
    print(f"OK    published {crate} {version}")
    return True


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Publish the mxc-sdk crate closure to crates.io."
    )
    parser.add_argument("--dry-run", action="store_true",
                        help="package and validate without publishing to crates.io")
    parser.add_argument("--manifest-path", default="src/Cargo.toml",
                        help="workspace manifest (default: src/Cargo.toml)")
    args = parser.parse_args()

    if not args.dry_run and not os.environ.get("CARGO_REGISTRY_TOKEN"):
        print("CARGO_REGISTRY_TOKEN is not set; cannot publish to crates.io")
        return 1

    versions = _workspace_versions(args.manifest_path)
    missing = [crate for crate in CRATES if crate not in versions]
    if missing:
        print("Crates not found in workspace metadata: " + ", ".join(missing))
        return 1

    mode = "DRY RUN" if args.dry_run else "PUBLISH"
    print(f"=== crates.io {mode}: {len(CRATES)} crates (leaf-first) ===")
    for crate in CRATES:
        print(f"  {crate} {versions[crate]}")
    print(flush=True)

    for crate in CRATES:
        if not _publish_one(crate, versions[crate], args.manifest_path, args.dry_run):
            print(f"\nAborting: {crate} failed.")
            return 1

    print(f"\n=== crates.io {mode} complete: all {len(CRATES)} crates OK ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())
