#!/usr/bin/env python3
"""Seed the public MxcDependencies cargo feed from src/Cargo.lock.

The feed can be read without credentials, so cargo does not send a token when it reads.
As a result, cargo cannot make Azure Artifacts pull a missing crate from its crates.io
upstream. This script instead sends an authenticated request for each locked crate, which
makes the feed fetch and cache it. Later credential-free reads then resolve every dependency.

The script only reads Cargo.lock and never runs cargo or build scripts, so it is safe to run
against a fork's lockfile.
"""
import json
import os
import sys
import tomllib
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import NamedTuple

FEED_INDEX_URL = "https://pkgs.dev.azure.com/shine-oss/mxc/_packaging/MxcDependencies/Cargo/index"
CARGO_LOCK = "src/Cargo.lock"
MAX_WORKERS = 16
REQUEST_TIMEOUT = 30  # seconds; fail a stuck request instead of hanging the job


class Crate(NamedTuple):
    name: str
    version: str


class _NoFollowRedirects(urllib.request.HTTPRedirectHandler):
    """Return the feed's redirect response instead of following it.

    An authenticated request for an uncached crate triggers the upstream save and then
    answers with a 302 to blob storage. The save has already happened, so following the
    redirect would only download the crate and resend the token to another host.
    """

    def http_error_302(self, req, fp, code, msg, headers):
        return fp

    # Route every other redirect status through the same no-follow handler.
    http_error_301 = http_error_303 = http_error_307 = http_error_308 = http_error_302


_opener = urllib.request.build_opener(_NoFollowRedirects)


def _authenticated_get(url: str, token: str) -> None:
    request = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
    try:
        _opener.open(request, timeout=REQUEST_TIMEOUT).close()
    except OSError as error:
        raise RuntimeError(f"{url}: {error}") from error


def _sparse_index_path(name: str) -> str:
    """Path cargo uses to locate a crate in a sparse index."""
    name = name.lower()
    if len(name) == 1:
        return f"1/{name}"
    if len(name) == 2:
        return f"2/{name}"
    if len(name) == 3:
        return f"3/{name[0]}/{name}"
    return f"{name[:2]}/{name[2:4]}/{name}"


def _seed_crate(crate: Crate, download_template: str, token: str) -> None:
    _authenticated_get(f"{FEED_INDEX_URL}/{_sparse_index_path(crate.name)}", token)
    download_url = download_template.replace("{crate}", crate.name).replace("{version}", crate.version)
    _authenticated_get(download_url, token)


def _read_locked_crates() -> list[Crate]:
    with open(CARGO_LOCK, "rb") as lockfile:
        packages = tomllib.load(lockfile).get("package", [])
    return [
        Crate(package["name"], package["version"])
        for package in packages
        if "crates.io" in package.get("source", "")
    ]


def main() -> int:
    token = os.environ.get("SYSTEM_ACCESSTOKEN")
    if not token:
        print("SYSTEM_ACCESSTOKEN is not set; cannot authenticate to the feed")
        return 1

    with urllib.request.urlopen(f"{FEED_INDEX_URL}/config.json") as response:
        download_template = json.load(response)["dl"]

    crates = _read_locked_crates()
    print(f"Seeding {len(crates)} crates.io crates into MxcDependencies")

    failures: list[str] = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        future_to_crate = {
            pool.submit(_seed_crate, crate, download_template, token): crate for crate in crates
        }
        for future in as_completed(future_to_crate):
            crate = future_to_crate[future]
            try:
                future.result()
            except RuntimeError as error:
                failures.append(f"{crate.name} {crate.version}: {error}")

    if failures:
        print(f"Failed to seed {len(failures)} of {len(crates)} crates:")
        for failure in sorted(failures):
            print(f"  {failure}")
        return 1

    print(f"Seeded all {len(crates)} crates")
    return 0


if __name__ == "__main__":
    sys.exit(main())
