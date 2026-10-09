#!/usr/bin/env python3
"""Seed the public MxcDependencies feeds from pinned repository dependencies.

The Cargo feed can be read without credentials, so cargo does not send a token when it
reads. As a result, cargo cannot make Azure Artifacts pull a missing crate from its
crates.io upstream. This script instead sends an authenticated request for each locked
crate, which makes the feed fetch and cache it. Later credential-free reads then resolve
every dependency.

The NuGet mode reads the pinned IsolationSession package identity and hash, downloads that
public package, verifies it, and publishes it through the authenticated NuGet client.
"""
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import tomllib
import urllib.request
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import NamedTuple

FEED_INDEX_URL = "https://pkgs.dev.azure.com/shine-oss/mxc/_packaging/MxcDependencies/Cargo/index"
CARGO_LOCK = "src/Cargo.lock"
ISOLATION_SESSION_PIN = "src/mxc-sdk/build/build_mxc_build_common.rs"
NUGET_FEED_URL = (
    "https://pkgs.dev.azure.com/shine-oss/mxc/"
    "_packaging/MxcDependencies/nuget/v3/index.json"
)
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


def _read_isolation_session_pin() -> tuple[str, str, str]:
    content = Path(ISOLATION_SESSION_PIN).read_text(encoding="utf-8")

    def constant(name: str) -> str:
        match = re.search(
            rf'pub const {name}: &str =\s*"([^"]+)";',
            content,
        )
        if not match:
            raise RuntimeError(f"Could not read {name} from {ISOLATION_SESSION_PIN}")
        return match.group(1)

    return (
        constant("PACKAGE_ID"),
        constant("PACKAGE_VERSION"),
        constant("PACKAGE_SHA256"),
    )


def _seed_nuget_package() -> None:
    package_id, version, expected_hash = _read_isolation_session_pin()
    lower_id = package_id.lower()
    file_name = f"{lower_id}.{version}.nupkg"
    source_url = f"https://api.nuget.org/v3-flatcontainer/{lower_id}/{version}/{file_name}"

    with tempfile.TemporaryDirectory() as directory:
        package_path = Path(directory) / file_name
        print(f"Downloading {package_id} {version} from NuGet.org for feed seeding")
        with urllib.request.urlopen(source_url, timeout=REQUEST_TIMEOUT) as response:
            package_path.write_bytes(response.read())

        actual_hash = hashlib.sha256(package_path.read_bytes()).hexdigest()
        if actual_hash.lower() != expected_hash.lower():
            raise RuntimeError(
                f"{package_id} {version} hash mismatch: "
                f"expected {expected_hash}, got {actual_hash}"
            )

        subprocess.run(
            [
                "dotnet",
                "nuget",
                "push",
                str(package_path),
                "--source",
                NUGET_FEED_URL,
                "--api-key",
                "AzureDevOps",
                "--skip-duplicate",
            ],
            check=True,
        )
        print(f"Seeded {package_id} {version} into MxcDependencies")


def main() -> int:
    if sys.argv[1:] == ["--nuget-only"]:
        try:
            _seed_nuget_package()
        except (OSError, RuntimeError, subprocess.CalledProcessError) as error:
            print(f"Failed to seed IsolationSession SDK package: {error}")
            return 1
        return 0

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
