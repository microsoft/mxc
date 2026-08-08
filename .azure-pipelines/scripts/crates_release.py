#!/usr/bin/env python3
"""crates.io release helper for the `mxc-sdk` crate closure, ESRP edition.

MXC publishes crates through ESRP Release under the official
`microsoft-oss-releases` account. ESRP accepts pre-built `.crate` files, so this
repository never handles a `CARGO_REGISTRY_TOKEN`. See:
https://eng.ms/docs/microsoft-security/identity/trust-and-security-services/tss-release-distribute/tss-release-esrp-parent/oss-publishing/releasing-open-source/cratesio

ESRP does not sort a multi-crate dependency graph. The pipeline publishes one
crate at a time in leaf-first order, an order this helper validates offline
against the workspace's real dependency edges.

The release pool enforces 1ES network isolation (CFSClean), which blocks
crates.io. This helper therefore performs NO crates.io reads. The guarantees
that used to depend on them are covered earlier or elsewhere:

  * a dependency's version requirement matching its real version is enforced by
    `cargo package` itself at packaging time (it fails the build);
  * leaf-first ordering is enforced offline by `_validate_release_graph`;
  * a dependency crate existing at all is enforced server-side by crates.io,
    which rejects a publish naming an unknown crate;
  * yank detection and the published-checksum audit are out-of-band concerns
    and do not belong in the isolated release job.

Subcommands
-----------
package       Validate and package the complete first-party closure, then write
              `.crate` files and release-order.json.

order         Print the leaf-first publish order, derived from `cargo metadata`.
              Developer-facing: paste its output over the `crateOrder` default
              in templates/Publish.CratesIo.Job.yml. Not used by the pipeline.

verify-order  Assert that the crates the pipeline is about to publish are a
              correctly-ordered subset of what was packaged. A partial subset is
              allowed so an operator can resume a release that failed partway.

stage         Copy one `.crate` file into a clean directory for an ESRP task,
              re-checking its recorded SHA-256 first.

Resuming a failed release
-------------------------
There is no automated resume. crates.io rejects a duplicate version outright, so
re-running a partially-completed release unchanged fails on the first crate that
already landed. The isolated pool cannot ask crates.io what landed, so the
operator asserts it: re-queue the release with the finished crates removed from
the `crateOrder` parameter. `verify-order` still enforces that whatever remains
is published in correct leaf-first order, and logs every dependency it is
therefore assuming is already live.
"""
from __future__ import annotations

import argparse

import hashlib
import json
import os
import shutil
import subprocess
import sys

# Cargo package names in the crates.io release closure. These names remain
# provisional until the public naming scheme is approved; the crates.io release
# pipeline (.azure-pipelines/1ES.Release.Crates.yml) is manual-trigger only and
# defaults to a dry run, so nothing reaches crates.io until that is settled.
#
# ORDER HERE IS NOT MEANINGFUL.  This is the SET of packages to publish.  The
# publish order is a topological sort of the dependency graph computed by
# _release_order() from `cargo metadata`, so no one maintains a leaf-first
# ordering by hand.  The list is kept in dependency order below purely because
# it reads well next to the pipeline logs.
#
# ADDING A CRATE:
#
#   1. Add the package name to this list.  Anywhere.
#   2. Regenerate the template's crateOrder and paste the output over it:
#        python3 .azure-pipelines/scripts/crates_release.py order
#      (writes YAML lines for the `crateOrder` default in
#      .azure-pipelines/templates/Publish.CratesIo.Job.yml)
#
# That is the whole procedure.  `order` validates the graph before printing,
# so a bad edit produces a named error rather than a list that fails mid
# release.  Forgetting step 1 is caught too: _validate_release_graph fails
# packaging with "local dependency is missing from CRATES" as soon as any
# published crate depends on the new one.
#
# The pipeline cannot use `cargo publish --workspace` (which would order the
# publish itself) because ESRP performs the upload, one .crate file at a time,
# so the order has to exist as data rather than as cargo's internal plan.
CRATES: list[str] = [
    "nanvix_common",
    "mxc_telemetry",
    "wxc_common",
    "nanvix_runner",
    "hyperlight_common",
    "mxc_pty",
    "lxc_common",
    "bwrap_common",
    "seatbelt_common",
    "sandbox_spec",
    "process_security_environment_spec",
    "learning_mode_core",
    "learning_mode_windows",
    "appcontainer_common",
    "isolation_session_bindings",
    "isolation_session_common",
    "windows_sandbox_common",
    "windows_sandbox_lifecycle",
    "wslc_common",
    "mxc_engine",
    "mxc-sdk",
]

# The pipeline packages this list on a Windows, a Linux, and a macOS agent, so
# every crate here has to compile on all three.  A platform-specific crate
# gates its code with cfg and builds to an empty library elsewhere.


def _cargo_metadata(manifest_path: str) -> dict:
    result = subprocess.run(
        [
            "cargo",
            "metadata",
            "--no-deps",
            "--format-version",
            "1",
            "--manifest-path",
            manifest_path,
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(result.stdout)


def _run(args: list[str], cwd: str | None = None) -> int:
    print("+ " + " ".join(args), flush=True)
    return subprocess.run(args, cwd=cwd).returncode


def _load_order(order_file: str) -> list[dict]:
    with open(order_file, encoding="utf-8") as fh:
        return json.load(fh)["crates"]


def _entry_for_crate(order_file: str, crate: str) -> dict | None:
    return next(
        (
            entry
            for entry in _load_order(order_file)
            if entry["name"] == crate
        ),
        None,
    )


def _crate_file(order_file: str, entry: dict) -> str:
    return os.path.join(
        os.path.dirname(os.path.abspath(order_file)),
        entry["file"],
    )


def _sha256(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _release_order(metadata: dict) -> list[str]:
    """Return the publish order: a leaf-first topological sort of CRATES.

    This is the single source of truth for ordering.  CRATES itself carries no
    ordering meaning -- it is the SET of packages to publish -- so nobody has to
    maintain a topological sort by hand.  Ties are broken alphabetically, which
    makes the output stable across runs and keeps diffs readable.

    Names absent from the workspace metadata are dropped here and reported by
    _validate_release_graph, so a typo surfaces as a clear validation error
    rather than a confusing cycle.
    """
    packages = {package["name"]: package for package in metadata["packages"]}
    wanted = {crate for crate in CRATES if crate in packages}

    edges: dict[str, set[str]] = {
        name: {
            dependency["name"]
            for dependency in packages[name]["dependencies"]
            if dependency.get("path") and dependency["name"] in wanted
            and _survives_publish(dependency)
        }
        for name in wanted
    }

    ordered: list[str] = []
    placed: set[str] = set()
    while len(ordered) < len(wanted):
        ready = sorted(name for name in wanted - placed if edges[name] <= placed)
        if not ready:
            remaining = ", ".join(sorted(wanted - placed))
            raise RuntimeError(
                "dependency cycle among publishable crates: " + remaining
            )
        ordered.extend(ready)
        placed.update(ready)
    return ordered


def _survives_publish(dependency: dict) -> bool:
    """Whether a path dependency is still named in the published manifest.

    Cargo rewrites path dependencies into registry dependencies when packaging
    and drops the ones carrying no version, so a version-less dev-dependency
    never reaches crates.io and never needs a release slot.
    """
    return dependency.get("req") not in (None, "*")


def _validate_release_graph(metadata: dict) -> dict[str, list[str]]:
    """Validate the full local dependency closure and return its edges."""
    packages = {package["name"]: package for package in metadata["packages"]}
    order = _release_order(metadata)
    positions = {crate: index for index, crate in enumerate(order)}
    dependencies: dict[str, list[str]] = {}
    errors: list[str] = []

    if len(set(CRATES)) != len(CRATES):
        errors.append("CRATES contains duplicate package names")

    for crate in CRATES:
        package = packages.get(crate)
        if package is None:
            errors.append(f"{crate}: not found in workspace metadata")
            continue

        allowed_registries = package.get("publish")
        if allowed_registries == []:
            errors.append(f"{crate}: package has publish = false")
        elif (
            allowed_registries is not None
            and "crates-io" not in allowed_registries
        ):
            errors.append(
                f"{crate}: package publish list does not include crates-io"
            )

        local_dependencies: list[str] = []
        for dependency in package["dependencies"]:
            dependency_name = dependency["name"]
            if not dependency.get("path") or dependency_name not in packages:
                continue
            if not _survives_publish(dependency):
                if dependency.get("kind") == "dev":
                    continue
                errors.append(
                    f"{crate} -> {dependency_name}: local dependency is missing "
                    "a registry version"
                )
            if dependency_name not in positions:
                errors.append(
                    f"{crate} -> {dependency_name}: local dependency is missing "
                    "from CRATES"
                )
                continue
            # Guaranteed by the topological sort, so a failure here is a bug in
            # _release_order rather than bad input.  Cheap to assert, and it
            # would otherwise surface as a mid-release crates.io rejection.
            if positions[dependency_name] >= positions[crate]:
                errors.append(
                    f"{crate} -> {dependency_name}: computed order places a "
                    "dependency after its dependent"
                )
            local_dependencies.append(dependency_name)

        dependencies[crate] = sorted(
            set(local_dependencies),
            key=positions.__getitem__,
        )

    if errors:
        raise RuntimeError(
            "Invalid crates.io release graph:\n  - " + "\n  - ".join(errors)
        )
    return dependencies


def cmd_package(args: argparse.Namespace) -> int:
    metadata = _cargo_metadata(args.manifest_path)
    versions = {
        package["name"]: package["version"]
        for package in metadata["packages"]
    }
    try:
        dependencies = _validate_release_graph(metadata)
    except RuntimeError as error:
        print(f"FAIL  {error}")
        return 1

    # The packaged order is the derived order, never CRATES' literal order --
    # that is what lets CRATES stay an unordered set of names.
    order = _release_order(metadata)

    target_dir = metadata["target_directory"]
    package_dir = os.path.join(target_dir, "package")
    out_dir = os.path.abspath(args.out_dir)
    os.makedirs(out_dir, exist_ok=True)

    print(f"=== cargo package: {len(order)} crates (leaf-first) ===")
    for crate in order:
        print(f"  {crate} {versions[crate]}")
    print(flush=True)

    manifest = os.path.abspath(args.manifest_path)
    # Verification stays on. Passing --registry (rather than the default
    # crates-io) is what makes cargo resolve sibling crates against the
    # temporary package registry, so the overlay bug in cargo#17196 does not
    # apply here and --no-verify is unnecessary. --allow-dirty is likewise
    # omitted: the only file the pipeline modifies is the workspace
    # .cargo/config.toml, which lies outside every package directory, so a
    # dirty-tree failure here means a crate source really was modified.

    package_args = [
        "cargo",
        "package",
        "--registry",
        args.registry,
        "--manifest-path",
        manifest,
    ]
    for crate in order:
        package_args += ["-p", crate]
    rc = _run(package_args)
    if rc != 0:
        print(f"FAIL  cargo package exited {rc}", flush=True)
        return 1

    ordered: list[dict] = []
    for crate in order:
        version = versions[crate]
        crate_file = f"{crate}-{version}.crate"
        source = os.path.join(package_dir, crate_file)
        if not os.path.isfile(source):
            print(f"FAIL  expected {source} was not produced by cargo package")
            return 1
        destination = os.path.join(out_dir, crate_file)
        shutil.copy2(source, destination)
        ordered.append(
            {
                "name": crate,
                "version": version,
                "file": crate_file,
                # Recorded so an out-of-band auditor can confirm what crates.io
                # actually serves matches what this build produced. The release
                # job itself cannot check that -- crates.io is unreachable from
                # the isolated pool.
                "sha256": _sha256(destination),
                "dependencies": dependencies[crate],
            }
        )
        print(f"OK    packaged {crate_file}", flush=True)

    order_path = os.path.join(out_dir, "release-order.json")
    with open(order_path, "w", encoding="utf-8") as fh:
        json.dump({"crates": ordered}, fh, indent=2)
    print(f"\nWrote {order_path}")
    print(f"=== packaged {len(ordered)} crates into {out_dir} ===")
    return 0


def cmd_verify_order(args: argparse.Namespace) -> int:
    entries = _load_order(args.order_file)
    packaged = [entry["name"] for entry in entries]
    by_name = {entry["name"]: entry for entry in entries}
    requested = json.loads(args.expected)

    if len(set(requested)) != len(requested):
        print("The crateOrder parameter lists the same crate more than once.")
        return 1

    unknown = [name for name in requested if name not in by_name]
    if unknown:
        print(
            "The crateOrder parameter names crates that were not packaged: "
            f"{unknown}"
        )
        print(f"  release-order.json : {packaged}")
        return 1

    # A release may deliberately publish a SUBSET of the packaged closure: that
    # is how an operator resumes a run that failed partway through. The release
    # pool cannot ask crates.io what already landed (network isolation), so the
    # operator asserts it by removing the finished crates from crateOrder.
    # The subset must remain a SUBSEQUENCE of the packaged leaf-first order, so
    # that whatever is published is still published in dependency order.
    remaining = iter(packaged)
    if not all(name in remaining for name in requested):
        print(
            "The crateOrder parameter is not in packaged leaf-first order. It "
            "must list a subset of the packaged crates in the same relative "
            "order."
        )
        print(f"  pipeline crateOrder : {requested}")
        print(f"  release-order.json  : {packaged}")
        return 1

    positions = {name: index for index, name in enumerate(requested)}
    assumed_published: list[str] = []
    for name in requested:
        entry = by_name[name]
        if "dependencies" not in entry:
            print(f"Crate {name} is missing dependency metadata.")
            return 1
        for dependency in entry["dependencies"]:
            if dependency not in by_name:
                print(f"Crate {name} depends on unpackaged crate {dependency}.")
                return 1
            if dependency not in positions:
                assumed_published.append(f"{name} -> {dependency}")
                continue
            if positions[dependency] >= positions[name]:
                print(f"Crate {name} appears before dependency {dependency}.")
                return 1

    if len(requested) == len(packaged):
        print(f"Crate order verified ({len(packaged)} crates, leaf-first).")
        return 0

    skipped = [name for name in packaged if name not in positions]
    print(
        f"Crate order verified ({len(requested)} of {len(packaged)} crates, "
        "leaf-first)."
    )
    print(
        "##vso[task.logissue type=warning]PARTIAL RELEASE: publishing "
        f"{len(requested)} of {len(packaged)} packaged crates. Skipping: "
        f"{skipped}"
    )
    for edge in assumed_published:
        print(
            f"##vso[task.logissue type=warning]Assuming already published on "
            f"crates.io: {edge}"
        )
    return 0


def cmd_stage(args: argparse.Namespace) -> int:
    entry = _entry_for_crate(args.order_file, args.crate)
    if entry is None:
        print(f"Crate {args.crate!r} not found in {args.order_file}")
        return 1

    out_dir = os.path.abspath(args.out_dir)
    if os.path.isdir(out_dir):
        shutil.rmtree(out_dir)
    os.makedirs(out_dir, exist_ok=True)

    source = _crate_file(args.order_file, entry)
    if not os.path.isfile(source):
        print(f"Crate file not found: {source}")
        return 1

    # Staging is the last point at which a truncated or substituted archive can
    # be caught: past here ESRP uploads it and the crates.io version is
    # immutable. Fail closed when the digest is missing as well as when it
    # disagrees, so an order file written without one cannot silently skip this.
    expected = entry.get("sha256")
    if not expected:
        print(f"FAIL  no sha256 recorded for {entry['file']} in {args.order_file}")
        return 1
    actual = _sha256(source)
    if actual != expected:
        print(f"FAIL  checksum mismatch for {entry['file']}")
        print(f"      expected {expected}")
        print(f"      actual   {actual}")
        return 1

    shutil.copy2(source, os.path.join(out_dir, entry["file"]))
    print(
        f"Staged {entry['file']} ({args.crate} {entry['version']}) "
        f"into {out_dir} for ESRP, sha256 verified."
    )
    return 0




RESUME_MARKER = "RESUME-SUBSET"


def _template_crate_order(template_path: str) -> tuple[list[str], str | None]:
    """Read the crateOrder default out of Publish.CratesIo.Job.yml.

    Returns the crate names and the resume-subset reason, if one is declared.

    Deliberately a line scan rather than a YAML parse, so this runs anywhere
    python3 does with no third-party module. That trade is only safe because
    this refuses to guess: anything it does not recognize raises instead of
    returning a partial list, since a short list read from a misparse is
    indistinguishable from a short list that was deliberately trimmed, and one
    of those silently skips a crate.
    """
    with open(template_path, encoding="utf-8") as handle:
        lines = handle.read().splitlines()

    def indent_of(text: str) -> int:
        return len(text) - len(text.lstrip())

    def strip_comment(text: str) -> str:
        # Only an unquoted '#' preceded by whitespace opens a comment.
        for pos, char in enumerate(text):
            if char == "#" and (pos == 0 or text[pos - 1].isspace()):
                return text[:pos]
        return text

    matches = [i for i, line in enumerate(lines) if line.strip() == "- name: crateOrder"]
    if not matches:
        raise RuntimeError(f"no 'name: crateOrder' parameter found in {template_path}")
    if len(matches) > 1:
        # Two matches means either a duplicated parameter or text inside a block
        # scalar that merely looks like one. Either way this cannot tell which
        # is authoritative, and picking the wrong one is a silent partial
        # publish, so refuse rather than choose.
        raise RuntimeError(
            f"{template_path} contains {len(matches)} lines reading "
            f"'- name: crateOrder' (lines {[i + 1 for i in matches]}). "
            "Exactly one is required."
        )

    start = matches[0]
    param_indent = indent_of(lines[start])
    resume_reason = None
    names: list[str] = []
    entry_indent = None
    cursor = start + 1
    found_default = False

    while cursor < len(lines):
        raw = lines[cursor]
        body = strip_comment(raw).rstrip()

        if RESUME_MARKER in raw and not found_default:
            resume_reason = raw.split(RESUME_MARKER, 1)[1].lstrip(" :#").strip() or "(no reason given)"

        if not body.strip():
            cursor += 1
            continue

        # A sibling parameter at the same indent ends this block.
        if indent_of(body) <= param_indent and body.strip().startswith("- "):
            break

        if not found_default:
            if body.strip() == "default:":
                found_default = True
            elif indent_of(body) <= param_indent:
                break
            cursor += 1
            continue

        item = body.strip()
        if not item.startswith("- "):
            break
        current_indent = indent_of(body)
        if entry_indent is None:
            entry_indent = current_indent
        elif current_indent != entry_indent:
            break

        name = item[2:].strip().strip("'\"")
        if not name:
            raise RuntimeError(f"{template_path}:{cursor + 1}: empty crateOrder entry")
        if any(ch in name for ch in "[]{},:"):
            # Flow style (`default: [a, b]`) or a nested mapping. Both are legal
            # YAML this scanner cannot read, and guessing produces a wrong list.
            raise RuntimeError(
                f"{template_path}:{cursor + 1}: unsupported crateOrder entry {name!r}. "
                "Write one plain '- crate_name' per line, as `order` emits."
            )
        names.append(name)
        cursor += 1

    if not found_default:
        raise RuntimeError(f"no 'default:' found for crateOrder in {template_path}")
    if not names:
        raise RuntimeError(f"crateOrder default in {template_path} is empty")
    return names, resume_reason


def cmd_check_template(args: argparse.Namespace) -> int:
    """Assert the template's crateOrder equals the computed order.

    Without this, forgetting to regenerate the template fails OPEN rather than
    closed. `verify-order` accepts a subset on purpose, because that is how an
    operator resumes a part-published release -- so a template that is missing a
    newly-added crate passes it, and the crate is silently never published. That
    is only visible as a PARTIAL RELEASE warning in a release log nobody reads
    until afterwards, and a missed publish is not fixable by re-running: the
    crates that did land cannot be republished.

    This runs in two places on purpose. In CI it catches drift at PR time, which
    is where it is cheap to fix. In the release pipeline it catches drift at
    release time, which is where it is irreversible -- CI alone cannot cover
    that, because a release ref can be pushed straight to the remote without
    ever opening a pull request.

    A deliberate resume is the one legitimate reason for the template to hold a
    short list, and it is declared in the template itself with a RESUME-SUBSET
    marker rather than a pipeline parameter, so the release ref carries the
    intent. A resume list still has to be an ordered subsequence of the computed
    order; trimming is allowed, reordering is not.
    """
    metadata = _cargo_metadata(args.manifest_path)
    _validate_release_graph(metadata)
    expected = _release_order(metadata)
    actual, resume_reason = _template_crate_order(args.template_path)

    if resume_reason is not None:
        unknown = [name for name in actual if name not in expected]
        if unknown:
            print(f"FAIL  {args.template_path} declares a resume subset naming unknown crates: {unknown}")
            return 1
        if actual != [name for name in expected if name in set(actual)]:
            print(f"FAIL  {args.template_path} declares a resume subset that is out of dependency order.")
            print(f"    template : {actual}")
            print(f"    required : {[n for n in expected if n in set(actual)]}")
            return 1
        skipped = [name for name in expected if name not in actual]
        print(f"RESUME SUBSET declared in {args.template_path}: {resume_reason}")
        print(f"  publishing {len(actual)} of {len(expected)} crates, in valid dependency order.")
        print(f"  assumed ALREADY PUBLISHED and skipped: {skipped or '(none)'}")
        print("  Remove the RESUME-SUBSET marker and restore the full list on main once the release completes.")
        return 0

    if expected == actual:
        print(f"Crate order in {args.template_path} is up to date ({len(expected)} crates).")
        return 0

    print(f"FAIL  {args.template_path} crateOrder does not match the computed order.")
    missing = [name for name in expected if name not in actual]
    extra = [name for name in actual if name not in expected]
    if missing:
        print(f"  missing from the template (would NOT be published): {missing}")
    if extra:
        print(f"  in the template but not packaged: {extra}")
    if not missing and not extra:
        print("  same crates, different order:")
        print(f"    computed : {expected}")
        print(f"    template : {actual}")
    print()
    print("  Regenerate it and paste the output over the crateOrder default:")
    print("    python3 .azure-pipelines/scripts/crates_release.py order")
    return 1


def cmd_order(args: argparse.Namespace) -> int:
    metadata = _cargo_metadata(args.manifest_path)
    # Validate before printing.  Emitting an order derived from a broken graph
    # would hand the developer a list that fails the release instead of an
    # error naming what is wrong.
    _validate_release_graph(metadata)
    for crate in _release_order(metadata):
        print(f"    - {crate}" if args.format == "yaml" else crate)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    package = sub.add_parser(
        "package",
        help="validate and cargo package the complete closure",
    )
    package.add_argument("--manifest-path", default="src/Cargo.toml")
    package.add_argument("--out-dir", required=True)
    # Which registry cargo resolves unpublished workspace siblings against.
    # Defaults to the private feed because that is the only value known to
    # work: verification is enabled (see cmd_package), and with the default
    # crates-io the overlay bug in rust-lang/cargo#17196 fails the run. Keeping
    # this aligned with the pipeline also means a local repro matches CI.
    package.add_argument("--registry", default="Mxc-Azure-Feed")
    package.set_defaults(func=cmd_package)

    verify_order = sub.add_parser(
        "verify-order",
        help="assert crateOrder matches the packaged dependency graph",
    )
    verify_order.add_argument("--order-file", required=True)
    verify_order.add_argument("--expected", required=True)
    verify_order.set_defaults(func=cmd_verify_order)

    stage = sub.add_parser(
        "stage",
        help="copy one crate into a clean ESRP input directory",
    )
    stage.add_argument("--order-file", required=True)
    stage.add_argument("--crate", required=True)
    stage.add_argument("--out-dir", required=True)
    stage.set_defaults(func=cmd_stage)

    order = sub.add_parser(
        "order",
        help="print the leaf-first publish order for pasting into the template",
    )
    order.add_argument("--manifest-path", default="src/Cargo.toml")
    order.add_argument(
        "--format",
        choices=["yaml", "plain"],
        default="yaml",
        help="yaml (default) emits lines ready to paste into crateOrder",
    )
    order.set_defaults(func=cmd_order)

    # CI-only. Developers never run this: it is what makes forgetting to paste
    # the `order` output a failed build instead of a silently skipped crate.
    check_template = sub.add_parser(
        "check-template",
        help="CI guard: assert the template's crateOrder equals the computed order",
    )
    check_template.add_argument("--manifest-path", default="src/Cargo.toml")
    check_template.add_argument(
        "--template-path",
        default=".azure-pipelines/templates/Publish.CratesIo.Job.yml",
    )
    check_template.set_defaults(func=cmd_check_template)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
