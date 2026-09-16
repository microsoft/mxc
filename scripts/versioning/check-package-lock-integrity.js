#!/usr/bin/env node
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

const { execFileSync } = require("child_process");
const { readFileSync } = require("fs");
const {
  dirname,
  isAbsolute,
  relative,
  resolve,
  sep,
} = require("path");

function hasSha512Integrity(value) {
  if (typeof value !== "string") {
    return false;
  }

  return value.split(/\s+/).some((token) => {
    if (!token.startsWith("sha512-")) {
      return false;
    }

    const digest = token.slice("sha512-".length).split("?", 1)[0];
    if (!/^[A-Za-z0-9+/]+={0,2}$/.test(digest)) {
      return false;
    }

    return Buffer.from(digest, "base64").length === 64;
  });
}

function jsonPath(parent, key) {
  return `${parent}[${JSON.stringify(key)}]`;
}

function isNpmRegistryUrl(value) {
  try {
    const url = new URL(value);
    return (
      url.protocol === "https:" &&
      url.hostname.toLowerCase() === "registry.npmjs.org" &&
      url.port === "" &&
      url.username === "" &&
      url.password === ""
    );
  } catch {
    return false;
  }
}

function localDependencyTarget(value, lockfileDirectory, repoRoot) {
  let candidate;
  if (value.startsWith("file:")) {
    candidate = value.slice("file:".length);
  } else if (/^\.{1,2}(?:[\\/]|$)/.test(value)) {
    candidate = value;
  } else {
    return null;
  }

  if (
    candidate.length === 0 ||
    candidate.startsWith("~") ||
    /^[A-Za-z]:/.test(candidate) ||
    /^[/\\]{2}/.test(candidate)
  ) {
    return null;
  }

  const normalizedCandidate = candidate.replace(/[\\/]+/g, sep);
  if (isAbsolute(normalizedCandidate)) {
    return null;
  }

  const target = resolve(lockfileDirectory, normalizedCandidate);
  const relativeTarget = relative(repoRoot, target);
  if (
    relativeTarget === ".." ||
    relativeTarget.startsWith(`..${sep}`) ||
    isAbsolute(relativeTarget)
  ) {
    return null;
  }

  return target;
}

function inspectPackageEntry(
  packagePath,
  entry,
  path,
  issues,
  lockfileDirectory,
  repoRoot
) {
  if (entry === null || typeof entry !== "object" || Array.isArray(entry)) {
    issues.push(`${path}: package entry must be an object`);
    return;
  }

  const hasIntegrity = Object.hasOwn(entry, "integrity");
  if (hasIntegrity && !hasSha512Integrity(entry.integrity)) {
    issues.push(`${jsonPath(path, "integrity")}: lacks a valid SHA-512 hash`);
  }

  const resolvedPath = jsonPath(path, "resolved");
  if (Object.hasOwn(entry, "resolved") && typeof entry.resolved !== "string") {
    issues.push(`${resolvedPath}: must be a string`);
    return;
  }

  if (typeof entry.resolved === "string") {
    const localTarget = localDependencyTarget(
      entry.resolved,
      lockfileDirectory,
      repoRoot
    );

    if (entry.link === true) {
      if (localTarget === null) {
        issues.push(
          `${resolvedPath}: linked package must resolve within the repository`
        );
      }
      return;
    }

    if (localTarget !== null) {
      return;
    }
    if (!isNpmRegistryUrl(entry.resolved)) {
      issues.push(
        `${resolvedPath}: must use ` +
          "https://registry.npmjs.org or resolve within the repository"
      );
    } else if (!hasIntegrity) {
      issues.push(
        `${jsonPath(path, "integrity")}: npmjs artifact lacks a SHA-512 hash`
      );
    }
    return;
  }

  if (
    packagePath === "" ||
    entry.inBundle === true ||
    !/(^|\/)node_modules\//.test(packagePath)
  ) {
    return;
  }

  if (entry.link === true) {
    issues.push(`${resolvedPath}: linked package must declare a local target`);
  } else {
    issues.push(
      `${resolvedPath}: installed package must declare its npmjs or local source`
    );
  }
}

function trackedPackageLocks(repoRoot) {
  const output = execFileSync("git", ["-C", repoRoot, "ls-files", "-z"], {
    encoding: "buffer",
  });

  return output
    .toString("utf8")
    .split("\0")
    .filter(
      (path) =>
        path === "package-lock.json" || path.endsWith("/package-lock.json")
    )
    .sort();
}

function checkPackageLocks(repoRoot) {
  const files = trackedPackageLocks(repoRoot);
  const issues = [];

  for (const file of files) {
    const lockfilePath = resolve(repoRoot, file);
    let lockfile;
    try {
      lockfile = JSON.parse(readFileSync(lockfilePath, "utf8"));
    } catch (error) {
      issues.push(`${file}: invalid JSON: ${error.message}`);
      continue;
    }

    const fileIssues = [];
    if (
      lockfile.packages === null ||
      typeof lockfile.packages !== "object" ||
      Array.isArray(lockfile.packages)
    ) {
      fileIssues.push(
        '$["packages"]: package-lock.json must contain a packages object'
      );
    } else {
      for (const [packagePath, entry] of Object.entries(lockfile.packages)) {
        inspectPackageEntry(
          packagePath,
          entry,
          jsonPath('$["packages"]', packagePath),
          fileIssues,
          dirname(lockfilePath),
          repoRoot
        );
      }
    }
    issues.push(...fileIssues.map((issue) => `${file}: ${issue}`));
  }

  return { files, issues };
}

function main() {
  let repoRoot;
  try {
    repoRoot = execFileSync("git", ["rev-parse", "--show-toplevel"], {
      encoding: "utf8",
    }).trim();
  } catch (error) {
    console.error(`Package lock integrity check FAILED: ${error.message}`);
    process.exit(1);
  }

  const { files, issues } = checkPackageLocks(repoRoot);
  if (issues.length > 0) {
    console.error("Package lock integrity check FAILED:");
    for (const issue of issues) {
      console.error(`  ${issue}`);
    }
    process.exit(1);
  }

  console.log(
    `Package lock integrity check OK: ${files.length} tracked lockfile(s).`
  );
}

if (require.main === module) {
  main();
}
