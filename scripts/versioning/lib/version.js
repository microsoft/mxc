// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

function parseVersion(value) {
  if (typeof value !== "string" || value.length > 256) return null;
  const match =
    /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$/.exec(
      value || ""
    );
  if (!match) return null;
  const core = match.slice(1, 4).map(Number);
  if (core.some((part) => !Number.isSafeInteger(part))) return null;
  const prerelease = match[4] || "";
  if (
    prerelease
      .split(".")
      .some((identifier) => /^\d+$/.test(identifier) && identifier.length > 1 && identifier[0] === "0")
  ) {
    return null;
  }
  return {
    major: core[0],
    minor: core[1],
    patch: core[2],
    prerelease,
    build: match[5] || "",
    raw: value,
  };
}

function comparePrerelease(a, b) {
  if (a === b) return 0;
  if (!a) return 1;
  if (!b) return -1;

  const left = a.split(".");
  const right = b.split(".");
  for (let i = 0; i < Math.max(left.length, right.length); i++) {
    if (left[i] === undefined) return -1;
    if (right[i] === undefined) return 1;

    const leftNumeric = /^\d+$/.test(left[i]);
    const rightNumeric = /^\d+$/.test(right[i]);
    if (leftNumeric && rightNumeric) {
      const difference = Number(left[i]) - Number(right[i]);
      if (difference) return difference < 0 ? -1 : 1;
    } else if (leftNumeric !== rightNumeric) {
      return leftNumeric ? -1 : 1;
    } else if (left[i] !== right[i]) {
      return left[i] < right[i] ? -1 : 1;
    }
  }
  return 0;
}

function compareVersions(a, b) {
  if (a.major !== b.major) return a.major - b.major;
  if (a.minor !== b.minor) return a.minor - b.minor;
  if (a.patch !== b.patch) return a.patch - b.patch;
  return comparePrerelease(a.prerelease, b.prerelease);
}

function majorMinor(value) {
  const parsed = typeof value === "string" ? parseVersion(value) : value;
  return parsed ? `${parsed.major}.${parsed.minor}` : null;
}

function parseMajorMinor(value) {
  const match = /^(0|[1-9]\d*)\.(0|[1-9]\d*)$/.exec(value || "");
  return match ? { major: Number(match[1]), minor: Number(match[2]), raw: value } : null;
}

function compareMajorMinor(a, b) {
  if (a.major !== b.major) return a.major - b.major;
  return a.minor - b.minor;
}

module.exports = {
  compareMajorMinor,
  compareVersions,
  majorMinor,
  parseMajorMinor,
  parseVersion,
};
