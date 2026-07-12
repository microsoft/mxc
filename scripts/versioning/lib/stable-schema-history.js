// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

const {
  compareVersions,
  majorMinor,
  parseVersion,
} = require("./version");

const FILE_RE = /^mxc-config\.schema\.(.+)\.json$/;

function versionForFile(file) {
  const match = FILE_RE.exec(file);
  return match ? parseVersion(match[1]) : null;
}

function highestVersion(files, errors, label) {
  const versions = [];
  for (const file of files.keys()) {
    const version = versionForFile(file);
    if (!version) {
      errors.push(`${label} contains unexpected file "${file}"`);
    } else {
      versions.push(version);
    }
  }
  versions.sort(compareVersions);
  return versions.length ? versions[versions.length - 1] : null;
}

function validateStableHistory({
  baseFiles,
  currentFiles,
  baseSchemaVersion,
  currentSchemaVersion,
  baseDevSchemaContent,
  currentDevSchemaContent,
  baseStabilityContent,
  currentStabilityContent,
}) {
  const errors = [];

  for (const [file, baseContent] of baseFiles) {
    if (!currentFiles.has(file)) {
      errors.push(`released stable schema "${file}" was deleted`);
    } else if (currentFiles.get(file) !== baseContent) {
      errors.push(`released stable schema "${file}" was modified`);
    }
  }

  const added = [...currentFiles.keys()].filter((file) => !baseFiles.has(file));
  if (added.length > 1) {
    errors.push(`a release change may add only one stable schema, found: ${added.join(", ")}`);
  }

  const baseHighest = highestVersion(baseFiles, errors, "base stable directory");
  const currentHighest = highestVersion(
    currentFiles,
    errors,
    "current stable directory"
  );
  const baseLatest = parseVersion(baseSchemaVersion.stableLatest);
  const currentLatest = parseVersion(currentSchemaVersion.stableLatest);
  if (!baseLatest) {
    errors.push(
      `base stableLatest "${baseSchemaVersion.stableLatest}" is not valid semver`
    );
  }
  if (!currentLatest) {
    errors.push(
      `current stableLatest "${currentSchemaVersion.stableLatest}" is not valid semver`
    );
  }
  if (
    baseHighest &&
    baseLatest &&
    compareVersions(baseHighest, baseLatest) !== 0
  ) {
    errors.push(
      `base stableLatest ${baseLatest.raw} is not the highest base stable schema (${baseHighest.raw})`
    );
  }
  if (
    currentHighest &&
    currentLatest &&
    compareVersions(currentHighest, currentLatest) !== 0
  ) {
    errors.push(
      `stableLatest ${currentLatest.raw} is not the highest current stable schema (${currentHighest.raw})`
    );
  }

  let newVersion = null;
  if (added.length === 0) {
    if (baseSchemaVersion.stableLatest !== currentSchemaVersion.stableLatest) {
      errors.push(
        `stableLatest changed ${baseSchemaVersion.stableLatest} -> ${currentSchemaVersion.stableLatest} without adding a stable schema`
      );
    }
  } else if (added.length === 1) {
    newVersion = versionForFile(added[0]);
    if (!newVersion) {
      errors.push(`new stable file "${added[0]}" does not encode a semver version`);
    } else {
      if (currentSchemaVersion.stableLatest !== newVersion.raw) {
        errors.push(
          `new stable schema ${newVersion.raw} must equal stableLatest ${currentSchemaVersion.stableLatest}`
        );
      }
      if (baseLatest && compareVersions(newVersion, baseLatest) <= 0) {
        errors.push(
          `new stable schema ${newVersion.raw} must be newer than ${baseLatest.raw}`
        );
      }
      if (majorMinor(newVersion) !== majorMinor(currentSchemaVersion.maxSupported)) {
        errors.push(
          `new stable schema ${newVersion.raw} must share the dev line ${currentSchemaVersion.maxSupported}`
        );
      }
    }

    if (baseSchemaVersion.maxSupported !== currentSchemaVersion.maxSupported) {
      errors.push(
        "a stable-freeze change must not advance maxSupported in the same change"
      );
    }
    if (baseSchemaVersion.devSchemaFile !== currentSchemaVersion.devSchemaFile) {
      errors.push(
        "a stable-freeze change must not advance devSchemaFile in the same change"
      );
    }
    if (baseDevSchemaContent !== currentDevSchemaContent) {
      errors.push(
        "a stable-freeze change must not modify the dev schema in the same change"
      );
    }
    if (baseStabilityContent !== currentStabilityContent) {
      errors.push(
        "a stable-freeze change must not modify config-stability.json in the same change"
      );
    }
  }

  return { errors, newVersion };
}

module.exports = { validateStableHistory };
