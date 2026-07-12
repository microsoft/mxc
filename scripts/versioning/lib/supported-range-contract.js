// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

const {
  compareMajorMinor,
  compareVersions,
  majorMinor,
  parseMajorMinor,
  parseVersion,
} = require("./version");

function parseInputs({
  previousVersion,
  newVersion,
  minVersion,
  generatedStableFloor,
}) {
  return {
    previous: parseVersion(previousVersion),
    next: parseVersion(newVersion),
    min: parseVersion(minVersion),
    generatedFloor: parseVersion(generatedStableFloor),
  };
}

function validateGeneratedStableFloor(previous, current) {
  if (previous !== undefined && previous !== current) {
    return [
      `generatedStableFloor is immutable once introduced (${previous} -> ${current})`,
    ];
  }
  return [];
}

function validateMinHistory(previous, current) {
  const previousVersion = parseVersion(previous);
  const currentVersion = parseVersion(current);
  if (!previousVersion || !currentVersion) {
    return ["previous or current min is not valid semver"];
  }
  if (compareMajorMinor(currentVersion, previousVersion) < 0) {
    return [
      `min cannot move backward from the ${majorMinor(previousVersion)} line to the ${majorMinor(currentVersion)} line`,
    ];
  }
  return [];
}

function validatePreFloorDevLine(
  stableLatest,
  maxSupported,
  generatedStableFloor
) {
  const stable = parseVersion(stableLatest);
  const maximum = parseVersion(maxSupported);
  const generatedFloor = parseVersion(generatedStableFloor);
  if (!stable || !maximum || !generatedFloor) {
    return ["stableLatest, maxSupported, or generatedStableFloor is not valid semver"];
  }
  if (
    compareVersions(stable, generatedFloor) < 0 &&
    compareMajorMinor(maximum, generatedFloor) !== 0
  ) {
    return [
      `maxSupported must remain on the ${majorMinor(generatedFloor)} line until generatedStableFloor ${generatedFloor.raw} is released`,
    ];
  }
  return [];
}

function evaluateSupportedRange({
  previousVersion,
  newVersion,
  minVersion,
  generatedStableFloor,
  breaks,
}) {
  const errors = [];
  const parsed = parseInputs({
    previousVersion,
    newVersion,
    minVersion,
    generatedStableFloor,
  });
  for (const [name, value] of Object.entries(parsed)) {
    if (!value) errors.push(`${name} version is not valid semver`);
  }
  if (errors.length) return { errors, mode: "invalid" };

  if (compareVersions(parsed.next, parsed.previous) <= 0) {
    errors.push(
      `new stable version ${parsed.next.raw} must be newer than ${parsed.previous.raw}`
    );
    return { errors, mode: "invalid" };
  }

  const previousLine = parseMajorMinor(majorMinor(parsed.previous));
  const nextLine = parseMajorMinor(majorMinor(parsed.next));
  const minLine = parseMajorMinor(majorMinor(parsed.min));
  const legacyBoundary =
    compareVersions(parsed.previous, parsed.generatedFloor) < 0 &&
    compareVersions(parsed.next, parsed.generatedFloor) >= 0;

  if (legacyBoundary) {
    if (compareVersions(parsed.next, parsed.generatedFloor) !== 0) {
      errors.push(
        `the first generated stable schema must be exactly ${parsed.generatedFloor.raw}, not ${parsed.next.raw}`
      );
    }
    if (compareMajorMinor(minLine, nextLine) < 0) {
      errors.push(
        `the first generated stable schema ${parsed.next.raw} cannot prove structural compatibility ` +
          `with legacy ${parsed.previous.raw}; advance min to the ${majorMinor(parsed.next)} line`
      );
    }
    return { errors, mode: "legacy-boundary" };
  }

  if (compareVersions(parsed.previous, parsed.generatedFloor) < 0) {
    errors.push(
      `compatibility between legacy schemas before ${parsed.generatedFloor.raw} is not evaluated by this gate`
    );
    return { errors, mode: "legacy" };
  }

  if (breaks.length > 0) {
    if (compareMajorMinor(previousLine, nextLine) === 0) {
      errors.push(
        `breaking changes cannot ship within the ${majorMinor(parsed.next)} line because the parser compares only major.minor`
      );
    } else if (compareMajorMinor(minLine, nextLine) < 0) {
      errors.push(
        `${parsed.next.raw} breaks ${parsed.previous.raw}, but min ${parsed.min.raw} still advertises older schema lines; ` +
          `advance min to the ${majorMinor(parsed.next)} line`
      );
    }
  }

  return { errors, mode: "generated" };
}

module.exports = {
  evaluateSupportedRange,
  validateGeneratedStableFloor,
  validateMinHistory,
  validatePreFloorDevLine,
};
