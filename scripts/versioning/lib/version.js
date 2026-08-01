// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Numeric identifiers must not have leading zeros, per SemVer, and must stay
// exactly representable. An unbounded digit run converts to Infinity, and
// Infinity - Infinity is NaN, for which the ordinary `< 0` / `> 0` regression
// checks are all false -- a malformed version would silently pass every
// ordering gate. Reject rather than compare something we cannot order.
function parseNumericIdentifier(text) {
  if (!/^(0|[1-9]\d*)$/.test(text)) return null;
  const value = Number(text);
  return Number.isSafeInteger(value) ? value : null;
}

// SemVer identifier grammars. A prerelease identifier is alphanumeric-or-hyphen
// and, when purely numeric, must not carry leading zeros. Build metadata uses
// the same character set but allows leading zeros, because it never participates
// in ordering.
const PRERELEASE_IDENTIFIER = /^(?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*)$/;
const BUILD_IDENTIFIER = /^[0-9A-Za-z-]+$/;

// Orders two purely numeric prerelease identifiers without converting them to
// `Number`. SemVer leaves these unbounded, so conversion loses precision well
// before the digits run out: two distinct values above 2^53 become the same
// float, and long ones become `Infinity`, whose difference is `NaN` -- falsy,
// so the comparison would report equality and an ordering gate would fail open.
//
// The grammar above has already rejected leading zeros, so both operands are
// canonical: the one with more digits is larger, and at equal length a
// lexicographic comparison is a numeric one. That is exact at any length, so
// unlike the core components these identifiers need no bound.
function compareNumericIdentifiers(left, right) {
  if (left.length !== right.length) return left.length < right.length ? -1 : 1;
  if (left === right) return 0;
  return left < right ? -1 : 1;
}

function validDotSeparated(text, identifier) {
  const parts = text.split(".");
  return parts.length > 0 && parts.every((part) => identifier.test(part));
}

function parseVersion(value) {
  // Only a real string is parsed. `RegExp.exec` coerces its argument, so a
  // single-element array, a boxed String, or any object with a `toString` would
  // otherwise parse -- and `raw` would then carry the non-string, breaking
  // round-tripping as well.
  if (typeof value !== "string") return null;
  const match =
    /^(\d+)\.(\d+)\.(\d+)(?:-([^+]*))?(?:\+(.*))?$/.exec(value || "");
  if (!match) return null;
  const major = parseNumericIdentifier(match[1]);
  const minor = parseNumericIdentifier(match[2]);
  const patch = parseNumericIdentifier(match[3]);
  if (major === null || minor === null || patch === null) return null;
  const prerelease = match[4];
  if (
    prerelease !== undefined &&
    !validDotSeparated(prerelease, PRERELEASE_IDENTIFIER)
  ) {
    return null;
  }
  const build = match[5];
  if (build !== undefined && !validDotSeparated(build, BUILD_IDENTIFIER)) {
    return null;
  }
  return {
    major,
    minor,
    patch,
    prerelease: prerelease || "",
    // Kept for round-tripping only. SemVer requires build metadata to be
    // accepted and then ignored when determining precedence, so it is
    // deliberately absent from every comparison below.
    build: build || "",
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
      const difference = compareNumericIdentifiers(left[i], right[i]);
      if (difference) return difference;
    } else if (leftNumeric !== rightNumeric) {
      return leftNumeric ? -1 : 1;
    } else if (left[i] !== right[i]) {
      return left[i] < right[i] ? -1 : 1;
    }
  }
  return 0;
}

// A component the parsers can actually produce: a non-negative safe integer.
// `Number.isSafeInteger` alone admits negatives, which no parser here emits, so
// a hand-built or mutated object would be ordered as a valid version instead of
// being rejected.
function isVersionComponent(value) {
  return Number.isSafeInteger(value) && value >= 0;
}

// Guards against being handed a raw string or a failed parse. Reading `.major`
// off either yields undefined, every comparison below is then false, and the
// caller is told the versions are equal -- the same fail-open shape as an
// unorderable numeric identifier.
//
// This is the major/minor-only check, which is all `compareMajorMinor` needs and
// so is also what a `parseMajorMinor` result satisfies.
function assertParsed(value, label) {
  if (
    !value ||
    typeof value !== "object" ||
    !isVersionComponent(value.major) ||
    !isVersionComponent(value.minor)
  ) {
    throw new TypeError(
      `${label} must be a parsed version object (from parseVersion / parseMajorMinor), got ${JSON.stringify(value)}`
    );
  }
}

// The stricter check for full-version ordering. A `parseMajorMinor` result
// carries no `patch` or `prerelease`, so it passes `assertParsed` and then makes
// `compareVersions` subtract `undefined` -- yielding `NaN`, for which both `< 0`
// and `> 0` are false. That is precisely the fail-open the guard exists to stop,
// so require the fields this comparison actually reads. Callers holding a
// version line rather than a full version want `compareMajorMinor`.
//
// The prerelease is checked against the same grammar `parseVersion` applies, not
// merely for being a string: `comparePrerelease` splits on "." and orders the
// identifiers, so a value the parser would have rejected -- "01", "alpha..1", a
// value with a space -- would otherwise be ordered rather than refused, and the
// guard would drift from the parser it is meant to stand in for.
function assertFullVersion(value, label) {
  assertParsed(value, label);
  const wellFormedPrerelease =
    typeof value.prerelease === "string" &&
    (value.prerelease === "" ||
      validDotSeparated(value.prerelease, PRERELEASE_IDENTIFIER));
  if (!isVersionComponent(value.patch) || !wellFormedPrerelease) {
    throw new TypeError(
      `${label} must be a full parsed version (from parseVersion); use compareMajorMinor to compare version lines, got ${JSON.stringify(value)}`
    );
  }
}

function compareVersions(a, b) {
  assertFullVersion(a, "a");
  assertFullVersion(b, "b");
  if (a.major !== b.major) return a.major - b.major;
  if (a.minor !== b.minor) return a.minor - b.minor;
  if (a.patch !== b.patch) return a.patch - b.patch;
  // Build metadata is intentionally not consulted: SemVer gives it no
  // precedence, so 1.2.3+a and 1.2.3+b are the same version.
  return comparePrerelease(a.prerelease, b.prerelease);
}

function majorMinor(value) {
  const parsed = typeof value === "string" ? parseVersion(value) : value;
  return parsed ? `${parsed.major}.${parsed.minor}` : null;
}

function parseMajorMinor(value) {
  // Same coercion guard as parseVersion.
  if (typeof value !== "string") return null;
  const match = /^(\d+)\.(\d+)$/.exec(value || "");
  if (!match) return null;
  const major = parseNumericIdentifier(match[1]);
  const minor = parseNumericIdentifier(match[2]);
  if (major === null || minor === null) return null;
  return { major, minor, raw: value };
}

function compareMajorMinor(a, b) {
  assertParsed(a, "a");
  assertParsed(b, "b");
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
