// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

const test = require("node:test");
const assert = require("node:assert/strict");
const {
  parseVersion,
  parseMajorMinor,
  compareVersions,
  compareMajorMinor,
  majorMinor,
} = require("../lib/version");

test("parseVersion accepts a plain release version", () => {
  assert.deepEqual(parseVersion("1.2.3"), {
    major: 1,
    minor: 2,
    patch: 3,
    prerelease: "",
    build: "",
    raw: "1.2.3",
  });
});

test("parseVersion captures a prerelease label", () => {
  const v = parseVersion("0.8.0-alpha");
  assert.equal(v.minor, 8);
  assert.equal(v.prerelease, "alpha");
});

test("parseVersion rejects malformed input", () => {
  for (const bad of ["", null, undefined, "1.2", "1.2.3.4", "v1.2.3", "a.b.c"]) {
    assert.equal(parseVersion(bad), null, `should reject ${JSON.stringify(bad)}`);
  }
});

test("parseVersion rejects leading zeros in numeric identifiers", () => {
  // SemVer forbids these, and accepting them would let 01.0.0 and 1.0.0 both
  // parse to the same ordering key.
  assert.equal(parseVersion("01.2.3"), null);
  assert.equal(parseVersion("1.02.3"), null);
  assert.equal(parseVersion("1.2.03"), null);
});

test("parseVersion rejects components too large to order", () => {
  // An unbounded digit run converts to Infinity; Infinity - Infinity is NaN, and
  // every ordinary `< 0` / `> 0` regression check against NaN is false, so a
  // version like this would silently pass an ordering gate.
  const huge = "1".repeat(400);
  assert.equal(parseVersion(`${huge}.0.0`), null);
  assert.equal(parseVersion(`0.${huge}.0`), null);
  assert.equal(parseVersion(`0.0.${huge}`), null);
});

test("numeric prerelease identifiers order exactly at any length", () => {
  // SemVer leaves these unbounded, so `Number` loses precision long before the
  // digits do: distinct values above 2^53 collapse to one float and long ones
  // become Infinity, whose difference is NaN -- falsy, so the comparison used to
  // report equality and an ordering gate would fail open. Leading zeros are
  // already rejected, so digit length then lexical order is exact.
  const lt = (a, b) => compareVersions(parseVersion(a), parseVersion(b)) < 0;
  assert.ok(lt("1.0.0-9007199254740992", "1.0.0-9007199254740993"), "past 2^53");
  assert.ok(
    compareVersions(
      parseVersion("1.0.0-9007199254740993"),
      parseVersion("1.0.0-9007199254740992")
    ) > 0,
    "antisymmetric past 2^53"
  );
  const long = "1".repeat(400);
  assert.ok(lt(`1.0.0-${long}`, `1.0.0-${"2".repeat(400)}`), "equal length");
  assert.ok(lt(`1.0.0-${long}`, `1.0.0-${"1".repeat(401)}`), "more digits is larger");
  assert.ok(lt(`1.0.0-alpha.${long}`, `1.0.0-alpha.${"2".repeat(400)}`), "dotted");
  assert.equal(
    compareVersions(parseVersion(`1.0.0-${long}`), parseVersion(`1.0.0-${long}`)),
    0,
    "identical long identifiers are equal"
  );
});

test("prerelease precedence follows the SemVer specification", () => {
  // The example chain from SemVer 11.4.12, which pins numeric-before-alphanumeric
  // and numeric-not-lexical ordering together.
  const chain = [
    "1.0.0-alpha",
    "1.0.0-alpha.1",
    "1.0.0-alpha.beta",
    "1.0.0-beta",
    "1.0.0-beta.2",
    "1.0.0-beta.11",
    "1.0.0-rc.1",
    "1.0.0",
  ];
  for (let i = 0; i + 1 < chain.length; i++) {
    assert.ok(
      compareVersions(parseVersion(chain[i]), parseVersion(chain[i + 1])) < 0,
      `${chain[i]} should precede ${chain[i + 1]}`
    );
  }
});

test("compareVersions orders by major, then minor, then patch", () => {
  const lt = (a, b) => compareVersions(parseVersion(a), parseVersion(b)) < 0;
  assert.ok(lt("1.0.0", "2.0.0"));
  assert.ok(lt("1.1.0", "1.2.0"));
  assert.ok(lt("1.1.1", "1.1.2"));
  assert.equal(compareVersions(parseVersion("1.2.3"), parseVersion("1.2.3")), 0);
});

test("compareVersions ranks a prerelease below its release", () => {
  assert.ok(compareVersions(parseVersion("1.0.0-alpha"), parseVersion("1.0.0")) < 0);
  assert.ok(compareVersions(parseVersion("1.0.0"), parseVersion("1.0.0-alpha")) > 0);
});

test("compareVersions orders prerelease identifiers per SemVer", () => {
  const lt = (a, b) => compareVersions(parseVersion(a), parseVersion(b)) < 0;
  assert.ok(lt("1.0.0-alpha", "1.0.0-beta"));
  // Numeric identifiers compare numerically, not as strings.
  assert.ok(lt("1.0.0-alpha.2", "1.0.0-alpha.10"));
  // Numeric identifiers rank below alphanumeric ones.
  assert.ok(lt("1.0.0-1", "1.0.0-alpha"));
  // A larger set of identifiers outranks its prefix.
  assert.ok(lt("1.0.0-alpha", "1.0.0-alpha.1"));
});

test("parseMajorMinor applies the same numeric guards", () => {
  assert.deepEqual(parseMajorMinor("0.8"), { major: 0, minor: 8, raw: "0.8" });
  assert.equal(parseMajorMinor("0.8.0"), null);
  assert.equal(parseMajorMinor("01.8"), null);
  assert.equal(parseMajorMinor(`1.${"9".repeat(400)}`), null);
});

test("compareMajorMinor ignores patch and prerelease", () => {
  assert.equal(compareMajorMinor(parseVersion("0.8.0-alpha"), parseVersion("0.8.9")), 0);
  assert.ok(compareMajorMinor(parseVersion("0.7.0"), parseVersion("0.8.0")) < 0);
});

test("majorMinor renders the line of a version", () => {
  assert.equal(majorMinor(parseVersion("0.8.0-alpha")), "0.8");
  assert.equal(majorMinor("0.8.0-alpha"), "0.8");
  assert.equal(majorMinor("invalid"), null);
  assert.equal(majorMinor(null), null);
  assert.throws(() => majorMinor({}), TypeError);
  assert.throws(() => majorMinor({ major: 1, minor: undefined }), TypeError);
});

// -- Round-1 review regressions -----------------------------------------------

test("parseVersion accepts build metadata", () => {
  const plain = parseVersion("1.2.3+build.5");
  assert.equal(plain.build, "build.5");
  assert.equal(plain.prerelease, "");
  const withPre = parseVersion("1.2.3-alpha+build.5");
  // Build metadata must not be folded into the prerelease label, or it would
  // take part in precedence.
  assert.equal(withPre.prerelease, "alpha");
  assert.equal(withPre.build, "build.5");
});

test("build metadata is ignored for precedence", () => {
  assert.equal(
    compareVersions(parseVersion("1.2.3+a"), parseVersion("1.2.3+b")),
    0
  );
  assert.equal(
    compareVersions(parseVersion("1.2.3"), parseVersion("1.2.3+build.99")),
    0
  );
  assert.ok(
    compareVersions(
      parseVersion("1.2.3-alpha+z"),
      parseVersion("1.2.3-beta+a")
    ) < 0
  );
});

test("parseVersion rejects malformed prerelease and build identifiers", () => {
  assert.equal(parseVersion("1.2.3-01"), null, "numeric prerelease leading zero");
  assert.equal(parseVersion("1.2.3-"), null, "empty prerelease");
  assert.equal(parseVersion("1.2.3+"), null, "empty build");
  assert.equal(parseVersion("1.2.3-al pha"), null, "space in prerelease");
  assert.equal(parseVersion("1.2.3+bui,ld"), null, "comma in build");
  assert.equal(parseVersion("1.2.3-alpha..1"), null, "empty identifier");
});

test("comparing anything other than a parsed version throws", () => {
  // Reading .major off a string or a failed parse yields undefined, which would
  // silently report the two versions as equal.
  assert.throws(() => compareVersions("1.2.3", "1.2.4"), TypeError);
  assert.throws(() => compareVersions(parseVersion("bad"), parseVersion("1.2.3")), TypeError);
  assert.throws(() => compareMajorMinor(null, parseMajorMinor("0.8")), TypeError);
});

test("compareVersions rejects a version line rather than returning NaN", () => {
  // A parseMajorMinor result has no patch or prerelease, so subtracting it
  // yields NaN, for which both `< 0` and `> 0` are false -- the same fail-open
  // the guard exists to prevent. compareMajorMinor is the function for these.
  const line = parseMajorMinor("1.2");
  const full = parseVersion("1.2.3");
  assert.throws(() => compareVersions(line, full), TypeError);
  assert.throws(() => compareVersions(full, line), TypeError);
  assert.throws(() => compareVersions(line, line), TypeError);
  // A hand-rolled object satisfying only the loose check is rejected too.
  assert.throws(() => compareVersions({ major: 1, minor: 2 }, full), TypeError);
  assert.throws(
    () => compareVersions({ major: 1, minor: 2, patch: 3 }, full),
    TypeError,
    "prerelease is still missing"
  );
  // The legitimate uses keep working.
  assert.ok(compareMajorMinor(line, parseVersion("1.3.0")) < 0);
  assert.equal(compareMajorMinor(line, parseMajorMinor("1.2")), 0);
  assert.equal(compareVersions(full, parseVersion("1.2.3")), 0);
});

test("version parsing rejects non-string input rather than coercing it", () => {
  // `RegExp.exec` coerces its argument, so a single-element array, a boxed
  // String, or any object with a `toString` would otherwise parse -- and `raw`
  // would carry the non-string, breaking round-tripping too.
  for (const value of [
    ["1.2.3"],
    new String("1.2.3"),
    { toString: () => "1.2.3" },
    123,
    null,
    undefined,
    true,
  ]) {
    assert.equal(parseVersion(value), null, `parseVersion ${String(value)}`);
  }
  for (const value of [["1.2"], new String("1.2"), { toString: () => "1.2" }]) {
    assert.equal(parseMajorMinor(value), null, `parseMajorMinor ${String(value)}`);
  }
  assert.equal(parseVersion("1.2.3").raw, "1.2.3", "a real string still parses");
});

test("the comparison guards reject components no parser can produce", () => {
  // `Number.isSafeInteger` admits negatives, and a bare typeof check admits a
  // prerelease the parser would have rejected. Either would be ordered rather
  // than refused, letting a hand-built or mutated object through the guard that
  // exists to stop exactly that.
  const ok = parseVersion("1.0.0");
  const full = (extra) => ({ major: 1, minor: 0, patch: 0, prerelease: "", ...extra });
  assert.throws(() => compareVersions(full({ major: -1 }), ok), TypeError, "negative major");
  assert.throws(() => compareVersions(full({ patch: -5 }), ok), TypeError, "negative patch");
  assert.throws(() => compareMajorMinor({ major: 1, minor: -2 }, parseMajorMinor("0.8")), TypeError);
  for (const prerelease of ["01", "alpha..1", "has space", "alpha+build"]) {
    assert.throws(
      () => compareVersions(full({ prerelease }), ok),
      TypeError,
      `prerelease ${JSON.stringify(prerelease)} is not a value parseVersion would produce`
    );
  }
  // The shapes a parser really does produce are still accepted.
  assert.equal(compareVersions(full({}), ok), 0);
  assert.ok(compareVersions(full({ prerelease: "alpha.1" }), ok) < 0);
});
