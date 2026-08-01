import assert from 'node:assert/strict';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import {
  expandPlan,
  readCatalog,
  resolvePlan,
  validateCatalog
} from '../resolve-test-matrix.mjs';

// Tests load a fresh catalog for each case so negative mutations cannot leak
// into later assertions.
const testDirectory = path.dirname(fileURLToPath(import.meta.url));
const catalogPath = path.resolve(testDirectory, '..', 'test-matrix.json');

function catalog() {
  return readCatalog(catalogPath);
}

function clone(value) {
  // Catalog values are JSON data, so a JSON round-trip is sufficient here.
  return JSON.parse(JSON.stringify(value));
}

test('catalog validates and contains all five build targets', () => {
  assert.doesNotThrow(() => validateCatalog(catalog()));
});

test('current rollout enables two PR jobs and no scheduled jobs', () => {
  const pr = resolvePlan(catalog(), 'pr');
  const nightly = resolvePlan(catalog(), 'nightly');
  const weekly = resolvePlan(catalog(), 'weekly');

  assert.equal(pr.windows.length + pr.linux.length + pr.macos.length, 2);
  assert.equal(nightly.windows.length + nightly.linux.length + nightly.macos.length, 0);
  assert.equal(weekly.windows.length + weekly.linux.length + weekly.macos.length, 0);
});

test('weekly includes all enabled nightly combinations', () => {
  const nightly = resolvePlan(catalog(), 'nightly');
  const weekly = resolvePlan(catalog(), 'weekly');

  for (const family of ['windows', 'linux', 'macos']) {
    // The weekly matrix must be a superset, not a separate replacement plan.
    const weeklyKeys = new Set(
      weekly[family].map(entry => `${entry.os}|${entry.architecture}|${entry.backend}`)
    );
    for (const entry of nightly[family]) {
      assert.ok(
        weeklyKeys.has(`${entry.os}|${entry.architecture}|${entry.backend}`),
        `weekly is missing ${family} nightly entry ${entry.os}/${entry.backend}`
      );
    }
  }
});

test('full plan expands supported backends to both architectures', () => {
  const expanded = expandPlan(catalog(), 'pr');
  const ubuntuBubblewrap = expanded
    .filter(entry => entry.os === 'ubuntu-26.04' && entry.backend === 'bubblewrap');
  assert.deepEqual(
    ubuntuBubblewrap.map(entry => entry.architecture).sort(),
    ['arm64', 'x64']
  );
});

test('arm64 never expands Hyperlight or MicroVM', () => {
  for (const plan of ['pr', 'nightly', 'weekly']) {
    const invalid = expandPlan(catalog(), plan)
      .filter(entry => (
        entry.architecture === 'arm64'
        && ['hyperlight', 'microvm'].includes(entry.backend)
      ));
    assert.deepEqual(invalid, []);
  }
});

test('enabled placeholder handlers are rejected', () => {
  // Seatbelt is declared in the capability map but intentionally not wired yet.
  const modified = clone(catalog());
  modified.enabled.push({
    plan: 'weekly',
    os: 'macos-15',
    architecture: 'arm64',
    backend: 'seatbelt'
  });
  assert.throws(
    () => validateCatalog(modified),
    /enabled entry has no wired handler/
  );
});

test('enabled handlers must support the selected architecture', () => {
  // WSLC remains in the arm64 capability catalog while its current test
  // dispatcher is explicitly restricted to x64.
  const modified = clone(catalog());
  modified.enabled.push({
    plan: 'weekly',
    os: 'windows-24h2',
    architecture: 'arm64',
    backend: 'wslc'
  });
  assert.throws(
    () => validateCatalog(modified),
    /enabled entry handler does not support arm64/
  );
});

test('duplicate enabled combinations are rejected', () => {
  const modified = clone(catalog());
  modified.enabled.push(clone(modified.enabled[0]));
  assert.throws(
    () => validateCatalog(modified),
    /duplicate enabled entry/
  );
});

test('prerelease platforms use neutral public aliases', () => {
  for (const platform of catalog().platforms.filter(entry => entry.prerelease === true)) {
    assert.match(platform.id, /^windows-prerelease-[a-z-]+$/);
  }
});
