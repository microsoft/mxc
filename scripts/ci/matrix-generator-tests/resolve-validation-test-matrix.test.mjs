import assert from 'node:assert/strict';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import {
  expandPlan,
  readCatalog,
  resolvePlan,
  validateCatalog
} from '../resolve-validation-test-matrix.mjs';

// Tests load a fresh catalog for each case so negative mutations cannot leak
// into later assertions.
const testDirectory = path.dirname(fileURLToPath(import.meta.url));
const catalogPath = path.resolve(testDirectory, '..', 'validation-test-matrix.json');

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

test('trigger categories resolve independently', () => {
  const pr = resolvePlan(catalog(), 'pr');
  const nightly = resolvePlan(catalog(), 'nightly');
  const weekly = resolvePlan(catalog(), 'weekly');

  assert.ok(
    pr.windows.some(entry => (
      entry.os === 'windows-25h2' && entry.backend === 'process-t3'
    ))
  );
  assert.ok(
    nightly.linux.some(entry => (
      entry.os === 'ubuntu-26.04' && entry.backend === 'bubblewrap'
    ))
  );
  assert.ok(
    weekly.macos.some(entry => (
      entry.os === 'macos-15' && entry.backend === 'seatbelt'
    ))
  );
});

test('macOS rollout uses 26 for PR and nightly with 15 added weekly', () => {
  const project = entry => ({
    plan: entry.plan,
    os: entry.os,
    runner: entry.runner,
    backend: entry.backend
  });

  assert.deepEqual(resolvePlan(catalog(), 'pr').macos.map(project), [
    { plan: 'pr', os: 'macos-26', runner: 'macos-26', backend: 'seatbelt' }
  ]);
  assert.deepEqual(resolvePlan(catalog(), 'nightly').macos.map(project), [
    { plan: 'nightly', os: 'macos-26', runner: 'macos-26', backend: 'seatbelt' }
  ]);
  assert.deepEqual(resolvePlan(catalog(), 'weekly').macos.map(project), [
    { plan: 'weekly', os: 'macos-15', runner: 'macos-15', backend: 'seatbelt' }
  ]);
});

test('enabled plan deduplicates and runs both macOS versions', () => {
  const enabled = resolvePlan(catalog(), 'enabled');
  assert.equal(enabled.windows.length + enabled.linux.length + enabled.macos.length, 4);
  assert.deepEqual(
    enabled.macos.map(entry => ({
      plan: entry.plan,
      os: entry.os,
      runner: entry.runner,
      backend: entry.backend
    })),
    [
      { plan: 'enabled', os: 'macos-15', runner: 'macos-15', backend: 'seatbelt' },
      { plan: 'enabled', os: 'macos-26', runner: 'macos-26', backend: 'seatbelt' }
    ]
  );
});

test('missing enabled trigger does not affect other plans', () => {
  const modified = clone(catalog());
  delete modified.triggers.enabled;

  assert.deepEqual(resolvePlan(modified, 'enabled'), {
    windows: [],
    linux: [],
    macos: []
  });
  assert.ok(
    resolvePlan(modified, 'pr').windows
      .some(entry => entry.os === 'windows-25h2' && entry.backend === 'process-t3')
  );
});

test('empty pools skip OS and architecture combinations', () => {
  const modified = clone(catalog());
  const windows25h2 = modified.platforms
    .find(platform => platform.id === 'windows-25h2');
  windows25h2.architectures.x64.pool = '';

  assert.doesNotThrow(() => validateCatalog(modified));
  assert.ok(
    !expandPlan(modified, 'pr')
      .some(entry => entry.os === 'windows-25h2')
  );
  assert.ok(
    !resolvePlan(modified, 'pr').windows
      .some(entry => entry.os === 'windows-25h2')
  );
});

test('resolved matrices never emit non-macOS arm64 tests', () => {
  const modified = clone(catalog());
  const windowsCanary = modified.platforms
    .find(platform => platform.id === 'windows-canary');
  windowsCanary.architectures.x64.backends = windowsCanary.architectures.x64.backends
    .filter(backend => backend !== 'process-t1');
  windowsCanary.architectures.arm64.pool = 'test-arm64-pool';
  modified.triggers.enabled.push({
    os: 'windows-canary',
    backends: ['process-t1']
  });

  for (const plan of ['pr', 'nightly', 'weekly', 'enabled']) {
    const resolved = resolvePlan(modified, plan);
    assert.ok(resolved.windows.every(entry => entry.architecture === 'x64'));
    assert.ok(resolved.linux.every(entry => entry.architecture === 'x64'));
    assert.ok(resolved.macos.every(entry => entry.architecture === 'arm64'));
  }
});

test('weekly does not inherit nightly combinations', () => {
  const nightly = resolvePlan(catalog(), 'nightly');
  const weekly = resolvePlan(catalog(), 'weekly');

  for (const family of ['windows', 'linux', 'macos']) {
    const nightlyKeys = new Set(
      nightly[family].map(entry => `${entry.os}|${entry.architecture}|${entry.backend}`)
    );
    const inherited = weekly[family].filter(entry => (
      nightlyKeys.has(`${entry.os}|${entry.architecture}|${entry.backend}`)
    ));
    assert.deepEqual(
      inherited,
      [],
      `${family} weekly entries unexpectedly overlap nightly`
    );
    assert.ok(
      weekly[family].map(entry => `${entry.os}|${entry.architecture}|${entry.backend}`)
        .every(key => !nightlyKeys.has(key))
    );
  }
});

test('full plan expands only architectures with available pools', () => {
  const expanded = expandPlan(catalog(), 'pr');
  const ubuntuBubblewrap = expanded
    .filter(entry => entry.os === 'ubuntu-26.04' && entry.backend === 'bubblewrap');
  assert.deepEqual(
    ubuntuBubblewrap.map(entry => entry.architecture).sort(),
    ['x64']
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

test('all trigger categories omit placeholder handlers', () => {
  const modified = clone(catalog());
  modified.triggers.enabled.push({
    os: 'ubuntu-24.04',
    backends: ['hyperlight']
  });
  assert.doesNotThrow(() => validateCatalog(modified));
  assert.ok(
    !resolvePlan(modified, 'enabled').linux
      .some(entry => entry.backend === 'hyperlight')
  );
});

test('enabled trigger respects handler architecture restrictions', () => {
  const modified = clone(catalog());
  const windows24h2 = modified.platforms
    .find(platform => platform.id === 'windows-24h2');
  windows24h2.architectures.x64.pool = 'test-x64-pool';
  windows24h2.architectures.arm64.pool = 'test-arm64-pool';
  modified.triggers.enabled.push({
    os: 'windows-24h2',
    backends: ['wslc']
  });
  assert.deepEqual(
    resolvePlan(modified, 'enabled').windows
      .filter(entry => entry.os === 'windows-24h2' && entry.backend === 'wslc')
      .map(entry => entry.architecture),
    ['x64']
  );
});

test('duplicate enabled requests are rejected', () => {
  const modified = clone(catalog());
  modified.triggers.enabled.push(clone(modified.triggers.enabled[0]));
  assert.throws(
    () => validateCatalog(modified),
    /duplicate enabled request/
  );
});

test('prerelease platforms use neutral public aliases', () => {
  for (const platform of catalog().platforms.filter(entry => entry.prerelease === true)) {
    assert.match(platform.id, /^windows-prerelease-[a-z-]+$/);
  }
});
