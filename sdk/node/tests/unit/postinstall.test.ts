// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { describe, it } from 'node:test';
import assert from 'node:assert';
import * as path from 'path';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { SUPPORTED_TUPLES as CANONICAL_TUPLES } from '../../src/platform.js';

const require = createRequire(import.meta.url);
const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Compiled to dist-tests/tests/unit/ — the postinstall .cjs lives at sdk/node/scripts.
const { evaluate, runPostinstall, SUPPORTED_TUPLES } = require(
  path.resolve(__dirname, '..', '..', '..', 'scripts', 'postinstall-check.cjs'),
) as {
  evaluate: (deps: {
    platform: string;
    arch: string;
    resolve: (id: string) => string;
    existsSync: (p: string) => boolean;
    scriptDir: string;
  }) => { action: string; message?: string; pkgName?: string };
  runPostinstall: (deps: {
    platform: string;
    arch: string;
    resolve: (id: string) => string;
    existsSync: (p: string) => boolean;
    scriptDir: string;
    error?: (msg: string) => void;
  }) => { action: string; message?: string; pkgName?: string };
  SUPPORTED_TUPLES: Set<string>;
};

const resolveOk = () => '/x/package.json';
const resolveFail = () => {
  throw new Error('not found');
};
const noFs = () => false;
// Treat any of the three native executor names as present on disk.
const binaryPresent = (p: string) =>
  p.endsWith('wxc-exec.exe') || p.endsWith('lxc-exec') || p.endsWith('mxc-exec-mac');
const base = { resolve: resolveFail, existsSync: noFs, scriptDir: '/x' };

describe('postinstall-check evaluate (#512)', () => {
  it('postinstall SUPPORTED_TUPLES deep-equals the platform.ts set (round-3 P2)', () => {
    // The .cjs must run uncompiled (before the SDK is built), so it duplicates
    // SUPPORTED_TUPLES. Bind the copy to the canonical set so they can't drift.
    assert.deepStrictEqual(
      [...SUPPORTED_TUPLES].sort(),
      [...CANONICAL_TUPLES].sort(),
    );
  });

  it('returns ok when the platform package is installed (binary present)', () => {
    const r = evaluate({
      ...base,
      platform: 'win32',
      arch: 'x64',
      resolve: resolveOk,
      existsSync: binaryPresent,
    });
    assert.strictEqual(r.action, 'ok');
  });

  it('warns when the package is installed but its native binary is missing (F8)', () => {
    // package.json resolves, but the executor is absent — an interrupted or
    // corrupt optional install must not be reported as "ok".
    const r = evaluate({
      ...base,
      platform: 'win32',
      arch: 'x64',
      resolve: resolveOk,
      existsSync: noFs, // binary not on disk
    });
    assert.strictEqual(r.action, 'warn');
    assert.match(r.message ?? '', /missing|interrupted|corrupt/i);
    assert.match(r.message ?? '', /wxc-exec\.exe/);
  });

  it('returns ok in a monorepo dev layout (staged dir present)', () => {
    const r = evaluate({
      platform: 'linux',
      arch: 'x64',
      resolve: resolveFail,
      existsSync: () => true, // sibling platform-packages/<tuple>/package.json
      scriptDir: '/repo/sdk/node/scripts',
    });
    assert.strictEqual(r.action, 'ok');
  });

  it('warns (naming the package) when supported but missing', () => {
    const r = evaluate({ ...base, platform: 'linux', arch: 'arm64' });
    assert.strictEqual(r.action, 'warn');
    assert.match(r.message ?? '', /@microsoft\/mxc-sdk-linux-arm64/);
  });

  it('reports darwin-x64 (Intel macOS) as supported-but-missing (names the package)', () => {
    const r = evaluate({ ...base, platform: 'darwin', arch: 'x64' });
    assert.strictEqual(r.action, 'warn');
    assert.match(r.message ?? '', /@microsoft\/mxc-sdk-darwin-x64/);
  });

  it('reports a 32-bit host as unsupported', () => {
    const r = evaluate({ ...base, platform: 'win32', arch: 'ia32' });
    assert.strictEqual(r.action, 'unsupported');
  });
});

describe('postinstall-check runPostinstall CLI seam (#512 F6)', () => {
  it('emits the warning to the error sink and never throws (warn path)', () => {
    const seen: string[] = [];
    const r = runPostinstall({
      platform: 'linux',
      arch: 'arm64',
      resolve: resolveFail,
      existsSync: noFs,
      scriptDir: '/x',
      error: (m) => seen.push(m),
    });
    assert.strictEqual(r.action, 'warn');
    assert.strictEqual(seen.length, 1);
    assert.match(seen[0], /@microsoft\/mxc-sdk-linux-arm64/);
  });

  it('emits the unsupported notice on an unsupported host (32-bit Windows)', () => {
    const seen: string[] = [];
    runPostinstall({
      platform: 'win32',
      arch: 'ia32',
      resolve: resolveFail,
      existsSync: noFs,
      scriptDir: '/x',
      error: (m) => seen.push(m),
    });
    assert.strictEqual(seen.length, 1);
    assert.match(seen[0], /not a supported/i);
  });

  it('stays silent (no error emitted) when the package is present', () => {
    const seen: string[] = [];
    const r = runPostinstall({
      platform: 'win32',
      arch: 'x64',
      resolve: resolveOk,
      existsSync: binaryPresent,
      scriptDir: '/x',
      error: (m) => seen.push(m),
    });
    assert.strictEqual(r.action, 'ok');
    assert.strictEqual(seen.length, 0);
  });

  it('never throws (and reports ok) even if evaluate would throw', () => {
    const r = runPostinstall({
      platform: 'win32',
      arch: 'x64',
      // A resolve impl that throws a non-"not found" error simulates an
      // unexpected failure; the install must still not fail.
      resolve: () => {
        throw new Error('boom');
      },
      existsSync: () => {
        throw new Error('boom');
      },
      scriptDir: '/x',
      error: () => {
        throw new Error('sink boom');
      },
    });
    assert.strictEqual(r.action, 'ok');
  });
});
