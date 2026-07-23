// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { describe, it } from 'node:test';
import assert from 'node:assert';
import * as fs from 'fs';
import * as path from 'path';
import { execSync } from 'child_process';
import { fileURLToPath } from 'node:url';
import { isSupportedPlatformTuple, SUPPORTED_TUPLES } from '../../src/platform.js';

// Resolve the SDK root from this file's own location (compiled to
// dist-tests/tests/unit/), NOT process.cwd() — so the suite works regardless of
// the directory `node --test` is launched from.
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const sdkRoot = path.resolve(__dirname, '..', '..', '..');
const metaPkgPath = path.join(sdkRoot, 'package.json');
const platformPackagesDir = path.join(sdkRoot, 'platform-packages');

const meta = JSON.parse(fs.readFileSync(metaPkgPath, 'utf8'));

// Derive the platform-package set from disk (single source of truth) rather than
// a hand-maintained regex, and validate each on-disk dir against the SDK's own
// `isSupportedPlatformTuple()` — the same predicate the resolver uses — so the
// packaging matrix and the runtime support matrix can never silently diverge.
function parseTuple(dir: string): { platform: NodeJS.Platform; arch: string } | null {
  const i = dir.lastIndexOf('-');
  if (i <= 0) return null;
  return {
    platform: dir.slice(0, i) as NodeJS.Platform,
    arch: dir.slice(i + 1),
  };
}

const allPlatformDirs = fs
  .readdirSync(platformPackagesDir, { withFileTypes: true })
  .filter((d) => d.isDirectory())
  .map((d) => d.name)
  .sort();

const platformDirs = allPlatformDirs.filter((d) => {
  const t = parseTuple(d);
  return t !== null && isSupportedPlatformTuple(t.platform, t.arch);
});

function readPlatformPkg(dir: string): Record<string, unknown> {
  return JSON.parse(
    fs.readFileSync(path.join(platformPackagesDir, dir, 'package.json'), 'utf8'),
  );
}

const SCOPE = '@microsoft/mxc-sdk-';
const isPlatformDep = (name: string): boolean => name.startsWith(SCOPE);

describe('on-disk platform packages match the runtime support matrix (#512)', () => {
  it('there is at least one platform package', () => {
    assert.ok(platformDirs.length >= 1, 'no supported platform packages found on disk');
  });

  it('every on-disk dir is a supported platform tuple (no orphan dirs)', () => {
    for (const dir of allPlatformDirs) {
      const t = parseTuple(dir);
      assert.ok(
        t !== null && isSupportedPlatformTuple(t.platform, t.arch),
        `platform-packages/${dir} is not a supported tuple per isSupportedPlatformTuple() — ` +
          `either remove the dir or add the tuple to the support matrix`,
      );
    }
  });

  it('the on-disk tuple set EQUALS SUPPORTED_TUPLES (bidirectional, round-3 P0-3)', () => {
    // Forward: every on-disk dir is supported (covered above). Reverse: every
    // tuple the runtime advertises in SUPPORTED_TUPLES has a directory + package.
    // Without this, deleting a platform dir (and its pin) or adding a tuple to
    // SUPPORTED_TUPLES without a dir passes every other check green while the
    // runtime still advertises a tuple whose package crashes on load.
    const onDisk = new Set(allPlatformDirs);
    for (const tuple of SUPPORTED_TUPLES) {
      assert.ok(
        onDisk.has(tuple),
        `SUPPORTED_TUPLES advertises "${tuple}" but sdk/node/platform-packages/${tuple} does not exist`,
      );
    }
    // And no extra supported-looking dir beyond the runtime set.
    for (const dir of allPlatformDirs) {
      assert.ok(
        SUPPORTED_TUPLES.has(dir),
        `sdk/node/platform-packages/${dir} exists but is not in SUPPORTED_TUPLES`,
      );
    }
    assert.strictEqual(onDisk.size, SUPPORTED_TUPLES.size, 'tuple set size mismatch');
  });

  it('Intel macOS (darwin-x64) is not shipped', () => {
    assert.ok(
      !platformDirs.includes('darwin-x64'),
      'darwin-x64 must not be shipped (Intel macOS is unsupported)',
    );
  });
});

describe('meta package ships no native binaries (#512)', () => {
  it('does not include bin/ in files', () => {
    const files: string[] = meta.files ?? [];
    assert.ok(
      !files.some((f) => f === 'bin/' || f === 'bin' || f.startsWith('bin/')),
      `meta package "files" must not ship bin/: ${JSON.stringify(files)}`,
    );
  });

  it('files is a tight allowlist (dist, postinstall, docs only)', () => {
    const files: string[] = meta.files ?? [];
    const allowed = new Set([
      'dist/',
      'scripts/postinstall-check.cjs',
      'LICENSE.md',
      'README.md',
    ]);
    for (const f of files) {
      assert.ok(allowed.has(f), `unexpected entry in meta "files": ${f}`);
    }
  });

  it('npm pack ships zero native binaries', () => {
    const out = execSync('npm pack --dry-run --json', {
      cwd: sdkRoot,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
    });
    const files: string[] = JSON.parse(out)[0].files.map(
      (f: { path: string }) => f.path,
    );
    const binaryLike = files.filter(
      (f) =>
        /\.(exe|dll|img|initrd|elf|vmem|cbor)$/.test(f) ||
        /^bin\//.test(f) ||
        /(^|\/)(wxc-exec|lxc-exec|mxc-exec-mac)$/.test(f),
    );
    assert.deepStrictEqual(
      binaryLike,
      [],
      `meta tarball must contain no native binaries, found: ${binaryLike.join(', ')}`,
    );
  });
});

describe('optionalDependencies exactly pin the on-disk platform packages (#512)', () => {
  const opt: Record<string, string> = meta.optionalDependencies ?? {};
  const expectedNames = platformDirs.map((d) => readPlatformPkg(d).name as string);

  it('every on-disk platform package is an exact-pinned optional dependency', () => {
    for (const name of expectedNames) {
      assert.strictEqual(
        opt[name],
        meta.version,
        `${name} must be pinned to the meta version ${meta.version}`,
      );
    }
  });

  it('has no optionalDependency without a backing platform package (no zombies)', () => {
    for (const name of Object.keys(opt)) {
      if (!isPlatformDep(name)) continue;
      assert.ok(
        expectedNames.includes(name),
        `stale optional dependency with no platform package on disk: ${name}`,
      );
    }
  });

  it('every platform optional-dep pin is an exact version (no range qualifier)', () => {
    for (const [name, version] of Object.entries(opt)) {
      if (!isPlatformDep(name)) continue;
      assert.match(
        version,
        /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/,
        `pin must be an exact version, got "${name}": "${version}"`,
      );
    }
  });
});

describe('platform package manifests (#512)', () => {
  for (const dir of platformDirs) {
    describe(dir, () => {
      const pkg = readPlatformPkg(dir);
      const [pkgOs, pkgCpu] = dir.split('-');

      it('name matches the directory', () => {
        assert.strictEqual(pkg.name, `@microsoft/mxc-sdk-${dir}`);
      });

      it('version matches the meta version', () => {
        assert.strictEqual(pkg.version, meta.version);
      });

      it('os/cpu match the directory', () => {
        assert.deepStrictEqual(pkg.os, [pkgOs]);
        assert.deepStrictEqual(pkg.cpu, [pkgCpu]);
      });

      it('linux declares a glibc libc constraint', { skip: pkgOs !== 'linux' }, () => {
        assert.deepStrictEqual(pkg.libc, ['glibc']);
      });

      it('files is an explicit allowlist, not a catch-all glob', () => {
        assert.ok(Array.isArray(pkg.files) && (pkg.files as string[]).length > 0, '"files" must be a non-empty array');
        assert.ok(
          !(pkg.files as string[]).includes('**/*'),
          '"files" must not use the **/* catch-all (would publish stray artifacts)',
        );
      });

      it('has a prepack binary-presence guard', () => {
        const scripts = pkg.scripts as Record<string, string> | undefined;
        assert.ok(
          scripts && typeof scripts.prepack === 'string' && scripts.prepack.length > 0,
          'each platform package must have a prepack guard',
        );
      });

      it('repository.directory points at the package folder', () => {
        const repo = pkg.repository as { directory?: string } | undefined;
        assert.strictEqual(repo?.directory, `sdk/node/platform-packages/${dir}`);
      });
    });
  }
});

describe('platform packages of the same OS ship consistent file sets (#512)', () => {
  // Same-OS packages must agree on the architecture-independent payload, but the
  // micro-VM payload (nanvixd + kernel assets) is x64-ONLY because nanvixd is an
  // x64 binary — win32-arm64 legitimately omits it. Assert that the files arrays
  // are identical AFTER excluding that arch-specific micro-VM payload, and that
  // the micro-VM payload appears only in x64 packages.
  const MICROVM_FILES = new Set([
    'nanvixd.exe',
    'nanvix_rootfs.img',
    'python3.initrd',
    'bin/kernel.elf',
    'snapshots/kernel.vmem',
    'snapshots/kernel.whp.cbor',
  ]);

  const byOs = new Map<string, string[]>();
  for (const dir of platformDirs) {
    const os_ = dir.split('-')[0];
    if (!byOs.has(os_)) byOs.set(os_, []);
    byOs.get(os_)!.push(dir);
  }

  for (const [os_, dirs] of byOs) {
    if (dirs.length < 2) continue;
    it(`${os_} packages (${dirs.join(', ')}) share an identical arch-independent file set`, () => {
      const coreFiles = (d: string) =>
        [...((readPlatformPkg(d).files as string[]) ?? [])].filter((f) => !MICROVM_FILES.has(f)).sort();
      const ref = coreFiles(dirs[0]);
      for (const d of dirs.slice(1)) {
        assert.deepStrictEqual(
          coreFiles(d),
          ref,
          `${d} arch-independent files differ from ${dirs[0]} — same-OS packages must ship the same core files`,
        );
      }
    });

    it(`${os_}: the x64-only micro-VM payload appears only in x64 packages`, () => {
      for (const d of dirs) {
        const files = new Set((readPlatformPkg(d).files as string[]) ?? []);
        const hasMicrovm = [...MICROVM_FILES].some((f) => files.has(f));
        const arch = d.split('-')[1];
        if (arch === 'x64') {
          // x64 Windows ships micro-VM; other OSes may not have it at all (fine).
          if (os_ === 'win32') {
            assert.ok(hasMicrovm, `${d} (x64 win32) must ship the micro-VM payload`);
          }
        } else {
          assert.ok(!hasMicrovm, `${d} must NOT ship the x64-only micro-VM payload`);
        }
      }
    });
  }
});

describe('platform-packages source hygiene (#512)', () => {
  it('only package.json and README.md are git-tracked per package', () => {
    const tracked = execSync('git ls-files platform-packages', {
      cwd: sdkRoot,
      encoding: 'utf8',
    })
      .split('\n')
      .map((s) => s.trim())
      .filter(Boolean);

    const offenders = tracked.filter((f) => {
      if (f === 'platform-packages/.gitignore') return false;
      const base = path.basename(f);
      return base !== 'package.json' && base !== 'README.md';
    });
    assert.deepStrictEqual(
      offenders,
      [],
      `native binaries must not be committed; unexpected tracked files: ${offenders.join(', ')}`,
    );
  });
});
