// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { describe, it } from 'node:test';
import assert from 'node:assert';
import {
  regenerateSandboxPolicy,
  isSystemCritical,
} from '../../src/policy-regen.js';
import type { DeniedResource } from '../../src/denial-stream.js';
import type { SandboxPolicy } from '../../src/types.js';

// ---- fixtures -------------------------------------------------------------

function fileDenial(
  path: string,
  accessType: DeniedResource['accessType'] = 'read',
): DeniedResource {
  return {
    kind: 'file',
    path,
    resourceType: 'file',
    accessType,
    pid: 1,
    filetime: 1,
  };
}

const basePolicy: SandboxPolicy = {
  version: '0.5.0-alpha',
  filesystem: {
    readwritePaths: [],
    readonlyPaths: [],
    deniedPaths: [],
  },
};

// ---- isSystemCritical -----------------------------------------------------

describe('isSystemCritical', () => {
  it('rejects Windows registry hives', () => {
    assert.ok(isSystemCritical('\\REGISTRY\\USER\\.DEFAULT\\Foo'));
    assert.ok(isSystemCritical('\\REGISTRY\\MACHINE\\Software\\Bar'));
  });

  it('rejects System32 / SysWOW64 / WinSxS', () => {
    assert.ok(isSystemCritical('C:\\Windows\\System32\\kernel32.dll'));
    assert.ok(isSystemCritical('C:\\Windows\\SysWOW64\\ntdll.dll'));
    assert.ok(isSystemCritical('C:\\Windows\\WinSxS\\amd64_foo\\bar.dll'));
  });

  it('rejects critical system files', () => {
    assert.ok(isSystemCritical('C:\\Windows\\ntoskrnl.exe'));
    assert.ok(isSystemCritical('C:\\bootmgr'));
    assert.ok(isSystemCritical('C:\\pagefile.sys'));
    assert.ok(isSystemCritical('C:\\hiberfil.sys'));
  });

  it('accepts user-profile paths', () => {
    assert.ok(!isSystemCritical('C:\\Users\\Alice\\Documents\\report.txt'));
    assert.ok(!isSystemCritical('C:\\ProgramData\\MyApp\\config.json'));
    assert.ok(!isSystemCritical('C:\\Windows\\Temp\\foo.tmp')); // Temp is *not* in the critical list
  });

  it('is case-insensitive', () => {
    assert.ok(isSystemCritical('c:\\windows\\system32\\kernel32.dll'));
    assert.ok(isSystemCritical('C:\\WINDOWS\\SYSTEM32\\kernel32.dll'));
  });
});

// ---- regenerateSandboxPolicy --------------------------------------------

describe('regenerateSandboxPolicy', () => {
  it('adds a single approved file as readonly by default', () => {
    const result = regenerateSandboxPolicy({
      basePolicy,
      approvedDenials: [fileDenial('C:\\Users\\Alice\\Documents\\a.txt', 'read')],
    });
    assert.deepStrictEqual(result.policy.filesystem?.readonlyPaths, [
      'C:\\Users\\Alice\\Documents\\a.txt',
    ]);
    assert.deepStrictEqual(result.policy.filesystem?.readwritePaths, []);
    assert.deepStrictEqual(result.added, [
      { kind: 'readonly', path: 'C:\\Users\\Alice\\Documents\\a.txt' },
    ]);
    assert.strictEqual(result.skipped.length, 0);
  });

  it('strips the \\??\\ NT-DOS-namespace prefix from the granted path', () => {
    const result = regenerateSandboxPolicy({
      basePolicy,
      approvedDenials: [fileDenial('\\??\\C:\\Users\\Bob\\foo.txt')],
    });
    assert.deepStrictEqual(result.policy.filesystem?.readonlyPaths, [
      'C:\\Users\\Bob\\foo.txt',
    ]);
    assert.strictEqual(result.added[0].path, 'C:\\Users\\Bob\\foo.txt');
  });

  it('grants readwrite for write denials when upgrade flag is on', () => {
    const result = regenerateSandboxPolicy({
      basePolicy,
      approvedDenials: [fileDenial('C:\\Users\\Carol\\out.log', 'write')],
      upgradeWritesToReadwrite: true,
    });
    assert.deepStrictEqual(result.policy.filesystem?.readwritePaths, [
      'C:\\Users\\Carol\\out.log',
    ]);
    assert.deepStrictEqual(result.policy.filesystem?.readonlyPaths, []);
  });

  it('defaults write denials to readonly when upgrade flag is off', () => {
    const result = regenerateSandboxPolicy({
      basePolicy,
      approvedDenials: [fileDenial('C:\\Users\\Carol\\out.log', 'write')],
      // upgradeWritesToReadwrite defaults to false
    });
    assert.deepStrictEqual(result.policy.filesystem?.readonlyPaths, [
      'C:\\Users\\Carol\\out.log',
    ]);
    assert.deepStrictEqual(result.policy.filesystem?.readwritePaths, []);
  });

  it('refuses system-critical paths even when approved', () => {
    const denials = [
      fileDenial('C:\\Windows\\System32\\kernel32.dll'),
      fileDenial('\\REGISTRY\\USER\\.DEFAULT\\Control Panel\\International'),
      fileDenial('C:\\Users\\Dan\\file.txt'), // not critical, should pass through
    ];
    const result = regenerateSandboxPolicy({ basePolicy, approvedDenials: denials });
    assert.deepStrictEqual(result.policy.filesystem?.readonlyPaths, [
      'C:\\Users\\Dan\\file.txt',
    ]);
    assert.deepStrictEqual(
      result.skipped.map((s) => s.reason),
      ['system-critical', 'system-critical'],
    );
  });

  it('skips approvals already granted in the base policy (idempotent)', () => {
    const base: SandboxPolicy = {
      ...basePolicy,
      filesystem: {
        readonlyPaths: ['C:\\Users\\Eve\\file.txt'],
        readwritePaths: [],
      },
    };
    const result = regenerateSandboxPolicy({
      basePolicy: base,
      approvedDenials: [fileDenial('C:\\Users\\Eve\\file.txt')],
    });
    // No duplicate added.
    assert.deepStrictEqual(result.policy.filesystem?.readonlyPaths, [
      'C:\\Users\\Eve\\file.txt',
    ]);
    assert.strictEqual(result.added.length, 0);
    assert.deepStrictEqual(result.skipped, [
      { path: 'C:\\Users\\Eve\\file.txt', reason: 'already-granted' },
    ]);
  });

  it('treats path matching as case-insensitive for idempotence checks', () => {
    const base: SandboxPolicy = {
      ...basePolicy,
      filesystem: { readonlyPaths: ['C:\\Users\\Frank\\file.txt'] },
    };
    const result = regenerateSandboxPolicy({
      basePolicy: base,
      // Same path, different case + trailing slash variation.
      approvedDenials: [fileDenial('c:\\users\\frank\\file.txt')],
    });
    assert.strictEqual(result.added.length, 0);
    assert.strictEqual(result.skipped.length, 1);
    assert.strictEqual(result.skipped[0].reason, 'already-granted');
  });

  it('upgrades a previously-readonly path to readwrite (and drops the readonly entry)', () => {
    const base: SandboxPolicy = {
      ...basePolicy,
      filesystem: { readonlyPaths: ['C:\\Users\\Grace\\out.log'] },
    };
    const result = regenerateSandboxPolicy({
      basePolicy: base,
      approvedDenials: [fileDenial('C:\\Users\\Grace\\out.log', 'write')],
      upgradeWritesToReadwrite: true,
    });
    // Should now be readwrite, not in both buckets.
    assert.deepStrictEqual(result.policy.filesystem?.readwritePaths, [
      'C:\\Users\\Grace\\out.log',
    ]);
    assert.deepStrictEqual(result.policy.filesystem?.readonlyPaths, []);
    assert.deepStrictEqual(result.added, [
      { kind: 'readwrite', path: 'C:\\Users\\Grace\\out.log' },
    ]);
  });

  it('an existing readwrite grant covers any new approval for the same path', () => {
    const base: SandboxPolicy = {
      ...basePolicy,
      filesystem: { readwritePaths: ['C:\\Users\\Henry\\rw.txt'] },
    };
    const result = regenerateSandboxPolicy({
      basePolicy: base,
      approvedDenials: [fileDenial('C:\\Users\\Henry\\rw.txt', 'read')],
    });
    assert.strictEqual(result.added.length, 0);
    assert.deepStrictEqual(result.skipped, [
      { path: 'C:\\Users\\Henry\\rw.txt', reason: 'already-granted' },
    ]);
    // No change to either bucket.
    assert.deepStrictEqual(result.policy.filesystem?.readwritePaths, [
      'C:\\Users\\Henry\\rw.txt',
    ]);
  });

  it('preserves untouched policy fields verbatim', () => {
    const base: SandboxPolicy = {
      version: '0.5.0-alpha',
      timeoutMs: 5000,
      filesystem: { deniedPaths: ['C:\\secret'] },
      network: { allowOutbound: false },
    };
    const result = regenerateSandboxPolicy({
      basePolicy: base,
      approvedDenials: [fileDenial('C:\\Users\\Iris\\f.txt')],
    });
    assert.strictEqual(result.policy.version, '0.5.0-alpha');
    assert.strictEqual(result.policy.timeoutMs, 5000);
    assert.deepStrictEqual(result.policy.filesystem?.deniedPaths, ['C:\\secret']);
    assert.deepStrictEqual(result.policy.network, { allowOutbound: false });
  });

  it('does not mutate the base policy', () => {
    const base: SandboxPolicy = {
      ...basePolicy,
      filesystem: { readonlyPaths: ['C:\\existing'] },
    };
    const baseSnapshot = JSON.stringify(base);
    regenerateSandboxPolicy({
      basePolicy: base,
      approvedDenials: [fileDenial('C:\\Users\\Jack\\new.txt')],
    });
    assert.strictEqual(JSON.stringify(base), baseSnapshot);
  });

  it('rejects empty-path denials as invalid', () => {
    const result = regenerateSandboxPolicy({
      basePolicy,
      approvedDenials: [fileDenial('   ')],
    });
    assert.strictEqual(result.added.length, 0);
    assert.deepStrictEqual(result.skipped, [
      { path: '   ', reason: 'invalid-path' },
    ]);
  });

  it('returns an empty result when no approvals are passed', () => {
    const result = regenerateSandboxPolicy({
      basePolicy,
      approvedDenials: [],
    });
    assert.strictEqual(result.added.length, 0);
    assert.strictEqual(result.skipped.length, 0);
    // Policy filesystem fields exist as empty arrays.
    assert.deepStrictEqual(result.policy.filesystem?.readonlyPaths, []);
    assert.deepStrictEqual(result.policy.filesystem?.readwritePaths, []);
  });
});
