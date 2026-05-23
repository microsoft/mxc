// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { describe, it } from 'node:test';
import assert from 'node:assert';
import {
  ContainmentRegistry,
  ExperimentalContainments,
  judge,
} from '../../src/version-registry.js';
import { ContainmentBackend } from '../../src/types.js';

describe('judge (containment)', () => {
  describe('canonical values', () => {
    it("returns 'ok' for a stable value in any supported version", () => {
      for (const v of ['0.4.0-alpha', '0.5.0-alpha', '0.6.0-alpha']) {
        const verdict = judge(ContainmentRegistry, 'lxc', v);
        assert.strictEqual(verdict.kind, 'ok', `version ${v}`);
        if (verdict.kind === 'ok') {
          assert.strictEqual(verdict.canonical, 'lxc');
          assert.strictEqual(verdict.entry.experimental, undefined);
        }
      }
    });

    it("returns 'ok' for a value introduced in the declared version", () => {
      const verdict = judge(ContainmentRegistry, 'processcontainer', '0.6.0-alpha');
      assert.strictEqual(verdict.kind, 'ok');
      if (verdict.kind === 'ok') {
        assert.strictEqual(verdict.canonical, 'processcontainer');
      }
    });

    it('exposes the experimental flag on the verdict entry', () => {
      const verdict = judge(ContainmentRegistry, 'hyperlight', '0.6.0-alpha');
      assert.strictEqual(verdict.kind, 'ok');
      if (verdict.kind === 'ok') {
        assert.strictEqual(verdict.entry.experimental, true);
      }
    });

    it('exposes the abstract flag on the verdict entry', () => {
      const verdict = judge(ContainmentRegistry, 'process', '0.6.0-alpha');
      assert.strictEqual(verdict.kind, 'ok');
      if (verdict.kind === 'ok') {
        assert.strictEqual(verdict.entry.abstract, true);
      }
    });
  });

  describe('deprecated aliases', () => {
    it("returns 'ok-deprecated' for 'appcontainer' regardless of declared version", () => {
      for (const v of ['0.4.0-alpha', '0.5.0-alpha', '0.6.0-alpha']) {
        const verdict = judge(ContainmentRegistry, 'appcontainer', v);
        assert.strictEqual(verdict.kind, 'ok-deprecated', `version ${v}`);
        if (verdict.kind === 'ok-deprecated') {
          assert.strictEqual(verdict.canonical, 'processcontainer');
          assert.strictEqual(verdict.deprecatedSince, '0.6.0-alpha');
        }
      }
    });

    it("returns 'ok-deprecated' for 'macos_sandbox' with the canonical pointing to seatbelt", () => {
      const verdict = judge(ContainmentRegistry, 'macos_sandbox', '0.5.0-alpha');
      assert.strictEqual(verdict.kind, 'ok-deprecated');
      if (verdict.kind === 'ok-deprecated') {
        assert.strictEqual(verdict.canonical, 'seatbelt');
        assert.strictEqual(verdict.entry.experimental, undefined);
      }
    });
  });

  describe('sunset (removeIn)', () => {
    it("returns 'removed' once the declared version reaches removeIn", () => {
      const reg = {
        ...ContainmentRegistry,
        appcontainer: {
          addedIn: '0.4.0-alpha',
          deprecatedSince: '0.6.0-alpha',
          renamedTo: 'processcontainer',
          removeIn: '0.7.0-alpha',
        },
      };
      const verdict = judge(reg, 'appcontainer', '0.7.0-alpha');
      assert.strictEqual(verdict.kind, 'removed');
      if (verdict.kind === 'removed') {
        assert.strictEqual(verdict.removedIn, '0.7.0-alpha');
        assert.strictEqual(verdict.canonical, 'processcontainer');
      }
    });

    it("still returns 'ok-deprecated' below the removeIn threshold", () => {
      const reg = {
        ...ContainmentRegistry,
        appcontainer: {
          addedIn: '0.4.0-alpha',
          deprecatedSince: '0.6.0-alpha',
          renamedTo: 'processcontainer',
          removeIn: '0.7.0-alpha',
        },
      };
      const verdict = judge(reg, 'appcontainer', '0.6.0-alpha');
      assert.strictEqual(verdict.kind, 'ok-deprecated');
    });
  });

  describe('anachronism (too-new)', () => {
    it("returns 'too-new' when the value was added after the declared version", () => {
      const verdict = judge(ContainmentRegistry, 'isolation_session', '0.5.0-alpha');
      assert.strictEqual(verdict.kind, 'too-new');
      if (verdict.kind === 'too-new') {
        assert.strictEqual(verdict.canonical, 'isolation_session');
        assert.strictEqual(verdict.addedIn, '0.6.0-alpha');
      }
    });

    it("returns 'ok' when the declared version exactly matches addedIn", () => {
      const verdict = judge(ContainmentRegistry, 'isolation_session', '0.6.0-alpha');
      assert.strictEqual(verdict.kind, 'ok');
    });
  });

  describe('unknown values', () => {
    it("returns 'unknown' for a value not in the registry", () => {
      const verdict = judge(ContainmentRegistry, 'definitely-not-real', '0.6.0-alpha');
      assert.strictEqual(verdict.kind, 'unknown');
      if (verdict.kind === 'unknown') {
        assert.strictEqual(verdict.rawValue, 'definitely-not-real');
      }
    });
  });

  describe('version handling', () => {
    it('treats an unparseable declared version as "no anachronism / no sunset"', () => {
      // Deprecation still fires (version-agnostic policy), but anachronism
      // checks are skipped.
      const v1 = judge(ContainmentRegistry, 'isolation_session', 'not-semver');
      assert.strictEqual(v1.kind, 'ok');
      const v2 = judge(ContainmentRegistry, 'appcontainer', 'not-semver');
      assert.strictEqual(v2.kind, 'ok-deprecated');
    });

    it('treats a missing declared version the same way', () => {
      const verdict = judge(ContainmentRegistry, 'isolation_session', undefined);
      assert.strictEqual(verdict.kind, 'ok');
    });
  });
});

describe('ContainmentRegistry coverage', () => {
  it('has a registry entry for every value in the ContainmentBackend union', () => {
    // Defensive: if a new backend lands in the TS union without a registry
    // entry, the SDK falls back to 'unknown' and loses experimental gating
    // for that value. The hyperlight drift bug (#TBD) is exactly this.
    const unionMembers: ContainmentBackend[] = [
      'processcontainer',
      'windows_sandbox',
      'wslc',
      'lxc',
      'microvm',
      'hyperlight',
      'seatbelt',
      'isolation_session',
      'bubblewrap',
    ];
    for (const v of unionMembers) {
      assert.ok(
        ContainmentRegistry[v],
        `ContainmentRegistry is missing an entry for '${v}'`,
      );
    }
  });

  it('ExperimentalContainments is derived correctly from the registry', () => {
    const expected = ['windows_sandbox', 'microvm', 'wslc', 'isolation_session', 'hyperlight'];
    for (const v of expected) {
      assert.ok(
        ExperimentalContainments.includes(v),
        `ExperimentalContainments missing '${v}'`,
      );
    }
    // Non-experimental values should not appear.
    for (const v of ['lxc', 'appcontainer', 'processcontainer', 'macos_sandbox', 'seatbelt', 'bubblewrap', 'process', 'vm']) {
      assert.ok(
        !ExperimentalContainments.includes(v),
        `ExperimentalContainments unexpectedly includes '${v}'`,
      );
    }
  });
});
