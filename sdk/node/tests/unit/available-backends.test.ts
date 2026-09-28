// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import assert from 'node:assert/strict';
import { afterEach, describe, it } from 'node:test';
import {
  _setAvailableBackendsJsonReader,
  getAvailableBackends,
} from '../../src/available-backends.js';
import { readAvailableBackendsJsonWithNative } from '../../src/bindings/available-backends.js';

afterEach(() => {
  _setAvailableBackendsJsonReader();
});

describe('getAvailableBackends', () => {
  it('preserves future strings and normalizes omitted arrays', () => {
    _setAvailableBackendsJsonReader(() => JSON.stringify([
      {
        backend: 'future_backend',
        tier: 'future-tier',
        capabilities: ['futureCapability'],
      },
      { backend: 'seatbelt' },
    ]));

    assert.deepStrictEqual(getAvailableBackends(), [
      {
        backend: 'future_backend',
        tier: 'future-tier',
        capabilities: ['futureCapability'],
        warnings: [],
      },
      {
        backend: 'seatbelt',
        capabilities: [],
        warnings: [],
      },
    ]);
  });

  it('accepts an empty discovery result', () => {
    _setAvailableBackendsJsonReader(() => '[]');
    assert.deepStrictEqual(getAvailableBackends(), []);
  });

  for (const [name, payload, message] of [
    ['top-level non-array', '{}', /expected an array/],
    ['missing backend', '[{}]', /backend must be a string/],
    ['non-string backend', '[{"backend":1}]', /backend must be a string/],
    ['non-string tier', '[{"backend":"lxc","tier":1}]', /tier must be a string/],
    ['non-array capabilities', '[{"backend":"lxc","capabilities":null}]', /capabilities must be an array/],
    ['non-array warnings', '[{"backend":"lxc","warnings":{}}]', /warnings must be an array/],
    ['non-string capability', '[{"backend":"lxc","capabilities":[1]}]', /capabilities entries must be strings/],
    ['non-string warning', '[{"backend":"lxc","warnings":[null]}]', /warnings entries must be strings/],
  ] as const) {
    it(`rejects ${name}`, () => {
      _setAvailableBackendsJsonReader(() => payload);
      assert.throws(() => getAvailableBackends(), message);
    });
  }
});

describe('available backend native ownership', () => {
  for (const pointer of [null, undefined, 0, 0n]) {
    it(`rejects ${String(pointer)} without freeing`, () => {
      let frees = 0;
      assert.throws(
        () => readAvailableBackendsJsonWithNative({
          availableBackends: () => pointer,
          freeString: () => { frees += 1; },
        }),
        /probing available backends failed/,
      );
      assert.strictEqual(frees, 0);
    });
  }

  it('decodes and frees a non-null pointer exactly once', () => {
    const pointer = { address: 1 };
    const freed: unknown[] = [];
    const value = readAvailableBackendsJsonWithNative(
      {
        availableBackends: () => pointer,
        freeString: (candidate) => freed.push(candidate),
      },
      (candidate) => candidate === pointer ? '[]' : undefined,
    );
    assert.strictEqual(value, '[]');
    assert.deepStrictEqual(freed, [pointer]);
  });

  it('frees after decode failure', () => {
    const pointer = { address: 1 };
    let frees = 0;
    assert.throws(
      () => readAvailableBackendsJsonWithNative(
        {
          availableBackends: () => pointer,
          freeString: () => { frees += 1; },
        },
        () => { throw new Error('decode failed'); },
      ),
      /decode failed/,
    );
    assert.strictEqual(frees, 1);
  });

  it('has already freed native memory before JSON projection fails', () => {
    const pointer = { address: 1 };
    let frees = 0;
    const json = readAvailableBackendsJsonWithNative(
      {
        availableBackends: () => pointer,
        freeString: () => { frees += 1; },
      },
      () => 'not json',
    );
    assert.strictEqual(frees, 1);
    _setAvailableBackendsJsonReader(() => json);
    assert.throws(() => getAvailableBackends(), SyntaxError);
    assert.strictEqual(frees, 1);
  });
});
