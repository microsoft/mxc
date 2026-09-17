// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { afterEach, describe, it, mock } from 'node:test';
import assert from 'node:assert';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import koffi from 'koffi';
import { _mxcFfiCandidates, loadMxcFfi } from '../../src/native-library.js';

const oldFfiDir = process.env.MXC_FFI_DIR;

afterEach(() => {
  if (oldFfiDir === undefined) delete process.env.MXC_FFI_DIR;
  else process.env.MXC_FFI_DIR = oldFfiDir;
});

describe('mxc_ffi library resolution', () => {
  it('uses the packaged library for each platform', () => {
    delete process.env.MXC_FFI_DIR;

    assert.strictEqual(
      _mxcFfiCandidates('sdk', 'win32', 'x64')[0],
      path.join('sdk', 'bin', 'x64', 'mxc_ffi.dll'),
    );
    assert.strictEqual(
      _mxcFfiCandidates('sdk', 'linux', 'arm64')[0],
      path.join('sdk', 'bin', 'arm64', 'libmxc_ffi.so'),
    );
    assert.strictEqual(
      _mxcFfiCandidates('sdk', 'darwin', 'arm64')[0],
      path.join('sdk', 'bin', 'arm64', 'libmxc_ffi.dylib'),
    );
  });

  it('prefers the explicit native library location', () => {
    process.env.MXC_FFI_DIR = path.join('custom', 'ffi');

    const candidates = _mxcFfiCandidates('sdk', 'win32', 'x64');
    assert.strictEqual(candidates[0], path.join('custom', 'ffi', 'mxc_ffi.dll'));
  });

  it('falls back to target-specific Cargo output', () => {
    delete process.env.MXC_FFI_DIR;

    const candidates = _mxcFfiCandidates('sdk', 'linux', 'x64');
    assert.strictEqual(
      candidates[1],
      path.join('..', 'src', 'target', 'x86_64-unknown-linux-gnu', 'release', 'libmxc_ffi.so'),
    );
  });

  it('reports every searched location when the library is missing', () => {
    const candidates = [
      path.join('custom', 'ffi', 'mxc_ffi.dll'),
      path.join('sdk', 'bin', 'x64', 'mxc_ffi.dll'),
    ];

    assert.throws(
      () => loadMxcFfi(candidates),
      (error: unknown) => error instanceof Error
        && candidates.every((candidate) => error.message.includes(candidate)),
    );
  });

  it('loads the selected library and binds mxc_version', () => {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'mxc-node-loader-'));
    const libraryPath = path.join(directory, 'mxc_ffi.dll');
    fs.writeFileSync(libraryPath, '');

    try {
      let loadedPath: string | null | undefined;
      let boundDeclaration: string | undefined;
      const version = () => 'test-version';
      const load = mock.method(koffi, 'load', (candidate: string | null) => {
        loadedPath = candidate;
        return {
          func(...args: unknown[]) {
            boundDeclaration = String(args[0]);
            return version;
          },
        };
      });

      try {
        const library = loadMxcFfi([libraryPath]);

        assert.strictEqual(loadedPath, libraryPath);
        assert.strictEqual(boundDeclaration, 'const char *mxc_version(void)');
        assert.strictEqual(library.version(), 'test-version');
      } finally {
        load.mock.restore();
      }
    } finally {
      fs.rmSync(directory, { recursive: true, force: true });
    }
  });
});
