// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import koffi, { type LibraryHandle } from 'koffi';

const require = createRequire(import.meta.url);

function getPackageRoot(): string {
  try {
    return path.dirname(require.resolve('@microsoft/mxc-sdk/package.json'));
  } catch {
    const parent = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
    return fs.existsSync(path.join(parent, 'package.json')) ? parent : path.join(parent, '..');
  }
}

function libraryName(platform: NodeJS.Platform): string {
  switch (platform) {
    case 'win32':
      return 'mxc_ffi.dll';
    case 'darwin':
      return 'libmxc_ffi.dylib';
    case 'linux':
      return 'libmxc_ffi.so';
    default:
      throw new Error(`Unsupported platform: ${platform}`);
  }
}

function targetTriple(platform: NodeJS.Platform, arch: string): string {
  if (arch !== 'arm64' && arch !== 'x64') {
    throw new Error(`Unsupported architecture: ${arch}`);
  }
  const prefix = arch === 'arm64' ? 'aarch64' : 'x86_64';
  switch (platform) {
    case 'win32':
      return `${prefix}-pc-windows-msvc`;
    case 'darwin':
      return `${prefix}-apple-darwin`;
    case 'linux':
      return `${prefix}-unknown-linux-gnu`;
    default:
      throw new Error(`Unsupported platform: ${platform}`);
  }
}

/** @internal Candidate paths are exported for deterministic unit tests. */
export function _mxcFfiCandidates(
  packageRoot = getPackageRoot(),
  platform = os.platform(),
  arch = os.arch(),
): string[] {
  const file = libraryName(platform);
  const sdkArch = arch === 'arm64' ? 'arm64' : 'x64';
  const targetDir = path.join(packageRoot, '..', '..', 'src', 'target');
  const candidates = [
    path.join(packageRoot, 'bin', sdkArch, file),
    path.join(targetDir, targetTriple(platform, arch), 'release', file),
    path.join(targetDir, targetTriple(platform, arch), 'debug', file),
    path.join(targetDir, 'release', file),
    path.join(targetDir, 'debug', file),
  ];

  if (process.env.MXC_FFI_DIR) {
    candidates.unshift(path.join(process.env.MXC_FFI_DIR, file));
  }
  return candidates;
}

export function findMxcFfiLibrary(candidates = _mxcFfiCandidates()): string | null {
  return candidates.find((candidate) => {
    try {
      return fs.statSync(candidate).isFile();
    } catch {
      return false;
    }
  }) ?? null;
}

export type MxcNativeLibrary = {
  path: string;
  handle: LibraryHandle;
  version: () => string;
};

export function loadMxcFfi(candidates = _mxcFfiCandidates()): MxcNativeLibrary {
  const libraryPath = findMxcFfiLibrary(candidates);
  if (!libraryPath) {
    throw new Error(
      `mxc_ffi native library was not found. Searched:\n${candidates.map((candidate) => `- ${candidate}`).join('\n')}`,
    );
  }
  const handle = koffi.load(libraryPath);
  const version = handle.func('const char *mxc_version(void)') as () => string;
  return { path: libraryPath, handle, version };
}
