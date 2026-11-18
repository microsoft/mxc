// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import koffi, { type LibraryHandle } from 'koffi';
import { AbiErrorDetailType, nativeStatusError, type AbiErrorDetail } from './bindings/native-error.js';

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

type RuntimeDependencies = {
  resolve: (name: string) => string;
  readFile: (name: string) => string;
  realpath: (name: string) => string;
  isDirectory: (name: string) => boolean;
};

const runtimeDependencies: RuntimeDependencies = {
  resolve: (name) => require.resolve(name),
  readFile: (name) => fs.readFileSync(name, 'utf8'),
  realpath: (name) => fs.realpathSync(name),
  isDirectory: (name) => fs.statSync(name).isDirectory(),
};

type RuntimeNative = {
  register: (backend: string, directory: string, detail: AbiErrorDetail) => number;
  freeError: (detail: AbiErrorDetail) => void;
};

/** @internal Resolve the optional runtime and register it with the native library. */
export function _bootstrapNvxRuntimeForTest(
  native: RuntimeNative,
  dependencies: RuntimeDependencies = runtimeDependencies,
  packageRoot = getPackageRoot(),
): void {
  let runtimeManifest: string;
  try {
    runtimeManifest = dependencies.resolve('@microsoft/mxc-sdk-nvx-runtime-win32-x64/package.json');
  } catch (error) {
    if (error !== null && typeof error === 'object' && 'code' in error
      && (error.code === 'MODULE_NOT_FOUND' || error.code === 'ERR_MODULE_NOT_FOUND')) return;
    throw error;
  }
  let directory: string;
  try {
    const runtime: unknown = JSON.parse(dependencies.readFile(runtimeManifest));
    const sdk: unknown = JSON.parse(dependencies.readFile(path.join(packageRoot, 'package.json')));
    if (!runtime || typeof runtime !== 'object' || !('version' in runtime)
      || typeof runtime.version !== 'string' || !runtime.version
      || !sdk || typeof sdk !== 'object' || !('version' in sdk)
      || typeof sdk.version !== 'string' || !sdk.version) {
      throw new Error('package version is missing or invalid');
    }
    if (runtime.version !== sdk.version) {
      throw new Error(`runtime version ${runtime.version} does not match SDK version ${sdk.version}`);
    }
    directory = dependencies.realpath(path.join(path.dirname(runtimeManifest), 'aci-edge-sandboxes'));
    if (!dependencies.isDirectory(directory)) throw new Error('aci-edge-sandboxes is not a directory');
  } catch (error) {
    throw new Error(`Invalid @microsoft/mxc-sdk-nvx-runtime-win32-x64 installation: ${error instanceof Error ? error.message : String(error)}`);
  }
  const detail = {} as AbiErrorDetail;
  const status = native.register('microvm', directory, detail);
  if (status !== 0) {
    try {
      throw nativeStatusError(status, detail, 'NVX runtime directory registration failed');
    } finally {
      native.freeError(detail);
    }
  }
}

function bootstrapNvxRuntime(handle: LibraryHandle): void {
  // Resolve first: an absent optional package must not require the new native symbol.
  let manifest: string;
  try {
    manifest = runtimeDependencies.resolve('@microsoft/mxc-sdk-nvx-runtime-win32-x64/package.json');
  } catch (error) {
    if (error !== null && typeof error === 'object' && 'code' in error
      && (error.code === 'MODULE_NOT_FOUND' || error.code === 'ERR_MODULE_NOT_FOUND')) return;
    throw error;
  }
  const register = handle.func('mxc_register_runtime_directory', 'int32_t', [
    'const char *', 'const char *', koffi.out(koffi.pointer(AbiErrorDetailType)),
  ]) as RuntimeNative['register'];
  const freeError = handle.func('mxc_error_detail_free', 'void', [
    koffi.pointer(AbiErrorDetailType),
  ]) as RuntimeNative['freeError'];
  _bootstrapNvxRuntimeForTest({ register, freeError }, {
    ...runtimeDependencies,
    resolve: () => manifest,
  });
}

export function loadMxcFfi(candidates = _mxcFfiCandidates()): MxcNativeLibrary {
  const libraryPath = findMxcFfiLibrary(candidates);
  if (!libraryPath) {
    throw new Error(
      `mxc_ffi native library was not found. Searched:\n${candidates.map((candidate) => `- ${candidate}`).join('\n')}`,
    );
  }
  const handle = koffi.load(libraryPath);
  try {
    const version = handle.func('const char *mxc_version(void)') as () => string;
    if (process.platform === 'win32' && process.arch === 'x64') bootstrapNvxRuntime(handle);
    return { path: libraryPath, handle, version };
  } catch (error) {
    handle.unload();
    throw error;
  }
}
