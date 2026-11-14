// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';

export interface PackagedRuntimeTestOptions {
  sdkRoot: string;
  runtimeRoot: string;
  library: string;
  dependencyRoots: string[];
  fixtureParent: string;
  inventoryFile?: string;
  buildSdk?: boolean;
  baseTarball?: string;
  runtimeTarball?: string;
}

function findNpmCli(): string {
  if (process.env.npm_execpath) return process.env.npm_execpath;
  const dirs = (process.env.PATH ?? '').split(path.delimiter);
  const candidates = dirs.flatMap(dir => [
    path.join(dir, 'node_modules', 'npm', 'bin', 'npm-cli.js'),
    path.join(dir, '..', 'lib', 'node_modules', 'npm', 'bin', 'npm-cli.js'),
  ]);
  const cli = candidates.find(file => fs.existsSync(file));
  if (!cli) throw new Error('npm CLI is required for the packaged-runtime integration test');
  return cli;
}

function digest(file: string): string {
  return createHash('sha256').update(fs.readFileSync(file)).digest('hex');
}

function packageDirectory(name: string, roots: string[]): string {
  for (const root of roots) {
    const candidates = [path.join(root, ...name.split('/')),
      path.join(root, 'node-pty', 'node_modules', ...name.split('/'))];
    for (const candidate of candidates) {
      if (fs.existsSync(path.join(candidate, 'package.json'))) return candidate;
    }
  }
  throw new Error(`Missing locally installed dependency ${name} for offline npm install`);
}

export function verifyPackagedRuntime(options: PackagedRuntimeTestOptions): void {
  if (!fs.existsSync(options.library)) throw new Error(`Required mxc_ffi.dll is missing: ${options.library}`);
  const fixture = fs.mkdtempSync(path.join(options.fixtureParent, '.nvx-npm-consumer-'));
  try {
    const npm = findNpmCli();
    const archives = path.join(fixture, 'archives');
    const consumer = path.join(fixture, 'consumer');
    fs.mkdirSync(archives);
    fs.mkdirSync(consumer);
    const localAppData = path.join(fixture, 'local-appdata');
    fs.mkdirSync(localAppData);
    fs.writeFileSync(path.join(consumer, 'package.json'), JSON.stringify({ private: true, type: 'module' }));
    const env: NodeJS.ProcessEnv = { ...process.env, MXC_FFI_DIR: '',
      ACI_EDGE_SANDBOXES_AGENT_ARTIFACTS_DIR: '', LOCALAPPDATA: localAppData,
      npm_config_cache: path.join(fixture, 'npm-cache') };
    delete env.MXC_NVX_TEST_DLL;
    delete env.NODE_PATH;
    const runNpm = (args: string[], cwd: string) => {
      const child = spawnSync(process.execPath, [npm, ...args], { cwd, env, encoding: 'utf8', timeout: 180_000 });
      assert.ifError(child.error);
      assert.equal(child.status, 0, child.stdout + child.stderr);
      return child.stdout;
    };
    const pack = (source: string) => {
      const info = JSON.parse(
        runNpm(['pack', '--pack-destination', archives, '--json', '--ignore-scripts', '--offline'], source),
      )[0] as { filename: string; files: Array<{ path: string }> };
      return { file: path.join(archives, info.filename), files: info.files.map(file => file.path) };
    };

    const sdkBin = path.join(options.sdkRoot, 'bin', 'x64');
    const stagedDll = path.join(sdkBin, 'mxc_ffi.dll');
    const createdBin = !fs.existsSync(sdkBin);
    let stagedByTest = false;
    let stagedHash = '';
    let baseTarball: string;
    try {
      if (options.baseTarball) {
        baseTarball = options.baseTarball;
      } else {
        fs.mkdirSync(sdkBin, { recursive: true });
        if (!fs.existsSync(stagedDll)) {
          fs.copyFileSync(options.library, stagedDll, fs.constants.COPYFILE_EXCL);
          stagedByTest = true;
          stagedHash = digest(stagedDll);
        } else {
          assert.equal(digest(stagedDll), digest(options.library), 'existing SDK DLL differs from the selected fixture');
        }
        if (options.buildSdk) runNpm(['run', 'build'], options.sdkRoot);
        const base = pack(options.sdkRoot);
        assert.ok(base.files.includes('bin/x64/mxc_ffi.dll'));
        assert.ok(!base.files.some(file => file.includes('aci-edge-sandboxes')));
        baseTarball = base.file;
      }
    } finally {
      if (stagedByTest) {
        assert.equal(digest(stagedDll), stagedHash, 'refusing to delete a changed SDK fixture DLL');
        fs.unlinkSync(stagedDll);
      }
      if (createdBin && !options.baseTarball) fs.rmdirSync(sdkBin);
    }

    let synthetic = false;
    let runtimeTarball = options.runtimeTarball;
    if (!runtimeTarball) {
      let runtimeSource = options.runtimeRoot;
      if (!fs.existsSync(path.join(runtimeSource, 'aci-edge-sandboxes', 'bundle-manifest.json'))) {
        runtimeSource = path.join(fixture, 'runtime-source');
        fs.mkdirSync(runtimeSource);
        for (const file of ['package.json', 'README.md']) {
          fs.copyFileSync(path.join(options.runtimeRoot, file), path.join(runtimeSource, file));
        }
        const bundled = path.join(path.dirname(options.library), 'aci-edge-sandboxes');
        const destination = path.join(runtimeSource, 'aci-edge-sandboxes');
        if (fs.existsSync(path.join(bundled, 'bundle-manifest.json'))) {
          fs.cpSync(bundled, destination, { recursive: true });
        } else {
          synthetic = true;
          if (!options.inventoryFile) throw new Error('NVX runtime bundle and synthetic inventory are missing');
          const contract = fs.readFileSync(options.inventoryFile, 'utf8');
          const inventory = contract.match(/const REQUIRED_BUNDLE_FILES:[^=]+=[^\[]*\[([\s\S]*?)\];/);
          assert.ok(inventory, 'NVX bundle inventory not found');
          const files = [...inventory[1].matchAll(/r"([^"\r\n]+)"/g)].map(match => match[1]);
          assert.equal(files.length, 147);
          for (const file of files) {
            const target = path.join(destination, ...file.split('\\'));
            fs.mkdirSync(path.dirname(target), { recursive: true });
            fs.writeFileSync(target, file === 'bundle-manifest.json' ? '{}' : 'synthetic');
          }
        }
      }
      const runtimePack = pack(runtimeSource);
      assert.ok(runtimePack.files.includes('aci-edge-sandboxes/bundle-manifest.json'));
      assert.ok(runtimePack.files.includes('aci-edge-sandboxes/bin/aci_edge_agent.dll'));
      if (synthetic) assert.equal(runtimePack.files.filter(file => file.startsWith('aci-edge-sandboxes/')).length, 147);
      runtimeTarball = runtimePack.file;
    }

    const dependencies = ['koffi', '@koromix/koffi-win32-x64', 'node-pty', 'node-addon-api', 'semver']
      .map(name => {
        const source = packageDirectory(name, options.dependencyRoots);
        const staging = path.join(fixture, 'dependency-sources', name.replace(/[^a-z0-9-]/gi, '-'));
        fs.mkdirSync(staging, { recursive: true });
        fs.cpSync(source, path.join(staging, 'package'), {
          recursive: true, filter: entry => path.basename(entry) !== 'node_modules',
        });
        const archive = path.join(archives, `${name.replace(/[^a-z0-9-]/gi, '-')}.tgz`);
        const packed = spawnSync('tar', ['-czf', path.basename(archive), '-C', staging, 'package'], {
          cwd: archives, encoding: 'utf8', timeout: 60_000,
        });
        assert.ifError(packed.error);
        assert.equal(packed.status, 0, packed.stdout + packed.stderr);
        return archive;
      });
    runNpm(['install', '--no-save', '--no-audit', '--no-fund', '--offline', '--ignore-scripts',
      baseTarball, runtimeTarball, ...dependencies], consumer);
    const lock = JSON.parse(fs.readFileSync(path.join(consumer, 'node_modules', '.package-lock.json'), 'utf8'));
    for (const name of ['@microsoft/mxc-sdk', '@microsoft/mxc-sdk-nvx-runtime-win32-x64']) {
      assert.ok(String(lock.packages[`node_modules/${name}`]?.resolved).startsWith('file:'), `${name} was not installed from a tarball`);
    }
    const script = `
      import assert from 'node:assert/strict';
      import path from 'node:path';
      import fs from 'node:fs';
      import { createRequire } from 'node:module';
      import koffi from 'koffi';
      import { getPlatformSupport, getAvailableBackends, MxcError } from '@microsoft/mxc-sdk/v1';
      import { validateProvisionJson } from '@microsoft/mxc-sdk/v1/dev';
      assert.ok(!process.env.MXC_FFI_DIR && !process.env.ACI_EDGE_SANDBOXES_AGENT_ARTIFACTS_DIR);
      const require = createRequire(import.meta.url);
      for (const name of ['@microsoft/mxc-sdk', '@microsoft/mxc-sdk-nvx-runtime-win32-x64', 'koffi', 'node-pty', 'semver']) {
        const resolved = fs.realpathSync(require.resolve(name === 'node-pty' ? name : name.startsWith('@microsoft/') ? name + '/package.json' : name));
        assert.ok(resolved.toLowerCase().startsWith(fs.realpathSync('node_modules').toLowerCase() + path.sep), name + ' resolved outside the consumer');
      }
      const kernel = koffi.load('kernel32.dll');
      const getPid = kernel.func('uint32_t GetCurrentProcessId(void)');
      await new Promise((resolve, reject) => getPid.async((error, value) => error ? reject(error) : resolve(value)));
      assert.throws(() => koffi.config({ async_stack_size: 2 * 1024 * 1024 }), /Cannot change Koffi configuration/);
      assert.equal(typeof getPlatformSupport().isSupported, 'boolean');
      assert.ok(Array.isArray(getAvailableBackends()));
      const request = JSON.stringify({ version: '1.1.0-alpha', phase: 'provision', containment: 'microvm',
        microvm: { image: 'mcr.microsoft.com/azurelinux/base/core:3.0' } });
      try {
        await validateProvisionJson(request, { experimental: true });
        assert.equal(process.argv[1], 'real', 'synthetic runtime unexpectedly validated');
      } catch (error) {
        assert.ok(error instanceof MxcError);
        assert.equal(error.code, 'backend_unavailable');
        if (process.argv[1] === 'synthetic') {
          assert.match(error.message, /does not match the approved SHA-256/i);
          assert.ok(error.message.toLowerCase().includes(path.resolve('node_modules/@microsoft/mxc-sdk-nvx-runtime-win32-x64/aci-edge-sandboxes/bin/aci_edge_agent.dll').toLowerCase()));
        } else {
          assert.match(error.message, /hypervisor|capabilit|whp/i);
          assert.doesNotMatch(error.message, /no agent bundle|bundle is missing|signature rejected|does not match the approved SHA-256/i);
        }
      }
      const native = koffi.load(path.resolve('node_modules/@microsoft/mxc-sdk/bin/x64/mxc_ffi.dll'));
      const detailType = koffi.struct('NvxPackageSmokeError', {
        message: 'void *', operation: 'void *', nativeCode: 'void *', remediation: 'void *',
      });
      const register = native.func('mxc_register_runtime_directory', 'int32_t',
        ['const char *', 'const char *', koffi.out(koffi.pointer(detailType))]);
      const free = native.func('mxc_error_detail_free', 'void', [koffi.pointer(detailType)]);
      const detail = {};
      try { assert.equal(register('microvm', process.cwd(), detail), 11); }
      finally { free(detail); native.unload(); }
    `;
    const child = spawnSync(process.execPath, ['--input-type=module', '-e', script, synthetic ? 'synthetic' : 'real'], {
      cwd: consumer, env, encoding: 'utf8', timeout: 120_000,
    });
    assert.ifError(child.error);
    assert.equal(child.status, 0, child.stdout + child.stderr);
  } finally {
    fs.rmSync(fixture, { recursive: true, force: true });
  }
}
