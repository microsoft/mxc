// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import assert from 'node:assert/strict';
import { it } from 'node:test';
import { runJson, spawnJson, spawnWithPtyJson, validateProcessJson } from '@microsoft/mxc-sdk/v1/dev';
import { MxcError } from '@microsoft/mxc-sdk/v1';
import { isLinuxRoot, sandboxSkipReason } from './test-helpers.js';
import { createRequire } from 'node:module';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { verifyPackagedRuntime } from './packaged-runtime-test.js';

const windows = process.platform === 'win32';
const creationSkip = windows ? sandboxSkipReason
  : process.platform === 'linux' ? (isLinuxRoot ? undefined : 'Bubblewrap requires root')
  : process.platform === 'darwin' ? undefined : 'Unsupported host';

async function readAll(stream: NodeJS.ReadableStream): Promise<string> {
  let text = '';
  for await (const chunk of stream) text += chunk.toString();
  return text;
}

for (const version of ['1.0.0', '1.1.0-alpha']) {
  const request = (commandLine: string) => JSON.stringify({
    version,
    containment: 'process',
    process: { commandLine, timeout: 30000 },
  });

  it(`V1.Dev runJson captures output and exit status (${version})`, { skip: creationSkip }, async () => {
    const result = await runJson(request(windows
      ? 'cmd.exe /c "echo DEV_CAPTURE_OK & echo DEV_CAPTURE_ERR 1>&2 & exit /b 7"'
      : "printf 'DEV_CAPTURE_OK\\n'; printf 'DEV_CAPTURE_ERR\\n' >&2; exit 7"));
    assert.equal(result.exitCode, 7);
    assert.equal(result.timedOut, false);
    assert.ok(result.stdout.includes('DEV_CAPTURE_OK'));
    assert.ok(result.stderr.includes('DEV_CAPTURE_ERR'));
    assert.ok(Array.isArray(result.warnings));
  });

  it(`V1.Dev spawnJson supports bidirectional pipes (${version})`, { skip: creationSkip }, async () => {
    const proc = await spawnJson(request(windows
      ? 'cmd.exe /v:on /c "set /p L= & echo DEV_PIPE:!L! & echo DEV_PIPE_ERR 1>&2 & exit /b 9"'
      : 'IFS= read -r line; printf "DEV_PIPE:%s\\n" "$line"; printf "DEV_PIPE_ERR\\n" >&2; exit 9'),
    { experimental: true });
    try {
      assert.ok(proc.standardInput);
      assert.ok(proc.standardOutput);
      assert.ok(proc.standardError);
      const stdout = readAll(proc.standardOutput);
      const stderr = readAll(proc.standardError);
      proc.standardInput.end(windows ? 'ping-pong\r\n' : 'ping-pong\n');
      const result = await proc.wait();
      assert.equal(result.exitCode, 9);
      assert.equal(result.timedOut, false);
      assert.ok((await stdout).includes('DEV_PIPE:ping-pong'));
      assert.ok((await stderr).includes('DEV_PIPE_ERR'));
    } finally {
      proc.dispose();
    }
  });

  it(`V1.Dev spawnWithPtyJson supports an interactive terminal (${version})`, { skip: creationSkip }, async () => {
    const command = windows ? 'cmd.exe'
      : 'test -t 0 && test -t 1 || exit 12; IFS= read -r value; '
        + 'stty size; printf "DEV_PTY_%s\\n" "$value"; exit 13';
    const terminal = await spawnWithPtyJson(request(command), {
      size: { rows: 30, columns: 90 },
    });
    try {
      const output = readAll(terminal.output);
      terminal.resize({ rows: 40, columns: 100 });
      terminal.input.write(windows
        ? 'set MXC_DEV_MARK=OK\r\necho DEV_PTY_%MXC_DEV_MARK%\r\nexit /b 13\r\n'
        : 'OK\n');
      const result = await terminal.wait();
      const text = await output;
      assert.equal(result.exitCode, 13, text);
      assert.equal(result.timedOut, false);
      assert.match(text, /DEV_PTY_OK/);
      if (!windows) assert.match(text, /40 100/);
    } finally {
      terminal.dispose();
    }
  });
}

it('V1.Dev rejects unknown fields and unregistered exact versions through native', async () => {
  const unregistered =
    '{"version":"999.0.0","process":{"commandLine":"echo must-not-run"}}';
  await assert.rejects(
    runJson(unregistered),
    (error: unknown) => error instanceof MxcError && error.code === 'malformed_request',
  );

  const unknownField =
    '{"version":"1.0.0","phase":"exec","sandboxId":"iso:unused","process":{"commandLine":"echo must-not-run"},"extra":true}';
  await assert.rejects(
    validateProcessJson(unknownField),
    (error: unknown) => error instanceof MxcError && error.code === 'malformed_request',
  );
});


it('V1.Dev installs both npm packages and discovers NVX without overrides', {
  skip: process.platform !== 'win32' || process.arch !== 'x64',
  timeout: 300_000,
}, () => {
  const require = createRequire(import.meta.url);
  const installedSdk = path.dirname(require.resolve('@microsoft/mxc-sdk/package.json'));
  const integrationRoot = process.cwd();
  const sdkSource = path.resolve(integrationRoot, '..', '..');
  const inCheckout = fs.existsSync(path.join(sdkSource, 'package.json')) &&
    fs.existsSync(path.join(sdkSource, '..', 'node-nvx-runtime', 'package.json'));
  const repoRoot = inCheckout ? path.resolve(sdkSource, '..', '..') : undefined;
  const packageDir = process.env.MXC_SDK_PACKAGE_DIR;
  const runtimeDir = process.env.MXC_NVX_PACKAGE_DIR;
  const singleTarball = (directory: string | undefined): string | undefined => {
    if (!directory) return undefined;
    const files = fs.readdirSync(directory).filter(file => file.endsWith('.tgz'));
    assert.equal(files.length, 1, `expected exactly one package in ${directory}`);
    return path.resolve(directory, files[0]);
  };
  const candidates = [
    ...(process.env.MXC_NVX_TEST_DLL ? [path.resolve(process.env.MXC_NVX_TEST_DLL)] : []),
    path.join(installedSdk, 'bin', 'x64', 'mxc_ffi.dll'),
  ];
  if (repoRoot) candidates.push(
    path.join(repoRoot, 'src', 'target', 'debug', 'mxc_ffi.dll'),
    path.join(repoRoot, 'src', 'target', 'release', 'mxc_ffi.dll'),
    path.join(repoRoot, 'src', 'target', 'x86_64-pc-windows-msvc', 'debug', 'mxc_ffi.dll'),
    path.join(repoRoot, 'src', 'target', 'x86_64-pc-windows-msvc', 'release', 'mxc_ffi.dll'),
  );
  const library = candidates.find(file => fs.existsSync(file));
  assert.ok(library, 'Windows x64 integration requires a built mxc_ffi.dll');
  const runtimeRoot = runtimeDir ? runtimeDir : inCheckout
    ? path.join(sdkSource, '..', 'node-nvx-runtime')
    : path.dirname(require.resolve('@microsoft/mxc-sdk-nvx-runtime-win32-x64/package.json'));
  verifyPackagedRuntime({
    sdkRoot: inCheckout && !packageDir ? sdkSource : installedSdk,
    runtimeRoot,
    library,
    dependencyRoots: [path.join(installedSdk, 'node_modules'), path.join(integrationRoot, 'node_modules'),
      ...(inCheckout ? [path.join(sdkSource, 'node_modules')] : [])],
    fixtureParent: integrationRoot,
    inventoryFile: repoRoot ? path.join(repoRoot, 'src', 'mxc-sdk', 'src', 'backends', 'nvx', 'crate_runtime.rs') : undefined,
    buildSdk: inCheckout && !packageDir,
    baseTarball: singleTarball(packageDir),
    runtimeTarball: singleTarball(runtimeDir),
  });
});
