// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import assert from 'node:assert';
import { once } from 'node:events';
import os from 'node:os';
import path from 'node:path';
import { describe, it } from 'node:test';
import { pathToFileURL } from 'node:url';
import type { Readable, Writable } from 'node:stream';
import semver from 'semver';
import type { ContainerConfig } from '@microsoft/mxc-sdk';
import {
  debugSpawnOptions,
  getSdkPackageRoot,
  isLinuxBubblewrap,
  sandboxSkipReason,
  sdk,
  supportedVersions,
} from './test-helpers.js';

interface NativeSandbox {
  readonly standardInput: Writable | null;
  readonly standardOutput: Readable | null;
  readonly standardError: Readable | null;
  waitAsync(): Promise<{ exitCode: number; timedOut: boolean }>;
}

interface RequestModule {
  prepareRequestSpec(
    config: ContainerConfig,
    options?: { experimental?: boolean },
  ): unknown;
}

interface StreamingModule {
  spawnBindingSandboxProcess(request: unknown): NativeSandbox;
}

const platformSupport = sdk.getPlatformSupport();
const schemaVersion = supportedVersions.at(-1)!;
const nativeStreamingNodeRequirement = os.platform() === 'win32'
  ? 'Node.js 24.21.0 or newer within Node.js 24, or Node.js 26.8.0 or newer'
  : 'Node.js 24.0.0 or newer';
const supportsNativeStreamingRuntime = os.platform() === 'win32'
  ? semver.satisfies(process.version, '>=24.21.0 <25 || >=26.8.0')
  : semver.gte(process.version, '24.0.0');
const skipReason =
  sandboxSkipReason ??
  (!platformSupport.isSupported ? `Platform not supported: ${platformSupport.reason}` : undefined) ??
  (!supportsNativeStreamingRuntime
    ? `Native streaming on ${os.platform()} requires ` +
      nativeStreamingNodeRequirement
    : undefined) ??
  (os.platform() === 'linux' && !isLinuxBubblewrap
    ? 'Native streaming requires Bubblewrap on Linux'
    : undefined);

describe(`Internal native streaming (schema ${schemaVersion})`, { skip: skipReason }, () => {
  it('delivers output before the sandbox exits', { timeout: 30000 }, async () => {
    const packageRoot = getSdkPackageRoot();
    const requestModule = await import(pathToFileURL(
      path.join(packageRoot, 'dist', 'bindings', 'request.js'),
    ).href) as RequestModule;
    const streamingModule = await import(pathToFileURL(
      path.join(packageRoot, 'dist', 'bindings', 'streaming.js'),
    ).href) as StreamingModule;

    const command = os.platform() === 'win32'
      ? 'powershell.exe -NoProfile -Command "Write-Output STREAM_FIRST; ' +
        '[Console]::ReadLine() | Out-Null; Write-Output STREAM_SECOND; ' +
        '[Console]::Error.WriteLine(\'STREAM_ERROR\')"'
      : 'sh -c "printf \'STREAM_FIRST\\n\'; IFS= read -r _; ' +
        'printf \'STREAM_SECOND\\n\'; printf \'STREAM_ERROR\\n\' >&2"';
    const policy = {
      version: schemaVersion.raw,
      ...(os.platform() === 'win32' ? { ui: { allowWindows: true } } : {}),
    };
    const config = sdk.createConfigFromPolicy(policy);
    config.process!.commandLine = command;
    const request = requestModule.prepareRequestSpec(config, {
      experimental: debugSpawnOptions.experimental,
    });
    const sandbox = streamingModule.spawnBindingSandboxProcess(request);
    const standardInput = sandbox.standardInput;
    const standardOutput = sandbox.standardOutput;
    const standardError = sandbox.standardError;
    assert.ok(standardInput, 'streaming stdin should be available');
    assert.ok(standardOutput, 'streaming stdout should be available');
    assert.ok(standardError, 'streaming stderr should be available');

    let stdout = '';
    let stderr = '';
    let resolveFirstChunk: (() => void) | undefined;
    const firstChunk = new Promise<void>((resolve) => {
      resolveFirstChunk = resolve;
    });
    standardOutput.on('data', (data: Buffer) => {
      stdout += data.toString();
      if (stdout.includes('STREAM_FIRST')) {
        resolveFirstChunk?.();
      }
    });
    standardError.on('data', (data: Buffer) => {
      stderr += data.toString();
    });

    let completed = false;
    const wait = sandbox.waitAsync().then((result) => {
      completed = true;
      return result;
    });
    const outputEnded = once(standardOutput, 'end');
    const errorEnded = once(standardError, 'end');
    await firstChunk;
    assert.strictEqual(completed, false, 'first output should arrive before process completion');
    standardInput.end('continue\n');

    const result = await wait;
    await Promise.all([outputEnded, errorEnded]);
    assert.strictEqual(result.exitCode, 0, stderr);
    assert.ok(stdout.includes('STREAM_FIRST'));
    assert.ok(stdout.includes('STREAM_SECOND'));
    assert.ok(stderr.includes('STREAM_ERROR'));
  });

  it('drains untaken native output without blocking completion', { timeout: 30000 }, async () => {
    const packageRoot = getSdkPackageRoot();
    const requestModule = await import(pathToFileURL(
      path.join(packageRoot, 'dist', 'bindings', 'request.js'),
    ).href) as RequestModule;
    const streamingModule = await import(pathToFileURL(
      path.join(packageRoot, 'dist', 'bindings', 'streaming.js'),
    ).href) as StreamingModule;

    const command = os.platform() === 'win32'
      ? 'powershell.exe -NoProfile -Command "$chunk = \'x\' * 8192; ' +
        '1..256 | ForEach-Object { [Console]::Out.Write($chunk); ' +
        '[Console]::Error.Write($chunk) }"'
      : 'sh -c "head -c 2097152 /dev/zero; head -c 2097152 /dev/zero >&2"';
    const policy = {
      version: schemaVersion.raw,
      ...(os.platform() === 'win32' ? { ui: { allowWindows: true } } : {}),
    };
    const config = sdk.createConfigFromPolicy(policy);
    config.process!.commandLine = command;
    const request = requestModule.prepareRequestSpec(config, {
      experimental: debugSpawnOptions.experimental,
    });
    const sandbox = streamingModule.spawnBindingSandboxProcess(request);

    const result = await sandbox.waitAsync();
    assert.strictEqual(result.exitCode, 0);
  });
});
