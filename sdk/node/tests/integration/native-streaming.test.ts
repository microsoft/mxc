// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import assert from 'node:assert';
import { once } from 'node:events';
import os from 'node:os';
import path from 'node:path';
import { describe, it } from 'node:test';
import { pathToFileURL } from 'node:url';
import type { Readable } from 'node:stream';
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
const minimumNativeStreamingNodeVersion =
  os.platform() === 'win32'
    ? '24.21.0'
    : os.platform() === 'linux'
      ? '24.0.0'
      : undefined;
const skipReason =
  sandboxSkipReason ??
  (!platformSupport.isSupported ? `Platform not supported: ${platformSupport.reason}` : undefined) ??
  (minimumNativeStreamingNodeVersion !== undefined &&
    semver.lt(process.version, minimumNativeStreamingNodeVersion)
    ? `Native streaming on ${os.platform()} requires Node.js ` +
      `${minimumNativeStreamingNodeVersion} or newer`
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
        'Start-Sleep -Milliseconds 500; Write-Output STREAM_SECOND; ' +
        '[Console]::Error.WriteLine(\'STREAM_ERROR\')"'
      : 'sh -c "printf \'STREAM_FIRST\\n\'; sleep 1; ' +
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
    const standardOutput = sandbox.standardOutput;
    const standardError = sandbox.standardError;
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

    const result = await wait;
    await Promise.all([outputEnded, errorEnded]);
    assert.strictEqual(result.exitCode, 0, stderr);
    assert.ok(stdout.includes('STREAM_FIRST'));
    assert.ok(stdout.includes('STREAM_SECOND'));
    assert.ok(stderr.includes('STREAM_ERROR'));
  });
});
