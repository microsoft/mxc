// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import assert from 'node:assert';
import os from 'node:os';
import path from 'node:path';
import { describe, it } from 'node:test';
import { pathToFileURL } from 'node:url';
import type { Readable, Writable } from 'node:stream';
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
const skipReason =
  sandboxSkipReason ??
  (!platformSupport.isSupported ? `Platform not supported: ${platformSupport.reason}` : undefined) ??
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
        '$null = [Console]::In.ReadLine(); Write-Output STREAM_SECOND; ' +
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
    assert.ok(sandbox.standardInput, 'streaming stdin should be available');
    assert.ok(sandbox.standardOutput, 'streaming stdout should be available');
    assert.ok(sandbox.standardError, 'streaming stderr should be available');

    let stdout = '';
    let stderr = '';
    let resolveFirstChunk: (() => void) | undefined;
    const firstChunk = new Promise<void>((resolve) => {
      resolveFirstChunk = resolve;
    });
    sandbox.standardOutput.on('data', (data: Buffer) => {
      stdout += data.toString();
      if (stdout.includes('STREAM_FIRST')) {
        resolveFirstChunk?.();
      }
    });
    sandbox.standardError.on('data', (data: Buffer) => {
      stderr += data.toString();
    });

    let completed = false;
    const wait = sandbox.waitAsync().then((result) => {
      completed = true;
      return result;
    });

    await firstChunk;
    assert.strictEqual(completed, false, 'first output should arrive before process completion');
    sandbox.standardInput.end('continue\n');

    const result = await wait;
    assert.strictEqual(result.exitCode, 0, stderr);
    assert.ok(stdout.includes('STREAM_FIRST'));
    assert.ok(stdout.includes('STREAM_SECOND'));
    assert.ok(stderr.includes('STREAM_ERROR'));
  });
});
