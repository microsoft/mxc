// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { describe, it } from 'node:test';
import assert from 'node:assert';
import { getPipePath, redeemCookie } from './cookieRedeemer';

describe('getPipePath', () => {
  it('returns a Windows named pipe path', () => {
    const pipePath = getPipePath();
    assert.ok(pipePath.startsWith('\\\\.\\pipe\\aegis-'), `Expected pipe path to start with \\\\.\\pipe\\aegis-, got: ${pipePath}`);
  });

  it('includes the current username', () => {
    const pipePath = getPipePath();
    const username = process.env.USERNAME || process.env.USER || 'unknown';
    assert.ok(pipePath.endsWith(username), `Expected pipe path to end with ${username}, got: ${pipePath}`);
  });
});

describe('redeemCookie', () => {
  it('returns error when cookie is invalid or daemon is not running', async () => {
    const argsJson = JSON.stringify({ command: 'echo hello' });
    const result = await redeemCookie('nonexistent-cookie', 'bash', argsJson, '/workspace');
    assert.strictEqual(result.valid, false);
    assert.ok(result.error);
    // May get connection error (daemon not running) or invalid cookie (daemon running but cookie unknown)
    assert.ok(
      result.error!.includes('AEGIS daemon connection failed') || result.error!.includes('Invalid') || result.error!.includes('cookie'),
      `Unexpected error: ${result.error}`
    );
  });
});
