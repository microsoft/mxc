// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { describe, it, afterEach, mock } from 'node:test';
import assert from 'node:assert';
import { getAvailableToolsPolicy } from '../../src/policy';
import * as fs from 'fs';
import os from 'os';
import * as path from 'path';

describe('getAvailableToolsPolicy - PowerShell discovery', () => {
    let tmpDir: string | undefined;

    const mockWindows = () => {
        mock.method(os, 'platform', () => 'win32');
    };

    const mockLinux = () => {
        mock.method(os, 'platform', () => 'linux');
    };

    /** Create a temp directory containing a fake pwsh.exe and return its path. */
    const createFakePwshDir = (): string => {
        tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'mxc-test-'));
        fs.writeFileSync(path.join(tmpDir, 'pwsh.exe'), '');
        return tmpDir;
    };

    afterEach(() => {
        mock.restoreAll();
        if (tmpDir) {
            fs.rmSync(tmpDir, { recursive: true, force: true });
            tmpDir = undefined;
        }
    });

    it('should add system root to readonlyPaths when pwsh.exe is on PATH', () => {
        mockWindows();
        const pwshDir = createFakePwshDir();
        const env = { PATH: pwshDir, USERPROFILE: 'C:\\Users\\TestUser' };
        const result = getAvailableToolsPolicy(env);
        assert.ok(
            result.readonlyPaths.some(p => /^[a-z]:\\$/i.test(p)),
            'System root (e.g. C:\\) should be in readonlyPaths when pwsh.exe is on PATH',
        );
    });

    it('should add PSReadLine dir to readwritePaths when pwsh.exe is on PATH', () => {
        mockWindows();
        const pwshDir = createFakePwshDir();
        const env = { PATH: pwshDir, USERPROFILE: 'C:\\Users\\TestUser' };
        const result = getAvailableToolsPolicy(env);
        const expected = path.join(
            'C:\\Users\\TestUser', 'AppData', 'Roaming', 'Microsoft', 'Windows', 'PowerShell', 'PSReadLine',
        );
        assert.ok(
            result.readwritePaths.some(p => p.toLowerCase() === expected.toLowerCase()),
            'PSReadLine directory should be in readwritePaths',
        );
    });

    it('should not add PowerShell paths when pwsh.exe is not on PATH', () => {
        mockWindows();
        const env = { PATH: 'C:\\Windows\\System32', USERPROFILE: 'C:\\Users\\TestUser' };
        const result = getAvailableToolsPolicy(env);
        assert.ok(
            !result.readonlyPaths.some(p => /^[a-z]:\\$/i.test(p)),
            'System root should not be in readonlyPaths when pwsh.exe is not on PATH',
        );
        assert.strictEqual(result.readwritePaths.length, 0,
            'readwritePaths should be empty when pwsh.exe is not on PATH',
        );
    });

    it('should return empty policy on non-Windows even when pwsh.exe is on PATH', () => {
        mockLinux();
        const pwshDir = createFakePwshDir();
        const env = { PATH: pwshDir, USERPROFILE: 'C:\\Users\\TestUser' };
        const result = getAvailableToolsPolicy(env);
        assert.strictEqual(result.readonlyPaths.length, 0,
            'readonlyPaths should be empty on Linux',
        );
        assert.strictEqual(result.readwritePaths.length, 0,
            'readwritePaths should be empty on Linux',
        );
    });

    it('should not add PSReadLine path when USERPROFILE is not set', () => {
        mockWindows();
        const pwshDir = createFakePwshDir();
        const env = { PATH: pwshDir };
        const result = getAvailableToolsPolicy(env);
        assert.ok(
            result.readonlyPaths.some(p => /^[a-z]:\\$/i.test(p)),
            'System root should still be in readonlyPaths',
        );
        assert.strictEqual(result.readwritePaths.length, 0,
            'readwritePaths should be empty without USERPROFILE',
        );
    });
});
