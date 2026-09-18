// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { describe, it, afterEach } from 'node:test';
import assert from 'node:assert';
import { getAvailableToolsPolicy } from '../../src/policy.js';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

// TODO: Investigate why Object.defineProperty(process, 'platform', ...) does not
// take effect on Linux ADO pipeline runners (Node.js v20.19.x). These tests mock
// process.platform to 'win32' and must be skipped on Linux until the root cause
// is understood.
const isLinux = process.platform === 'linux';

// `isSystemCriticalPath` resolves `%WINDIR%` from `process.env` and normalizes
// with the *host's* path flavor, so the write-path filter can only be exercised
// truthfully on a real Windows host — mocking `process.platform` does not turn
// the imported `path` module into `path.win32`.
const isWindowsHost = process.platform === 'win32';
const getWinDir = (): string => process.env['WINDIR'] || process.env['windir'] || 'C:\\Windows';

describe('getAvailableToolsPolicy - PowerShell discovery', () => {
    let originalPlatform: PropertyDescriptor | undefined;
    let tmpDir: string | undefined;

    const mockWindows = () => {
        originalPlatform = Object.getOwnPropertyDescriptor(process, 'platform');
        Object.defineProperty(process, 'platform', { value: 'win32' });
    };

    const mockLinux = () => {
        originalPlatform = Object.getOwnPropertyDescriptor(process, 'platform');
        Object.defineProperty(process, 'platform', { value: 'linux' });
    };

    /** Create a temp directory containing a fake pwsh.exe and return its path. */
    const createFakePwshDir = (): string => {
        tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'mxc-test-'));
        fs.writeFileSync(path.join(tmpDir, 'pwsh.exe'), '');
        return tmpDir;
    };

    afterEach(() => {
        if (originalPlatform) {
            Object.defineProperty(process, 'platform', originalPlatform);
            originalPlatform = undefined;
        }
        if (tmpDir) {
            fs.rmSync(tmpDir, { recursive: true, force: true });
            tmpDir = undefined;
        }
    });

    it('should never add the drive root to readonlyPaths when pwsh.exe is on PATH', { skip: isLinux }, () => {
        mockWindows();
        const pwshDir = createFakePwshDir();
        const env = { PATH: pwshDir, USERPROFILE: 'C:\\Users\\TestUser' };
        const result = getAvailableToolsPolicy(env);
        assert.ok(
            !result.readonlyPaths.some(p => /^[a-z]:\\$/i.test(p)),
            'Finding pwsh.exe must not grant a recursive read of the whole volume',
        );
    });

    it('should still grant $PSHOME read-only via PATH discovery', { skip: isLinux }, () => {
        mockWindows();
        const pwshDir = createFakePwshDir();
        const env = { PATH: pwshDir, USERPROFILE: 'C:\\Users\\TestUser' };
        const result = getAvailableToolsPolicy(env);
        assert.ok(
            result.readonlyPaths.some(p => p.toLowerCase() === pwshDir.toLowerCase()),
            'The directory holding pwsh.exe is a PATH directory and stays granted',
        );
    });

    it('should add PSReadLine dir to readwritePaths when pwsh.exe is on PATH', { skip: isLinux }, () => {
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

    it('should not add PowerShell paths when pwsh.exe is not on PATH', { skip: isLinux }, () => {
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

    it('should return empty policy on non-Windows even when pwsh.exe is on PATH', { skip: isLinux }, () => {
        mockLinux();
        const pwshDir = createFakePwshDir();
        const env = { PATH: pwshDir, USERPROFILE: 'C:\\Users\\TestUser' };
        const result = getAvailableToolsPolicy(env);
        assert.ok(
            !result.readonlyPaths.some(p => /^[a-z]:\\$/i.test(p)),
            'System root (e.g. C:\\) should not be in readonlyPaths on Linux',
        );
        assert.strictEqual(result.readwritePaths.length, 0,
            'readwritePaths should be empty on Linux',
        );
    });

    it('should not add PSReadLine path when USERPROFILE is not set', { skip: isLinux }, () => {
        mockWindows();
        const pwshDir = createFakePwshDir();
        const env = { PATH: pwshDir };
        const result = getAvailableToolsPolicy(env);
        assert.ok(
            !result.readonlyPaths.some(p => /^[a-z]:\\$/i.test(p)),
            'System root must not be in readonlyPaths',
        );
        assert.strictEqual(result.readwritePaths.length, 0,
            'readwritePaths should be empty without USERPROFILE',
        );
    });

    it('should not grant write access under %WINDIR% (SYSTEM profile)', { skip: !isWindowsHost }, () => {
        const pwshDir = createFakePwshDir();
        const env = {
            PATH: pwshDir,
            // The SYSTEM account's profile legitimately lives under %WINDIR%.
            USERPROFILE: path.join(getWinDir(), 'System32', 'config', 'systemprofile'),
        };
        const result = getAvailableToolsPolicy(env);
        assert.deepStrictEqual(result.readwritePaths, [],
            'A PSReadLine write grant must never land beneath %WINDIR%',
        );
    });

    it('should keep the PSReadLine grant when the directory does not exist yet', { skip: !isWindowsHost }, () => {
        const pwshDir = createFakePwshDir();
        const env = { PATH: pwshDir, USERPROFILE: 'C:\\Users\\mxc-nonexistent-profile' };
        const result = getAvailableToolsPolicy(env);
        assert.ok(
            result.readwritePaths.some(p => p.includes('PSReadLine')),
            'PowerShell creates the history directory on first use, so it need not pre-exist',
        );
    });
});
