// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { describe, it, afterEach } from 'node:test';
import assert from 'node:assert';
import { getAvailableToolsPolicy, getTemporaryFilesPolicy, getUserProfilePolicy } from '../../src/policy.js';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

// ---------------------------------------------------------------------------
// Platform mocking helpers
// ---------------------------------------------------------------------------

let originalPlatform: PropertyDescriptor | undefined;

function mockWindows() {
    originalPlatform = Object.getOwnPropertyDescriptor(process, 'platform');
    Object.defineProperty(process, 'platform', { value: 'win32' });
}

function mockLinux() {
    originalPlatform = Object.getOwnPropertyDescriptor(process, 'platform');
    Object.defineProperty(process, 'platform', { value: 'linux' });
}

function restorePlatform() {
    if (originalPlatform) {
        Object.defineProperty(process, 'platform', originalPlatform);
        originalPlatform = undefined;
    }
}

/**
 * Find the directory containing pwsh.exe by scanning the real process PATH.
 * Returns undefined if PowerShell is not installed.
 */
function findPwshDir(): string | undefined {
    const pathValue = process.env['PATH'] || process.env['Path'] || '';
    const dirs = pathValue.split(';');
    for (const dir of dirs) {
        if (dir && fs.existsSync(path.join(dir, 'pwsh.exe'))) {
            return dir;
        }
    }
    return undefined;
}

/**
 * Find a real directory on PATH that exists on this machine (for use
 * in tests that need a real existing directory in the env).
 */
function findExistingPathDir(): string | undefined {
    const pathValue = process.env['PATH'] || process.env['Path'] || '';
    const dirs = pathValue.split(os.platform() === 'win32' ? ';' : ':');
    for (const dir of dirs) {
        if (dir) {
            try {
                if (fs.statSync(dir).isDirectory()) {
                    return dir;
                }
            } catch {
                // continue
            }
        }
    }
    return undefined;
}

// ============================================================================
// getAvailableToolsPolicy
// ============================================================================

describe('getAvailableToolsPolicy', () => {

    afterEach(() => {
        restorePlatform();
    });

    // --- PATH discovery ---

    describe('PATH discovery', () => {
        it('should include existing PATH directories in readonlyPaths', () => {
            mockWindows();
            const existingDir = findExistingPathDir();
            if (!existingDir) return;

            const env = { PATH: existingDir };
            const result = getAvailableToolsPolicy(env);
            assert.ok(
                result.readonlyPaths.some(p => p.toLowerCase() === path.resolve(existingDir).toLowerCase()),
                `${existingDir} should be in readonlyPaths`,
            );
        });

        it('should filter out non-existent PATH directories', () => {
            mockWindows();
            const fakeDir = 'C:\\This\\Does\\Not\\Exist\\At\\All\\12345';
            const env = { PATH: fakeDir };
            const result = getAvailableToolsPolicy(env);
            assert.ok(
                !result.readonlyPaths.some(p => p.toLowerCase() === path.resolve(fakeDir).toLowerCase()),
                'Non-existent directories should be filtered out',
            );
        });

        it('should filter out system-critical paths under WINDIR', () => {
            mockWindows();
            const winDir = process.env['WINDIR'] || 'C:\\Windows';
            const system32 = path.join(winDir, 'System32');
            const env = { PATH: system32, WINDIR: winDir };
            const result = getAvailableToolsPolicy(env);
            assert.ok(
                !result.readonlyPaths.some(p => p.toLowerCase() === path.resolve(system32).toLowerCase()),
                'System32 under WINDIR should be filtered out',
            );
        });

        it('should deduplicate paths', () => {
            mockWindows();
            const existingDir = findExistingPathDir();
            if (!existingDir) return;

            const env = { PATH: `${existingDir};${existingDir}` };
            const result = getAvailableToolsPolicy(env);
            const matches = result.readonlyPaths.filter(
                p => p.toLowerCase() === path.resolve(existingDir).toLowerCase(),
            );
            assert.ok(matches.length <= 1, 'Duplicate paths should be deduplicated');
        });

        it('should return empty policy for empty environment', () => {
            mockWindows();
            const result = getAvailableToolsPolicy({});
            assert.ok(Array.isArray(result.readonlyPaths));
            assert.ok(Array.isArray(result.readwritePaths));
        });

        it('should read Path (capitalized) when PATH is not set', () => {
            mockWindows();
            const existingDir = findExistingPathDir();
            if (!existingDir) return;

            const env = { Path: existingDir };
            const result = getAvailableToolsPolicy(env);
            assert.ok(
                result.readonlyPaths.some(p => p.toLowerCase() === path.resolve(existingDir).toLowerCase()),
                'Should read from "Path" env var',
            );
        });
    });

    // --- Known environment variables ---

    describe('known environment variables', () => {
        it('should include JAVA_HOME directory when it exists', () => {
            mockWindows();
            const existingDir = findExistingPathDir();
            if (!existingDir) return;

            const env = { JAVA_HOME: existingDir };
            const result = getAvailableToolsPolicy(env);
            assert.ok(
                result.readonlyPaths.some(p => p.toLowerCase() === path.resolve(existingDir).toLowerCase()),
                'JAVA_HOME directory should be in readonlyPaths',
            );
        });

        it('should split semicolon-delimited variables like PSModulePath on Windows', () => {
            mockWindows();
            const existingDir = findExistingPathDir();
            if (!existingDir) return;

            const env = { PSModulePath: existingDir };
            const result = getAvailableToolsPolicy(env);
            assert.ok(
                result.readonlyPaths.some(p => p.toLowerCase() === path.resolve(existingDir).toLowerCase()),
                'PSModulePath directory should be in readonlyPaths',
            );
        });

        it('should not include non-existent env var directories', () => {
            mockWindows();
            const fakeDir = 'C:\\Fake\\Java\\Home\\12345';
            const env = { JAVA_HOME: fakeDir };
            const result = getAvailableToolsPolicy(env);
            assert.ok(
                !result.readonlyPaths.some(p => p.toLowerCase() === path.resolve(fakeDir).toLowerCase()),
                'Non-existent JAVA_HOME should be filtered out',
            );
        });
    });

    // --- PowerShell discovery ---

    describe('PowerShell discovery', () => {
        it('should add C:\\ to readonlyPaths when pwsh.exe is on PATH', () => {
            mockWindows();
            const pwshDir = findPwshDir();
            if (!pwshDir) return;

            const env = { PATH: pwshDir, USERPROFILE: 'C:\\Users\\TestUser' };
            const result = getAvailableToolsPolicy(env);
            assert.ok(
                result.readonlyPaths.some(p => p.toLowerCase() === 'c:\\'),
                'C:\\ should be in readonlyPaths when pwsh.exe is on PATH',
            );
        });

        it('should add PSReadLine dir to readwritePaths when pwsh.exe is on PATH', () => {
            mockWindows();
            const pwshDir = findPwshDir();
            if (!pwshDir) return;

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
                !result.readonlyPaths.some(p => p.toLowerCase() === 'c:\\'),
                'C:\\ should not be in readonlyPaths when pwsh.exe is not on PATH',
            );
            assert.strictEqual(result.readwritePaths.length, 0,
                'readwritePaths should be empty when pwsh.exe is not on PATH',
            );
        });

        it('should not add PowerShell paths on non-Windows platforms', () => {
            mockLinux();
            const pwshDir = findPwshDir();
            if (!pwshDir) return;

            const env = { PATH: pwshDir, USERPROFILE: 'C:\\Users\\TestUser' };
            const result = getAvailableToolsPolicy(env);
            assert.ok(
                !result.readonlyPaths.some(p => p.toLowerCase() === 'c:\\'),
                'C:\\ should not be added on Linux',
            );
            assert.strictEqual(result.readwritePaths.length, 0,
                'readwritePaths should be empty on Linux',
            );
        });

        it('should not add PSReadLine path when USERPROFILE is not set', () => {
            mockWindows();
            const pwshDir = findPwshDir();
            if (!pwshDir) return;

            const env = { PATH: pwshDir };
            const result = getAvailableToolsPolicy(env);
            assert.ok(
                result.readonlyPaths.some(p => p.toLowerCase() === 'c:\\'),
                'C:\\ should still be in readonlyPaths',
            );
            assert.strictEqual(result.readwritePaths.length, 0,
                'readwritePaths should be empty without USERPROFILE',
            );
        });
    });
});

// ============================================================================
// getUserProfilePolicy
// ============================================================================

describe('getUserProfilePolicy', () => {

    afterEach(() => {
        restorePlatform();
    });

    it('should return a FilesystemPolicyResult with both arrays', () => {
        const result = getUserProfilePolicy();
        assert.ok(Array.isArray(result.readonlyPaths));
        assert.ok(Array.isArray(result.readwritePaths));
    });

    it('should always return empty readwritePaths', () => {
        const result = getUserProfilePolicy();
        assert.strictEqual(result.readwritePaths.length, 0,
            'getUserProfilePolicy should never return readwritePaths');
    });

    it('should include subdirectories of LOCALAPPDATA\\Programs on Windows', () => {
        mockWindows();
        const localAppData = process.env['LOCALAPPDATA'];
        if (!localAppData) return;

        const programsDir = path.join(localAppData, 'Programs');
        if (!fs.existsSync(programsDir)) return;

        let entries: string[];
        try {
            entries = fs.readdirSync(programsDir, { withFileTypes: true })
                .filter(e => e.isDirectory())
                .map(e => path.join(programsDir, e.name));
        } catch {
            return;
        }
        if (entries.length === 0) return;

        const result = getUserProfilePolicy();
        const found = entries.some(expected =>
            result.readonlyPaths.some(p => p.toLowerCase() === expected.toLowerCase()),
        );
        assert.ok(found,
            'At least one LOCALAPPDATA\\Programs subdirectory should be in readonlyPaths');
    });
});

// ============================================================================
// getTemporaryFilesPolicy
// ============================================================================

describe('getTemporaryFilesPolicy', () => {

    afterEach(() => {
        restorePlatform();
    });

    it('should always return empty readonlyPaths', () => {
        const result = getTemporaryFilesPolicy();
        assert.strictEqual(result.readonlyPaths.length, 0,
            'getTemporaryFilesPolicy should never return readonlyPaths');
    });

    it('should return TEMP directory in readwritePaths on Windows', () => {
        mockWindows();
        const tempDir = process.env['TEMP'] || process.env['TMP'];
        if (!tempDir) return;

        const env = { TEMP: tempDir };
        const result = getTemporaryFilesPolicy(env);
        assert.ok(
            result.readwritePaths.some(p => p.toLowerCase() === tempDir.toLowerCase()),
            'TEMP directory should be in readwritePaths',
        );
    });

    it('should return empty readwritePaths when TEMP is not set', () => {
        mockWindows();
        const result = getTemporaryFilesPolicy({});
        assert.strictEqual(result.readwritePaths.length, 0,
            'readwritePaths should be empty when TEMP is not set',
        );
    });

    it('should return empty readwritePaths when TEMP points to non-existent directory', () => {
        mockWindows();
        const env = { TEMP: 'C:\\This\\Does\\Not\\Exist\\Temp\\12345' };
        const result = getTemporaryFilesPolicy(env);
        assert.strictEqual(result.readwritePaths.length, 0,
            'readwritePaths should be empty for non-existent TEMP',
        );
    });

    it('should fall back to TMP when TEMP is not set', () => {
        mockWindows();
        const tempDir = process.env['TEMP'] || process.env['TMP'];
        if (!tempDir) return;

        const env = { TMP: tempDir };
        const result = getTemporaryFilesPolicy(env);
        assert.ok(
            result.readwritePaths.some(p => p.toLowerCase() === tempDir.toLowerCase()),
            'TMP directory should be used as fallback',
        );
    });
});
