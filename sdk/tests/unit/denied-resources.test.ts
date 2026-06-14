// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { describe, it } from 'node:test';
import assert from 'node:assert';
import * as os from 'os';
import { parseDeniedResources, DeniedResourceInfo } from '../../src/denied-resources.js';
import { generateUpdatedPolicy, ApprovedPath, PolicyGenerationResult } from '../../src/policy-regen.js';
import { SandboxPolicy } from '../../src/types.js';

// Current user's profile base for test paths (avoids "other users' profiles" blocklist)
const TEST_USER = os.userInfo().username;
const U = `C:\\Users\\${TEST_USER}`;

// ---------------------------------------------------------------------------
// parseDeniedResources — pattern matching
// ---------------------------------------------------------------------------

describe('parseDeniedResources', () => {
    describe('Python patterns', () => {
        it('detects PermissionError with WinError', () => {
            const output = `PermissionError: [WinError 5] Access is denied: 'C:\\Users\\me\\data.txt'`;
            const results = parseDeniedResources(output);
            assert.strictEqual(results.length, 1);
            assert.ok(results[0].path.endsWith('data.txt'));
            assert.strictEqual(results[0].accessType, 'write');
            assert.strictEqual(results[0].resourceType, 'file');
            assert.strictEqual(results[0].matchedPattern, 'python_permission_error');
        });

        it('detects PermissionError with Errno', () => {
            const output = `PermissionError: [Errno 13] Permission denied: 'C:\\locked\\file.log'`;
            const results = parseDeniedResources(output);
            assert.strictEqual(results.length, 1);
            assert.ok(results[0].path.endsWith('file.log'));
            assert.strictEqual(results[0].resourceType, 'file');
        });

        it('detects OSError with Access is denied', () => {
            const output = `OSError: [WinError 5] Access is denied: 'C:\\Windows\\System32\\config'`;
            const results = parseDeniedResources(output);
            assert.ok(results.length >= 1);
            const match = results.find(r => r.matchedPattern === 'python_os_error_access_denied');
            assert.ok(match);
            assert.strictEqual(match!.accessType, 'unknown');
            assert.strictEqual(match!.resourceType, 'file');
        });
    });

    describe('Node.js patterns', () => {
        it('detects EACCES error', () => {
            const output = `Error: EACCES: permission denied, open 'C:\\secret\\key.pem'`;
            const results = parseDeniedResources(output);
            assert.strictEqual(results.length, 1);
            assert.ok(results[0].path.endsWith('key.pem'));
            assert.strictEqual(results[0].matchedPattern, 'nodejs_eacces');
            assert.strictEqual(results[0].accessType, 'unknown');
            assert.strictEqual(results[0].resourceType, 'file');
        });

        it('detects EPERM error', () => {
            const output = `Error: EPERM: operation not permitted, mkdir 'C:\\Program Files\\myapp'`;
            const results = parseDeniedResources(output);
            assert.strictEqual(results.length, 1);
            assert.ok(results[0].path.includes('myapp'));
            assert.strictEqual(results[0].matchedPattern, 'nodejs_eperm');
            assert.strictEqual(results[0].accessType, 'write');
            assert.strictEqual(results[0].resourceType, 'file');
        });
    });

    describe('PowerShell patterns', () => {
        it('detects Access to the path is denied', () => {
            const output = `Access to the path 'C:\\Protected\\secret.dat' is denied`;
            const results = parseDeniedResources(output);
            assert.strictEqual(results.length, 1);
            assert.ok(results[0].path.endsWith('secret.dat'));
            assert.strictEqual(results[0].matchedPattern, 'powershell_access_denied');
            assert.strictEqual(results[0].accessType, 'write');
            assert.strictEqual(results[0].resourceType, 'file');
        });

        it('detects UnauthorizedAccessException', () => {
            const output = `UnauthorizedAccessException: Access to path 'C:\\Admin\\config.xml' is denied`;
            const results = parseDeniedResources(output);
            assert.strictEqual(results.length, 1);
            assert.ok(results[0].path.endsWith('config.xml'));
            assert.strictEqual(results[0].matchedPattern, 'powershell_unauthorized');
            assert.strictEqual(results[0].resourceType, 'file');
        });
    });

    describe('.NET patterns', () => {
        it('detects IOException access denied', () => {
            const output = `System.IO.IOException: Access to the file is denied: 'C:\\Logs\\app.log'`;
            const results = parseDeniedResources(output);
            assert.strictEqual(results.length, 1);
            assert.ok(results[0].path.endsWith('app.log'));
            assert.strictEqual(results[0].matchedPattern, 'dotnet_io_exception');
            assert.strictEqual(results[0].resourceType, 'file');
        });
    });

    describe('Windows native patterns', () => {
        it('detects path then "Access is denied"', () => {
            const output = `C:\\Restricted\\folder - Access is denied`;
            const results = parseDeniedResources(output);
            assert.strictEqual(results.length, 1);
            assert.ok(results[0].path.includes('Restricted'));
            assert.strictEqual(results[0].matchedPattern, 'windows_native_path_then_denied');
            assert.strictEqual(results[0].resourceType, 'file');
        });

        it('detects "Access is denied" then path', () => {
            const output = `Access is denied: C:\\Protected\\item.bin`;
            const results = parseDeniedResources(output);
            assert.strictEqual(results.length, 1);
            assert.ok(results[0].path.endsWith('item.bin'));
            assert.strictEqual(results[0].matchedPattern, 'windows_native_denied_then_path');
            assert.strictEqual(results[0].resourceType, 'file');
        });
    });

    describe('Linux patterns', () => {
        it('detects permission denied with unix path', function () {
            if (process.platform === 'win32') {
                // Unix paths are not plausible on Windows — isPlausiblePath rejects them
                return;
            }
            const output = `bash: /etc/shadow: permission denied`;
            const results = parseDeniedResources(output);
            assert.strictEqual(results.length, 1);
            assert.strictEqual(results[0].path, '/etc/shadow');
            assert.strictEqual(results[0].matchedPattern, 'linux_permission_denied');
            assert.strictEqual(results[0].resourceType, 'file');
        });
    });

    describe('Generic patterns', () => {
        it('detects "cannot open" with Windows path', () => {
            const output = `cannot open C:\\Data\\report.csv: permission denied`;
            const results = parseDeniedResources(output);
            assert.ok(results.some(r => r.matchedPattern === 'generic_cannot_access'));
        });

        it('detects "cannot write" with Unix path', () => {
            const output = `cannot write /var/log/app.log`;
            const results = parseDeniedResources(output);
            assert.ok(results.some(r => r.matchedPattern === 'generic_cannot_access'));
        });
    });

    describe('Rust patterns', () => {
        it('detects Os { code: 5 } error with path in quotes', () => {
            // Rust IO error where path is the quoted value (e.g. custom error formatting)
            const output = `thread 'main' panicked: Os { code: 5, path: "C:\\Secure\\data" }`;
            const results = parseDeniedResources(output);
            assert.strictEqual(results.length, 1);
            assert.ok(results[0].path.toLowerCase().includes('secure'));
            assert.strictEqual(results[0].matchedPattern, 'rust_io_error');
            assert.strictEqual(results[0].resourceType, 'file');
        });
    });

    describe('Network patterns', () => {
        it('detects Node.js ECONNREFUSED', () => {
            const output = `Error: connect ECONNREFUSED 127.0.0.1:3000`;
            const results = parseDeniedResources(output);
            assert.strictEqual(results.length, 1);
            assert.strictEqual(results[0].path, '127.0.0.1:3000');
            assert.strictEqual(results[0].resourceType, 'network');
            assert.strictEqual(results[0].matchedPattern, 'node_econnrefused');
        });

        it('detects generic connection refused', () => {
            const output = `Connection refused: 10.0.0.5:8080`;
            const results = parseDeniedResources(output);
            assert.strictEqual(results.length, 1);
            assert.strictEqual(results[0].path, '10.0.0.5:8080');
            assert.strictEqual(results[0].resourceType, 'network');
            assert.strictEqual(results[0].matchedPattern, 'generic_connection_refused');
        });

        it('detects DNS resolution failure', () => {
            const output = `Error: getaddrinfo ENOTFOUND api.example.com`;
            const results = parseDeniedResources(output);
            assert.strictEqual(results.length, 1);
            assert.strictEqual(results[0].path, 'api.example.com');
            assert.strictEqual(results[0].resourceType, 'network');
            assert.strictEqual(results[0].matchedPattern, 'dns_resolution_failed');
        });

        it('detects WinHTTP error', () => {
            const output = `WinHttpSendRequest failed for host proxy.corp.net:443`;
            const results = parseDeniedResources(output);
            assert.strictEqual(results.length, 1);
            assert.strictEqual(results[0].path, 'proxy.corp.net:443');
            assert.strictEqual(results[0].resourceType, 'network');
            assert.strictEqual(results[0].matchedPattern, 'winhttp_error');
        });
    });

    describe('deduplication', () => {
        it('deduplicates the same path matched by multiple patterns', () => {
            // This output matches both powershell_access_denied and potentially windows_native
            const output = `Access to the path 'C:\\Users\\me\\file.txt' is denied\nAccess to the path 'C:\\Users\\me\\file.txt' is denied`;
            const results = parseDeniedResources(output);
            assert.strictEqual(results.length, 1);
        });

        it('deduplicates case-insensitively on Windows', () => {
            const output = [
                `Access to the path 'C:\\Users\\ME\\file.txt' is denied`,
                `EPERM: operation not permitted, open 'C:\\Users\\me\\file.txt'`,
            ].join('\n');
            const results = parseDeniedResources(output);
            // On Windows, these are the same path
            if (process.platform === 'win32') {
                assert.strictEqual(results.length, 1);
            }
        });
    });

    describe('edge cases', () => {
        it('returns empty array for output with no denials', () => {
            const output = 'Hello world\nEverything is fine\nProcess exited with code 0';
            const results = parseDeniedResources(output);
            assert.deepStrictEqual(results, []);
        });

        it('returns empty array for empty string', () => {
            const results = parseDeniedResources('');
            assert.deepStrictEqual(results, []);
        });

        it('includes matchedLine from original output', () => {
            const output = `line 1\nAccess to the path 'C:\\test\\a.txt' is denied\nline 3`;
            const results = parseDeniedResources(output);
            assert.strictEqual(results.length, 1);
            assert.ok(results[0].matchedLine?.includes('Access to the path'));
        });

        it('all results have source set to output_parsing', () => {
            const output = `EACCES: denied 'C:\\a\\b'\nEPERM: denied 'C:\\c\\d'`;
            const results = parseDeniedResources(output);
            for (const r of results) {
                assert.strictEqual(r.source, 'output_parsing');
            }
        });
    });
});

// ---------------------------------------------------------------------------
// generateUpdatedPolicy — merging and validation
// ---------------------------------------------------------------------------

describe('generateUpdatedPolicy', () => {
    const basePolicy: SandboxPolicy = {
        version: '0.4.0-alpha',
        filesystem: {
            readwritePaths: [`${U}\\project`],
            readonlyPaths: ['C:\\Python311'],
        },
    };

    describe('basic merging', () => {
        it('adds a readwrite path', () => {
            const result = generateUpdatedPolicy(basePolicy, [
                { path: `${U}\\data`, accessLevel: 'readwrite' },
            ]);
            assert.ok(result.policy.filesystem!.readwritePaths!.some(
                p => p.toLowerCase().includes('data')
            ));
            assert.strictEqual(result.addedCount, 1);
            assert.strictEqual(result.rejected.length, 0);
        });

        it('adds a readonly path', () => {
            const result = generateUpdatedPolicy(basePolicy, [
                { path: 'C:\\Tools\\bin', accessLevel: 'readonly' },
            ]);
            assert.ok(result.policy.filesystem!.readonlyPaths!.some(
                p => p.toLowerCase().includes('tools')
            ));
            assert.strictEqual(result.addedCount, 1);
        });

        it('does not modify the original policy', () => {
            const original = JSON.parse(JSON.stringify(basePolicy));
            generateUpdatedPolicy(basePolicy, [
                { path: 'C:\\new\\path', accessLevel: 'readwrite' },
            ]);
            assert.deepStrictEqual(basePolicy, original);
        });

        it('initializes filesystem section when missing', () => {
            const emptyPolicy: SandboxPolicy = { version: '0.4.0-alpha' };
            const result = generateUpdatedPolicy(emptyPolicy, [
                { path: `${U}\\work`, accessLevel: 'readwrite' },
            ]);
            assert.ok(result.policy.filesystem);
            assert.ok(result.policy.filesystem!.readwritePaths!.length >= 1);
            assert.strictEqual(result.addedCount, 1);
        });

        it('readwrite supersedes readonly for the same path', () => {
            const policy: SandboxPolicy = {
                version: '0.4.0-alpha',
                filesystem: {
                    readonlyPaths: [`${U}\\shared`],
                    readwritePaths: [],
                },
            };
            const result = generateUpdatedPolicy(policy, [
                { path: `${U}\\shared`, accessLevel: 'readwrite' },
            ]);
            // Should be in readwrite, not in readonly
            const rwPaths = result.policy.filesystem!.readwritePaths!.map(p => p.toLowerCase());
            const roPaths = result.policy.filesystem!.readonlyPaths!.map(p => p.toLowerCase());
            assert.ok(rwPaths.some(p => p.includes('shared')));
            assert.ok(!roPaths.some(p => p.includes('shared')));
        });
    });

    describe('deduplication', () => {
        it('skips paths already covered by existing readwrite paths', () => {
            const result = generateUpdatedPolicy(basePolicy, [
                { path: `${U}\\project\\subdir`, accessLevel: 'readwrite' },
            ]);
            // subdir is already covered by the user's project path
            assert.strictEqual(result.addedCount, 0);
        });

        it('skips readonly paths already covered by existing readwrite paths', () => {
            const result = generateUpdatedPolicy(basePolicy, [
                { path: `${U}\\project\\file.txt`, accessLevel: 'readonly' },
            ]);
            assert.strictEqual(result.addedCount, 0);
        });

        it('deduplicates final path lists', () => {
            const policy: SandboxPolicy = {
                version: '0.4.0-alpha',
                filesystem: { readwritePaths: [], readonlyPaths: [] },
            };
            const result = generateUpdatedPolicy(policy, [
                { path: `${U}\\dup`, accessLevel: 'readwrite' },
                { path: `${U}\\dup`, accessLevel: 'readwrite' },
            ]);
            const count = result.policy.filesystem!.readwritePaths!.filter(
                p => p.toLowerCase().includes('dup')
            ).length;
            assert.strictEqual(count, 1);
        });
    });

    describe('system-critical path rejection', () => {
        it('rejects paths under Windows directory', () => {
            const result = generateUpdatedPolicy(basePolicy, [
                { path: 'C:\\Windows\\System32\\drivers', accessLevel: 'readwrite' },
            ]);
            assert.strictEqual(result.rejected.length, 1);
            assert.ok(result.rejected[0].reason.includes('system-critical'));
            assert.strictEqual(result.addedCount, 0);
        });

        it('rejects paths under Program Files', () => {
            const result = generateUpdatedPolicy(basePolicy, [
                { path: 'C:\\Program Files\\app', accessLevel: 'readonly' },
            ]);
            assert.strictEqual(result.rejected.length, 1);
            assert.ok(result.rejected[0].reason.includes('system-critical'));
        });

        it('rejects paths under Program Files (x86)', () => {
            const result = generateUpdatedPolicy(basePolicy, [
                { path: 'C:\\Program Files (x86)\\tool', accessLevel: 'readonly' },
            ]);
            assert.strictEqual(result.rejected.length, 1);
        });

        it('allows system-critical paths when rejectSystemCriticalPaths is false', () => {
            const result = generateUpdatedPolicy(basePolicy, [
                { path: 'C:\\Windows\\Temp', accessLevel: 'readwrite' },
            ], { rejectSystemCriticalPaths: false });
            assert.strictEqual(result.rejected.length, 0);
            assert.strictEqual(result.addedCount, 1);
        });

        it('rejects multiple paths and reports all', () => {
            const result = generateUpdatedPolicy(basePolicy, [
                { path: 'C:\\Windows\\System32', accessLevel: 'readwrite' },
                { path: 'C:\\Program Files\\bad', accessLevel: 'readwrite' },
                { path: `${U}\\good`, accessLevel: 'readwrite' },
            ]);
            assert.strictEqual(result.rejected.length, 2);
            assert.strictEqual(result.addedCount, 1);
        });
    });

    describe('useParentDirectories option', () => {
        it('converts file paths to parent directory when enabled', () => {
            const policy: SandboxPolicy = {
                version: '0.4.0-alpha',
                filesystem: { readwritePaths: [], readonlyPaths: [] },
            };
            const result = generateUpdatedPolicy(policy, [
                { path: `${U}\\project\\file.txt`, accessLevel: 'readwrite' },
            ], { useParentDirectories: true });
            // Should add the parent directory, not the file itself
            const rwPaths = result.policy.filesystem!.readwritePaths!;
            assert.ok(rwPaths.some(p => p.toLowerCase().includes('project')));
            assert.ok(!rwPaths.some(p => p.toLowerCase().includes('file.txt')));
        });
    });

    describe('preserves other policy fields', () => {
        it('keeps network and version unchanged', () => {
            const fullPolicy: SandboxPolicy = {
                version: '0.4.0-alpha',
                filesystem: { readwritePaths: [], readonlyPaths: [] },
                network: { allowOutbound: true },
            };
            const result = generateUpdatedPolicy(fullPolicy, [
                { path: `${U}\\new`, accessLevel: 'readwrite' },
            ]);
            assert.strictEqual(result.policy.version, '0.4.0-alpha');
            assert.strictEqual(result.policy.network?.allowOutbound, true);
        });
    });
});
