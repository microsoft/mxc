// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert';
import * as os from 'os';
import { DeniedResourceInfo } from '../../src/denied-resources.js';
import { SandboxPolicy } from '../../src/types.js';
import {
    getDeniedResources,
    generateUpdatedPolicyFromDetection,
    DetectionResult,
} from '../../src/tiered-detection.js';

// We need to import the helper for deduplication testing
// The deduplicateDenials function is exported from the module
import { deduplicateDenials } from '../../src/tiered-detection.js';

// ---------------------------------------------------------------------------
// getDeniedResources — output-only (no service)
// ---------------------------------------------------------------------------

describe('getDeniedResources', () => {
    it('detects denials from output when service is unavailable', async () => {
        const output = `PermissionError: [WinError 5] Access is denied: 'C:\\Users\\me\\secret.txt'`;
        const result = await getDeniedResources({ output });

        assert.ok(result.deniedResources.length >= 1);
        assert.ok(result.sourcesUsed.includes('output_parsing'));
        assert.strictEqual(result.serviceAvailable, false);
        const denial = result.deniedResources.find(d => d.path.includes('secret.txt'));
        assert.ok(denial);
        assert.strictEqual(denial!.resourceType, 'file');
        assert.strictEqual(denial!.source, 'output_parsing');
    });

    it('returns empty results when no options provided', async () => {
        const result = await getDeniedResources({});

        assert.strictEqual(result.deniedResources.length, 0);
        assert.strictEqual(result.sourcesUsed.length, 0);
    });

    it('detects network denials from output', async () => {
        const output = `Error: connect ECONNREFUSED 127.0.0.1:3000`;
        const result = await getDeniedResources({ output });

        assert.ok(result.deniedResources.length >= 1);
        const networkDenial = result.deniedResources.find(d => d.resourceType === 'network');
        assert.ok(networkDenial);
        assert.strictEqual(networkDenial!.source, 'output_parsing');
    });
});

// ---------------------------------------------------------------------------
// deduplicateDenials
// ---------------------------------------------------------------------------

describe('deduplicateDenials', () => {
    it('removes duplicates by normalized path + resourceType', () => {
        const denials: DeniedResourceInfo[] = [
            {
                path: 'C:\\Users\\me\\file.txt',
                resourceType: 'file',
                source: 'output_parsing',
                confidence: 'low',
                accessType: 'write',
            },
            {
                path: 'C:\\Users\\me\\file.txt',
                resourceType: 'file',
                source: 'output_parsing',
                confidence: 'low',
                accessType: 'read',
            },
        ];

        const result = deduplicateDenials(denials);
        assert.strictEqual(result.length, 1);
    });

    it('ETW source takes priority over output parsing for same path', () => {
        const denials: DeniedResourceInfo[] = [
            {
                path: 'C:\\Users\\me\\data.txt',
                resourceType: 'file',
                source: 'output_parsing',
                confidence: 'low',
                accessType: 'write',
                matchedPattern: 'python_permission_error',
            },
            {
                path: 'C:\\Users\\me\\data.txt',
                resourceType: 'file',
                source: 'etw_service',
                confidence: 'high',
                accessType: 'read',
            },
        ];

        const result = deduplicateDenials(denials);
        assert.strictEqual(result.length, 1);
        assert.strictEqual(result[0].source, 'etw_service');
    });

    it('keeps entries with different resourceTypes as separate', () => {
        const denials: DeniedResourceInfo[] = [
            {
                path: 'C:\\Users\\me\\file.txt',
                resourceType: 'file',
                source: 'output_parsing',
                confidence: 'low',
                accessType: 'write',
            },
            {
                path: '127.0.0.1:3000',
                resourceType: 'network',
                source: 'output_parsing',
                confidence: 'low',
                accessType: 'unknown',
            },
        ];

        const result = deduplicateDenials(denials);
        assert.strictEqual(result.length, 2);
    });
});

// ---------------------------------------------------------------------------
// generateUpdatedPolicyFromDetection — policyMode='managed' rejection
// ---------------------------------------------------------------------------

describe('generateUpdatedPolicyFromDetection', () => {
    it('throws error when policyMode is managed', () => {
        const originalPolicy = {
            version: '0.5.0-alpha',
            policyMode: 'managed',
        } as SandboxPolicy & { policyMode: string };

        const detectionResult: DetectionResult = {
            deniedResources: [],
            sourcesUsed: [],
            serviceAvailable: false,
        };

        assert.throws(
            () => generateUpdatedPolicyFromDetection(
                originalPolicy,
                detectionResult,
                [{ path: 'C:\\temp', accessLevel: 'readwrite' }],
            ),
            /managed policy/i,
        );
    });

    it('adds approved network hosts to allowedHosts with port stripped', () => {
        const originalPolicy: SandboxPolicy = {
            version: '0.5.0-alpha',
        };

        const detectionResult: DetectionResult = {
            deniedResources: [
                {
                    path: 'example.com:443',
                    resourceType: 'network',
                    source: 'output_parsing',
                confidence: 'low',
                    accessType: 'unknown',
                },
                {
                    path: 'api.nuget.org:443',
                    resourceType: 'network',
                    source: 'etw_service',
                confidence: 'high',
                    accessType: 'unknown',
                },
                {
                    path: 'pypi.org:443',
                    resourceType: 'network',
                    source: 'output_parsing',
                confidence: 'low',
                    accessType: 'unknown',
                },
            ],
            sourcesUsed: ['output_parsing', 'etw_service'],
            serviceAvailable: true,
        };

        // User approves only example.com and api.nuget.org (not pypi.org)
        const result = generateUpdatedPolicyFromDetection(
            originalPolicy,
            detectionResult,
            [
                { path: 'example.com:443', accessLevel: 'readwrite' },
                { path: 'api.nuget.org:443', accessLevel: 'readwrite' },
            ],
        );

        // Should enable outbound (required for allowedHosts to work)
        assert.strictEqual(result.policy.network?.allowOutbound, true);
        // Should add individual hosts (port stripped)
        assert.deepStrictEqual(result.policy.network?.allowedHosts, ['example.com', 'api.nuget.org']);
    });

    it('deduplicates network hosts with existing policy allowedHosts', () => {
        const originalPolicy: SandboxPolicy = {
            version: '0.5.0-alpha',
            network: {
                allowOutbound: true,
                allowedHosts: ['existing.com', 'example.com'],
            },
        };

        const detectionResult: DetectionResult = {
            deniedResources: [
                {
                    path: 'example.com:443',
                    resourceType: 'network',
                    source: 'output_parsing',
                confidence: 'low',
                    accessType: 'unknown',
                },
                {
                    path: 'newhost.com:80',
                    resourceType: 'network',
                    source: 'output_parsing',
                confidence: 'low',
                    accessType: 'unknown',
                },
            ],
            sourcesUsed: ['output_parsing'],
            serviceAvailable: false,
        };

        const result = generateUpdatedPolicyFromDetection(
            originalPolicy,
            detectionResult,
            [
                { path: 'example.com:443', accessLevel: 'readwrite' },
                { path: 'newhost.com:80', accessLevel: 'readwrite' },
            ],
        );

        assert.strictEqual(result.policy.network?.allowOutbound, true);
        // Should have all 3, no duplicates
        assert.deepStrictEqual(result.policy.network?.allowedHosts, ['existing.com', 'example.com', 'newhost.com']);
    });

    it('does not set network policy when no network denials approved', () => {
        const originalPolicy: SandboxPolicy = {
            version: '0.5.0-alpha',
        };

        const detectionResult: DetectionResult = {
            deniedResources: [
                {
                    path: '127.0.0.1:3000',
                    resourceType: 'network',
                    source: 'output_parsing',
                confidence: 'low',
                    accessType: 'unknown',
                },
            ],
            sourcesUsed: ['output_parsing'],
            serviceAvailable: false,
        };

        // Approve a filesystem path, not the network one
        const result = generateUpdatedPolicyFromDetection(
            originalPolicy,
            detectionResult,
            [{ path: 'C:\\temp\\data', accessLevel: 'readwrite' }],
        );

        assert.strictEqual(result.policy.network, undefined);
    });

    it('generates updated policy with filesystem approvals', () => {
        const testUser = os.userInfo().username;
        const testPath = `C:\\Users\\${testUser}\\project`;
        const originalPolicy: SandboxPolicy = {
            version: '0.5.0-alpha',
            filesystem: {
                readwritePaths: ['C:\\existing'],
            },
        };

        const detectionResult: DetectionResult = {
            deniedResources: [
                {
                    path: testPath,
                    resourceType: 'file',
                    source: 'output_parsing',
                confidence: 'low',
                    accessType: 'write',
                },
            ],
            sourcesUsed: ['output_parsing'],
            serviceAvailable: false,
        };

        const result = generateUpdatedPolicyFromDetection(
            originalPolicy,
            detectionResult,
            [{ path: testPath, accessLevel: 'readwrite' }],
        );

        assert.strictEqual(result.addedCount, 1);
        assert.ok(result.policy.filesystem?.readwritePaths?.some(
            p => p.toLowerCase().includes('project'),
        ));
    });

    it('includes serviceInstallHint when service is not running', async () => {
        const result = await getDeniedResources({
            output: 'PermissionError: [Errno 13] Permission denied: \'C:\\\\test.txt\'',
        });
        // Service is likely not running in test environment
        if (!result.serviceAvailable) {
            assert.ok(result.serviceInstallHint);
            assert.ok(result.serviceInstallHint!.includes('Install-MxcDiagnosticService.ps1'));
        }
    });
});
