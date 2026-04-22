// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { describe, it } from 'node:test';
import assert from 'node:assert';
import { buildSandboxPayload, createConfigFromPolicy, spawnSandbox, spawnSandboxFromConfig } from './sandbox';
import { SandboxPolicy } from './types';

describe('buildSandboxPayload', () => {
  const defaultPolicy: SandboxPolicy = { version: '0.4.0-alpha' };

  describe('Windows', () => {
    let originalPlatform: PropertyDescriptor | undefined;

    const mockWindows = () => {
      originalPlatform = Object.getOwnPropertyDescriptor(process, 'platform');
      Object.defineProperty(process, 'platform', { value: 'win32' });
    };

    const restore = () => {
      if (originalPlatform) {
        Object.defineProperty(process, 'platform', originalPlatform);
      }
    };

    it('should set process.commandLine from script parameter', () => {
      mockWindows();
      try {
        const payload = buildSandboxPayload('echo hello', defaultPolicy);
        assert.strictEqual(payload.process!.commandLine, 'echo hello');
      } finally {
        restore();
      }
    });

    it('should map network policy to appcontainer capabilities', () => {
      mockWindows();
      try {
        const policy: SandboxPolicy = {
          version: '0.4.0-alpha',
          network: { allowOutbound: true, allowLocalNetwork: true },
        };
        const payload = buildSandboxPayload('echo hi', policy);
        assert.ok(payload.appContainer!.capabilities!.includes('internetClient'));
        assert.ok(payload.appContainer!.capabilities!.includes('privateNetworkClientServer'));
      } finally {
        restore();
      }
    });

    it('should pass filesystem policy through', () => {
      const policy: SandboxPolicy = {
        version: '0.4.0-alpha',
        filesystem: {
          readwritePaths: ['C:\\temp'],
          readonlyPaths: ['C:\\data'],
        },
      };
      const payload = buildSandboxPayload('echo hi', policy);
      assert.deepStrictEqual(payload.filesystem!.readwritePaths![0], 'C:\\temp');
      assert.deepStrictEqual(payload.filesystem!.readonlyPaths, ['C:\\data']);
    });

    it('should set ContainerConfig.version to match SandboxPolicy.version', () => {
      mockWindows();
      try {
        const payload = buildSandboxPayload('echo hi', { version: '0.4.0-alpha' });
        assert.strictEqual(payload.version, '0.4.0-alpha');
      } finally {
        restore();
      }
    });

    it('should accept a compatible version', () => {
      mockWindows();
      try {
        assert.doesNotThrow(() => buildSandboxPayload('echo hi', { version: '0.5.0-alpha' }));
      } finally {
        restore();
      }
    });

    it('should accept older version 0.4.0-alpha', () => {
      mockWindows();
      try {
        assert.doesNotThrow(() => buildSandboxPayload('echo hi', { version: '0.4.0-alpha' }));
      } finally {
        restore();
      }
    });

    it('should reject a newer minor version within same major', () => {
      mockWindows();
      try {
        assert.throws(
          () => buildSandboxPayload('echo hi', { version: '0.99.0' }),
          { message: /newer than supported/ },
        );
      } finally {
        restore();
      }
    });

    it('should reject a different major version', () => {
      mockWindows();
      try {
        assert.throws(
          () => buildSandboxPayload('echo hi', { version: '1.0.0' }),
          { message: /newer than supported/ },
        );
      } finally {
        restore();
      }
    });

    it('should reject a version older than minimum', () => {
      mockWindows();
      try {
        assert.throws(
          () => buildSandboxPayload('echo hi', { version: '0.3.0-alpha' }),
          { message: /older than supported/ },
        );
      } finally {
        restore();
      }
    });

    it('should reject an invalid semver string', () => {
      mockWindows();
      try {
        assert.throws(
          () => buildSandboxPayload('echo hi', { version: 'not-a-version' }),
          { message: /Invalid policy version/ },
        );
      } finally {
        restore();
      }
    });

    it('should reject an empty version string', () => {
      mockWindows();
      try {
        assert.throws(
          () => buildSandboxPayload('echo hi', { version: '' }),
          { message: /version is required/ },
        );
      } finally {
        restore();
      }
    });

    it('should pass builtinTestServer proxy through to network config', () => {
      mockWindows();
      try {
        const policy: SandboxPolicy = {
          version: '0.4.0-alpha',
          network: { proxy: { builtinTestServer: true } },
        };
        const payload = buildSandboxPayload('echo hi', policy);
        assert.deepStrictEqual(payload.network!.proxy, { builtinTestServer: true });
      } finally {
        restore();
      }
    });

    it('should pass localhost proxy through to network config', () => {
      mockWindows();
      try {
        const policy: SandboxPolicy = {
          version: '0.4.0-alpha',
          network: { proxy: { localhost: 8080 } },
        };
        const payload = buildSandboxPayload('echo hi', policy);
        assert.deepStrictEqual(payload.network!.proxy, { localhost: 8080 });
      } finally {
        restore();
      }
    });

    it('should not set network.proxy when proxy is not specified', () => {
      mockWindows();
      try {
        const policy: SandboxPolicy = {
          version: '0.4.0-alpha',
          network: { allowOutbound: true },
        };
        const payload = buildSandboxPayload('echo hi', policy);
        assert.strictEqual(payload.network?.proxy, undefined);
      } finally {
        restore();
      }
    });
  });

  describe('Linux', () => {
    let originalPlatform: PropertyDescriptor | undefined;

    const mockLinux = () => {
      originalPlatform = Object.getOwnPropertyDescriptor(process, 'platform');
      Object.defineProperty(process, 'platform', { value: 'linux' });
    };

    const restore = () => {
      if (originalPlatform) {
        Object.defineProperty(process, 'platform', originalPlatform);
      }
    };

    it('should default to lxc on Linux', () => {
      mockLinux();
      try {
        const payload = buildSandboxPayload('echo hi', defaultPolicy);
        assert.strictEqual(payload.containment, 'lxc');
        assert.strictEqual(payload.lxc!.destroyOnExit, true);
      } finally {
        restore();
      }
    });

    it('should reject proxy configuration on Linux', () => {
      mockLinux();
      try {
        const policy: SandboxPolicy = {
          version: '0.4.0-alpha',
          network: { proxy: { builtinTestServer: true } },
        };
        assert.throws(
          () => buildSandboxPayload('echo hi', policy),
          { message: /not supported on Linux/ },
        );
      } finally {
        restore();
      }
    });
  });

  describe('Containment override', () => {
    let originalPlatform: PropertyDescriptor | undefined;

    const mockWindows = () => {
      originalPlatform = Object.getOwnPropertyDescriptor(process, 'platform');
      Object.defineProperty(process, 'platform', { value: 'win32' });
    };

    const restore = () => {
      if (originalPlatform) {
        Object.defineProperty(process, 'platform', originalPlatform);
      }
    };

    it('should return minimal config for microvm without filesystem', () => {
      mockWindows();
      try {
        const payload = buildSandboxPayload('print(42)', defaultPolicy, undefined, undefined, 'microvm');
        assert.strictEqual(payload.containment, 'microvm');
        assert.strictEqual(payload.filesystem, undefined);
        assert.strictEqual(payload.appContainer, undefined);
      } finally {
        restore();
      }
    });

    it('should include filesystem with clearPolicyOnExit for microvm when policy has paths', () => {
      mockWindows();
      try {
        const policy: SandboxPolicy = {
          version: '0.4.0-alpha',
          filesystem: { readwritePaths: ['/tmp'] },
        };
        const payload = buildSandboxPayload('print(42)', policy, undefined, undefined, 'microvm');
        assert.strictEqual(payload.containment, 'microvm');
        assert.deepStrictEqual(payload.filesystem!.readwritePaths, ['/tmp']);
        assert.strictEqual(payload.filesystem!.clearPolicyOnExit, true);
      } finally {
        restore();
      }
    });

    it('should honor clearPolicyOnExit false for microvm', () => {
      mockWindows();
      try {
        const policy: SandboxPolicy = {
          version: '0.4.0-alpha',
          filesystem: { readwritePaths: ['/tmp'], clearPolicyOnExit: false },
        };
        const payload = buildSandboxPayload('print(42)', policy, undefined, undefined, 'microvm');
        assert.strictEqual(payload.filesystem!.clearPolicyOnExit, false);
      } finally {
        restore();
      }
    });

    it('should build appcontainer config on Windows with default process containment', () => {
      mockWindows();
      try {
        const policy: SandboxPolicy = {
          version: '0.4.0-alpha',
          network: { allowOutbound: true },
        };
        const payload = buildSandboxPayload('echo hi', policy);
        assert.ok(payload.appContainer, 'appContainer section should be present');
        assert.ok(payload.appContainer!.capabilities!.includes('internetClient'));
      } finally {
        restore();
      }
    });

    it('should reject network policies for microvm', () => {
      mockWindows();
      try {
        const policy: SandboxPolicy = {
          version: '0.4.0-alpha',
          network: { allowOutbound: true },
        };
        assert.throws(
          () => buildSandboxPayload('print(42)', policy, undefined, undefined, 'microvm'),
          { message: /does not support network policy/ },
        );
      } finally {
        restore();
      }
    });

    it('should reject microvm on non-Windows platforms', () => {
      const orig = Object.getOwnPropertyDescriptor(process, 'platform');
      Object.defineProperty(process, 'platform', { value: 'linux' });
      try {
        assert.throws(
          () => buildSandboxPayload('print(42)', defaultPolicy, undefined, undefined, 'microvm'),
          { message: /only supported on Windows/ },
        );
      } finally {
        if (orig) Object.defineProperty(process, 'platform', orig);
      }
    });

    it('should preserve lifecycle config for microvm', () => {
      mockWindows();
      try {
        const policy: SandboxPolicy = {
          version: '0.4.0-alpha',
          filesystem: { clearPolicyOnExit: false },
        };
        const payload = buildSandboxPayload('print(42)', policy, undefined, undefined, 'microvm');
        assert.strictEqual(payload.lifecycle!.destroyOnExit, true);
        assert.strictEqual(payload.lifecycle!.preservePolicy, true);
      } finally {
        restore();
      }
    });

    it('should set process commandLine and containerId for microvm', () => {
      mockWindows();
      try {
        const payload = buildSandboxPayload('print(42)', defaultPolicy, undefined, 'my-container', 'microvm');
        assert.strictEqual(payload.process!.commandLine, 'print(42)');
        assert.strictEqual(payload.containerId, 'my-container');
      } finally {
        restore();
      }
    });

  });

  describe('WSLC', () => {
    it('should set containment to wslc when containment option is passed', () => {
      const payload = buildSandboxPayload('echo hello', { version: '0.5.0-alpha' }, undefined, undefined, 'wslc');
      assert.strictEqual(payload.containment, 'wslc');
      assert.strictEqual(payload.process!.commandLine, 'echo hello');
    });

    it('should populate experimental.wslc with default image', () => {
      const payload = buildSandboxPayload('echo hello', { version: '0.5.0-alpha' }, undefined, undefined, 'wslc');
      assert.ok(payload.experimental?.wslc);
      assert.strictEqual(payload.experimental!.wslc!.image, 'alpine:latest');
    });

    it('should not set appContainer or lxc config', () => {
      const payload = buildSandboxPayload('echo hello', { version: '0.5.0-alpha' }, undefined, undefined, 'wslc');
      assert.strictEqual(payload.appContainer, undefined);
      assert.strictEqual(payload.lxc, undefined);
    });

    it('should set default-deny network', () => {
      const payload = buildSandboxPayload('echo hello', { version: '0.5.0-alpha' }, undefined, undefined, 'wslc');
      assert.strictEqual(payload.network!.defaultPolicy, 'block');
    });
  });
});

describe('createConfigFromPolicy', () => {
  const defaultPolicy: SandboxPolicy = { version: '0.4.0-alpha' };

  it('should produce a locked-down config when only version is set', () => {
    const config = createConfigFromPolicy(defaultPolicy);
    assert.strictEqual(config.version, '0.4.0-alpha');
    assert.deepStrictEqual(config.filesystem!.readwritePaths, []);
    assert.deepStrictEqual(config.filesystem!.readonlyPaths, []);
    assert.deepStrictEqual(config.filesystem!.deniedPaths, []);
    assert.strictEqual(config.ui!.disable, true);
    assert.strictEqual(config.ui!.clipboard, 'none');
    assert.strictEqual(config.ui!.injection, false);
    assert.strictEqual(config.process!.timeout, 0);
    assert.strictEqual(config.process!.commandLine, '');
    assert.strictEqual(config.lifecycle!.destroyOnExit, true);
    assert.strictEqual(config.lifecycle!.preservePolicy, false);
  });

  it('should pass filesystem paths through', () => {
    const config = createConfigFromPolicy({
      version: '0.4.0-alpha',
      filesystem: {
        readwritePaths: ['/workspace'],
        readonlyPaths: ['/tools'],
        deniedPaths: ['/secrets'],
      },
    });
    assert.deepStrictEqual(config.filesystem!.readwritePaths, ['/workspace']);
    assert.deepStrictEqual(config.filesystem!.readonlyPaths, ['/tools']);
    assert.deepStrictEqual(config.filesystem!.deniedPaths, ['/secrets']);
  });

  it('should map UI fields correctly', () => {
    const config = createConfigFromPolicy({
      version: '0.4.0-alpha',
      ui: { allowWindows: true, clipboard: 'read', allowInputInjection: true },
    });
    assert.strictEqual(config.ui!.disable, false);
    assert.strictEqual(config.ui!.clipboard, 'read');
    assert.strictEqual(config.ui!.injection, true);
  });

  it('should map timeoutMs to process.timeout', () => {
    const config = createConfigFromPolicy({ version: '0.4.0-alpha', timeoutMs: 30000 });
    assert.strictEqual(config.process!.timeout, 30000);
  });

  describe('Windows', () => {
    let originalPlatform: PropertyDescriptor | undefined;

    const mockWindows = () => {
      originalPlatform = Object.getOwnPropertyDescriptor(process, 'platform');
      Object.defineProperty(process, 'platform', { value: 'win32' });
    };

    const restore = () => {
      if (originalPlatform) {
        Object.defineProperty(process, 'platform', originalPlatform);
      }
    };

    it('should set appContainer with UI defaults for process containment', () => {
      mockWindows();
      try {
        const config = createConfigFromPolicy(defaultPolicy, 'process');
        assert.ok(config.appContainer);
        assert.deepStrictEqual(config.appContainer!.capabilities, []);
        assert.strictEqual(config.appContainer!.ui!.isolation, 'container');
        assert.strictEqual(config.appContainer!.ui!.desktopSystemControl, false);
      } finally {
        restore();
      }
    });

    it('should map network policy to capabilities and hosts', () => {
      mockWindows();
      try {
        const config = createConfigFromPolicy({
          version: '0.4.0-alpha',
          network: {
            allowOutbound: true,
            allowLocalNetwork: true,
            allowedHosts: ['example.com'],
            blockedHosts: ['evil.com'],
          },
        });
        assert.ok(config.appContainer!.capabilities!.includes('internetClient'));
        assert.ok(config.appContainer!.capabilities!.includes('privateNetworkClientServer'));
        assert.deepStrictEqual(config.network!.allowedHosts, ['example.com']);
        assert.deepStrictEqual(config.network!.blockedHosts, ['evil.com']);
      } finally {
        restore();
      }
    });

    it('should pass proxy through to config', () => {
      mockWindows();
      try {
        const builtin = createConfigFromPolicy({
          version: '0.4.0-alpha',
          network: { proxy: { builtinTestServer: true } },
        });
        assert.deepStrictEqual(builtin.network!.proxy, { builtinTestServer: true });

        const url = createConfigFromPolicy({
          version: '0.4.0-alpha',
          network: { proxy: { url: 'http://localhost:8080' } },
        });
        assert.deepStrictEqual(url.network!.proxy, { url: 'http://localhost:8080' });
      } finally {
        restore();
      }
    });
  });

  describe('Linux', () => {
    let originalPlatform: PropertyDescriptor | undefined;

    const mockLinux = () => {
      originalPlatform = Object.getOwnPropertyDescriptor(process, 'platform');
      Object.defineProperty(process, 'platform', { value: 'linux' });
    };

    const restore = () => {
      if (originalPlatform) {
        Object.defineProperty(process, 'platform', originalPlatform);
      }
    };

    it('should default to lxc containment', () => {
      mockLinux();
      try {
        const config = createConfigFromPolicy(defaultPolicy);
        assert.strictEqual(config.containment, 'lxc');
        assert.strictEqual(config.lxc!.distribution, 'alpine');
        assert.strictEqual(config.lxc!.destroyOnExit, true);
      } finally {
        restore();
      }
    });

    it('should reject proxy on Linux', () => {
      mockLinux();
      try {
        assert.throws(
          () => createConfigFromPolicy({
            version: '0.4.0-alpha',
            network: { proxy: { builtinTestServer: true } },
          }),
          { message: /not supported on Linux/ },
        );
      } finally {
        restore();
      }
    });
  });

  describe('network validation', () => {
    it('should reject allowedHosts without allowOutbound', () => {
      assert.throws(
        () => createConfigFromPolicy({
          version: '0.4.0-alpha',
          network: { allowedHosts: ['example.com'] },
        }),
        { message: /allowedHosts\/blockedHosts require allowOutbound/ },
      );
    });

    it('should reject blockedHosts without allowOutbound', () => {
      assert.throws(
        () => createConfigFromPolicy({
          version: '0.4.0-alpha',
          network: { blockedHosts: ['evil.com'] },
        }),
        { message: /allowedHosts\/blockedHosts require allowOutbound/ },
      );
    });
  });

  describe('WSLC', () => {
    it('should set containment to wslc and populate experimental.wslc', () => {
      const config = createConfigFromPolicy({ version: '0.5.0-alpha' }, 'wslc');
      assert.strictEqual(config.containment, 'wslc');
      assert.ok(config.experimental?.wslc);
      assert.strictEqual(config.experimental!.wslc!.image, 'alpine:latest');
    });

    it('should set default-deny network when no network policy is specified', () => {
      const config = createConfigFromPolicy({ version: '0.5.0-alpha' }, 'wslc');
      assert.strictEqual(config.network!.defaultPolicy, 'block');
    });

    it('should map allowOutbound to network allow policy', () => {
      const config = createConfigFromPolicy({
        version: '0.5.0-alpha',
        network: { allowOutbound: true },
      }, 'wslc');
      assert.strictEqual(config.network!.defaultPolicy, 'allow');
    });

    it('should not set enforcementMode for wslc', () => {
      const config = createConfigFromPolicy({
        version: '0.5.0-alpha',
        network: { allowOutbound: true },
      }, 'wslc');
      assert.strictEqual(config.network!.enforcementMode, undefined);
    });

    it('should allow allowedHosts without allowOutbound (block + allowlist)', () => {
      const config = createConfigFromPolicy({
        version: '0.5.0-alpha',
        network: { allowedHosts: ['example.com'] },
      }, 'wslc');
      assert.strictEqual(config.network!.defaultPolicy, 'block');
      assert.deepStrictEqual(config.network!.allowedHosts, ['example.com']);
    });

    it('should not set appContainer config for wslc', () => {
      const config = createConfigFromPolicy({ version: '0.5.0-alpha' }, 'wslc');
      assert.strictEqual(config.appContainer, undefined);
    });

    it('should not set lxc config for wslc', () => {
      const config = createConfigFromPolicy({ version: '0.5.0-alpha' }, 'wslc');
      assert.strictEqual(config.lxc, undefined);
    });

    it('should map filesystem paths correctly', () => {
      const config = createConfigFromPolicy({
        version: '0.5.0-alpha',
        filesystem: {
          readwritePaths: ['C:\\workspace'],
          readonlyPaths: ['C:\\data'],
          deniedPaths: ['C:\\secrets'],
        },
      }, 'wslc');
      assert.deepStrictEqual(config.filesystem!.readwritePaths, ['C:\\workspace']);
      assert.deepStrictEqual(config.filesystem!.readonlyPaths, ['C:\\data']);
      assert.deepStrictEqual(config.filesystem!.deniedPaths, ['C:\\secrets']);
    });

    it('should map timeoutMs to process.timeout', () => {
      const config = createConfigFromPolicy({
        version: '0.5.0-alpha',
        timeoutMs: 30000,
      }, 'wslc');
      assert.strictEqual(config.process!.timeout, 30000);
    });

    it('should set containerId', () => {
      const config = createConfigFromPolicy({ version: '0.5.0-alpha' }, 'wslc', 'my-container');
      assert.strictEqual(config.containerId, 'my-container');
    });

    it('should throw from spawnSandbox when experimental is not set', () => {
      assert.throws(
        () => spawnSandbox('echo hello', { version: '0.5.0-alpha' }, {}, undefined, undefined, undefined, 'wslc'),
        { message: /experimental mode/ },
      );
    });

    it('should throw from spawnSandboxFromConfig when experimental is not set', () => {
      const config = createConfigFromPolicy({ version: '0.5.0-alpha' }, 'wslc');
      config.process!.commandLine = 'echo hello';
      assert.throws(
        () => spawnSandboxFromConfig(config),
        { message: /experimental mode/ },
      );
    });
  });
});
