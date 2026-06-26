// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { describe, it } from 'node:test';
import assert from 'node:assert';
import { buildSandboxPayload, createConfigFromPolicy, spawnSandbox, spawnSandboxFromConfig } from '../../src/sandbox.js';
import { resolveExecutableAndArgs } from '../../src/helper.js';
import { ContainerConfig, SandboxPolicy, SandboxingMethod } from '../../src/types.js';
import { platformSkip } from './test-helpers.js';

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

    it('should map network policy to processcontainer capabilities', () => {
      mockWindows();
      try {
        const policy: SandboxPolicy = {
          version: '0.4.0-alpha',
          network: { allowOutbound: true, allowLocalNetwork: true },
        };
        const payload = buildSandboxPayload('echo hi', policy);
        assert.ok(payload.processContainer!.capabilities!.includes('internetClient'));
        assert.ok(payload.processContainer!.capabilities!.includes('privateNetworkClientServer'));
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

    it('should accept version 0.6.0-alpha', () => {
      mockWindows();
      try {
        assert.doesNotThrow(() => buildSandboxPayload('echo hi', { version: '0.6.0-alpha' }));
      } finally {
        restore();
      }
    });

    it('should accept version 0.7.0-alpha', () => {
      mockWindows();
      try {
        assert.doesNotThrow(() => buildSandboxPayload('echo hi', { version: '0.7.0-alpha' }));
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

    it('should default to process containment on Linux (resolved by binary to bubblewrap)', () => {
      mockLinux();
      try {
        const payload = buildSandboxPayload('echo hi', defaultPolicy);
        assert.strictEqual(payload.containment, 'process');
        // Abstract 'process' on Linux resolves to Bubblewrap at runtime;
        // the wire-format payload must NOT carry an LXC-specific block.
        assert.strictEqual(payload.lxc, undefined);
      } finally {
        restore();
      }
    });

    it('should accept proxy configuration on Linux for the default process containment (resolves to bubblewrap)', () => {
      mockLinux();
      try {
        const policy: SandboxPolicy = {
          version: '0.4.0-alpha',
          network: { proxy: { builtinTestServer: true } },
        };
        const config = buildSandboxPayload('echo hi', policy);
        assert.strictEqual(config.containment, 'process');
        assert.deepStrictEqual(config.network!.proxy, { builtinTestServer: true });
      } finally {
        restore();
      }
    });

    it('should accept proxy configuration on Linux for explicit bubblewrap containment', () => {
      mockLinux();
      try {
        const policy: SandboxPolicy = {
          version: '0.4.0-alpha',
          network: { proxy: { builtinTestServer: true } },
        };
        const config = buildSandboxPayload('echo hi', policy, undefined, undefined, 'bubblewrap');
        assert.strictEqual(config.containment, 'bubblewrap');
        assert.deepStrictEqual(config.network!.proxy, { builtinTestServer: true });
      } finally {
        restore();
      }
    });

    it('should reject proxy configuration on Linux for non-bubblewrap containments (e.g. lxc)', () => {
      mockLinux();
      try {
        const policy: SandboxPolicy = {
          version: '0.4.0-alpha',
          network: { proxy: { builtinTestServer: true } },
        };
        assert.throws(
          () => buildSandboxPayload('echo hi', policy, undefined, undefined, 'lxc'),
          { message: /not supported on Linux containment='lxc'/ },
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
        assert.strictEqual(payload.processContainer, undefined);
      } finally {
        restore();
      }
    });

    it('should map clearPolicyOnExit to lifecycle.preservePolicy for microvm when policy has paths', () => {
      mockWindows();
      try {
        const policy: SandboxPolicy = {
          version: '0.4.0-alpha',
          filesystem: { readwritePaths: ['/tmp'] },
        };
        const payload = buildSandboxPayload('print(42)', policy, undefined, undefined, 'microvm');
        assert.strictEqual(payload.containment, 'microvm');
        assert.deepStrictEqual(payload.filesystem!.readwritePaths, ['/tmp']);
        // clearPolicyOnExit is not a wire `filesystem` field; the intent is
        // carried canonically by lifecycle.preservePolicy (default clear => not preserved).
        assert.strictEqual(payload.lifecycle!.preservePolicy, false);
      } finally {
        restore();
      }
    });

    it('should honor clearPolicyOnExit false for microvm (via lifecycle.preservePolicy)', () => {
      mockWindows();
      try {
        const policy: SandboxPolicy = {
          version: '0.4.0-alpha',
          filesystem: { readwritePaths: ['/tmp'], clearPolicyOnExit: false },
        };
        const payload = buildSandboxPayload('print(42)', policy, undefined, undefined, 'microvm');
        assert.strictEqual(payload.lifecycle!.preservePolicy, true);
      } finally {
        restore();
      }
    });

    it('should build processcontainer config on Windows with default process containment', () => {
      mockWindows();
      try {
        const policy: SandboxPolicy = {
          version: '0.4.0-alpha',
          network: { allowOutbound: true },
        };
        const payload = buildSandboxPayload('echo hi', policy);
        assert.ok(payload.processContainer, 'processContainer section should be present');
        assert.ok(payload.processContainer!.capabilities!.includes('internetClient'));
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

    it('should not set processContainer or lxc config', () => {
      const payload = buildSandboxPayload('echo hello', { version: '0.5.0-alpha' }, undefined, undefined, 'wslc');
      assert.strictEqual(payload.processContainer, undefined);
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

    it('should set processContainer with UI defaults for process containment', () => {
      mockWindows();
      try {
        const config = createConfigFromPolicy(defaultPolicy, 'process');
        assert.ok(config.processContainer);
        assert.deepStrictEqual(config.processContainer!.capabilities, []);
        assert.strictEqual(config.processContainer!.ui!.isolation, 'container');
        assert.strictEqual(config.processContainer!.ui!.desktopSystemControl, false);
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
        assert.ok(config.processContainer!.capabilities!.includes('internetClient'));
        assert.ok(config.processContainer!.capabilities!.includes('privateNetworkClientServer'));
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

    it('should default to process containment (resolved by binary to bubblewrap on Linux)', () => {
      mockLinux();
      try {
        const config = createConfigFromPolicy(defaultPolicy);
        assert.strictEqual(config.containment, 'process');
        // Abstract 'process' on Linux resolves to Bubblewrap at runtime;
        // the wire-format config must NOT carry an LXC-specific block.
        assert.strictEqual(config.lxc, undefined);
      } finally {
        restore();
      }
    });

    it('should force enforcementMode=firewall when host filtering is requested (process resolves to bubblewrap on Linux)', () => {
      mockLinux();
      try {
        const config = createConfigFromPolicy({
          version: '0.5.0-alpha',
          network: { allowOutbound: true, allowedHosts: ['example.com'] },
        });
        assert.strictEqual(config.containment, 'process');
        assert.strictEqual(config.lxc, undefined);
        // Abstract 'process' on Linux must apply the same iptables firewall
        // enforcement as explicit 'bubblewrap', because the native binary
        // resolves the abstract intent to Bubblewrap server-side.
        assert.strictEqual(config.network!.enforcementMode, 'firewall');
      } finally {
        restore();
      }
    });

    it('should allow allowedHosts without allowOutbound on Linux (bubblewrap supports per-host filtering)', () => {
      mockLinux();
      try {
        const config = createConfigFromPolicy({
          version: '0.5.0-alpha',
          network: { allowedHosts: ['example.com'] },
        });
        assert.strictEqual(config.containment, 'process');
        assert.deepStrictEqual(config.network!.allowedHosts, ['example.com']);
        assert.strictEqual(config.network!.defaultPolicy, 'block');
        assert.strictEqual(config.network!.enforcementMode, 'firewall');
      } finally {
        restore();
      }
    });

    it('should accept proxy on Linux for the default process containment (resolves to bubblewrap)', () => {
      mockLinux();
      try {
        const config = createConfigFromPolicy({
          version: '0.4.0-alpha',
          network: { proxy: { builtinTestServer: true } },
        });
        assert.strictEqual(config.containment, 'process');
        assert.deepStrictEqual(config.network!.proxy, { builtinTestServer: true });
      } finally {
        restore();
      }
    });

    it('should accept proxy on Linux for explicit bubblewrap containment', () => {
      mockLinux();
      try {
        const config = createConfigFromPolicy(
          {
            version: '0.4.0-alpha',
            network: { proxy: { builtinTestServer: true } },
          },
          'bubblewrap',
        );
        assert.strictEqual(config.containment, 'bubblewrap');
        assert.deepStrictEqual(config.network!.proxy, { builtinTestServer: true });
      } finally {
        restore();
      }
    });

    it('should NOT force enforcementMode=firewall when proxy + host filtering are combined on bubblewrap', () => {
      // The Rust config_parser explicitly rejects bubblewrap+proxy+firewall
      // since the iptables path requires privilege the bwrap backend
      // deliberately avoids. Host enforcement happens at the proxy layer
      // instead, so the SDK must leave enforcementMode at its default.
      mockLinux();
      try {
        const config = createConfigFromPolicy(
          {
            version: '0.4.0-alpha',
            network: {
              allowOutbound: true,
              allowedHosts: ['example.com'],
              proxy: { builtinTestServer: true },
            },
          },
          'bubblewrap',
        );
        assert.strictEqual(config.containment, 'bubblewrap');
        assert.strictEqual(config.network!.enforcementMode, undefined);
        assert.deepStrictEqual(config.network!.proxy, { builtinTestServer: true });
        assert.deepStrictEqual(config.network!.allowedHosts, ['example.com']);
      } finally {
        restore();
      }
    });

    it('should reject proxy on Linux for explicit lxc containment', () => {
      mockLinux();
      try {
        assert.throws(
          () => createConfigFromPolicy(
            {
              version: '0.4.0-alpha',
              network: { proxy: { builtinTestServer: true } },
            },
            'lxc',
          ),
          { message: /not supported on Linux containment='lxc'/ },
        );
      } finally {
        restore();
      }
    });
  });

  describe('macOS', () => {
    let originalPlatform: PropertyDescriptor | undefined;

    const mockDarwin = () => {
      originalPlatform = Object.getOwnPropertyDescriptor(process, 'platform');
      Object.defineProperty(process, 'platform', { value: 'darwin' });
    };

    const restore = () => {
      if (originalPlatform) {
        Object.defineProperty(process, 'platform', originalPlatform);
      }
    };

    it('should allow allowedHosts without allowOutbound on macOS (seatbelt supports per-host filtering)', () => {
      mockDarwin();
      try {
        const config = createConfigFromPolicy({
          version: '0.5.0-alpha',
          network: { allowedHosts: ['api.github.com'] },
        });
        // Abstract 'process' on macOS resolves to 'seatbelt' in the wire format
        // (unlike Linux where the binary resolves it server-side).
        assert.strictEqual(config.containment, 'seatbelt');
        assert.deepStrictEqual(config.network!.allowedHosts, ['api.github.com']);
        assert.strictEqual(config.network!.defaultPolicy, 'block');
      } finally {
        restore();
      }
    });

    it('should allow blockedHosts without allowOutbound on macOS', () => {
      mockDarwin();
      try {
        const config = createConfigFromPolicy({
          version: '0.5.0-alpha',
          network: { blockedHosts: ['evil.com'] },
        });
        assert.strictEqual(config.containment, 'seatbelt');
        assert.deepStrictEqual(config.network!.blockedHosts, ['evil.com']);
        assert.strictEqual(config.network!.defaultPolicy, 'block');
      } finally {
        restore();
      }
    });

    it('should propagate allowLocalNetwork to network.allowLocalNetwork on macOS', () => {
      // server.listen() on macOS needs Seatbelt's `network-inbound` rule,
      // which the runner emits when ContainerPolicy.allow_local_network is
      // true. The SDK is responsible for forwarding allowLocalNetwork through
      // the wire format so the Rust profile builder sees it.
      mockDarwin();
      try {
        const config = createConfigFromPolicy({
          version: '0.5.0-alpha',
          network: { allowOutbound: true, allowLocalNetwork: true },
        });
        assert.strictEqual(config.containment, 'seatbelt');
        assert.strictEqual(config.network!.allowLocalNetwork, true);
      } finally {
        restore();
      }
    });

    it('should omit allowLocalNetwork when not set on macOS', () => {
      mockDarwin();
      try {
        const config = createConfigFromPolicy({
          version: '0.5.0-alpha',
          network: { allowOutbound: true },
        });
        assert.strictEqual(config.network!.allowLocalNetwork, undefined);
      } finally {
        restore();
      }
    });

    it('should reject proxy configuration on macOS', () => {
      mockDarwin();
      try {
        assert.throws(
          () => createConfigFromPolicy({
            version: '0.4.0-alpha',
            network: { proxy: { builtinTestServer: true } },
          }),
          { message: /not supported on macOS/ },
        );
      } finally {
        restore();
      }
    });
  });

  describe('network validation', () => {
    // These tests assert the "allowOutbound required for host filtering"
    // gate. The gate applies to backends that map host filtering to
    // capabilities/ACLs (Windows process container path). It is intentionally
    // waived for backends that do per-host iptables/Seatbelt filtering
    // (wslc, seatbelt, bubblewrap, and Linux abstract 'process' which
    // resolves to bubblewrap). Mock platform to win32 so the test asserts
    // the gate independent of the CI runner's OS.
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

    it('should reject allowedHosts without allowOutbound', () => {
      mockWindows();
      try {
        assert.throws(
          () => createConfigFromPolicy({
            version: '0.4.0-alpha',
            network: { allowedHosts: ['example.com'] },
          }),
          { message: /allowedHosts\/blockedHosts require allowOutbound/ },
        );
      } finally {
        restore();
      }
    });

    it('should reject blockedHosts without allowOutbound', () => {
      mockWindows();
      try {
        assert.throws(
          () => createConfigFromPolicy({
            version: '0.4.0-alpha',
            network: { blockedHosts: ['evil.com'] },
          }),
          { message: /allowedHosts\/blockedHosts require allowOutbound/ },
        );
      } finally {
        restore();
      }
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

    it('should not set processContainer config for wslc', () => {
      const config = createConfigFromPolicy({ version: '0.5.0-alpha' }, 'wslc');
      assert.strictEqual(config.processContainer, undefined);
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

    it('should throw from spawnSandbox when experimental backend is used via config', () => {
      const config = createConfigFromPolicy({ version: '0.5.0-alpha' }, 'wslc');
      config.process!.commandLine = 'echo hello';
      assert.throws(
        () => spawnSandboxFromConfig(config),
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

  describe('Bubblewrap', () => {
    it('should set containment to bubblewrap', () => {
      const config = createConfigFromPolicy({ version: '0.5.0-alpha' }, 'bubblewrap');
      assert.strictEqual(config.containment, 'bubblewrap');
    });

    it('should map filesystem and network policy fields through to ContainerConfig', () => {
      const config = createConfigFromPolicy({
        version: '0.5.0-alpha',
        filesystem: {
          readwritePaths: ['/workspace'],
          readonlyPaths: ['/data'],
          deniedPaths: ['/secrets'],
        },
        network: { allowOutbound: true, allowedHosts: ['example.com'] },
      }, 'bubblewrap');
      assert.deepStrictEqual(config.filesystem!.readwritePaths, ['/workspace']);
      assert.deepStrictEqual(config.filesystem!.readonlyPaths, ['/data']);
      assert.deepStrictEqual(config.filesystem!.deniedPaths, ['/secrets']);
      // Per applyLinuxNetworkPolicy, host filtering forces firewall mode.
      assert.strictEqual(config.network!.enforcementMode, 'firewall');
    });
  });

  describe('Lxc (explicit opt-in)', () => {
    it('should set containment to lxc and populate the lxc backend block', () => {
      // Regression guard: making bubblewrap the Linux default for the
      // abstract `"process"` intent must not break the explicit LXC path.
      const config = createConfigFromPolicy({ version: '0.5.0-alpha' }, 'lxc');
      assert.strictEqual(config.containment, 'lxc');
      assert.ok(config.lxc, 'lxc backend block should be populated');
      assert.strictEqual(config.lxc!.distribution, 'alpine');
    });

    it('should force enforcementMode=firewall when host filtering is requested', () => {
      // The LXC runner only invokes iptables when network_enforcement_mode is
      // Firewall|Both (see lxc_common::network_iptables). Without this stamp,
      // the parser would default to Capabilities and allowedHosts/blockedHosts
      // would be silently dropped on the floor.
      const config = createConfigFromPolicy({
        version: '0.5.0-alpha',
        network: { allowOutbound: true, allowedHosts: ['example.com'] },
      }, 'lxc');
      assert.strictEqual(config.containment, 'lxc');
      assert.strictEqual(config.network!.enforcementMode, 'firewall');
    });

    it('should allow allowedHosts without allowOutbound (LXC supports per-host iptables filtering)', () => {
      const config = createConfigFromPolicy({
        version: '0.5.0-alpha',
        network: { allowedHosts: ['example.com'] },
      }, 'lxc');
      assert.strictEqual(config.containment, 'lxc');
      assert.deepStrictEqual(config.network!.allowedHosts, ['example.com']);
      assert.strictEqual(config.network!.defaultPolicy, 'block');
      assert.strictEqual(config.network!.enforcementMode, 'firewall');
    });
  });
});

describe('Schema 0.6.0 vocabulary', () => {
  it('should accept isolation_session as a SandboxingMethod', () => {
    const m: SandboxingMethod = 'isolation_session';
    assert.strictEqual(m, 'isolation_session');
  });

  it('should accept isolation_session as a ContainerConfig.containment value', () => {
    const c: ContainerConfig = {
      version: '0.6.0-alpha',
      containment: 'isolation_session',
    };
    assert.strictEqual(c.containment, 'isolation_session');
  });
});

describe('resolveExecutableAndArgs (containment validation)', { skip: platformSkip }, () => {
  // Use the running node binary as a stand-in executable so the helper does
  // not try to discover wxc-exec on disk. The helper does not actually exec
  // anything; it just builds the path + args.
  const fakeExe = process.execPath;

  function makeConfig(containment: string): ContainerConfig {
    return {
      version: '0.5.0-alpha',
      containment: containment as ContainerConfig['containment'],
      process: { commandLine: 'echo hi' },
    };
  }

  it('should accept the abstract intent "process" without throwing', () => {
    // Regression guard: createConfigFromPolicy() defaults to "process" and
    // the SDK no longer pre-resolves it to a concrete backend. The validator
    // must accept abstract intents and let the native binary resolve them.
    assert.doesNotThrow(() =>
      resolveExecutableAndArgs(makeConfig('process'), { executablePath: fakeExe }),
    );
  });

  it('should accept the abstract intent "microvm" with experimental flag (Windows only)', function (this: { skip: (reason?: string) => void }) {
    if (process.platform !== 'win32') {
      this.skip('microvm is Windows-only');
      return;
    }
    assert.doesNotThrow(() =>
      resolveExecutableAndArgs(makeConfig('microvm'), {
        executablePath: fakeExe,
        experimental: true,
      }),
    );
  });

  it('should not require experimental mode for the non-experimental "process" intent', () => {
    // process is an abstract intent; only its concrete resolution may be
    // experimental (e.g. seatbelt today). The intent itself does not
    // require --experimental at the SDK boundary.
    assert.doesNotThrow(() =>
      resolveExecutableAndArgs(makeConfig('process'), { executablePath: fakeExe }),
    );
  });

  it('should accept the abstract intent "vm" without throwing', () => {
    // "vm" is a forward-looking ContainmentType intent. Even though no
    // concrete VM backend resolves it yet, the SDK validator must let it
    // pass — the binary owns the resolve/error step.
    assert.doesNotThrow(() =>
      resolveExecutableAndArgs(makeConfig('vm'), { executablePath: fakeExe }),
    );
  });

  it('should still reject genuinely unknown containment values', () => {
    assert.throws(
      () => resolveExecutableAndArgs(makeConfig('bogus_backend'), { executablePath: fakeExe }),
      { message: /not available on this platform/ },
    );
  });

  it('should still require experimental mode for experimental backends like wslc', () => {
    assert.throws(
      () => resolveExecutableAndArgs(makeConfig('wslc'), { executablePath: fakeExe }),
      { message: /experimental mode/ },
    );
  });

  it('should NOT require experimental mode for explicit lxc containment', function (this: { skip: (reason?: string) => void }) {
    if (process.platform !== 'linux') {
      this.skip('lxc is Linux-only');
      return;
    }
    assert.doesNotThrow(() =>
      resolveExecutableAndArgs(makeConfig('lxc'), { executablePath: fakeExe }),
    );
  });

  // Legacy wire-value aliases (PR #268 deprecation window). The native binary
  // accepts these via serde aliases; the SDK validator must mirror that so
  // existing 0.4.0-/0.5.0-alpha configs are not rejected before they reach
  // wxc-exec. See also Rust parser tests
  // `legacy_appcontainer_wire_value_aliases_processcontainer` and
  // `legacy_macos_sandbox_wire_value_aliases_seatbelt`.
  describe('legacy containment aliases', () => {
    it('should accept "appcontainer" as an alias of processcontainer (Windows)', function (this: { skip: (reason?: string) => void }) {
      if (process.platform !== 'win32') {
        this.skip('processcontainer is Windows-only');
        return;
      }
      assert.doesNotThrow(() =>
        resolveExecutableAndArgs(makeConfig('appcontainer'), { executablePath: fakeExe }),
      );
    });

    it('should reject "appcontainer" on non-Windows hosts with the canonical error', function (this: { skip: (reason?: string) => void }) {
      if (process.platform === 'win32') {
        this.skip('appcontainer is the native value on Windows');
        return;
      }
      assert.throws(
        () => resolveExecutableAndArgs(makeConfig('appcontainer'), { executablePath: fakeExe }),
        { message: /'appcontainer' is not available on this platform/ },
      );
    });

    it('should accept "macos_sandbox" on macOS', function (this: { skip: (reason?: string) => void }) {
      if (process.platform !== 'darwin') {
        this.skip('seatbelt is macOS-only');
        return;
      }
      assert.doesNotThrow(() =>
        resolveExecutableAndArgs(makeConfig('macos_sandbox'), { executablePath: fakeExe }),
      );
    });

    it('should forward the legacy wire value to the binary unchanged', () => {
      // The SDK resolves the alias only for its own validation; the on-wire
      // string sent to wxc-exec must still be the legacy form, because the
      // Rust serde alias is the canonical resolution point. Re-decoding the
      // base64 envelope confirms the wire form is preserved.
      const { args } = resolveExecutableAndArgs(
        // Force the validator to accept regardless of host: macOS would
        // otherwise fail on the experimental gate; Windows/Linux on platform
        // availability for non-native legacy values.
        makeConfig('appcontainer'),
        { executablePath: fakeExe, skipPlatformCheck: true },
      );
      const idx = args.indexOf('--config-base64');
      assert.ok(idx >= 0, '--config-base64 should be present in args');
      const decoded = Buffer.from(args[idx + 1], 'base64').toString('utf-8');
      const envelope = JSON.parse(decoded);
      assert.strictEqual(envelope.containment, 'appcontainer');
    });
  });

  describe('builtinTestServer testing-features gate', () => {
    it('forwards --allow-testing-features when the caller opts in via allowTestingFeatures', () => {
      const config: ContainerConfig = {
        version: '0.5.0-alpha',
        containment: 'process',
        process: { commandLine: 'echo hi' },
        network: { proxy: { builtinTestServer: true } },
      };
      const { args } = resolveExecutableAndArgs(config, {
        executablePath: fakeExe,
        skipPlatformCheck: true,
        allowTestingFeatures: true,
      });
      assert.ok(
        args.includes('--allow-testing-features'),
        'expected --allow-testing-features to be forwarded',
      );
    });

    it('throws when builtinTestServer is used without allowTestingFeatures', () => {
      const config: ContainerConfig = {
        version: '0.5.0-alpha',
        containment: 'process',
        process: { commandLine: 'echo hi' },
        network: { proxy: { builtinTestServer: true } },
      };
      assert.throws(
        () =>
          resolveExecutableAndArgs(config, {
            executablePath: fakeExe,
            skipPlatformCheck: true,
          }),
        { message: /allowTestingFeatures: true/ },
      );
    });

    it('does not forward --allow-testing-features for a non-test proxy', () => {
      const config: ContainerConfig = {
        version: '0.5.0-alpha',
        containment: 'process',
        process: { commandLine: 'echo hi' },
        network: { proxy: { url: 'http://localhost:8080' } },
      };
      const { args } = resolveExecutableAndArgs(config, {
        executablePath: fakeExe,
        skipPlatformCheck: true,
      });
      assert.ok(
        !args.includes('--allow-testing-features'),
        'did not expect --allow-testing-features for a url proxy',
      );
    });
  });
});
