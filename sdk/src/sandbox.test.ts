// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { describe, it } from 'node:test';
import assert from 'node:assert';
import { buildSandboxPayload } from './sandbox';
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
          network: { allowOutbound: true, proxy: { builtinTestServer: true } },
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
          network: { allowOutbound: true, proxy: { localhost: 8080 } },
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
          network: { allowOutbound: true, proxy: { builtinTestServer: true } },
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

  describe('WSLC', () => {
    it('should set containment to wslc when requested', () => {
      const payload = buildSandboxPayload('echo hello', defaultPolicy, undefined, 'test-wslc', 'wslc');
      assert.strictEqual(payload.containment, 'wslc');
    });

    it('should set experimental.wslc.image', () => {
      const payload = buildSandboxPayload('echo hello', defaultPolicy, undefined, 'test-wslc', 'wslc');
      assert.ok(payload.experimental?.wslc);
      assert.strictEqual(payload.experimental!.wslc!.image, 'alpine:latest');
    });

    it('should map filesystem policy for wslc', () => {
      const policy: SandboxPolicy = {
        version: '0.4.0-alpha',
        filesystem: {
          readwritePaths: ['C:\\workspace'],
          readonlyPaths: ['C:\\data'],
        },
      };
      const payload = buildSandboxPayload('echo hi', policy, undefined, 'test-wslc', 'wslc');
      assert.deepStrictEqual(payload.filesystem!.readwritePaths, ['C:\\workspace']);
      assert.deepStrictEqual(payload.filesystem!.readonlyPaths, ['C:\\data']);
    });

    it('should map network allow for wslc', () => {
      const policy: SandboxPolicy = {
        version: '0.4.0-alpha',
        network: { allowOutbound: true },
      };
      const payload = buildSandboxPayload('echo hi', policy, undefined, 'test-wslc', 'wslc');
      assert.strictEqual(payload.network!.defaultPolicy, 'allow');
    });

    it('should map network block for wslc', () => {
      const policy: SandboxPolicy = {
        version: '0.4.0-alpha',
        network: { allowOutbound: false },
      };
      const payload = buildSandboxPayload('echo hi', policy, undefined, 'test-wslc', 'wslc');
      assert.strictEqual(payload.network!.defaultPolicy, 'block');
    });

    it('should reject proxy configuration with wslc', () => {
      const policy: SandboxPolicy = {
        version: '0.4.0-alpha',
        network: { allowOutbound: true, proxy: { builtinTestServer: true } },
      };
      assert.throws(
        () => buildSandboxPayload('echo hi', policy, undefined, 'test-wslc', 'wslc'),
        { message: /not supported with WSLC/ },
      );
    });

    it('should not include appContainer config for wslc', () => {
      const payload = buildSandboxPayload('echo hello', defaultPolicy, undefined, 'test-wslc', 'wslc');
      assert.strictEqual(payload.appContainer, undefined);
    });
  });
});
