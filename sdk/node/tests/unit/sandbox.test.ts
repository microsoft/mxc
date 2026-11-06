// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { describe, it } from 'node:test';
import assert from 'node:assert';
import { createConfigFromRequest } from '../../src/v1/container.js';
import {
  _resetPlatformSupportCache,
  _setBwrapVersionRunner,
  _setLxcAvailabilityProbe,
} from '../../src/v1/platform.js';
import { ContainerConfig, ContainerRequest, SandboxingMethod } from '../../src/v1/types.js';
import { MxcError } from '../../src/v1/errors.js';

describe('ContainerRequest config mapping', () => {
  const defaultRequest: ContainerRequest = { command: '' };

  describe('Windows', () => {
    let originalPlatform: PropertyDescriptor | undefined;

    const mockPlatform = (platform: NodeJS.Platform) => {
      originalPlatform = Object.getOwnPropertyDescriptor(process, 'platform');
      Object.defineProperty(process, 'platform', { value: platform });
    };

    const mockWindows = () => mockPlatform('win32');

    const restore = () => {
      if (originalPlatform) {
        Object.defineProperty(process, 'platform', originalPlatform);
      }
    };

    it('should set process.commandLine from script parameter', () => {
      mockWindows();
      try {
        const payload = createConfigFromRequest({ ...defaultRequest, command: 'echo hello' });
        assert.strictEqual(payload.process!.commandLine, 'echo hello');
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
        const payload = createConfigFromRequest({ ...defaultRequest, command: 'echo hi' });
        assert.strictEqual(payload.containment, 'process');
        // Abstract 'process' on Linux resolves to Bubblewrap at runtime;
        // the wire-format payload must NOT carry an LXC-specific block.
        assert.strictEqual(payload.lxc, undefined);
      } finally {
        restore();
      }
    });

      });

});

describe('createConfigFromRequest', () => {
  const defaultRequest: ContainerRequest = { command: '' };

  it('should produce a locked-down v1 config for an empty request', () => {
    const config = createConfigFromRequest(defaultRequest);
    assert.strictEqual(config.version, '1.0.0');
    assert.deepStrictEqual(config.filesystem!.readwritePaths, []);
    assert.deepStrictEqual(config.filesystem!.readonlyPaths, []);
    assert.deepStrictEqual(config.filesystem!.deniedPaths, []);
    assert.strictEqual(config.ui, undefined);
    assert.strictEqual(config.process!.timeout, 0);
    assert.strictEqual(config.process!.commandLine, '');
    assert.strictEqual(config.lifecycle!.destroyOnExit, true);
    assert.strictEqual(config.lifecycle!.preservePolicy, false);
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

    it('should keep process containment abstract', () => {
      mockWindows();
      try {
        const config = createConfigFromRequest({
          ...defaultRequest,
          containment: { type: 'process' },
        });
        assert.strictEqual(config.containment, 'process');
        assert.strictEqual(config.processContainer, undefined);
      } finally {
        restore();
      }
    });

    it('should set required ProcessContainer defaults for explicit processcontainer', () => {
      mockWindows();
      try {
        const config = createConfigFromRequest({
          ...defaultRequest,
          containment: { type: 'processcontainer' },
        });
        assert.strictEqual(config.containment, 'processcontainer');
        assert.deepStrictEqual(config.processContainer, {
          capabilities: [],
          ui: {
            isolation: 'container',
            desktopSystemControl: false,
            systemSettings: 'none',
            ime: false,
          },
          filesystem: undefined,
          network: undefined,
        });
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
        const config = createConfigFromRequest(defaultRequest);
        assert.strictEqual(config.containment, 'process');
        // Abstract 'process' on Linux resolves to Bubblewrap at runtime;
        // the wire-format config must NOT carry an LXC-specific block.
        assert.strictEqual(config.lxc, undefined);
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

      });

});

describe('Development containment vocabulary', () => {
  it('should accept isolation_session as a SandboxingMethod', () => {
    const m: SandboxingMethod = 'isolation_session';
    assert.strictEqual(m, 'isolation_session');
  });

  it('should accept isolation_session as a ContainerConfig.containment value', () => {
    const c: ContainerConfig = {
      version: '0.9.0-alpha',
      containment: 'isolation_session',
    };
    assert.strictEqual(c.containment, 'isolation_session');
  });

});
