// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { MxcError, type MxcErrorFields } from './errors.js';
import { loadAddon } from './runtime.js';
import type {
  ExecAttachedOptions,
  PollResult,
  RunSandboxRequest,
  StateAwareRequest,
  WaitResult,
} from './types.js';

interface NativeInputStream {
  writeSync(bytes: Buffer): number;
  write(bytes: Buffer): Promise<number>;
  flushSync(): void;
  flush(): Promise<void>;
  dispose(): void;
}

interface NativeOutputStream {
  readSync(size: number): Buffer;
  read(size: number): Promise<Buffer>;
  dispose(): void;
}

interface NativeSandbox {
  takeStdin(): NativeInputStream | null;
  takeStdout(): NativeOutputStream | null;
  takeStderr(): NativeOutputStream | null;
  tryWait(): PollResult;
  waitSync(): WaitResult;
  wait(): Promise<WaitResult>;
  killSync(): void;
  kill(): Promise<void>;
  dispose(): void;
}

interface NativeHandleAddon {
  spawnSandboxSync(requestJson: string): NativeSandbox;
  spawnSandbox(requestJson: string): Promise<NativeSandbox>;
  execSandboxSync(requestJson: string, experimental: boolean): NativeSandbox;
  execSandbox(requestJson: string, experimental: boolean): Promise<NativeSandbox>;
}

function native(): NativeHandleAddon {
  return loadAddon() as NativeHandleAddon;
}

function serializeRequest(request: RunSandboxRequest): string {
  return typeof request === 'string' ? request : JSON.stringify(request);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function throwMxcError(error: unknown): never {
  if (isRecord(error) && typeof error.code === 'string' && typeof error.message === 'string') {
    const fields: MxcErrorFields = {
      code: error.code,
      message: error.message,
      ...(typeof error.operation === 'string' ? { operation: error.operation } : {}),
      ...(typeof error.nativeCode === 'string' ? { nativeCode: error.nativeCode } : {}),
      ...(typeof error.remediation === 'string' ? { remediation: error.remediation } : {}),
    };
    throw new MxcError(fields);
  }
  throw error;
}

/** A taken writable stdin stream owned by the native sandbox. */
export class SandboxInput {
  readonly #native: NativeInputStream;

  constructor(handle: NativeInputStream) {
    this.#native = handle;
  }

  writeSync(bytes: Uint8Array): number {
    try {
      return this.#native.writeSync(Buffer.from(bytes));
    } catch (error) {
      throwMxcError(error);
    }
  }

  async write(bytes: Uint8Array): Promise<number> {
    try {
      return await this.#native.write(Buffer.from(bytes));
    } catch (error) {
      throwMxcError(error);
    }
  }

  flushSync(): void {
    try {
      this.#native.flushSync();
    } catch (error) {
      throwMxcError(error);
    }
  }

  async flush(): Promise<void> {
    try {
      await this.#native.flush();
    } catch (error) {
      throwMxcError(error);
    }
  }

  dispose(): void {
    this.#native.dispose();
  }
}

/** A taken readable stdout or stderr stream owned by the native sandbox. */
export class SandboxOutput {
  readonly #native: NativeOutputStream;

  constructor(handle: NativeOutputStream) {
    this.#native = handle;
  }

  readSync(size = 64 * 1024): Buffer {
    try {
      return this.#native.readSync(size);
    } catch (error) {
      throwMxcError(error);
    }
  }

  async read(size = 64 * 1024): Promise<Buffer> {
    try {
      return await this.#native.read(size);
    } catch (error) {
      throwMxcError(error);
    }
  }

  dispose(): void {
    this.#native.dispose();
  }
}

/** A live sandbox process projected from the generated Diplomat C ABI. */
export class Sandbox {
  readonly #native: NativeSandbox;

  constructor(handle: NativeSandbox) {
    this.#native = handle;
  }

  takeStdin(): SandboxInput | undefined {
    try {
      const handle = this.#native.takeStdin();
      return handle === null ? undefined : new SandboxInput(handle);
    } catch (error) {
      throwMxcError(error);
    }
  }

  takeStdout(): SandboxOutput | undefined {
    try {
      const handle = this.#native.takeStdout();
      return handle === null ? undefined : new SandboxOutput(handle);
    } catch (error) {
      throwMxcError(error);
    }
  }

  takeStderr(): SandboxOutput | undefined {
    try {
      const handle = this.#native.takeStderr();
      return handle === null ? undefined : new SandboxOutput(handle);
    } catch (error) {
      throwMxcError(error);
    }
  }

  tryWait(): PollResult {
    try {
      return this.#native.tryWait();
    } catch (error) {
      throwMxcError(error);
    }
  }

  waitSync(): WaitResult {
    try {
      return this.#native.waitSync();
    } catch (error) {
      throwMxcError(error);
    }
  }

  async wait(): Promise<WaitResult> {
    try {
      return await this.#native.wait();
    } catch (error) {
      throwMxcError(error);
    }
  }

  killSync(): void {
    try {
      this.#native.killSync();
    } catch (error) {
      throwMxcError(error);
    }
  }

  async kill(): Promise<void> {
    try {
      await this.#native.kill();
    } catch (error) {
      throwMxcError(error);
    }
  }

  dispose(): void {
    this.#native.dispose();
  }
}

/** Spawns a live sandbox synchronously. */
export function spawnSandboxSync(request: RunSandboxRequest): Sandbox {
  try {
    return new Sandbox(native().spawnSandboxSync(serializeRequest(request)));
  } catch (error) {
    throwMxcError(error);
  }
}

/** Spawns a live sandbox without blocking the JavaScript thread. */
export async function spawnSandbox(request: RunSandboxRequest): Promise<Sandbox> {
  try {
    return new Sandbox(await native().spawnSandbox(serializeRequest(request)));
  } catch (error) {
    throwMxcError(error);
  }
}

/** Executes in a state-aware sandbox synchronously and returns a live process. */
export function execSandboxSync(
  request: StateAwareRequest,
  options: ExecAttachedOptions = {},
): Sandbox {
  try {
    return new Sandbox(
      native().execSandboxSync(serializeRequest(request), options.experimental ?? false),
    );
  } catch (error) {
    throwMxcError(error);
  }
}

/** Executes in a state-aware sandbox and returns a live process. */
export async function execSandbox(
  request: StateAwareRequest,
  options: ExecAttachedOptions = {},
): Promise<Sandbox> {
  try {
    return new Sandbox(
      await native().execSandbox(serializeRequest(request), options.experimental ?? false),
    );
  } catch (error) {
    throwMxcError(error);
  }
}
