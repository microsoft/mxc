// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Internal contracts between the native handle adapter and the Node stream
// facade. These types contain no Koffi-specific declarations.

export interface SandboxProcessWaitResult {
  exitCode: number;
  timedOut: boolean;
}

export interface SandboxReadableBinding {
  read(buffer: Buffer): Promise<number>;
  close(): void;
  free(): void;
}

export interface SandboxWritableBinding {
  write(buffer: Buffer): Promise<number>;
  flush(): Promise<void>;
  free(): void;
}

export interface SandboxProcessBinding {
  readonly id: number;
  readonly warnings: readonly string[];
  takeStdin(): SandboxWritableBinding | null;
  takeStdout(): SandboxReadableBinding | null;
  takeStderr(): SandboxReadableBinding | null;
  tryWait(): SandboxProcessWaitResult & { running: boolean };
  wait(): SandboxProcessWaitResult;
  outputMetadata(): unknown | undefined;
  kill(): void;
  free(): void;
}
