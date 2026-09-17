// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Internal contracts between the native handle adapter and the Node stream
// facade. These types contain no Koffi-specific declarations.

export interface SandboxWaitResult {
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
  warnings(): readonly string[];
  takeStdin(): SandboxWritableBinding | null;
  takeStdout(): SandboxReadableBinding | null;
  takeStderr(): SandboxReadableBinding | null;
  tryWait(): SandboxWaitResult & { running: boolean };
  wait(): SandboxWaitResult;
  outputMetadata(): unknown | undefined;
  kill(): void;
  free(): void;
}
