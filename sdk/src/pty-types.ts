// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * Minimal, vendored subset of the `node-pty` public type surface.
 *
 * `node-pty` is an *optional* peer dependency (see {@link ./lazyPty}). If the
 * SDK referenced `node-pty`'s own types in its public API, every consumer would
 * need `node-pty` installed just to type-check — even pipe-only consumers that
 * never spawn a PTY (they would otherwise hit `TS2307: Cannot find module
 * 'node-pty'`). Re-declaring the slice we expose keeps the generated `.d.ts`
 * self-contained.
 *
 * These declarations are structurally compatible with the real `node-pty`
 * types, so values produced by the actual module satisfy them at runtime.
 */

/** An object that can be disposed via a dispose function. */
export interface IDisposable {
  dispose(): void;
}

/**
 * An event that can be listened to.
 * @returns an `IDisposable` to stop listening.
 */
export interface IEvent<T> {
  (listener: (e: T) => unknown): IDisposable;
}

/** Options shared by all platforms when forking a pseudoterminal. */
export interface IBasePtyForkOptions {
  /** Name of the terminal to be set in environment ($TERM variable). */
  name?: string;
  /** Number of initial cols of the pty. */
  cols?: number;
  /** Number of initial rows of the pty. */
  rows?: number;
  /** Working directory to be set for the child program. */
  cwd?: string;
  /** Environment to be set for the child program. */
  env?: { [key: string]: string | undefined };
  /** String encoding of the underlying pty. */
  encoding?: string | null;
  /** (EXPERIMENTAL) Whether to enable flow control handling. */
  handleFlowControl?: boolean;
  /** (EXPERIMENTAL) String that pauses the pty when `handleFlowControl` is true. */
  flowControlPause?: string;
  /** (EXPERIMENTAL) String that resumes the pty when `handleFlowControl` is true. */
  flowControlResume?: string;
}

/** POSIX-specific fork options. */
export interface IPtyForkOptions extends IBasePtyForkOptions {
  uid?: number;
  gid?: number;
}

/** Windows-specific fork options. */
export interface IWindowsPtyForkOptions extends IBasePtyForkOptions {
  /** @deprecated Ignored by node-pty; retained for compatibility. */
  useConpty?: boolean;
  /** (EXPERIMENTAL) Use the conpty.dll shipped with node-pty. */
  useConptyDll?: boolean;
  /** Whether to use PSEUDOCONSOLE_INHERIT_CURSOR in conpty. */
  conptyInheritCursor?: boolean;
}

/** An interface representing a pseudoterminal. */
export interface IPty {
  /** The process ID of the outer process. */
  readonly pid: number;
  /** The column size in characters. */
  readonly cols: number;
  /** The row size in characters. */
  readonly rows: number;
  /** The title of the active process. */
  readonly process: string;
  /** (EXPERIMENTAL) Whether to handle flow control at runtime. */
  handleFlowControl: boolean;
  /** Fires when data is returned from the pty. */
  readonly onData: IEvent<string>;
  /** Fires when the pty exits. */
  readonly onExit: IEvent<{ exitCode: number; signal?: number }>;
  /** Resizes the dimensions of the pty. */
  resize(columns: number, rows: number, pixelSize?: { width: number; height: number }): void;
  /** Clears the pty's internal representation of its buffer (ConPTY only). */
  clear(): void;
  /** Writes data to the pty. */
  write(data: string | Buffer): void;
  /** Kills the pty. */
  kill(signal?: string): void;
  /** Pauses the pty for customizable flow control. */
  pause(): void;
  /** Resumes the pty for customizable flow control. */
  resume(): void;
}

/**
 * The slice of the `node-pty` module shape that the SDK calls into. Returned by
 * {@link ./lazyPty.loadPty}.
 */
export interface NodePty {
  spawn(
    file: string,
    args: string[] | string,
    options: IPtyForkOptions | IWindowsPtyForkOptions,
  ): IPty;
}
