// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import type { Readable, Writable } from 'node:stream';
import {
  MxcProcess,
  type LifecycleScheduler,
  type NativeLifecycleDriver,
} from './container-process.js';

/** Initial or updated terminal dimensions. */
export interface MxcPtySize {
  rows: number;
  columns: number;
}

type ResizePty = (size: MxcPtySize) => void;

/**
 * A container process attached to an MXC-owned pseudo-terminal.
 *
 * Terminal output is a single merged stream. Write terminal input, including
 * control characters and escape sequences, to {@link input}, and call
 * {@link resize} when the visible terminal dimensions change.
 */
export class MxcPtyProcess extends MxcProcess {
  /** @internal */
  constructor(
    driver: NativeLifecycleDriver,
    private readonly resizePty: ResizePty,
    timeoutMs?: number,
    scheduler?: LifecycleScheduler,
  ) {
    super(driver, timeoutMs, scheduler);
  }

  /** Writable PTY input. */
  get input(): Writable {
    const input = this.standardInput;
    if (input === null) {
      throw new Error('the selected backend did not expose PTY input');
    }
    return input;
  }

  /** Readable merged PTY output. */
  get output(): Readable {
    const output = this.standardOutput;
    if (output === null) {
      throw new Error('the selected backend did not expose PTY output');
    }
    return output;
  }

  /** Resize the child terminal. */
  resize(size: MxcPtySize): void {
    if (
      !Number.isInteger(size.rows) ||
      !Number.isInteger(size.columns) ||
      size.rows < 1 ||
      size.rows > 32767 ||
      size.columns < 1 ||
      size.columns > 32767
    ) {
      throw new RangeError(
        'PTY rows and columns must be integers between 1 and 32767',
      );
    }
    this.runWhileActive(() => this.resizePty(size));
  }
}
