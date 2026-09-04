// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

export interface MxcErrorFields {
  code: string;
  message: string;
  operation?: string;
  nativeCode?: string;
  remediation?: string;
  details?: Record<string, unknown>;
}

/** Typed error converted from the opaque error handle returned by mxc_ffi. */
export class MxcError extends Error {
  readonly code: string;
  readonly operation?: string;
  readonly nativeCode?: string;
  readonly remediation?: string;
  readonly details?: Record<string, unknown>;

  constructor(fields: MxcErrorFields) {
    super(fields.message);
    this.name = 'MxcError';
    this.code = fields.code;
    this.operation = fields.operation;
    this.nativeCode = fields.nativeCode;
    this.remediation = fields.remediation;
    this.details = fields.details;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}
