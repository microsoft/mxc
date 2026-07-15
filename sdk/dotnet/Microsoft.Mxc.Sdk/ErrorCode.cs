// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace Microsoft.Mxc.Sdk;

/// <summary>
/// Error codes returned across the native FFI boundary. Values 0–12 mirror the
/// Rust <c>MxcErrorCode</c> / <c>mxc_sdk::ErrorCode</c> one-for-one; values 100+
/// are FFI-local conditions with no Rust equivalent. Kept in lockstep with the
/// native <c>MXC_STATUS_*</c> constants by a CI drift gate.
/// </summary>
public enum ErrorCode
{
    /// <summary>Success.</summary>
    Success = 0,

    /// <summary>The request or policy was malformed.</summary>
    MalformedRequest = 1,

    /// <summary>The requested containment backend is not supported.</summary>
    UnsupportedContainment = 2,

    /// <summary>The requested state-aware phase is unsupported.</summary>
    UnsupportedPhase = 3,

    /// <summary>The backend is unavailable on this host.</summary>
    BackendUnavailable = 4,

    /// <summary>A sandbox id was malformed.</summary>
    MalformedId = 5,

    /// <summary>A sandbox id referred to stale state.</summary>
    StaleId = 6,

    /// <summary>The sandbox was not provisioned.</summary>
    NotProvisioned = 7,

    /// <summary>The sandbox was not started.</summary>
    NotStarted = 8,

    /// <summary>The sandbox was already started.</summary>
    AlreadyStarted = 9,

    /// <summary>The sandbox was already stopped.</summary>
    AlreadyStopped = 10,

    /// <summary>Policy validation failed.</summary>
    PolicyValidation = 11,

    /// <summary>A generic backend error.</summary>
    BackendError = 12,

    /// <summary>A required pointer argument was null (FFI-local).</summary>
    NullArgument = 100,

    /// <summary>An input string was not valid UTF-8 (FFI-local).</summary>
    InvalidUtf8 = 101,

    /// <summary>The native side panicked and was caught at the boundary (FFI-local).</summary>
    Panic = 102,
}
