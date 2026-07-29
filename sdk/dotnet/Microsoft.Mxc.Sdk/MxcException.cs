// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace Microsoft.Mxc.Sdk;

/// <summary>
/// Thrown when an MXC operation fails. <see cref="Code"/> carries the typed
/// <see cref="ErrorCode"/> from the native layer; <see cref="Exception.Message"/>
/// carries the human-readable detail.
/// </summary>
public sealed class MxcException : Exception
{
    /// <summary>The typed error code.</summary>
    public ErrorCode Code { get; }

    /// <summary>Create an exception with the given code and message.</summary>
    public MxcException(ErrorCode code, string message)
        : base(message)
    {
        Code = code;
    }

    /// <summary>
    /// Create an exception wrapping an underlying cause. Used where an
    /// unexpected exception is converted to the SDK's documented failure type
    /// so it does not escape raw, while preserving the original for diagnosis.
    /// </summary>
    public MxcException(ErrorCode code, string message, Exception innerException)
        : base(message, innerException)
    {
        Code = code;
    }

    /// <inheritdoc/>
    public override string ToString() =>
        InnerException is null ? $"{Code}: {Message}" : $"{Code}: {Message} ---> {InnerException}";
}
