// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace Microsoft.Mxc.Sdk;

/// <summary>
/// Thrown when an MXC operation fails. <see cref="Code"/> carries the typed
/// <see cref="ErrorCode"/> from the native layer; <see cref="Exception.Message"/>
/// carries the human-readable detail.
/// </summary>
/// <remarks>
/// <para>
/// When the failure came from an underlying platform API, <see cref="Operation"/>
/// names the call and <see cref="NativeCode"/> carries its status. Both are
/// <see langword="null"/> for failures raised before any API call was reached —
/// a malformed policy, say. <see cref="Remediation"/> holds an actionable hint
/// whenever the failure has one.
/// </para>
/// <para>
/// <see cref="NativeCode"/> is non-null only when <see cref="Operation"/> is: a
/// status with no call to attribute it to is not something the native layer can
/// express. <see cref="Remediation"/> carries no such coupling.
/// </para>
/// </remarks>
public sealed class MxcException : Exception
{
    /// <summary>The typed error code.</summary>
    public ErrorCode Code { get; }

    /// <summary>
    /// The API call that failed, namespaced by its interface and free of call
    /// parameters, so it can be grouped in telemetry. <see langword="null"/>
    /// when no API call was in flight.
    /// </summary>
    public string? Operation { get; }

    /// <summary>
    /// The underlying platform status, for example <c>0x80070490</c>.
    /// <see langword="null"/> unless <see cref="Operation"/> is set.
    /// </summary>
    public string? NativeCode { get; }

    /// <summary>
    /// An actionable hint for the caller, when the failure carries one.
    /// <see langword="null"/> otherwise.
    /// </summary>
    public string? Remediation { get; }

    /// <summary>Create an exception with the given code and message.</summary>
    public MxcException(ErrorCode code, string message)
        : this(code, message, null, null, null)
    {
    }

    /// <summary>
    /// Create an exception carrying the failing API call alongside the code and
    /// message.
    /// </summary>
    /// <remarks>
    /// Deliberately <see langword="internal"/>: keeping the overload internal is
    /// what makes the documented implication — a native code implies an
    /// operation — hold by construction rather than by convention. A public
    /// overload taking three independent nullable strings would let a caller
    /// build the state the documentation says cannot exist, and
    /// <see cref="ToString"/> would then silently drop the status.
    /// </remarks>
    internal MxcException(
        ErrorCode code,
        string message,
        string? operation,
        string? nativeCode,
        string? remediation)
        : base(message)
    {
        Code = code;
        Operation = operation;
        NativeCode = nativeCode;
        Remediation = remediation;
    }

    /// <inheritdoc/>
    /// <remarks>
    /// Appends the operation and status when present, so a caller that only
    /// logs the exception keeps the diagnosis rather than losing it.
    /// </remarks>
    public override string ToString()
    {
        if (Operation is null)
        {
            return $"{Code}: {Message}";
        }

        return NativeCode is null
            ? $"{Code}: {Message} [{Operation}]"
            : $"{Code}: {Message} [{Operation} {NativeCode}]";
    }
}
