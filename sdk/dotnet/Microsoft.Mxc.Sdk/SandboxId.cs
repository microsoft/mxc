// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace Microsoft.Mxc.Sdk;

/// <summary>
/// A state-aware sandbox identifier minted by
/// <see cref="MxcLifecycle.ProvisionSandbox"/>. Carries the backend prefix (e.g.
/// <c>iso:</c>) the later phases resolve the backend from. Treat it as opaque.
/// </summary>
public readonly struct SandboxId : IEquatable<SandboxId>
{
    /// <summary>The wire-format identifier string.</summary>
    public string Value { get; }

    /// <summary>Wrap a raw identifier string (e.g. one persisted between calls).</summary>
    /// <exception cref="ArgumentException"><paramref name="value"/> is null or empty.</exception>
    public SandboxId(string value)
    {
        if (string.IsNullOrEmpty(value))
        {
            throw new ArgumentException("sandbox id must be a non-empty string", nameof(value));
        }
        Value = value;
    }

    /// <inheritdoc/>
    public bool Equals(SandboxId other) => string.Equals(Value, other.Value, StringComparison.Ordinal);

    /// <inheritdoc/>
    public override bool Equals(object? obj) => obj is SandboxId other && Equals(other);

    /// <inheritdoc/>
    public override int GetHashCode() => Value is null ? 0 : Value.GetHashCode(StringComparison.Ordinal);

    /// <inheritdoc/>
    public override string ToString() => Value ?? string.Empty;

    /// <summary>Equality operator.</summary>
    public static bool operator ==(SandboxId left, SandboxId right) => left.Equals(right);

    /// <summary>Inequality operator.</summary>
    public static bool operator !=(SandboxId left, SandboxId right) => !left.Equals(right);
}
