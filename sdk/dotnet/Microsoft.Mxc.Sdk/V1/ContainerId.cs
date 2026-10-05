// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Text.Json.Serialization;

namespace Microsoft.Mxc.Sdk.V1;

/// <summary>
/// An opaque container identity minted by
/// <see cref="MxcLifecycle.ProvisionContainer"/>. Carries the backend prefix (e.g.
/// <c>iso:</c>, <c>wsb:</c>, or <c>wslc:</c>) the later phases resolve the
/// backend from. Treat it as opaque.
/// </summary>
public readonly struct ContainerId : IEquatable<ContainerId>
{
    /// <summary>The wire-format identifier string.</summary>
    public string Value { get; }

    /// <summary>Wrap a raw identifier string (e.g. one persisted between calls).</summary>
    /// <exception cref="ArgumentException"><paramref name="value"/> is null or empty.</exception>
    [JsonConstructor]
    public ContainerId(string value)
    {
        if (string.IsNullOrEmpty(value))
        {
            throw new ArgumentException("container id must be a non-empty string", nameof(value));
        }
        Value = value;
    }

    /// <inheritdoc/>
    public bool Equals(ContainerId other) => string.Equals(Value, other.Value, StringComparison.Ordinal);

    /// <inheritdoc/>
    public override bool Equals(object? obj) => obj is ContainerId other && Equals(other);

    /// <inheritdoc/>
    public override int GetHashCode() => Value is null ? 0 : Value.GetHashCode(StringComparison.Ordinal);

    /// <inheritdoc/>
    public override string ToString() => Value ?? string.Empty;

    /// <summary>Equality operator.</summary>
    public static bool operator ==(ContainerId left, ContainerId right) => left.Equals(right);

    /// <summary>Inequality operator.</summary>
    public static bool operator !=(ContainerId left, ContainerId right) => !left.Equals(right);
}
