// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace Microsoft.Mxc.Sdk.V1.Dev;

/// <summary>Invocation controls for preparing caller-authored MXC request JSON.</summary>
public sealed class PolicyPreparationOptions
{
    /// <summary>Authorize experimental backends independently of the JSON version.</summary>
    public bool Experimental { get; set; }
}
