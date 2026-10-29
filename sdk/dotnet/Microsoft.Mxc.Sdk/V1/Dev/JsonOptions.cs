// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace Microsoft.Mxc.Sdk.V1.Dev;

/// <summary>Invocation controls for caller-authored exact JSON.</summary>
public sealed class JsonOptions
{
    /// <summary>Authorize experimental backends independently of the JSON version.</summary>
    public bool Experimental { get; set; }
}

/// <summary>Invocation controls for caller-authored exact JSON with a PTY.</summary>
public sealed class PtyJsonOptions
{
    /// <summary>Authorize experimental backends independently of the JSON version.</summary>
    public bool Experimental { get; set; }

    /// <summary>Initial terminal dimensions; defaults to 24 rows by 80 columns.</summary>
    public MxcPtySize? Size { get; set; }
}
