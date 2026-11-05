// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace Microsoft.Mxc.Sdk.V1.Dev;

/// <summary>Invocation controls for caller-authored MXC request JSON.</summary>
public sealed class JsonOptions
{
    /// <summary>Authorize experimental backends independently of the JSON version.</summary>
    public bool Experimental { get; set; }

    /// <summary>Caller-owned policy observations for RunJson and SpawnJson creation operations only.</summary>
    public PolicyFailures? PolicyFailures { get; set; }

    internal void RejectPolicyFailures(string operation)
    {
        if (PolicyFailures is not null)
        {
            throw new MxcException(ErrorCode.MalformedRequest,
                $"{operation} does not accept PolicyFailures; feedback is supported only by RunJson and SpawnJson creation operations");
        }
    }
}

/// <summary>Invocation controls for caller-authored MXC request JSON with a PTY.</summary>
public sealed class PtyJsonOptions
{
    /// <summary>Authorize experimental backends independently of the JSON version.</summary>
    public bool Experimental { get; set; }

    /// <summary>Initial terminal dimensions; defaults to 24 rows by 80 columns.</summary>
    public MxcPtySize? Size { get; set; }
}
