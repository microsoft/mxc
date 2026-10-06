// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace Microsoft.Mxc.Sdk.V1;

/// <summary>Invocation controls for Run and RunAsync.</summary>
public sealed class RunOptions
{
    /// <summary>Authorize runtime-gated experimental features.</summary>
    public bool Experimental { get; set; }

    /// <summary>Per-invocation telemetry opt-in, subject to consent and policy.</summary>
    public TelemetryConfig? Telemetry { get; set; }
}

/// <summary>Invocation controls for Spawn and SpawnAsync.</summary>
public sealed class SpawnOptions
{
    /// <summary>Authorize runtime-gated experimental features.</summary>
    public bool Experimental { get; set; }

    /// <summary>Per-invocation telemetry opt-in, subject to consent and policy.</summary>
    public TelemetryConfig? Telemetry { get; set; }
}

/// <summary>Invocation controls for spawning a caller-controlled terminal.</summary>
public sealed class SpawnWithPtyOptions
{
    /// <summary>Authorize runtime-gated experimental features.</summary>
    public bool Experimental { get; set; }

    /// <summary>Per-invocation telemetry opt-in, subject to consent and policy.</summary>
    public TelemetryConfig? Telemetry { get; set; }

    /// <summary>Optional initial terminal dimensions; defaults to 24 rows by 80 columns.</summary>
    public MxcPtySize? Size { get; set; }
}

/// <summary>Invocation controls for spawning a workload in an existing container.</summary>
public sealed class SpawnInContainerOptions
{
    /// <summary>Authorize runtime-gated experimental features.</summary>
    public bool Experimental { get; set; }

    /// <summary>Optional telemetry preference, overriding the request when supplied.</summary>
    public TelemetryConfig? Telemetry { get; set; }
}

/// <summary>Invocation controls for captured execution in an existing container.</summary>
public sealed class RunInContainerOptions
{
    /// <summary>Authorize runtime-gated experimental features.</summary>
    public bool Experimental { get; set; }

    /// <summary>Optional telemetry preference, overriding the request when supplied.</summary>
    public TelemetryConfig? Telemetry { get; set; }
}

/// <summary>Invocation controls for a terminal in an existing container.</summary>
public sealed class SpawnInContainerWithPtyOptions
{
    /// <summary>Authorize runtime-gated experimental features.</summary>
    public bool Experimental { get; set; }

    /// <summary>Optional telemetry preference, overriding the request when supplied.</summary>
    public TelemetryConfig? Telemetry { get; set; }

    /// <summary>Optional initial terminal dimensions; defaults to 24 rows by 80 columns.</summary>
    public MxcPtySize? Size { get; set; }
}
