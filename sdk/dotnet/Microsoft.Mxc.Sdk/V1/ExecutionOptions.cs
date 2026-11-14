// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace Microsoft.Mxc.Sdk.V1;

/// <summary>Invocation controls for Run and RunAsync.</summary>
public sealed class RunOptions
{
    /// <summary>Compatibility preference; does not control Required telemetry.</summary>
    public TelemetryConfig? Telemetry { get; set; }
}

/// <summary>Invocation controls for Spawn and SpawnAsync.</summary>
public sealed class SpawnOptions
{
    /// <summary>Compatibility preference; does not control Required telemetry.</summary>
    public TelemetryConfig? Telemetry { get; set; }
}

/// <summary>Invocation controls for spawning a caller-controlled terminal.</summary>
public sealed class SpawnWithPtyOptions
{
    /// <summary>Compatibility preference; does not control Required telemetry.</summary>
    public TelemetryConfig? Telemetry { get; set; }

    /// <summary>Optional initial terminal dimensions; defaults to 24 rows by 80 columns.</summary>
    public MxcPtySize? Size { get; set; }
}

/// <summary>How SpawnWithExtendedOptions connects the workload's standard streams.</summary>
public enum SpawnStdio
{
    /// <summary>New pipes the caller reads and writes through <see cref="MxcProcess"/>, as with Spawn.</summary>
    Pipes = 0,

    /// <summary>The calling process's own standard input, output, and error.</summary>
    Inherit = 1,
}

/// <summary>Invocation controls for SpawnWithExtendedOptions.</summary>
public sealed class SpawnExtendedOptions
{
    /// <summary>Per-invocation telemetry opt-in, subject to consent and policy.</summary>
    public TelemetryConfig? Telemetry { get; set; }

    /// <summary>How the workload's standard streams are connected; defaults to <see cref="SpawnStdio.Pipes"/>.</summary>
    public SpawnStdio Stdio { get; set; }
}

/// <summary>Invocation controls for spawning a workload in an existing container.</summary>
public sealed class SpawnInContainerOptions
{
    /// <summary>Optional telemetry preference, overriding the request when supplied.</summary>
    public TelemetryConfig? Telemetry { get; set; }
}

/// <summary>Invocation controls for captured execution in an existing container.</summary>
public sealed class RunInContainerOptions
{
    /// <summary>Optional telemetry preference, overriding the request when supplied.</summary>
    public TelemetryConfig? Telemetry { get; set; }
}

/// <summary>Invocation controls for a terminal in an existing container.</summary>
public sealed class SpawnInContainerWithPtyOptions
{
    /// <summary>Optional telemetry preference, overriding the request when supplied.</summary>
    public TelemetryConfig? Telemetry { get; set; }

    /// <summary>Optional initial terminal dimensions; defaults to 24 rows by 80 columns.</summary>
    public MxcPtySize? Size { get; set; }
}
