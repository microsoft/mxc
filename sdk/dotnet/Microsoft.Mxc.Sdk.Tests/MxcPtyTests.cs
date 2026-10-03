// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.Mxc.Sdk;
using Microsoft.Mxc.Sdk.V1;
using Xunit;

namespace Microsoft.Mxc.Sdk.Tests;

public class MxcPtyTests
{
    [Fact]
    public void DefaultSize_IsStandardTerminalSize()
    {
        Assert.Equal((ushort)24, MxcPtySize.Default.Rows);
        Assert.Equal((ushort)80, MxcPtySize.Default.Columns);
    }

    [Fact]
    public void SpawnWithPty_NullPolicy_Throws()
    {
        Assert.Throws<ArgumentNullException>(
            () => MxcSandbox.SpawnWithPty(null!, "echo hi"));
    }

    [Fact]
    public void SpawnWithPty_NullCommand_Throws()
    {
        Assert.Throws<ArgumentNullException>(
            () => MxcSandbox.SpawnWithPty(new SandboxPolicy(), null!));
    }

    [Fact]
    public void SpawnWithPty_RejectsZeroDimensionsBeforeNativeCall()
    {
        Assert.Throws<ArgumentOutOfRangeException>(
            () => MxcSandbox.SpawnWithPty(
                new SandboxPolicy(),
                "echo hi",
                new MxcPtySize(0, 80)));
    }

    [Fact]
    public void PolicyCommandOverload_TargetsIsolationSession()
    {
        var request = MxcSandbox.CreatePtyCompatibilityRequest(
            new SandboxPolicy(),
            "echo hi");

        Assert.IsType<IsolationSessionContainment>(request.Containment);
    }
}
