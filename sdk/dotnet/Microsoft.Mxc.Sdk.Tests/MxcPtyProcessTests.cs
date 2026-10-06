// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.Mxc.Sdk;
using Microsoft.Mxc.Sdk.V1;
using Xunit;

namespace Microsoft.Mxc.Sdk.Tests;

public class MxcPtyProcessTests
{
    [Fact]
    public void DefaultSize_IsStandardTerminalSize()
    {
        Assert.Equal((ushort)24, MxcPtySize.Default.Rows);
        Assert.Equal((ushort)80, MxcPtySize.Default.Columns);
    }

    [Fact]
    public void SpawnWithPty_NullRequest_Throws()
    {
        Assert.Throws<ArgumentNullException>(
            () => MxcContainer.SpawnWithPty(null!));
    }

    [Fact]
    public void ContainerRequest_NullCommand_Throws()
    {
        Assert.Throws<ArgumentNullException>(
            () => new ContainerRequest(null!));
    }

    [Theory]
    [InlineData(0, 80)]
    [InlineData(24, 0)]
    [InlineData(32768, 80)]
    [InlineData(24, 32768)]
    public void SpawnWithPty_RejectsInvalidDimensionsBeforeNativeCall(
        ushort rows,
        ushort columns)
    {
        Assert.Throws<ArgumentOutOfRangeException>(
            () => MxcContainer.SpawnWithPty(
                new ContainerRequest("echo hi"),
                new SpawnWithPtyOptions
                {
                    Size = new MxcPtySize(rows, columns),
                }));
    }

    [Fact]
    public void PtyOptions_ResolveCustomAndDefaultInitialDimensions()
    {
        var size = new MxcPtySize(40, 120);
        var creation = new SpawnWithPtyOptions { Size = size };
        var existing = new SpawnInContainerWithPtyOptions { Size = size };

        Assert.Equal(size, MxcPtySize.ResolveInitial(creation.Size));
        Assert.Equal(size, MxcPtySize.ResolveInitial(existing.Size));
        Assert.Equal(MxcPtySize.Default, MxcPtySize.ResolveInitial(null));
    }
}
