// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Linq;
using System.Reflection;
using Microsoft.Mxc.Sdk;
using Xunit;

namespace Microsoft.Mxc.Sdk.Tests;

/// <summary>
/// The structured failure detail: how it is carried, and how it renders.
/// </summary>
/// <remarks>
/// The populated path is exercised here directly rather than through a native
/// call, because the native layer only fills these fields when a real platform
/// API fails — which needs a prepared host and a backend. What the native tests
/// below pin is the other half: that an error with no API behind it marshals as
/// <see langword="null"/> rather than as an empty string.
/// </remarks>
public class MxcExceptionTests
{
    [Fact]
    public void OnlyTheCodeAndMessageConstructorIsPublic()
    {
        // The invariant fix is a single `internal` modifier on the structured
        // constructor, and this assembly can see internals — so every other test
        // here compiles whether that modifier says `internal` or `public`.
        // Without this check, widening it back would restore the original defect
        // (a NativeCode with no Operation, which ToString silently drops) with a
        // completely green suite.
        var publicConstructors = typeof(MxcException)
            .GetConstructors(BindingFlags.Public | BindingFlags.Instance);

        var signatures = publicConstructors
            .Select(c => string.Join(", ", c.GetParameters().Select(p => p.ParameterType.Name)))
            .ToArray();

        Assert.Equal(
            new[] { $"{nameof(ErrorCode)}, {nameof(String)}" },
            signatures);
    }

    [Fact]
    public void ApiDetail_IsCarriedAlongsideTheCodeAndMessage()
    {
        var ex = new MxcException(
            ErrorCode.BackendError,
            "The provision was not found.",
            "IsoSessionOps.StopSessionAsync",
            "0x80070490",
            "Provision the session first.");

        Assert.Equal(ErrorCode.BackendError, ex.Code);
        Assert.Equal("The provision was not found.", ex.Message);
        Assert.Equal("IsoSessionOps.StopSessionAsync", ex.Operation);
        Assert.Equal("0x80070490", ex.NativeCode);
        Assert.Equal("Provision the session first.", ex.Remediation);
    }

    [Fact]
    public void WithoutApiDetail_TheCallFieldsAreNull()
    {
        var ex = new MxcException(ErrorCode.MalformedRequest, "bad json");

        Assert.Null(ex.Operation);
        Assert.Null(ex.NativeCode);
        Assert.Null(ex.Remediation);
    }

    [Fact]
    public void ToString_KeepsTheOperationAndStatusVisible()
    {
        var full = new MxcException(
            ErrorCode.BackendError,
            "The provision was not found.",
            "IsoSessionOps.StopSessionAsync",
            "0x80070490",
            null);
        Assert.Equal(
            "BackendError: The provision was not found. [IsoSessionOps.StopSessionAsync 0x80070490]",
            full.ToString());

        // An operation with no status renders without a dangling separator.
        var operationOnly = new MxcException(
            ErrorCode.BackendError, "nope", "Iface.Call", null, null);
        Assert.Equal("BackendError: nope [Iface.Call]", operationOnly.ToString());

        // No detail at all renders exactly as it did before this surface existed.
        var bare = new MxcException(ErrorCode.MalformedRequest, "bad");
        Assert.Equal("MalformedRequest: bad", bare.ToString());
    }

    [Fact]
    public void NativeFailureWithNoApiCall_MarshalsAbsentFieldsAsNull()
    {
        // A version-less policy is rejected by the native parser before any
        // backend API is reached, so the detail crosses with a message and
        // nothing else. Null rather than empty is the point: it is how a caller
        // tells "the API supplied no status" from "it supplied an empty one".
        var policy = new SandboxPolicy { Version = string.Empty };

        var ex = Assert.Throws<MxcException>(() => MxcSandbox.Run(policy, "echo hi"));

        Assert.Equal(ErrorCode.MalformedRequest, ex.Code);
        Assert.False(string.IsNullOrEmpty(ex.Message));
        Assert.Null(ex.Operation);
        Assert.Null(ex.NativeCode);
        Assert.Null(ex.Remediation);
    }

    [Fact]
    public void NativeSpawnFailure_AlsoMarshalsThroughTheSharedShape()
    {
        // The streaming entry point fills a caller-provided detail rather than
        // returning one inside a result struct; this pins that the same shape
        // reaches the caller by that route too.
        var policy = new SandboxPolicy { Version = string.Empty };

        var ex = Assert.Throws<MxcException>(() => MxcSandbox.Spawn(policy, "echo hi"));

        Assert.Equal(ErrorCode.MalformedRequest, ex.Code);
        Assert.False(string.IsNullOrEmpty(ex.Message));
        Assert.Null(ex.Operation);
    }
}
