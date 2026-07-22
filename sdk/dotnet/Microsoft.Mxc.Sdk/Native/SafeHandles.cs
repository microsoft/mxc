// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Runtime.InteropServices;
using Microsoft.Mxc.Sdk.Native;
using NativeSandbox = Microsoft.Mxc.Sdk.Native.MxcSandbox;

namespace Microsoft.Mxc.Sdk;

/// <summary>
/// Owns a native <c>MxcSandbox*</c>. Releasing it calls <c>mxc_sandbox_free</c>,
/// which kills the child tree if still running. A <see cref="SafeHandle"/> so a
/// dropped-without-Dispose process is still reclaimed (and its child killed) by
/// the finalizer, and so a free can never race an in-flight native call (the
/// refcount defers the actual free).
/// </summary>
internal sealed class MxcSandboxHandle : SafeHandle
{
    private MxcSandboxHandle() : base(IntPtr.Zero, ownsHandle: true) { }

    public override bool IsInvalid => handle == IntPtr.Zero;

    internal static unsafe MxcSandboxHandle FromRaw(NativeSandbox* ptr)
    {
        var safe = new MxcSandboxHandle();
        safe.SetHandle((IntPtr)ptr);
        return safe;
    }

    internal unsafe NativeSandbox* Ptr => (NativeSandbox*)handle;

    protected override bool ReleaseHandle()
    {
        unsafe
        {
            NativeMethods.mxc_sandbox_free((NativeSandbox*)handle);
        }
        return true;
    }
}

/// <summary>
/// Owns a native <c>MxcReadStream*</c> (a child stdout/stderr pipe). Releasing
/// it calls <c>mxc_read_stream_free</c>. The refcount makes a concurrent read
/// and dispose safe: the free is deferred until no read holds a reference.
/// </summary>
internal sealed class MxcReadStreamHandle : SafeHandle
{
    private MxcReadStreamHandle() : base(IntPtr.Zero, ownsHandle: true) { }

    public override bool IsInvalid => handle == IntPtr.Zero;

    internal static unsafe MxcReadStreamHandle FromRaw(MxcReadStream* ptr)
    {
        var safe = new MxcReadStreamHandle();
        safe.SetHandle((IntPtr)ptr);
        return safe;
    }

    internal unsafe MxcReadStream* Ptr => (MxcReadStream*)handle;

    protected override bool ReleaseHandle()
    {
        unsafe
        {
            NativeMethods.mxc_read_stream_free((MxcReadStream*)handle);
        }
        return true;
    }
}

/// <summary>
/// Owns a native <c>MxcWriteStream*</c> (a child stdin pipe). Releasing it calls
/// <c>mxc_write_stream_free</c> (closing stdin, sending EOF). The refcount makes
/// a concurrent write and dispose safe.
/// </summary>
internal sealed class MxcWriteStreamHandle : SafeHandle
{
    private MxcWriteStreamHandle() : base(IntPtr.Zero, ownsHandle: true) { }

    public override bool IsInvalid => handle == IntPtr.Zero;

    internal static unsafe MxcWriteStreamHandle FromRaw(MxcWriteStream* ptr)
    {
        var safe = new MxcWriteStreamHandle();
        safe.SetHandle((IntPtr)ptr);
        return safe;
    }

    internal unsafe MxcWriteStream* Ptr => (MxcWriteStream*)handle;

    protected override bool ReleaseHandle()
    {
        unsafe
        {
            NativeMethods.mxc_write_stream_free((MxcWriteStream*)handle);
        }
        return true;
    }
}
