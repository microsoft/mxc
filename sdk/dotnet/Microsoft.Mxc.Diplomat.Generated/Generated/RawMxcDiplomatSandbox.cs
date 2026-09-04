using System;
using System.Runtime.InteropServices;
using Microsoft.Mxc.Diplomat;
using Microsoft.Mxc.Diplomat.Diplomat;

namespace Microsoft.Mxc.Diplomat.Raw;

[StructLayout(LayoutKind.Sequential)]
internal partial struct MxcDiplomatSandbox
{

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "MxcDiplomatSandbox_take_stdin", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultMxcDiplomatInputStreamMxcDiplomatError TakeStdin(MxcDiplomatSandbox* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "MxcDiplomatSandbox_take_stdout", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultMxcDiplomatOutputStreamMxcDiplomatError TakeStdout(MxcDiplomatSandbox* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "MxcDiplomatSandbox_take_stderr", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultMxcDiplomatOutputStreamMxcDiplomatError TakeStderr(MxcDiplomatSandbox* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "MxcDiplomatSandbox_try_wait", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultMxcDiplomatPollResultMxcDiplomatError TryWait(MxcDiplomatSandbox* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "MxcDiplomatSandbox_wait", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultMxcDiplomatWaitResultMxcDiplomatError Wait(MxcDiplomatSandbox* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "MxcDiplomatSandbox_kill", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultVoidMxcDiplomatError Kill(MxcDiplomatSandbox* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "MxcDiplomatSandbox_destroy", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void Destroy(MxcDiplomatSandbox* handle);
}