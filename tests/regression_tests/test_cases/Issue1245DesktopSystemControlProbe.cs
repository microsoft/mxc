// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;

internal static class Program
{
    private const uint DesktopCreateWindow = 0x0002;
    private const int ErrorAccessDenied = 5;
    private const uint EwxForceIfHung = 0x0010;
    private const uint EwxLogoff = 0x0000;
    private const uint GenericAll = 0x10000000;

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateDesktopW(
        string desktop,
        IntPtr device,
        IntPtr devMode,
        uint flags,
        uint desiredAccess,
        IntPtr securityAttributes);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool CloseDesktop(IntPtr desktop);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool ExitWindowsEx(uint flags, uint reason);

    public static int Main()
    {
        string name = "mxc_issue_1245_" + Process.GetCurrentProcess().Id;
        IntPtr desktop = CreateDesktopW(
            name,
            IntPtr.Zero,
            IntPtr.Zero,
            0,
            DesktopCreateWindow | GenericAll,
            IntPtr.Zero);

        if (desktop == IntPtr.Zero)
        {
            int error = Marshal.GetLastWin32Error();
            Console.WriteLine("CREATE_DESKTOP=blocked win32Error=" + error + " message=" + new Win32Exception(error).Message);
            if (error != ErrorAccessDenied)
            {
                return 1;
            }
        }
        else
        {
            CloseDesktop(desktop);
            Console.WriteLine("CREATE_DESKTOP=allowed");
            Console.WriteLine("EXIT_WINDOWS=not-attempted safety=CreateDesktopW-was-allowed");
            return 2;
        }

        // Only attempt logoff after CreateDesktopW has already demonstrated
        // that this environment is denying desktop-system-control operations.
        bool logoffAccepted = ExitWindowsEx(EwxLogoff | EwxForceIfHung, 0);
        int logoffError = Marshal.GetLastWin32Error();
        if (logoffAccepted)
        {
            Console.WriteLine("EXIT_WINDOWS=allowed");
            return 1;
        }

        Console.WriteLine("EXIT_WINDOWS=blocked win32Error=" + logoffError + " message=" + new Win32Exception(logoffError).Message);
        return logoffError == ErrorAccessDenied ? 0 : 1;
    }
}
