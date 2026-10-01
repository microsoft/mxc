// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

internal static class ClipboardProbe
{
    private const uint CfUnicodeText = 13;
    private const uint GmemMoveable = 0x0002;
    private const int ErrorAccessDenied = 5;
    private static readonly IntPtr HwndMessage = new IntPtr(-3);

    private enum ProbeResult
    {
        Allowed,
        Blocked,
        Inconclusive
    }

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateWindowEx(
        uint extendedStyle,
        string className,
        string windowName,
        uint style,
        int x,
        int y,
        int width,
        int height,
        IntPtr parent,
        IntPtr menu,
        IntPtr instance,
        IntPtr parameter);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool DestroyWindow(IntPtr window);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool OpenClipboard(IntPtr owner);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool CloseClipboard();

    [DllImport("user32.dll", SetLastError = true)]
    private static extern IntPtr GetClipboardData(uint format);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool EmptyClipboard();

    [DllImport("user32.dll", SetLastError = true)]
    private static extern IntPtr SetClipboardData(uint format, IntPtr memory);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr GlobalAlloc(uint flags, UIntPtr bytes);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr GlobalLock(IntPtr memory);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GlobalUnlock(IntPtr memory);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr GlobalFree(IntPtr memory);

    [DllImport("kernel32.dll")]
    private static extern void SetLastError(uint error);

    private static IntPtr CreateClipboardOwner()
    {
        IntPtr owner = CreateWindowEx(
            0,
            "STATIC",
            "MxcIssue1246ClipboardProbe",
            0,
            0,
            0,
            0,
            0,
            HwndMessage,
            IntPtr.Zero,
            IntPtr.Zero,
            IntPtr.Zero);
        if (owner == IntPtr.Zero)
        {
            Console.Error.WriteLine("CreateWindowEx failed: {0}", Marshal.GetLastWin32Error());
        }

        return owner;
    }

    private static ProbeResult ProbeReadText(out string value)
    {
        value = null;
        IntPtr owner = CreateClipboardOwner();
        if (owner == IntPtr.Zero)
        {
            return ProbeResult.Inconclusive;
        }

        if (!OpenClipboard(owner))
        {
            Console.Error.WriteLine("OpenClipboard for read failed: {0}", Marshal.GetLastWin32Error());
            Thread.Sleep(100);
            DestroyWindow(owner);
            return ProbeResult.Inconclusive;
        }

        SetLastError(0);
        IntPtr memory = GetClipboardData(CfUnicodeText);
        if (memory == IntPtr.Zero)
        {
            int error = Marshal.GetLastWin32Error();
            CloseClipboard();
            DestroyWindow(owner);
            if (error == ErrorAccessDenied)
            {
                Console.Error.WriteLine("GetClipboardData was denied: {0}", error);
                Thread.Sleep(100);
                return ProbeResult.Blocked;
            }

            if (error == 0)
            {
                return ProbeResult.Allowed;
            }

            Console.Error.WriteLine("GetClipboardData failed: {0}", error);
            Thread.Sleep(100);
            return ProbeResult.Inconclusive;
        }

        IntPtr text = GlobalLock(memory);
        if (text == IntPtr.Zero)
        {
            Console.Error.WriteLine("GlobalLock for read failed: {0}", Marshal.GetLastWin32Error());
            Thread.Sleep(100);
            CloseClipboard();
            DestroyWindow(owner);
            return ProbeResult.Inconclusive;
        }

        value = Marshal.PtrToStringUni(text);
        GlobalUnlock(memory);
        CloseClipboard();
        DestroyWindow(owner);
        return ProbeResult.Allowed;
    }

    private static ProbeResult ProbeWriteText(string value)
    {
        IntPtr owner = CreateClipboardOwner();
        if (owner == IntPtr.Zero)
        {
            return ProbeResult.Inconclusive;
        }

        byte[] bytes = Encoding.Unicode.GetBytes(value + "\0");
        IntPtr memory = GlobalAlloc(GmemMoveable, (UIntPtr)bytes.Length);
        if (memory == IntPtr.Zero)
        {
            Console.Error.WriteLine("GlobalAlloc failed: {0}", Marshal.GetLastWin32Error());
            Thread.Sleep(100);
            DestroyWindow(owner);
            return ProbeResult.Inconclusive;
        }

        IntPtr text = GlobalLock(memory);
        if (text == IntPtr.Zero)
        {
            Console.Error.WriteLine("GlobalLock for write failed: {0}", Marshal.GetLastWin32Error());
            Thread.Sleep(100);
            GlobalFree(memory);
            DestroyWindow(owner);
            return ProbeResult.Inconclusive;
        }

        Marshal.Copy(bytes, 0, text, bytes.Length);
        GlobalUnlock(memory);

        if (!OpenClipboard(owner))
        {
            Console.Error.WriteLine("OpenClipboard for write failed: {0}", Marshal.GetLastWin32Error());
            Thread.Sleep(100);
            GlobalFree(memory);
            DestroyWindow(owner);
            return ProbeResult.Inconclusive;
        }

        SetLastError(0);
        if (!EmptyClipboard())
        {
            int error = Marshal.GetLastWin32Error();
            Console.Error.WriteLine("EmptyClipboard failed: {0}", error);
            Thread.Sleep(100);
            CloseClipboard();
            GlobalFree(memory);
            DestroyWindow(owner);
            return error == ErrorAccessDenied ? ProbeResult.Blocked : ProbeResult.Inconclusive;
        }

        SetLastError(0);
        IntPtr result = SetClipboardData(CfUnicodeText, memory);
        int setError = result == IntPtr.Zero ? Marshal.GetLastWin32Error() : 0;
        CloseClipboard();
        DestroyWindow(owner);
        if (result == IntPtr.Zero)
        {
            Console.Error.WriteLine("SetClipboardData failed: {0}", setError);
            Thread.Sleep(100);
            GlobalFree(memory);
            return setError == ErrorAccessDenied ? ProbeResult.Blocked : ProbeResult.Inconclusive;
        }

        return ProbeResult.Allowed;
    }

    private static string FormatResult(ProbeResult result)
    {
        return result.ToString().ToLowerInvariant();
    }

    private static int Main(string[] args)
    {
        if (args.Length == 2 && args[0] == "write")
        {
            ProbeResult result = ProbeWriteText(args[1]);
            return result == ProbeResult.Allowed ? 0 : result == ProbeResult.Blocked ? 1 : 2;
        }

        if (args.Length == 2 && args[0] == "matches")
        {
            string value;
            ProbeResult result = ProbeReadText(out value);
            if (result != ProbeResult.Allowed)
            {
                return 2;
            }

            return result == ProbeResult.Allowed && value == args[1] ? 0 : 1;
        }

        if (args.Length == 3 && args[0] == "sandbox")
        {
            string value;
            ProbeResult readResult = ProbeReadText(out value);
            if (readResult == ProbeResult.Allowed && value != args[1])
            {
                Console.Error.WriteLine("Clipboard read returned an unexpected value.");
                readResult = ProbeResult.Inconclusive;
            }

            ProbeResult writeResult = ProbeWriteText(args[2]);
            Console.WriteLine("READCLIPBOARD={0}", FormatResult(readResult));
            Console.WriteLine("WRITECLIPBOARD={0}", FormatResult(writeResult));
            return readResult == ProbeResult.Inconclusive || writeResult == ProbeResult.Inconclusive ? 2 : 0;
        }

        Console.Error.WriteLine("Usage: ClipboardProbe write <text> | matches <text> | sandbox <read-token> <write-token>");
        return 64;
    }
}
