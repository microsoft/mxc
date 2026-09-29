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
    private static readonly IntPtr HwndMessage = new IntPtr(-3);

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

    private static bool TryReadText(out string value)
    {
        value = null;
        IntPtr owner = CreateClipboardOwner();
        if (owner == IntPtr.Zero)
        {
            return false;
        }

        if (!OpenClipboard(owner))
        {
            Console.Error.WriteLine("OpenClipboard for read failed: {0}", Marshal.GetLastWin32Error());
            Thread.Sleep(100);
            DestroyWindow(owner);
            return false;
        }

        IntPtr memory = GetClipboardData(CfUnicodeText);
        if (memory == IntPtr.Zero)
        {
            Console.Error.WriteLine("GetClipboardData failed: {0}", Marshal.GetLastWin32Error());
            Thread.Sleep(100);
            CloseClipboard();
            DestroyWindow(owner);
            return false;
        }

        IntPtr text = GlobalLock(memory);
        if (text == IntPtr.Zero)
        {
            Console.Error.WriteLine("GlobalLock for read failed: {0}", Marshal.GetLastWin32Error());
            Thread.Sleep(100);
            CloseClipboard();
            DestroyWindow(owner);
            return false;
        }

        value = Marshal.PtrToStringUni(text);
        GlobalUnlock(memory);
        CloseClipboard();
        DestroyWindow(owner);
        return true;
    }

    private static bool TryWriteText(string value)
    {
        IntPtr owner = CreateClipboardOwner();
        if (owner == IntPtr.Zero)
        {
            return false;
        }

        byte[] bytes = Encoding.Unicode.GetBytes(value + "\0");
        IntPtr memory = GlobalAlloc(GmemMoveable, (UIntPtr)bytes.Length);
        if (memory == IntPtr.Zero)
        {
            Console.Error.WriteLine("GlobalAlloc failed: {0}", Marshal.GetLastWin32Error());
            Thread.Sleep(100);
            DestroyWindow(owner);
            return false;
        }

        IntPtr text = GlobalLock(memory);
        if (text == IntPtr.Zero)
        {
            Console.Error.WriteLine("GlobalLock for write failed: {0}", Marshal.GetLastWin32Error());
            Thread.Sleep(100);
            GlobalFree(memory);
            DestroyWindow(owner);
            return false;
        }

        Marshal.Copy(bytes, 0, text, bytes.Length);
        GlobalUnlock(memory);

        if (!OpenClipboard(owner))
        {
            Console.Error.WriteLine("OpenClipboard for write failed: {0}", Marshal.GetLastWin32Error());
            Thread.Sleep(100);
            GlobalFree(memory);
            DestroyWindow(owner);
            return false;
        }

        if (!EmptyClipboard())
        {
            Console.Error.WriteLine("EmptyClipboard failed: {0}", Marshal.GetLastWin32Error());
            Thread.Sleep(100);
            CloseClipboard();
            GlobalFree(memory);
            DestroyWindow(owner);
            return false;
        }

        IntPtr result = SetClipboardData(CfUnicodeText, memory);
        int setError = result == IntPtr.Zero ? Marshal.GetLastWin32Error() : 0;
        CloseClipboard();
        DestroyWindow(owner);
        if (result == IntPtr.Zero)
        {
            Console.Error.WriteLine("SetClipboardData failed: {0}", setError);
            Thread.Sleep(100);
            GlobalFree(memory);
            return false;
        }

        return true;
    }

    private static int Main(string[] args)
    {
        if (args.Length == 2 && args[0] == "write")
        {
            return TryWriteText(args[1]) ? 0 : 2;
        }

        if (args.Length == 2 && args[0] == "matches")
        {
            string value;
            return TryReadText(out value) && value == args[1] ? 0 : 1;
        }

        if (args.Length == 3 && args[0] == "sandbox")
        {
            string value;
            bool readAllowed = TryReadText(out value) && value == args[1];
            bool writeAllowed = TryWriteText(args[2]);
            Console.WriteLine("READCLIPBOARD={0}", readAllowed ? "allowed" : "blocked");
            Console.WriteLine("WRITECLIPBOARD={0}", writeAllowed ? "allowed" : "blocked");
            return 0;
        }

        Console.Error.WriteLine("Usage: ClipboardProbe write <text> | matches <text> | sandbox <read-token> <write-token>");
        return 64;
    }
}
