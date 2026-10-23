// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

internal static class FinalPathProbe
{
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFinalPathNameByHandleW(
        SafeFileHandle file, StringBuilder path, uint length, uint flags);

    private static string GetPath(SafeFileHandle file, uint flags)
    {
        var path = new StringBuilder(256);
        while (true)
        {
            uint length = GetFinalPathNameByHandleW(file, path, (uint)path.Capacity, flags);
            if (length == 0)
                throw new Win32Exception(Marshal.GetLastWin32Error());
            if (length < path.Capacity)
                return path.ToString();
            if (length > 32768)
                throw new IOException("Final path exceeds the Windows extended-path limit.");
            path.Capacity = checked((int)length + 1);
        }
    }

    public static int Main(string[] args)
    {
        if (args.Length != 1)
        {
            Console.Error.WriteLine("Usage: final-path-probe.exe <existing-file>");
            return 2;
        }

        int failures = 0;
        using (var file = new FileStream(args[0], FileMode.Open, FileAccess.Read,
            FileShare.ReadWrite | FileShare.Delete))
        {
            foreach (uint flags in new uint[] { 0, 2 })
            {
                string name = flags == 0 ? "VOLUME_NAME_DOS" : "VOLUME_NAME_NT";
                try
                {
                    Console.WriteLine(name + ": " + GetPath(file.SafeFileHandle, flags));
                }
                catch (Win32Exception error)
                {
                    Console.Error.WriteLine(name + " error: " + error.Message);
                    failures++;
                }
            }
        }
        return failures == 0 ? 0 : 1;
    }
}
