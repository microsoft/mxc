// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Diagnostics;
using System.IO;
using System.Threading;

internal static class NativeProcessCaptureProbe
{
    private static int Main(string[] args)
    {
        if (args.Length == 2 && args[0] == "--hold-output")
        {
            Console.WriteLine("descendant stdout");
            Console.Error.WriteLine("descendant stderr");
            File.WriteAllText(args[1], "ready");
            Thread.Sleep(20000);
            return 0;
        }

        if (args.Length < 3 || args[0] != "--log-file")
        {
            throw new ArgumentException("Expected --log-file <path> <scenario>.");
        }
        File.WriteAllText(args[1], "capture probe log");
        if (args[2] == "capture")
        {
            Console.Write("captured stdout");
            Console.Error.Write("captured stderr");
            return 7;
        }
        if (args[2] != "inherited-output" || args.Length != 4)
        {
            throw new ArgumentException("Unknown capture scenario.");
        }

        var readyPath = args[3] + ".ready";
        string executable;
        using (var current = Process.GetCurrentProcess())
        {
            executable = current.MainModule.FileName;
        }
        var start = new ProcessStartInfo(executable, "--hold-output \"" + readyPath + "\"")
        {
            UseShellExecute = false,
            CreateNoWindow = true
        };
        using (var child = Process.Start(start))
        {
            File.WriteAllText(args[3], child.Id.ToString());
            var deadline = Stopwatch.StartNew();
            while (!File.Exists(readyPath))
            {
                if (child.HasExited || deadline.Elapsed > TimeSpan.FromSeconds(5))
                {
                    throw new InvalidOperationException("Output-holding descendant did not become ready.");
                }
                Thread.Sleep(10);
            }
        }
        Console.WriteLine("executor exited");
        return 0;
    }
}
