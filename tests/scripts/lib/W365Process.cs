// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Mxc.W365Manual
{
    public sealed class ChildResult
    {
        public int ExitCode;
        public string Stdout;
        public string Stderr;
        public string Failure;
    }

    public static class ChildProcess
    {
        private static async Task<string> Drain(Stream source, Stream destination, CancellationToken token)
        {
            using (var capture = new MemoryStream())
            {
                var buffer = new byte[16384];
                int count;
                while ((count = await source.ReadAsync(buffer, 0, buffer.Length, token).ConfigureAwait(false)) != 0)
                {
                    if (destination != null)
                    {
                        await destination.WriteAsync(buffer, 0, count, token).ConfigureAwait(false);
                        await destination.FlushAsync(token).ConfigureAwait(false);
                    }
                    else
                    {
                        if (capture.Length + count > 1048576)
                            throw new IOException("capture_limit");
                        capture.Write(buffer, 0, count);
                    }
                }
                return destination == null ? Encoding.UTF8.GetString(capture.ToArray()) : null;
            }
        }

        public static ChildResult Run(ProcessStartInfo start, int timeoutMs, bool stream)
        {
            start.UseShellExecute = false;
            start.RedirectStandardInput = true;
            start.RedirectStandardOutput = true;
            start.RedirectStandardError = true;
            using (var process = new Process { StartInfo = start })
            using (var cancel = new CancellationTokenSource())
            {
                var result = new ChildResult { ExitCode = -1 };
                Task<string[]> drains = null;
                try
                {
                    if (!process.Start())
                        throw new IOException("start_failed");
                    process.StandardInput.Close();
                    var stdout = Drain(process.StandardOutput.BaseStream,
                        stream ? Console.OpenStandardOutput() : null, cancel.Token);
                    var stderr = Drain(process.StandardError.BaseStream,
                        stream ? Console.OpenStandardError() : null, cancel.Token);
                    drains = Task.WhenAll(stdout, stderr);
                    var clock = Stopwatch.StartNew();
                    while (!process.WaitForExit(50))
                    {
                        if (stdout.IsFaulted || stderr.IsFaulted)
                        {
                            result.Failure = "output_failed";
                            break;
                        }
                        if (clock.ElapsedMilliseconds >= timeoutMs)
                        {
                            result.Failure = "client_deadline_outcome_unknown";
                            break;
                        }
                    }
                    if (result.Failure == null)
                    {
                        result.ExitCode = process.ExitCode;
                        if (!drains.Wait(5000))
                            result.Failure = "output_drain_outcome_unknown";
                        else
                        {
                            result.Stdout = stdout.GetAwaiter().GetResult();
                            result.Stderr = stderr.GetAwaiter().GetResult();
                        }
                    }
                }
                catch (Exception)
                {
                    // This is a private process boundary; never return exception
                    // text that could include token-bearing auth output.
                    result.Failure = "child_transport_outcome_unknown";
                }
                finally
                {
                    cancel.Cancel();
                    if (result.Failure != null)
                    {
                        try
                        {
                            if (!process.HasExited)
                            {
                                process.Kill(true);
                                if (!process.WaitForExit(5000))
                                    result.Failure += "_local_cleanup_failed";
                            }
                        }
                        catch (Exception) { result.Failure += "_local_cleanup_failed"; }
                    }
                    if (drains != null && !drains.IsCompleted)
                    {
                        process.StandardOutput.Close();
                        process.StandardError.Close();
                        try
                        {
                            if (!drains.Wait(1000))
                                result.Failure = (result.Failure ?? "output_failed") + "_worker_cleanup_failed";
                        }
                        catch (AggregateException)
                        {
                            // Cancellation/closed pipes are expected on this path.
                            if (result.Failure == null)
                                result.Failure = "output_failed";
                        }
                    }
                    if (drains != null && drains.IsFaulted)
                    {
                        // Observe all worker faults before disposing the process.
                        var observed = drains.Exception;
                    }
                }
                return result;
            }
        }
    }
}
