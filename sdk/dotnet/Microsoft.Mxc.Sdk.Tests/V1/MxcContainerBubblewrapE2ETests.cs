// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Text;
using Microsoft.Mxc.Sdk.V1;
using Xunit;

namespace Microsoft.Mxc.Sdk.Tests.V1;

public class MxcContainerBubblewrapE2ETests
{
    private static readonly TimeSpan OperationTimeout = TimeSpan.FromSeconds(15);

    [Fact]
    public void Spawn_OutlivesTheThreadThatSpawnedIt()
    {
        BubblewrapHost.Require();

        var (proc, stdout, stdoutCloser) = SpawnOnShortLivedThread();
        var completed = false;
        try
        {
            Assert.Equal("survived", ReadToEndWithin(stdout, OperationTimeout).Trim());

            var result = proc.Wait();
            Assert.False(result.TimedOut);
            Assert.Equal(0, result.ExitCode);
            completed = true;
        }
        finally
        {
            Cleanup(proc, stdout, stdoutCloser, terminate: !completed);
        }
    }

    private static (MxcProcess Process, StreamReader Reader, MxcStreamCloser? Closer) SpawnOnShortLivedThread()
    {
        var completion = new TaskCompletionSource<(MxcProcess Process, StreamReader Reader, MxcStreamCloser? Closer)>(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var spawner = new Thread(() =>
        {
            MxcProcess? proc = null;
            StreamReader? stdout = null;
            MxcStreamCloser? stdoutCloser = null;
            var transferred = false;
            try
            {
                proc = MxcContainer.Spawn(
                    new ContainerRequest("echo ready; sleep 1; echo survived")
                    {
                        Containment = new Containment.Bubblewrap(),
                        Filesystem = new FilesystemPolicy { ReadwritePaths = ["/tmp"] },
                        TimeoutMs = 30_000,
                    });
                stdout = new StreamReader(proc.StandardOutput!, Encoding.UTF8);
                stdoutCloser = proc.StandardOutputCloser;
                Assert.Equal("ready", ReadLineWithin(stdout, OperationTimeout));
                transferred = completion.TrySetResult((proc, stdout, stdoutCloser));
            }
            catch (Exception ex)
            {
                completion.TrySetException(ex);
            }
            finally
            {
                if (!transferred && proc is not null)
                {
                    Cleanup(proc, stdout, stdoutCloser, terminate: true);
                }
            }
        })
        {
            IsBackground = true,
            Name = "mxc-bwrap-test-spawner",
        };
        spawner.Start();

        var completed = Task.WhenAny(completion.Task, Task.Delay(OperationTimeout))
            .GetAwaiter()
            .GetResult() == completion.Task;
        if (!completed)
        {
            if (!completion.TrySetCanceled() && completion.Task.IsCompletedSuccessfully)
            {
                var abandoned = completion.Task.GetAwaiter().GetResult();
                Cleanup(abandoned.Process, abandoned.Reader, abandoned.Closer, terminate: true);
            }
            throw new TimeoutException(
                $"Bubblewrap spawn thread did not finish within {OperationTimeout}.");
        }

        var result = completion.Task.GetAwaiter().GetResult();
        if (!spawner.Join(OperationTimeout))
        {
            Cleanup(result.Process, result.Reader, result.Closer, terminate: true);
            throw new TimeoutException(
                $"Bubblewrap spawn thread did not exit within {OperationTimeout}.");
        }
        return result;
    }

    private static void Cleanup(
        MxcProcess proc,
        StreamReader? stdout,
        MxcStreamCloser? stdoutCloser,
        bool terminate)
    {
        try
        {
            if (terminate)
            {
                stdoutCloser?.Close();
                proc.Kill();
            }
        }
        finally
        {
            proc.Dispose();
            stdoutCloser?.Dispose();
            stdout?.Dispose();
        }
    }

    private static string ReadLineWithin(StreamReader reader, TimeSpan timeout)
    {
        var read = Task.Run(reader.ReadLine);
        Assert.True(read.Wait(timeout), $"stdout did not produce its first line within {timeout}.");
        return read.GetAwaiter().GetResult() ?? string.Empty;
    }

    private static string ReadToEndWithin(StreamReader reader, TimeSpan timeout)
    {
        var read = Task.Run(reader.ReadToEnd);
        Assert.True(read.Wait(timeout), $"stdout did not reach EOF within {timeout}.");
        return read.GetAwaiter().GetResult();
    }
}
