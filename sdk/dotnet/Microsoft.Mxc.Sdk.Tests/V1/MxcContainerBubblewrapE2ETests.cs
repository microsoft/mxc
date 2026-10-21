// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Runtime.ExceptionServices;
using System.Text;
using Microsoft.Mxc.Sdk.V1;
using Xunit;

namespace Microsoft.Mxc.Sdk.Tests.V1;

public class MxcContainerBubblewrapE2ETests
{
    [Fact]
    public void Spawn_OutlivesTheThreadThatSpawnedIt()
    {
        // `bwrap --die-with-parent` arms PR_SET_PDEATHSIG, which Linux fires
        // when the *thread* that forked bwrap exits. A caller that spawns on a
        // thread-pool or short-lived thread and waits elsewhere must not have
        // the sandbox killed when that thread exits.
        BubblewrapHost.Require();

        MxcProcess? proc = null;
        StreamReader? stdout = null;
        ExceptionDispatchInfo? failure = null;
        var spawner = new Thread(() =>
        {
            try
            {
                proc = MxcContainer.Spawn(new ContainerRequest("echo ready; sleep 1; echo survived")
                {
                    Containment = new Containment.Bubblewrap(),
                    Filesystem = new FilesystemPolicy { ReadwritePaths = ["/tmp"] },
                    TimeoutMs = 30_000,
                });
                stdout = new StreamReader(proc.StandardOutput!, Encoding.UTF8);
                // The workload is running, so bwrap has armed its parent-death signal.
                Assert.Equal("ready", stdout.ReadLine());
            }
            catch (Exception ex)
            {
                failure = ExceptionDispatchInfo.Capture(ex);
            }
        });
        spawner.Start();
        spawner.Join();
        failure?.Throw();

        using (proc)
        using (stdout)
        {
            Assert.Equal("survived", stdout!.ReadToEnd().Trim());
            var result = proc!.Wait();
            Assert.False(result.TimedOut);
            Assert.Equal(0, result.ExitCode);
        }
    }
}
