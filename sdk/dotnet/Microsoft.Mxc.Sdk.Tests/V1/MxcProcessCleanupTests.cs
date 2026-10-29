// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Runtime.InteropServices;
using Microsoft.Mxc.Sdk.Native;
using Microsoft.Mxc.Sdk.V1;
using Xunit;
using NativeSandbox = Microsoft.Mxc.Sdk.Native.MxcSandbox;

namespace Microsoft.Mxc.Sdk.Tests.V1;

/// <summary>
/// Drives <see cref="MxcProcess"/> over a test-support native sandbox whose
/// native wait and output the test holds open.
/// </summary>
public sealed class MxcProcessCleanupTests
{
    private static readonly TimeSpan Prompt = TimeSpan.FromSeconds(5);

    [Fact]
    public async Task ADisposeDuringCleanupDoesNotHoldTheWaitOnOutputThatStaysOpen()
    {
        using var fake = FakeSandbox.Create(exitCode: 3, heldStdout: true);
        var wait = fake.Process.WaitAsync(TestContext.Current.CancellationToken);
        fake.AssertCleanupStarted();

        await AssertCompletesWithinAsync(Task.Run(fake.Process.Dispose, TestContext.Current.CancellationToken), Prompt, "Dispose waited for the cleanup");
        fake.ReleaseWait();

        await AssertCompletesWithinAsync(wait, TimeSpan.FromSeconds(10), "the wait waited for output that is still open");
        Assert.Equal(3, (await wait).ExitCode);
    }

    [Fact]
    public async Task CancellingAWaitDuringCleanupReturnsAtOnceAndALaterWaitGetsTheResult()
    {
        using var fake = FakeSandbox.Create(exitCode: 5);
        using var cancel = new CancellationTokenSource();
        var cancelled = fake.Process.WaitAsync(cancel.Token);
        fake.AssertCleanupStarted();

        cancel.Cancel();

        var cancelledEarly = await Task.WhenAny(cancelled, Task.Delay(Prompt, TestContext.Current.CancellationToken)) == cancelled;
        Assert.True(cancelledEarly, "the cancelled wait waited for the cleanup");
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => cancelled);
        var wait = fake.Process.WaitAsync(TestContext.Current.CancellationToken);
        fake.ReleaseWait();
        await AssertCompletesWithinAsync(wait, Prompt, "the later wait did not return the result");
        Assert.Equal(5, (await wait).ExitCode);
    }

    [Fact]
    public async Task ControlDuringCleanupOfAnExitedProcessDoesNotWaitForIt()
    {
        using var fake = FakeSandbox.Create(exitCode: 6);
        var wait = fake.Process.WaitAsync(TestContext.Current.CancellationToken);
        fake.AssertCleanupStarted();

        await AssertCompletesWithinAsync(Task.Run(fake.Process.Kill, TestContext.Current.CancellationToken), Prompt, "Kill waited for the cleanup");
        var warnings = await CompletesWithinAsync(() => fake.Process.Warnings, "Warnings waited for the cleanup");
        Assert.Equal(new[] { "fake warning" }, warnings);
        var metadata = await CompletesWithinAsync(() => fake.Process.OutputMetadata, "OutputMetadata waited for the cleanup");
        Assert.Null(metadata);
        var exited = await CompletesWithinAsync(() => (fake.Process.TryGetExitCode(out var code), code), "TryGetExitCode waited for the cleanup");
        Assert.Equal((true, 6), exited);

        fake.ReleaseWait();
        await AssertCompletesWithinAsync(wait, Prompt, "the wait did not finish");
        Assert.False((await wait).TimedOut);
    }

    [Fact]
    public async Task ControlDuringCleanupAfterATimeoutKillDoesNotWaitForIt()
    {
        using var fake = FakeSandbox.Create(exitCode: 137, exited: false, timeoutMs: 200);
        var wait = fake.Process.WaitAsync(TestContext.Current.CancellationToken);
        fake.AssertCleanupStarted();

        using var cancel = new CancellationTokenSource();
        var cancelled = fake.Process.WaitAsync(cancel.Token);
        cancel.Cancel();
        var cancelledEarly = await Task.WhenAny(cancelled, Task.Delay(Prompt, TestContext.Current.CancellationToken)) == cancelled;
        Assert.True(cancelledEarly, "the cancelled wait waited for the cleanup");
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => cancelled);
        await AssertCompletesWithinAsync(Task.Run(fake.Process.Kill, TestContext.Current.CancellationToken), Prompt, "Kill waited for the cleanup");
        await CompletesWithinAsync(() => fake.Process.Warnings, "Warnings waited for the cleanup");
        var exited = await CompletesWithinAsync(() => fake.Process.TryGetExitCode(out _), "TryGetExitCode waited for the cleanup");
        Assert.False(exited, "an exit code was reported for a process killed at its timeout before its cleanup finished");
        await AssertCompletesWithinAsync(Task.Run(fake.Process.Dispose, TestContext.Current.CancellationToken), Prompt, "Dispose waited for the cleanup");

        fake.ReleaseWait();
        await AssertCompletesWithinAsync(wait, Prompt, "the wait did not finish");
        Assert.True((await wait).TimedOut);
    }

    private static async Task<T> CompletesWithinAsync<T>(Func<T> read, string message)
    {
        var task = Task.Run(read, TestContext.Current.CancellationToken);
        await AssertCompletesWithinAsync(task, Prompt, message);
        return await task;
    }

    private static async Task AssertCompletesWithinAsync(Task task, TimeSpan limit, string message)
    {
        var finished = await Task.WhenAny(task, Task.Delay(limit, TestContext.Current.CancellationToken));
        Assert.True(finished == task, message);
        await task;
    }

    private sealed unsafe class FakeSandbox : IDisposable
    {
        private static readonly IntPtr Library = LoadLibrary();

        private static readonly delegate* unmanaged<int, int, int, NativeSandbox**, IntPtr*, int> New =
            (delegate* unmanaged<int, int, int, NativeSandbox**, IntPtr*, int>)Export("mxc_test_fake_sandbox_new");

        private static readonly delegate* unmanaged<IntPtr, uint, int> AwaitWait =
            (delegate* unmanaged<IntPtr, uint, int>)Export("mxc_test_fake_control_await_wait");

        private static readonly delegate* unmanaged<IntPtr, void> ReleaseWaitExport =
            (delegate* unmanaged<IntPtr, void>)Export("mxc_test_fake_control_release_wait");

        private static readonly delegate* unmanaged<IntPtr, void> ReleaseOutputExport =
            (delegate* unmanaged<IntPtr, void>)Export("mxc_test_fake_control_release_output");

        private static readonly delegate* unmanaged<IntPtr, void> FreeControl =
            (delegate* unmanaged<IntPtr, void>)Export("mxc_test_fake_control_free");

        private readonly IntPtr _control;

        private FakeSandbox(MxcProcess process, IntPtr control)
        {
            Process = process;
            _control = control;
        }

        public MxcProcess Process { get; }

        public static FakeSandbox Create(int exitCode, bool exited = true, bool heldStdout = false, uint? timeoutMs = null)
        {
            NativeSandbox* sandbox = null;
            IntPtr control = IntPtr.Zero;
            Assert.Equal(0, New(exitCode, exited ? 1 : 0, heldStdout ? 1 : 0, &sandbox, &control));
            return new FakeSandbox(new MxcProcess(MxcSandboxHandle.FromRaw(sandbox), timeoutMs), control);
        }

        public void AssertCleanupStarted() =>
            Assert.True(AwaitWait(_control, 10_000) != 0, "the wait never started the native cleanup");

        public void ReleaseWait() => ReleaseWaitExport(_control);

        public void Dispose()
        {
            ReleaseWaitExport(_control);
            ReleaseOutputExport(_control);
            Process.Dispose();
            FreeControl(_control);
        }

        // Loaded through the SDK's resolver, so the fake and the SDK share one native module.
        private static IntPtr LoadLibrary()
        {
            NativeLibraryResolver.Initialize();
            return NativeLibrary.Load("mxc_ffi", typeof(MxcProcess).Assembly, null);
        }

        private static IntPtr Export(string name) => NativeLibrary.GetExport(Library, name);
    }
}
