// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// captureDenials C# reference consumer - end-to-end demo.
//
// Drives wxc-exec directly (no SDK) and receives the denial stream live over an
// anonymous pipe whose inheritable write handle is passed to wxc-exec via the
// --denials-fd flag. See docs/learning-mode/consumer-guide.md for the full
// integration contract.
//
//   dotnet run --project MxcDenialConsumer -- <wxc-exec.exe> <config.json>
//
// The config must set "captureDenials": true (see the consumer guide §3).

using System.Diagnostics;
using Microsoft.Mxc.Samples.DenialConsumer;

if (args.Length < 2)
{
    Console.Error.WriteLine("usage: MxcDenialConsumer <path-to-wxc-exec.exe> <path-to-config.json>");
    return 2;
}

string wxcExecPath = args[0];
string configPath = args[1];

// 1) Construct the consumer FIRST. This creates the anonymous pipe and its
//    inheritable write handle, ready to hand to wxc-exec.
using var consumer = new DenialPipeConsumer(applyDefaultFilters: true);

// React to denials live, the moment each one happens. An app such as Copilot
// would surface this to the user / queue a broadened policy for the next run.
consumer.DenialReceived += d =>
{
    string when = DateTimeOffset.FromFileTime((long)d.Filetime).ToLocalTime().ToString("HH:mm:ss");
    Console.WriteLine($"  [blocked {when}] {d.AccessType,-7} {DenialFilters.StripNtPrefix(d.Path)} (pid {d.Pid})");
};

consumer.SummaryReceived += s =>
{
    Console.WriteLine(
        $"  [summary] exit={s.ExitCode} unique={s.TotalDenials} active={s.CaptureDenialsActive} " +
        $"truncated={s.DeniedResourcesTruncated} descendants={s.DescendantPidsCovered}");
};

// 2) Spawn wxc-exec, passing the inherited write handle via --denials-fd.
//    RedirectStandardError forces .NET to start the child with handle
//    inheritance enabled (bInheritHandles=TRUE), so the inheritable client
//    handle crosses into wxc-exec at the same numeric value.
var psi = new ProcessStartInfo
{
    FileName = wxcExecPath,
    UseShellExecute = false,
    RedirectStandardError = true,
};
psi.ArgumentList.Add(configPath);
psi.ArgumentList.Add("--denials-fd");
psi.ArgumentList.Add(consumer.ClientHandle);

Console.WriteLine($"spawning: {wxcExecPath} {configPath} --denials-fd {consumer.ClientHandle}");
Console.WriteLine();

using var child = Process.Start(psi)
    ?? throw new InvalidOperationException($"failed to start {wxcExecPath}");

// 3) Release our copy of the inheritable write handle now that the child holds
//    it, so the read end observes EOF once the child exits.
consumer.DisposeLocalCopyOfClientHandle();

// 4) Drain wxc-exec's stderr so it can never block, and begin reading denials.
Task<string> stderrTask = child.StandardError.ReadToEndAsync();
using var cts = new CancellationTokenSource();
Task consumeTask = consumer.RunAsync(cts.Token);

await child.WaitForExitAsync();

// 5) Give trailing bytes a brief grace to flush, then release the consumer.
//    If wxc-exec fell back to stderr (handle could not be adopted), no summary
//    will arrive and the cancellation releases the pending read.
try
{
    using var grace = new CancellationTokenSource(TimeSpan.FromSeconds(2));

    // Wait for either the stream to end naturally (summary + EOF) or the grace
    // period to elapse.
    Task finished = await Task.WhenAny(consumeTask, Task.Delay(Timeout.Infinite, grace.Token));
    if (finished != consumeTask)
    {
        cts.Cancel();
    }
}
catch (OperationCanceledException)
{
    cts.Cancel();
}

await consumeTask;
string stderr = await stderrTask;

Console.WriteLine();
if (consumer.FinalSummary is { } summary)
{
    Console.WriteLine(
        summary.CaptureDenialsActive
            ? $"done: workload exited {summary.ExitCode}, {summary.TotalDenials} denial(s) captured."
            : "done: capture was NOT active (is MxcLearningModeShim installed and running?).");
}
else
{
    // No summary over the pipe: either captureDenials was not enabled, or
    // wxc-exec fell back to stderr. Surface wxc-exec's stderr in that case.
    Console.WriteLine(
        "done: no denial summary arrived over the pipe. " +
        "Check that the config sets captureDenials:true and inspect wxc-exec stderr for a fallback warning.");
    if (!string.IsNullOrWhiteSpace(stderr))
    {
        Console.Error.WriteLine("--- wxc-exec stderr ---");
        Console.Error.WriteLine(stderr);
    }
}

return child.ExitCode;
