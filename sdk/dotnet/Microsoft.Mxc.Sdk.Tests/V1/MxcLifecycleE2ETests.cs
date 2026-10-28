// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Text.Json;
using System.Text;
using Microsoft.Mxc.Sdk;
using Microsoft.Mxc.Sdk.V1;
using Microsoft.Mxc.Sdk.Tests;
using Xunit;
using Dev = Microsoft.Mxc.Sdk.V1.Dev;

namespace Microsoft.Mxc.Sdk.Tests.V1;

/// <summary>
/// Drives the state-aware lifecycle against a live IsolationSession host, which
/// needs Windows, the OS-side service, and a native library built with the
/// isolation_session feature.
/// </summary>
/// <remarks>
/// These establish that the lifecycle works end to end through this binding
/// rather than only through the engine: the identity and workspace that
/// provision reports, and the output and exit code an exec returns.
/// </remarks>
[Collection("MxcLiveHost")]
public class MxcLifecycleE2ETests
{
    private const string Cmd = @"C:\Windows\System32\cmd.exe";

    [Fact]
    public async Task DevJson_LifecyclePreservesResponsesExecutionAndCallerOwnership()
    {
        IsolationSessionHost.Require();
        const string provision = """
            {
                "version":"1.1.0-alpha","phase":"provision","containment":"isolation_session",
                "network":{
                    "egress":{"default":"allow"},
                    "ingress":{"default":"allow","hostLoopback":"allow"}
                }
            }
            """;
        static void AssertEmptyResult(string json)
        {
            using var response = JsonDocument.Parse(json);
            Assert.Empty(response.RootElement.GetProperty("result").EnumerateObject());
        }
        AssertEmptyResult(await Dev.MxcLifecycle.ValidateProvisionJsonAsync(provision));
        using var provisioned = JsonDocument.Parse(
            await Dev.MxcLifecycle.ProvisionContainerJsonAsync(provision));
        var result = provisioned.RootElement.GetProperty("result");
        var id = result.GetProperty("sandboxId").GetString();
        Assert.False(string.IsNullOrEmpty(id));
        using var teardown = new Teardown(new ContainerId(id!));
        var metadata = result.GetProperty("metadata");
        Assert.False(string.IsNullOrEmpty(metadata.GetProperty("agentUserName").GetString()));
        Assert.False(string.IsNullOrEmpty(metadata.GetProperty("agentUserSid").GetString()));
        var workspace = metadata.GetProperty("ephemeralWorkspacePath").GetString()!;
        Assert.True(Directory.Exists(workspace));

        string Phase(string phase) =>
            $$$"""{"version":"1.0.0","phase":"{{{phase}}}","sandboxId":"{{{JsonEncodedText.Encode(id!)}}}"}""";
        string Exec(string command) =>
            $$$"""{"version":"1.1.0-alpha","phase":"exec","sandboxId":"{{{JsonEncodedText.Encode(id!)}}}","process":{"commandLine":"{{{JsonEncodedText.Encode(command)}}}","timeout":30000}}""";

        AssertEmptyResult(Dev.MxcLifecycle.ValidateStartJson(Phase("start")));
        AssertEmptyResult(Dev.MxcLifecycle.StartContainerJson(
            Phase("start"), new Dev.JsonOptions { Experimental = true }));
        var validationFile = Path.Combine(workspace, "dev-must-not-run.txt");
        AssertEmptyResult(await Dev.MxcLifecycle.ValidateProcessJsonAsync(
            Exec($"echo MUST_NOT_RUN> \"{validationFile}\"")));
        Assert.False(File.Exists(validationFile));
        var captured = await Dev.MxcLifecycle.RunInContainerJsonAsync(
            Exec("echo DEV_EXEC_OUT & echo DEV_EXEC_ERR 1>&2 & exit /b 7"),
            cancellationToken: TestContext.Current.CancellationToken);
        Assert.False(captured.TimedOut);
        Assert.Equal(7, captured.ExitCode);
        Assert.Contains("DEV_EXEC_OUT", captured.Stdout);
        Assert.Contains("DEV_EXEC_ERR", captured.Stderr);

        using (var pipe = Dev.MxcLifecycle.SpawnInContainerJson(
            Exec("cmd.exe /v:on /c \"set /p L= & echo DEV_PIPE:!L! & exit /b 9\"")))
        {
            using var stdin = pipe.StandardInput;
            Assert.NotNull(stdin);
            var output = pipe.WaitForExitWithOutputAsync(TestContext.Current.CancellationToken);
            await stdin.WriteAsync(Encoding.UTF8.GetBytes("ping-pong\r\n"),
                TestContext.Current.CancellationToken);
            stdin.Dispose();
            var (outcome, stdout, _) = await output;
            Assert.False(outcome.TimedOut);
            Assert.Equal(9, outcome.ExitCode);
            Assert.Contains("DEV_PIPE:ping-pong", Encoding.UTF8.GetString(stdout));
        }
        using (var terminal = Dev.MxcLifecycle.SpawnInContainerWithPtyJson(
            Exec("cmd.exe /q"), new Dev.PtyJsonOptions { Size = new MxcPtySize(30, 90) }))
        {
            using var reader = new StreamReader(terminal.Output, Encoding.UTF8);
            var output = reader.ReadToEndAsync(TestContext.Current.CancellationToken);
            terminal.Resize(new MxcPtySize(40, 100));
            await terminal.Input.WriteAsync(
                Encoding.UTF8.GetBytes("set MXC_DEV_MARK=OK\r\necho DEV_PTY_%MXC_DEV_MARK%\r\nexit /b 13\r\n"),
                TestContext.Current.CancellationToken);
            var outcome = await terminal.WaitAsync(TestContext.Current.CancellationToken);
            Assert.False(outcome.TimedOut);
            Assert.Equal(13, outcome.ExitCode);
            Assert.Contains("DEV_PTY_OK", await output);
        }
        AssertEmptyResult(Dev.MxcLifecycle.ValidateStopJson(Phase("stop")));
        var stillOwned = Dev.MxcLifecycle.RunInContainerJson(Exec("echo DEV_CALLER_OWNS_CONTAINER"));
        Assert.Equal(0, stillOwned.ExitCode);
        Assert.Contains("DEV_CALLER_OWNS_CONTAINER", stillOwned.Stdout);
        AssertEmptyResult(await Dev.MxcLifecycle.StopContainerJsonAsync(Phase("stop")));
        AssertEmptyResult(Dev.MxcLifecycle.ValidateDeprovisionJson(Phase("deprovision")));
        AssertEmptyResult(Dev.MxcLifecycle.DeprovisionContainerJson(Phase("deprovision")));
        teardown.Defuse();
        Assert.False(Directory.Exists(workspace));
        var stale = Assert.Throws<MxcException>(
            () => Dev.MxcLifecycle.StartContainerJson(Phase("start")));
        Assert.Equal(ErrorCode.StaleId, stale.Code);
    }

    /// <summary>
    /// Deprovisions a sandbox the test did not deprovision itself. Provision
    /// mints a real OS account, so an assertion that throws part-way would
    /// otherwise leave it on the host.
    /// </summary>
    private sealed class Teardown : IDisposable
    {
        private ContainerId? _id;

        public Teardown(ContainerId id) => _id = id;

        /// <summary>
        /// Gives up ownership once the test has deprovisioned itself.
        /// Deprovision is not idempotent, so without this the disposal below
        /// would report a failure that did not happen.
        /// </summary>
        public void Defuse() => _id = null;

        public void Dispose()
        {
            if (_id is not { } id)
            {
                return;
            }
            _id = null;
            try
            {
                MxcLifecycle.StopContainer(id);
            }
            catch (MxcException)
            {
                // A sandbox that never started, or already stopped, still has to
                // be deprovisioned — that is the step that frees the account.
            }
            try
            {
                MxcLifecycle.DeprovisionContainer(id);
            }
            catch (MxcException e)
            {
                Console.Error.WriteLine(
                    $"WARNING: deprovision failed, the agent account may leak: {e.Message}");
            }
        }
    }

    private sealed record Started(
        ContainerId Id, string AgentUserName, string WorkspacePath, Teardown Teardown);

    private static Started ProvisionAndStart()
    {
        var provisioned = MxcLifecycle.ProvisionContainer(
            new IsolationSessionProvisionRequest(
                new NetworkPolicy
                {
                    Egress = new NetworkEgressPolicy { Default = NetworkAction.Allow },
                    Ingress = new NetworkIngressPolicy
                    {
                        Default = NetworkAction.Allow,
                        HostLoopback = NetworkAction.Allow,
                    },
                })
            {
                AppId = null,
            });

        // Nothing asserts the id's shape: it is contractually opaque, and the
        // later phases accepting it is the proof.
        var teardown = new Teardown(provisioned.ContainerId);
        try
        {
            Assert.NotNull(provisioned.Warnings);
            var metadata = Assert.IsType<IsolationSessionProvisionMetadata>(provisioned.Metadata);
            var agentUserName = metadata.AgentUserName;
            Assert.False(
                string.IsNullOrEmpty(agentUserName),
                "provision metadata carried no agentUserName");
            var workspace = metadata.EphemeralWorkspacePath;
            Assert.False(
                string.IsNullOrEmpty(workspace),
                "provision metadata carried no ephemeralWorkspacePath");

            var started = MxcLifecycle.StartContainer(provisioned.ContainerId);
            Assert.NotNull(started.Warnings);
            return new Started(provisioned.ContainerId, agentUserName!, workspace!, teardown);
        }
        catch
        {
            teardown.Dispose();
            throw;
        }
    }

    /// <summary>Runs a command to completion and returns its stdout.</summary>
    private static async Task<string> ExecCapture(ContainerId id, string command)
    {
        var run = await MxcLifecycle.RunInContainerAsync(id, new ExecutionRequest(command));
        return run.Stdout;
    }

    /// <summary>The account part of a <c>whoami</c> line, which prints
    /// <c>machine\user</c>. Compared alone so the machine name cannot satisfy
    /// the assertion.</summary>
    private static string AccountOf(string whoamiOutput) =>
        whoamiOutput.Trim().Split('\\').Last().ToLowerInvariant();

    /// <summary>
    /// The metadata this binding surfaces must describe the sandbox its exec
    /// actually runs in. Asserting the agent user is also what stops the rest of
    /// this file passing against an unsandboxed process.
    /// </summary>
    [Fact]
    public async Task Exec_RunsAsTheAgentUserFromTheProvisionMetadata()
    {
        IsolationSessionHost.Require();

        var started = ProvisionAndStart();
        using (started.Teardown)
        {
            var run = await MxcLifecycle.RunInContainerAsync(
            started.Id,
            new ExecutionRequest($"{Cmd} /c whoami"),
            cancellationToken: TestContext.Current.CancellationToken);

            Assert.Equal(0, run.ExitCode);
            Assert.Equal(started.AgentUserName.ToLowerInvariant(), AccountOf(run.Stdout));
        }
    }

    /// <summary>The sandboxed process's exit code must reach the caller
    /// unchanged, through the streaming handle's wait.</summary>
    [Fact]
    public void Exec_PropagatesANonZeroExitCode()
    {
        IsolationSessionHost.Require();

        var started = ProvisionAndStart();
        using (started.Teardown)
        {
            using var proc = MxcLifecycle.SpawnInContainer(
                started.Id,
                new ExecutionRequest($"{Cmd} /c exit 42"));
            var result = proc.Wait();

            Assert.False(result.TimedOut);
            Assert.Equal(42, result.ExitCode);
        }
    }

    /// <summary>A lifecycle exec timeout must be reported by the streaming
    /// process wrapper just like a one-shot policy timeout.</summary>
    [Fact]
    public void Exec_ReportsConfiguredTimeout()
    {
        IsolationSessionHost.Require();

        var started = ProvisionAndStart();
        using (started.Teardown)
        {
            using var proc = MxcLifecycle.SpawnInContainer(
                started.Id,
                new ExecutionRequest($"{Cmd} /c ping -n 6 127.0.0.1 >nul")
                {
                    TimeoutMs = 100,
                });
            var result = proc.Wait();

            Assert.True(result.TimedOut);
        }
    }

    /// <summary>
    /// Stop and deprovision must be reachable through this binding, and a
    /// deprovisioned id must not still be usable.
    /// </summary>
    [Fact]
    public void Deprovision_RetiresTheSandboxId()
    {
        IsolationSessionHost.Require();

        var started = ProvisionAndStart();
        using (started.Teardown)
        {
            var stopped = MxcLifecycle.StopContainer(started.Id);
            Assert.NotNull(stopped.Warnings);
            var deprovisioned = MxcLifecycle.DeprovisionContainer(started.Id);
            started.Teardown.Defuse();
            Assert.NotNull(deprovisioned.Warnings);

            var ex = Assert.Throws<MxcException>(
                () => MxcLifecycle.StartContainer(started.Id));
            Assert.Equal(ErrorCode.StaleId, ex.Code);
        }
    }

    /// <summary>The lifecycle runs a command and its output reaches the caller.</summary>
    [Fact]
    public async Task Lifecycle_RunsEndToEnd()
    {
        IsolationSessionHost.Require();

        var started = ProvisionAndStart();
        using (started.Teardown)
        {
            var captured = await ExecCapture(started.Id, $"{Cmd} /c echo state-aware-marker");
            Assert.Contains("state-aware-marker", captured);
        }
    }

    /// <summary>
    /// The ephemeral workspace named in the provision metadata is readable and
    /// writable from both sides, and deprovision removes it.
    /// </summary>
    [Fact]
    public async Task Workspace_IsSharedWithTheAgent_AndRemovedOnDeprovision()
    {
        IsolationSessionHost.Require();

        var started = ProvisionAndStart();
        using (started.Teardown)
        {
            var workspace = started.WorkspacePath;
            Assert.True(
                Directory.Exists(workspace),
                $"provision reported a workspace that is not a directory: {workspace}");

            var nonce = $"nonce-{Environment.ProcessId}";
            File.WriteAllText(Path.Combine(workspace, "from-caller.txt"), nonce + "\r\n");

            // Copying the caller's file proves the agent read it; appending
            // whoami proves the agent wrote, and names who did.
            var command =
                $"{Cmd} /c type \"{workspace}\\from-caller.txt\" > \"{workspace}\\from-agent.txt\"" +
                $" & whoami >> \"{workspace}\\from-agent.txt\"";
            await ExecCapture(started.Id, command);

            var produced = File.ReadAllText(Path.Combine(workspace, "from-agent.txt"));
            Assert.Contains(nonce, produced);
            var lastLine = produced
                .Split('\n', StringSplitOptions.RemoveEmptyEntries)
                .Last();
            Assert.Equal(started.AgentUserName.ToLowerInvariant(), AccountOf(lastLine));

            MxcLifecycle.StopContainer(started.Id);
            MxcLifecycle.DeprovisionContainer(started.Id);
            started.Teardown.Defuse();

            Assert.False(
                Directory.Exists(workspace),
                $"deprovision returned but the workspace is still present: {workspace}");
        }
    }
}
