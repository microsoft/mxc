// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Text.Json;
using Microsoft.Mxc.Sdk;
using Xunit;

namespace Microsoft.Mxc.Sdk.Tests;

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
public class MxcLifecycleE2ETests
{
    // Opt-in gate shared with the streaming E2E tests: a host that can really run
    // a sandbox sets MXC_E2E_HOST_PREPPED=1. Elsewhere these return early.
    private static bool HostRunsIsolationSession =>
        Environment.GetEnvironmentVariable("MXC_E2E_HOST_PREPPED") == "1"
        && OperatingSystem.IsWindows();

    private const string Cmd = @"C:\Windows\System32\cmd.exe";

    /// <summary>
    /// Deprovisions a sandbox the test did not deprovision itself. Provision
    /// mints a real OS account, so an assertion that throws part-way would
    /// otherwise leave it on the host.
    /// </summary>
    private sealed class Teardown : IDisposable
    {
        private SandboxId? _id;

        public Teardown(SandboxId id) => _id = id;

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
                MxcLifecycle.StopSandbox(id);
            }
            catch (MxcException)
            {
                // A sandbox that never started, or already stopped, still has to
                // be deprovisioned — that is the step that frees the account.
            }
            try
            {
                MxcLifecycle.DeprovisionSandbox(id);
            }
            catch (MxcException e)
            {
                Console.Error.WriteLine(
                    $"WARNING: deprovision failed, the agent account may leak: {e.Message}");
            }
        }
    }

    private sealed record Started(
        SandboxId Id, string AgentUserName, string WorkspacePath, Teardown Teardown);

    private static Started ProvisionAndStart()
    {
        var provisioned = MxcLifecycle.ProvisionSandbox(
            StateAwareContainment.IsolationSession,
            new ProvisionSandboxOptions
            {
                Network = new StateAwareNetworkPolicy
                {
                    DefaultPolicy = StateAwareNetworkDefault.Allow,
                    AllowLocalNetwork = true,
                },
            });

        // Nothing asserts the id's shape: it is contractually opaque, and the
        // later phases accepting it is the proof.
        var teardown = new Teardown(provisioned.SandboxId);
        try
        {
            var metadataJson = provisioned.MetadataJson;
            Assert.False(string.IsNullOrEmpty(metadataJson), "provision surfaced no metadata");

            using var doc = JsonDocument.Parse(metadataJson!);
            var agentUserName = doc.RootElement.GetProperty("agentUserName").GetString();
            Assert.False(
                string.IsNullOrEmpty(agentUserName),
                $"provision metadata carried no agentUserName: {metadataJson}");
            var workspace = doc.RootElement.GetProperty("ephemeralWorkspacePath").GetString();
            Assert.False(
                string.IsNullOrEmpty(workspace),
                $"provision metadata carried no ephemeralWorkspacePath: {metadataJson}");

            MxcLifecycle.StartSandbox(provisioned.SandboxId);
            return new Started(provisioned.SandboxId, agentUserName!, workspace!, teardown);
        }
        catch
        {
            teardown.Dispose();
            throw;
        }
    }

    /// <summary>Runs a command to completion and returns its stdout.</summary>
    private static async Task<string> ExecCapture(SandboxId id, string command)
    {
        var run = await MxcLifecycle.ExecInSandboxAsync(id, command);
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
        if (!HostRunsIsolationSession)
        {
            return; // skipped: no isolation-session host available
        }

        var started = ProvisionAndStart();
        using (started.Teardown)
        {
            var run = await MxcLifecycle.ExecInSandboxAsync(started.Id, $"{Cmd} /c whoami");

            Assert.Equal(0, run.ExitCode);
            Assert.Equal(started.AgentUserName.ToLowerInvariant(), AccountOf(run.Stdout));
        }
    }

    /// <summary>The sandboxed process's exit code must reach the caller
    /// unchanged, through the streaming handle's wait.</summary>
    [Fact]
    public void Exec_PropagatesANonZeroExitCode()
    {
        if (!HostRunsIsolationSession)
        {
            return; // skipped: no isolation-session host available
        }

        var started = ProvisionAndStart();
        using (started.Teardown)
        {
            using var proc = MxcLifecycle.ExecInSandbox(started.Id, $"{Cmd} /c exit 42");
            var result = proc.Wait();

            Assert.False(result.TimedOut);
            Assert.Equal(42, result.ExitCode);
        }
    }

    /// <summary>
    /// Stop and deprovision must be reachable through this binding, and a
    /// deprovisioned id must not still be usable.
    /// </summary>
    [Fact]
    public void Deprovision_RetiresTheSandboxId()
    {
        if (!HostRunsIsolationSession)
        {
            return; // skipped: no isolation-session host available
        }

        var started = ProvisionAndStart();
        using (started.Teardown)
        {
            MxcLifecycle.StopSandbox(started.Id);
            MxcLifecycle.DeprovisionSandbox(started.Id);
            started.Teardown.Defuse();

            var ex = Assert.Throws<MxcException>(
                () => MxcLifecycle.StartSandbox(started.Id));
            Assert.Equal(ErrorCode.StaleId, ex.Code);
        }
    }

    /// <summary>The lifecycle runs a command and its output reaches the caller.</summary>
    [Fact]
    public async Task Lifecycle_RunsEndToEnd()
    {
        if (!HostRunsIsolationSession)
        {
            return; // skipped: no isolation-session host available
        }

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
        if (!HostRunsIsolationSession)
        {
            return; // skipped: no isolation-session host available
        }

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

            MxcLifecycle.StopSandbox(started.Id);
            MxcLifecycle.DeprovisionSandbox(started.Id);
            started.Teardown.Defuse();

            Assert.False(
                Directory.Exists(workspace),
                $"deprovision returned but the workspace is still present: {workspace}");
        }
    }
}
