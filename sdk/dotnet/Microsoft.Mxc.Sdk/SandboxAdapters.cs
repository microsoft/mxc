// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace Microsoft.Mxc.Sdk;

/// <summary>
/// Injectable one-shot sandbox operations. Use <see cref="MxcSandboxRunner.Default"/>
/// in production and substitute a fake or mock in unit tests.
/// </summary>
public interface ISandboxRunner
{
    /// <summary>The loaded native MXC library version.</summary>
    string NativeVersion { get; }

    /// <summary>Probe every containment backend the current host can run.</summary>
    IReadOnlyList<AvailableBackend> GetAvailableBackends();

    /// <summary>Probe the containment backends the public SDK can launch.</summary>
    PlatformSupport GetPlatformSupport();

    /// <summary>Run a policy and command to completion.</summary>
    RunResult Run(SandboxPolicy policy, string command);

    /// <summary>Run a complete request to completion.</summary>
    RunResult Run(SandboxRequest request);

    /// <summary>Run a policy and command asynchronously.</summary>
    Task<RunResult> RunAsync(
        SandboxPolicy policy,
        string command,
        CancellationToken cancellationToken = default);

    /// <summary>Run a complete request asynchronously.</summary>
    Task<RunResult> RunAsync(
        SandboxRequest request,
        CancellationToken cancellationToken = default);

    /// <summary>Spawn a policy and command with live standard streams.</summary>
    ISandboxProcess Spawn(SandboxPolicy policy, string command);

    /// <summary>Spawn a complete request with live standard streams.</summary>
    ISandboxProcess Spawn(SandboxRequest request);
}

/// <summary>
/// Stateless <see cref="ISandboxRunner"/> adapter over <see cref="MxcSandbox"/>.
/// </summary>
public sealed class MxcSandboxRunner : ISandboxRunner
{
    /// <summary>Shared production adapter.</summary>
    public static MxcSandboxRunner Default { get; } = new();

    /// <inheritdoc/>
    public string NativeVersion => MxcSandbox.NativeVersion;

    /// <inheritdoc/>
    public IReadOnlyList<AvailableBackend> GetAvailableBackends() =>
        MxcSandbox.GetAvailableBackends();

    /// <inheritdoc/>
    public PlatformSupport GetPlatformSupport() =>
        MxcSandbox.GetPlatformSupport();

    /// <inheritdoc/>
    public RunResult Run(SandboxPolicy policy, string command) =>
        MxcSandbox.Run(policy, command);

    /// <inheritdoc/>
    public RunResult Run(SandboxRequest request) =>
        MxcSandbox.Run(request);

    /// <inheritdoc/>
    public Task<RunResult> RunAsync(
        SandboxPolicy policy,
        string command,
        CancellationToken cancellationToken = default) =>
        MxcSandbox.RunAsync(policy, command, cancellationToken);

    /// <inheritdoc/>
    public Task<RunResult> RunAsync(
        SandboxRequest request,
        CancellationToken cancellationToken = default) =>
        MxcSandbox.RunAsync(request, cancellationToken);

    /// <inheritdoc/>
    public ISandboxProcess Spawn(SandboxPolicy policy, string command) =>
        MxcSandbox.Spawn(policy, command);

    /// <inheritdoc/>
    public ISandboxProcess Spawn(SandboxRequest request) =>
        MxcSandbox.Spawn(request);
}

/// <summary>
/// Injectable state-aware sandbox lifecycle operations. Use
/// <see cref="MxcSandboxLifecycle.Default"/> in production and substitute a fake
/// or mock in unit tests.
/// </summary>
public interface ISandboxLifecycle
{
    /// <summary>Provision a new sandbox.</summary>
    ProvisionResult ProvisionSandbox(
        StateAwareContainment containment,
        StateAwareProvisionOptions? options = null);

    /// <summary>Validate a provision request without allocating a sandbox.</summary>
    void DryRunProvisionSandbox(
        StateAwareContainment containment,
        StateAwareProvisionOptions? options = null);

    /// <summary>Start a provisioned sandbox.</summary>
    void StartSandbox(SandboxId id, StateAwarePhaseOptions? options = null);

    /// <summary>Validate a start request without starting the sandbox.</summary>
    void DryRunStartSandbox(SandboxId id, StateAwarePhaseOptions? options = null);

    /// <summary>Execute with live standard streams.</summary>
    ISandboxProcess ExecInSandbox(
        SandboxId id,
        string command,
        StateAwareExecOptions? options = null);

    /// <summary>Execute attached to this process's terminal.</summary>
    SandboxWaitResult ExecInSandboxAttached(
        SandboxId id,
        string command,
        StateAwareExecOptions? options = null);

    /// <summary>Validate an exec request without starting a process.</summary>
    void DryRunExecInSandbox(
        SandboxId id,
        string command,
        StateAwareExecOptions? options = null);

    /// <summary>Execute to completion and capture output.</summary>
    Task<RunResult> ExecInSandboxAsync(
        SandboxId id,
        string command,
        CancellationToken cancellationToken = default);

    /// <summary>Execute with process options to completion and capture output.</summary>
    Task<RunResult> ExecInSandboxAsync(
        SandboxId id,
        string command,
        StateAwareExecOptions? options,
        CancellationToken cancellationToken = default);

    /// <summary>Stop a running sandbox.</summary>
    void StopSandbox(SandboxId id, StateAwarePhaseOptions? options = null);

    /// <summary>Validate a stop request without stopping the sandbox.</summary>
    void DryRunStopSandbox(SandboxId id, StateAwarePhaseOptions? options = null);

    /// <summary>Destroy a sandbox and release its resources.</summary>
    void DeprovisionSandbox(SandboxId id, StateAwarePhaseOptions? options = null);

    /// <summary>Validate a deprovision request without destroying the sandbox.</summary>
    void DryRunDeprovisionSandbox(
        SandboxId id,
        StateAwarePhaseOptions? options = null);
}

/// <summary>
/// Stateless <see cref="ISandboxLifecycle"/> adapter over
/// <see cref="MxcLifecycle"/>.
/// </summary>
public sealed class MxcSandboxLifecycle : ISandboxLifecycle
{
    /// <summary>Shared production adapter.</summary>
    public static MxcSandboxLifecycle Default { get; } = new();

    /// <inheritdoc/>
    public ProvisionResult ProvisionSandbox(
        StateAwareContainment containment,
        StateAwareProvisionOptions? options = null) =>
        MxcLifecycle.ProvisionSandbox(containment, options);

    /// <inheritdoc/>
    public void DryRunProvisionSandbox(
        StateAwareContainment containment,
        StateAwareProvisionOptions? options = null) =>
        MxcLifecycle.DryRunProvisionSandbox(containment, options);

    /// <inheritdoc/>
    public void StartSandbox(SandboxId id, StateAwarePhaseOptions? options = null) =>
        MxcLifecycle.StartSandbox(id, options);

    /// <inheritdoc/>
    public void DryRunStartSandbox(SandboxId id, StateAwarePhaseOptions? options = null) =>
        MxcLifecycle.DryRunStartSandbox(id, options);

    /// <inheritdoc/>
    public ISandboxProcess ExecInSandbox(
        SandboxId id,
        string command,
        StateAwareExecOptions? options = null) =>
        MxcLifecycle.ExecInSandbox(id, command, options);

    /// <inheritdoc/>
    public SandboxWaitResult ExecInSandboxAttached(
        SandboxId id,
        string command,
        StateAwareExecOptions? options = null) =>
        MxcLifecycle.ExecInSandboxAttached(id, command, options);

    /// <inheritdoc/>
    public void DryRunExecInSandbox(
        SandboxId id,
        string command,
        StateAwareExecOptions? options = null) =>
        MxcLifecycle.DryRunExecInSandbox(id, command, options);

    /// <inheritdoc/>
    public Task<RunResult> ExecInSandboxAsync(
        SandboxId id,
        string command,
        CancellationToken cancellationToken = default) =>
        MxcLifecycle.ExecInSandboxAsync(id, command, cancellationToken);

    /// <inheritdoc/>
    public Task<RunResult> ExecInSandboxAsync(
        SandboxId id,
        string command,
        StateAwareExecOptions? options,
        CancellationToken cancellationToken = default) =>
        MxcLifecycle.ExecInSandboxAsync(id, command, options, cancellationToken);

    /// <inheritdoc/>
    public void StopSandbox(SandboxId id, StateAwarePhaseOptions? options = null) =>
        MxcLifecycle.StopSandbox(id, options);

    /// <inheritdoc/>
    public void DryRunStopSandbox(SandboxId id, StateAwarePhaseOptions? options = null) =>
        MxcLifecycle.DryRunStopSandbox(id, options);

    /// <inheritdoc/>
    public void DeprovisionSandbox(
        SandboxId id,
        StateAwarePhaseOptions? options = null) =>
        MxcLifecycle.DeprovisionSandbox(id, options);

    /// <inheritdoc/>
    public void DryRunDeprovisionSandbox(
        SandboxId id,
        StateAwarePhaseOptions? options = null) =>
        MxcLifecycle.DryRunDeprovisionSandbox(id, options);
}
