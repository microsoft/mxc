// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.Mxc.Sdk;

namespace Microsoft.Mxc.Sdk.V1;

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

    /// <summary>Run a complete request to completion.</summary>
    Output Run(ContainerRequest request);

    /// <summary>Run a complete request asynchronously.</summary>
    Task<Output> RunAsync(
        ContainerRequest request,
        CancellationToken cancellationToken = default);

    /// <summary>Spawn a complete request with live standard streams.</summary>
    IMxcProcess Spawn(ContainerRequest request);
}

/// <summary>
/// Stateless <see cref="ISandboxRunner"/> adapter over <see cref="MxcSandbox"/>.
/// </summary>
public sealed class MxcSandboxRunner : ISandboxRunner
{
    /// <summary>Shared production adapter.</summary>
    public static MxcSandboxRunner Default { get; } = new();

    /// <inheritdoc/>
    public string NativeVersion => Microsoft.Mxc.Sdk.MxcPlatform.NativeVersion;

    /// <inheritdoc/>
    public IReadOnlyList<AvailableBackend> GetAvailableBackends() =>
        Microsoft.Mxc.Sdk.MxcPlatform.GetAvailableBackends();

    /// <inheritdoc/>
    public PlatformSupport GetPlatformSupport() =>
        Microsoft.Mxc.Sdk.MxcPlatform.GetPlatformSupport();

    /// <inheritdoc/>
    public Output Run(ContainerRequest request) =>
        MxcSandbox.Run(request);

    /// <inheritdoc/>
    public Task<Output> RunAsync(
        ContainerRequest request,
        CancellationToken cancellationToken = default) =>
        MxcSandbox.RunAsync(request, cancellationToken);

    /// <inheritdoc/>
    public IMxcProcess Spawn(ContainerRequest request) =>
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
    void StartSandbox(ContainerId id, StateAwarePhaseOptions? options = null);

    /// <summary>Validate a start request without starting the sandbox.</summary>
    void DryRunStartSandbox(ContainerId id, StateAwarePhaseOptions? options = null);

    /// <summary>Spawn an exec request with live standard streams.</summary>
    IMxcProcess SpawnInContainer(ContainerId id, ExecRequest request);

    /// <summary>Validate an exec request without starting a process.</summary>
    void DryRunExecInContainer(ContainerId id, ExecRequest request);

    /// <summary>Run an exec request to completion and capture output.</summary>
    Output RunInContainer(ContainerId id, ExecRequest request);

    /// <summary>Run an exec request asynchronously and capture output.</summary>
    Task<Output> RunInContainerAsync(
        ContainerId id,
        ExecRequest request,
        CancellationToken cancellationToken = default);

    /// <summary>Run state-aware exec with live standard streams.</summary>
    IMxcProcess ExecInSandbox(ContainerId id, ExecRequest request);

    /// <summary>Run state-aware exec attached to this process's terminal.</summary>
    WaitOutcome ExecInSandboxAttached(ContainerId id, ExecRequest request);

    /// <summary>Run state-aware exec asynchronously and capture output.</summary>
    Task<Output> ExecInSandboxAsync(
        ContainerId id,
        ExecRequest request,
        CancellationToken cancellationToken = default);

    /// <summary>Stop a running sandbox.</summary>
    void StopSandbox(ContainerId id, StateAwarePhaseOptions? options = null);

    /// <summary>Validate a stop request without stopping the sandbox.</summary>
    void DryRunStopSandbox(ContainerId id, StateAwarePhaseOptions? options = null);

    /// <summary>Destroy a sandbox and release its resources.</summary>
    void DeprovisionSandbox(ContainerId id, StateAwarePhaseOptions? options = null);

    /// <summary>Validate a deprovision request without destroying the sandbox.</summary>
    void DryRunDeprovisionSandbox(
        ContainerId id,
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
    public void StartSandbox(ContainerId id, StateAwarePhaseOptions? options = null) =>
        MxcLifecycle.StartSandbox(id, options);

    /// <inheritdoc/>
    public void DryRunStartSandbox(ContainerId id, StateAwarePhaseOptions? options = null) =>
        MxcLifecycle.DryRunStartSandbox(id, options);

    /// <inheritdoc/>
    public IMxcProcess SpawnInContainer(ContainerId id, ExecRequest request) =>
        MxcLifecycle.SpawnInContainer(id, request);

    /// <inheritdoc/>
    public void DryRunExecInContainer(ContainerId id, ExecRequest request) =>
        MxcLifecycle.DryRunExecInContainer(id, request);

    /// <inheritdoc/>
    public Output RunInContainer(ContainerId id, ExecRequest request) =>
        MxcLifecycle.RunInContainer(id, request);

    /// <inheritdoc/>
    public Task<Output> RunInContainerAsync(
        ContainerId id,
        ExecRequest request,
        CancellationToken cancellationToken = default) =>
        MxcLifecycle.RunInContainerAsync(id, request, cancellationToken);

    /// <inheritdoc/>
    public IMxcProcess ExecInSandbox(ContainerId id, ExecRequest request) =>
        MxcLifecycle.ExecInSandbox(id, request);

    /// <inheritdoc/>
    public WaitOutcome ExecInSandboxAttached(ContainerId id, ExecRequest request) =>
        MxcLifecycle.ExecInSandboxAttached(id, request);

    /// <inheritdoc/>
    public Task<Output> ExecInSandboxAsync(
        ContainerId id,
        ExecRequest request,
        CancellationToken cancellationToken = default) =>
        MxcLifecycle.ExecInSandboxAsync(id, request, cancellationToken);

    /// <inheritdoc/>
    public void StopSandbox(ContainerId id, StateAwarePhaseOptions? options = null) =>
        MxcLifecycle.StopSandbox(id, options);

    /// <inheritdoc/>
    public void DryRunStopSandbox(ContainerId id, StateAwarePhaseOptions? options = null) =>
        MxcLifecycle.DryRunStopSandbox(id, options);

    /// <inheritdoc/>
    public void DeprovisionSandbox(
        ContainerId id,
        StateAwarePhaseOptions? options = null) =>
        MxcLifecycle.DeprovisionSandbox(id, options);

    /// <inheritdoc/>
    public void DryRunDeprovisionSandbox(
        ContainerId id,
        StateAwarePhaseOptions? options = null) =>
        MxcLifecycle.DryRunDeprovisionSandbox(id, options);
}
