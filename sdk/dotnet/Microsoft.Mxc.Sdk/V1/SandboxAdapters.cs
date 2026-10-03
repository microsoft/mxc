// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.Mxc.Sdk;

namespace Microsoft.Mxc.Sdk.V1;

/// <summary>
/// Injectable one-shot sandbox operations. Use <see cref="MxcContainerRunner.Default"/>
/// in production and substitute a fake or mock in unit tests.
/// </summary>
public interface IContainerRunner
{
    /// <summary>The loaded native MXC library version.</summary>
    string NativeVersion { get; }

    /// <summary>Probe every containment backend the current host can run.</summary>
    IReadOnlyList<AvailableBackend> GetAvailableBackends();

    /// <summary>Probe the containment backends the public SDK can launch.</summary>
    PlatformSupport GetPlatformSupport();

    /// <summary>Run a complete request to completion.</summary>
    ExecutionOutput Run(ContainerRequest request);

    /// <summary>Run a complete request asynchronously.</summary>
    Task<ExecutionOutput> RunAsync(
        ContainerRequest request,
        CancellationToken cancellationToken = default);

    /// <summary>Spawn a complete request with live standard streams.</summary>
    IMxcProcess Spawn(ContainerRequest request);

    /// <summary>Spawn a complete request attached to a caller-controlled PTY.</summary>
    MxcPtyProcess SpawnWithPty(ContainerRequest request, MxcPtySize? size = null);
}

/// <summary>
/// Stateless <see cref="IContainerRunner"/> adapter over <see cref="MxcContainer"/>.
/// </summary>
public sealed class MxcContainerRunner : IContainerRunner
{
    /// <summary>Shared production adapter.</summary>
    public static MxcContainerRunner Default { get; } = new();

    /// <inheritdoc/>
    public string NativeVersion => Microsoft.Mxc.Sdk.MxcPlatform.NativeVersion;

    /// <inheritdoc/>
    public IReadOnlyList<AvailableBackend> GetAvailableBackends() =>
        Microsoft.Mxc.Sdk.MxcPlatform.GetAvailableBackends();

    /// <inheritdoc/>
    public PlatformSupport GetPlatformSupport() =>
        Microsoft.Mxc.Sdk.MxcPlatform.GetPlatformSupport();

    /// <inheritdoc/>
    public ExecutionOutput Run(ContainerRequest request) =>
        MxcContainer.Run(request);

    /// <inheritdoc/>
    public Task<ExecutionOutput> RunAsync(
        ContainerRequest request,
        CancellationToken cancellationToken = default) =>
        MxcContainer.RunAsync(request, cancellationToken);

    /// <inheritdoc/>
    public IMxcProcess Spawn(ContainerRequest request) =>
        MxcContainer.Spawn(request);

    /// <inheritdoc/>
    public MxcPtyProcess SpawnWithPty(ContainerRequest request, MxcPtySize? size = null) =>
        MxcContainer.SpawnWithPty(request, size);
}

/// <summary>
/// Injectable state-aware sandbox lifecycle operations. Use
/// <see cref="MxcContainerLifecycle.Default"/> in production and substitute a fake
/// or mock in unit tests.
/// </summary>
public interface IContainerLifecycle
{
    /// <summary>Provision a new sandbox.</summary>
    ProvisionResult ProvisionSandbox(
        LifecycleBackend containment,
        ProvisionOptions? options = null);

    /// <summary>Validate a provision request without allocating a sandbox.</summary>
    void DryRunProvisionSandbox(
        LifecycleBackend containment,
        ProvisionOptions? options = null);

    /// <summary>Start a provisioned sandbox.</summary>
    void StartSandbox(ContainerId id, LifecycleOptions? options = null);

    /// <summary>Validate a start request without starting the sandbox.</summary>
    void DryRunStartSandbox(ContainerId id, LifecycleOptions? options = null);

    /// <summary>Spawn an exec request with live standard streams.</summary>
    IMxcProcess SpawnInContainer(ContainerId id, ExecRequest request);

    /// <summary>Spawn an exec request attached to a caller-controlled PTY.</summary>
    MxcPtyProcess SpawnInContainerWithPty(
        ContainerId id,
        ExecRequest request,
        MxcPtySize? size = null) =>
        throw new NotSupportedException(
            "This lifecycle implementation does not support PTY processes.");

    /// <summary>Validate an exec request without starting a process.</summary>
    void DryRunExecInContainer(ContainerId id, ExecRequest request);

    /// <summary>Run an exec request to completion and capture output.</summary>
    ExecutionOutput RunInContainer(ContainerId id, ExecRequest request);

    /// <summary>Run an exec request asynchronously and capture output.</summary>
    Task<ExecutionOutput> RunInContainerAsync(
        ContainerId id,
        ExecRequest request,
        CancellationToken cancellationToken = default);

    /// <summary>Run state-aware exec with live standard streams.</summary>
    IMxcProcess ExecInSandbox(ContainerId id, ExecRequest request);

    /// <summary>Run state-aware exec asynchronously and capture output.</summary>
    Task<ExecutionOutput> ExecInSandboxAsync(
        ContainerId id,
        ExecRequest request,
        CancellationToken cancellationToken = default);

    /// <summary>Stop a running sandbox.</summary>
    void StopSandbox(ContainerId id, LifecycleOptions? options = null);

    /// <summary>Validate a stop request without stopping the sandbox.</summary>
    void DryRunStopSandbox(ContainerId id, LifecycleOptions? options = null);

    /// <summary>Destroy a sandbox and release its resources.</summary>
    void DeprovisionSandbox(ContainerId id, LifecycleOptions? options = null);

    /// <summary>Validate a deprovision request without destroying the sandbox.</summary>
    void DryRunDeprovisionSandbox(
        ContainerId id,
        LifecycleOptions? options = null);
}

/// <summary>
/// Stateless <see cref="IContainerLifecycle"/> adapter over
/// <see cref="MxcLifecycle"/>.
/// </summary>
public sealed class MxcContainerLifecycle : IContainerLifecycle
{
    /// <summary>Shared production adapter.</summary>
    public static MxcContainerLifecycle Default { get; } = new();

    /// <inheritdoc/>
    public ProvisionResult ProvisionSandbox(
        LifecycleBackend containment,
        ProvisionOptions? options = null) =>
        MxcLifecycle.ProvisionSandbox(containment, options);

    /// <inheritdoc/>
    public void DryRunProvisionSandbox(
        LifecycleBackend containment,
        ProvisionOptions? options = null) =>
        MxcLifecycle.DryRunProvisionSandbox(containment, options);

    /// <inheritdoc/>
    public void StartSandbox(ContainerId id, LifecycleOptions? options = null) =>
        MxcLifecycle.StartSandbox(id, options);

    /// <inheritdoc/>
    public void DryRunStartSandbox(ContainerId id, LifecycleOptions? options = null) =>
        MxcLifecycle.DryRunStartSandbox(id, options);

    /// <inheritdoc/>
    public IMxcProcess SpawnInContainer(ContainerId id, ExecRequest request) =>
        MxcLifecycle.SpawnInContainer(id, request);

    /// <inheritdoc/>
    public MxcPtyProcess SpawnInContainerWithPty(
        ContainerId id,
        ExecRequest request,
        MxcPtySize? size = null) =>
        MxcLifecycle.SpawnInContainerWithPty(id, request, size);

    /// <inheritdoc/>
    public void DryRunExecInContainer(ContainerId id, ExecRequest request) =>
        MxcLifecycle.DryRunExecInContainer(id, request);

    /// <inheritdoc/>
    public ExecutionOutput RunInContainer(ContainerId id, ExecRequest request) =>
        MxcLifecycle.RunInContainer(id, request);

    /// <inheritdoc/>
    public Task<ExecutionOutput> RunInContainerAsync(
        ContainerId id,
        ExecRequest request,
        CancellationToken cancellationToken = default) =>
        MxcLifecycle.RunInContainerAsync(id, request, cancellationToken);

    /// <inheritdoc/>
    public IMxcProcess ExecInSandbox(ContainerId id, ExecRequest request) =>
        MxcLifecycle.ExecInSandbox(id, request);

    /// <inheritdoc/>
    public Task<ExecutionOutput> ExecInSandboxAsync(
        ContainerId id,
        ExecRequest request,
        CancellationToken cancellationToken = default) =>
        MxcLifecycle.ExecInSandboxAsync(id, request, cancellationToken);

    /// <inheritdoc/>
    public void StopSandbox(ContainerId id, LifecycleOptions? options = null) =>
        MxcLifecycle.StopSandbox(id, options);

    /// <inheritdoc/>
    public void DryRunStopSandbox(ContainerId id, LifecycleOptions? options = null) =>
        MxcLifecycle.DryRunStopSandbox(id, options);

    /// <inheritdoc/>
    public void DeprovisionSandbox(
        ContainerId id,
        LifecycleOptions? options = null) =>
        MxcLifecycle.DeprovisionSandbox(id, options);

    /// <inheritdoc/>
    public void DryRunDeprovisionSandbox(
        ContainerId id,
        LifecycleOptions? options = null) =>
        MxcLifecycle.DryRunDeprovisionSandbox(id, options);
}
