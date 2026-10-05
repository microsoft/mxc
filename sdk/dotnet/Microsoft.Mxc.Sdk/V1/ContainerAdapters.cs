// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.Mxc.Sdk;
using Microsoft.Mxc.Sdk.V1;

namespace Microsoft.Mxc.Sdk.V1;

/// <summary>
/// Injectable container request operations. Use <see cref="MxcContainerRunner.Default"/>
/// in production and substitute a fake or mock in unit tests.
/// </summary>
internal interface IContainerRunner
{
    /// <summary>The loaded native MXC library version.</summary>
    string NativeVersion { get; }

    /// <summary>Probe every containment backend the current host can run.</summary>
    IReadOnlyList<AvailableBackend> GetAvailableBackends();

    /// <summary>Probe the containment backends the public SDK can launch.</summary>
    PlatformSupport GetPlatformSupport();

    /// <summary>Run a complete request to completion.</summary>
    ExecutionResult Run(ContainerRequest request, RunOptions? options = null);

    /// <summary>Run a complete request asynchronously.</summary>
    Task<ExecutionResult> RunAsync(
        ContainerRequest request,
        RunOptions? options = null,
        CancellationToken cancellationToken = default);

    /// <summary>Spawn a complete request with live standard streams.</summary>
    IMxcProcess Spawn(ContainerRequest request, SpawnOptions? options = null);

    /// <summary>Spawn a complete request asynchronously with live standard streams.</summary>
    Task<IMxcProcess> SpawnAsync(
        ContainerRequest request,
        SpawnOptions? options = null,
        CancellationToken cancellationToken = default);

    /// <summary>Spawn a complete request attached to a caller-controlled PTY.</summary>
    MxcPtyProcess SpawnWithPty(
        ContainerRequest request,
        SpawnWithPtyOptions? options = null);
}

/// <summary>
/// Stateless <see cref="IContainerRunner"/> adapter over <see cref="MxcContainer"/>.
/// </summary>
internal sealed class MxcContainerRunner : IContainerRunner
{
    /// <summary>Shared production adapter.</summary>
    public static MxcContainerRunner Default { get; } = new();

    /// <inheritdoc/>
    public string NativeVersion => Microsoft.Mxc.Sdk.V1.MxcPlatform.NativeVersion;

    /// <inheritdoc/>
    public IReadOnlyList<AvailableBackend> GetAvailableBackends() =>
        Microsoft.Mxc.Sdk.V1.MxcPlatform.GetAvailableBackends();

    /// <inheritdoc/>
    public PlatformSupport GetPlatformSupport() =>
        Microsoft.Mxc.Sdk.V1.MxcPlatform.GetPlatformSupport();

    /// <inheritdoc/>
    public ExecutionResult Run(ContainerRequest request, RunOptions? options = null) =>
        MxcContainer.Run(request, options);

    /// <inheritdoc/>
    public Task<ExecutionResult> RunAsync(
        ContainerRequest request,
        RunOptions? options = null,
        CancellationToken cancellationToken = default) =>
        MxcContainer.RunAsync(request, options, cancellationToken);

    /// <inheritdoc/>
    public IMxcProcess Spawn(ContainerRequest request, SpawnOptions? options = null) =>
        MxcContainer.Spawn(request, options);

    /// <inheritdoc/>
    public async Task<IMxcProcess> SpawnAsync(
        ContainerRequest request,
        SpawnOptions? options = null,
        CancellationToken cancellationToken = default) =>
        await MxcContainer.SpawnAsync(request, options, cancellationToken).ConfigureAwait(false);

    /// <inheritdoc/>
    public MxcPtyProcess SpawnWithPty(
        ContainerRequest request,
        SpawnWithPtyOptions? options = null) =>
        MxcContainer.SpawnWithPty(request, options);
}

/// <summary>
/// Injectable container lifecycle operations. Use
/// <see cref="MxcContainerLifecycle.Default"/> in production and substitute a fake
/// or mock in unit tests.
/// </summary>
internal interface IContainerLifecycle
{
    /// <summary>Provision a new container.</summary>
    ProvisionResult ProvisionContainer(
        ProvisionRequest request,
        ProvisionOptions? options = null);

    /// <summary>Validate a provision request without allocating a container.</summary>
    ValidationResult ValidateProvision(
        ProvisionRequest request,
        ProvisionOptions? options = null);

    /// <summary>Start a provisioned container.</summary>
    LifecycleResult StartContainer(ContainerId id, StartOptions? options = null);

    /// <summary>Validate a start request without starting the container.</summary>
    ValidationResult ValidateStart(ContainerId id, StartOptions? options = null);

    /// <summary>Spawn an execution request with live standard streams.</summary>
    IMxcProcess SpawnInContainer(
        ContainerId id,
        ExecutionRequest request,
        SpawnInContainerOptions? options = null);

    /// <summary>Spawn an execution request attached to a caller-controlled PTY.</summary>
    MxcPtyProcess SpawnInContainerWithPty(
        ContainerId id,
        ExecutionRequest request,
        SpawnInContainerWithPtyOptions? options = null) =>
        throw new NotSupportedException(
            "This lifecycle implementation does not support PTY processes.");

    /// <summary>Validate an execution request without starting a process.</summary>
    ValidationResult ValidateProcess(
        ContainerId id,
        ExecutionRequest request,
        SpawnInContainerOptions? options = null);

    /// <summary>Run an execution request to completion and capture output.</summary>
    ExecutionResult RunInContainer(
        ContainerId id,
        ExecutionRequest request,
        RunInContainerOptions? options = null);

    /// <summary>Run an execution request asynchronously and capture output.</summary>
    Task<ExecutionResult> RunInContainerAsync(
        ContainerId id,
        ExecutionRequest request,
        RunInContainerOptions? options = null,
        CancellationToken cancellationToken = default);

    /// <summary>Spawn a command asynchronously with live standard streams.</summary>
    Task<IMxcProcess> SpawnInContainerAsync(
        ContainerId id,
        ExecutionRequest request,
        SpawnInContainerOptions? options = null,
        CancellationToken cancellationToken = default);

    /// <summary>Stop a running container.</summary>
    LifecycleResult StopContainer(ContainerId id, StopOptions? options = null);

    /// <summary>Validate a stop request without stopping the container.</summary>
    ValidationResult ValidateStop(ContainerId id, StopOptions? options = null);

    /// <summary>Destroy a container and release its resources.</summary>
    LifecycleResult DeprovisionContainer(ContainerId id, DeprovisionOptions? options = null);

    /// <summary>Validate a deprovision request without destroying the container.</summary>
    ValidationResult ValidateDeprovision(
        ContainerId id,
        DeprovisionOptions? options = null);
}

/// <summary>
/// Stateless <see cref="IContainerLifecycle"/> adapter over
/// <see cref="MxcLifecycle"/>.
/// </summary>
internal sealed class MxcContainerLifecycle : IContainerLifecycle
{
    /// <summary>Shared production adapter.</summary>
    public static MxcContainerLifecycle Default { get; } = new();

    /// <inheritdoc/>
    public ProvisionResult ProvisionContainer(
        ProvisionRequest request,
        ProvisionOptions? options = null) =>
        MxcLifecycle.ProvisionContainer(request, options);

    /// <inheritdoc/>
    public ValidationResult ValidateProvision(
        ProvisionRequest request,
        ProvisionOptions? options = null) =>
        MxcLifecycle.ValidateProvision(request, options);

    /// <inheritdoc/>
    public LifecycleResult StartContainer(ContainerId id, StartOptions? options = null) =>
        MxcLifecycle.StartContainer(id, options);

    /// <inheritdoc/>
    public ValidationResult ValidateStart(ContainerId id, StartOptions? options = null) =>
        MxcLifecycle.ValidateStart(id, options);

    /// <inheritdoc/>
    public IMxcProcess SpawnInContainer(
        ContainerId id,
        ExecutionRequest request,
        SpawnInContainerOptions? options = null) =>
        MxcLifecycle.SpawnInContainer(id, request, options);

    /// <inheritdoc/>
    public MxcPtyProcess SpawnInContainerWithPty(
        ContainerId id,
        ExecutionRequest request,
        SpawnInContainerWithPtyOptions? options = null) =>
        MxcLifecycle.SpawnInContainerWithPty(id, request, options);

    /// <inheritdoc/>
    public ValidationResult ValidateProcess(
        ContainerId id,
        ExecutionRequest request,
        SpawnInContainerOptions? options = null) =>
        MxcLifecycle.ValidateProcess(id, request, options);

    /// <inheritdoc/>
    public ExecutionResult RunInContainer(
        ContainerId id,
        ExecutionRequest request,
        RunInContainerOptions? options = null) =>
        MxcLifecycle.RunInContainer(id, request, options);

    /// <inheritdoc/>
    public Task<ExecutionResult> RunInContainerAsync(
        ContainerId id,
        ExecutionRequest request,
        RunInContainerOptions? options = null,
        CancellationToken cancellationToken = default) =>
        MxcLifecycle.RunInContainerAsync(id, request, options, cancellationToken);

    /// <inheritdoc/>
    public async Task<IMxcProcess> SpawnInContainerAsync(
        ContainerId id,
        ExecutionRequest request,
        SpawnInContainerOptions? options = null,
        CancellationToken cancellationToken = default) =>
        await MxcLifecycle.SpawnInContainerAsync(id, request, options, cancellationToken)
            .ConfigureAwait(false);

    /// <inheritdoc/>
    public LifecycleResult StopContainer(ContainerId id, StopOptions? options = null) =>
        MxcLifecycle.StopContainer(id, options);

    /// <inheritdoc/>
    public ValidationResult ValidateStop(ContainerId id, StopOptions? options = null) =>
        MxcLifecycle.ValidateStop(id, options);

    /// <inheritdoc/>
    public LifecycleResult DeprovisionContainer(
        ContainerId id,
        DeprovisionOptions? options = null) =>
        MxcLifecycle.DeprovisionContainer(id, options);

    /// <inheritdoc/>
    public ValidationResult ValidateDeprovision(
        ContainerId id,
        DeprovisionOptions? options = null) =>
        MxcLifecycle.ValidateDeprovision(id, options);
}
