// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Reflection;
using Microsoft.Mxc.Sdk;
using Microsoft.Mxc.Sdk.V1;
using Xunit;

namespace Microsoft.Mxc.Sdk.Tests.V1;

public class SandboxAdapterTests
{
    [Fact]
    public void DefaultAdaptersImplementInjectableContracts()
    {
        ISandboxRunner runner = MxcSandboxRunner.Default;
        ISandboxLifecycle lifecycle = MxcSandboxLifecycle.Default;

        Assert.Same(MxcSandboxRunner.Default, runner);
        Assert.Same(MxcSandboxLifecycle.Default, lifecycle);
    }

    [Fact]
    public void RunnerAdapterDelegatesStaticArgumentValidation()
    {
        ISandboxRunner runner = new MxcSandboxRunner();

        Assert.Throws<ArgumentNullException>(
            () => runner.Run((ContainerRequest)null!));
        Assert.Throws<ArgumentNullException>(
            () => runner.Spawn((ContainerRequest)null!));
    }

    [Fact]
    public void ExistingRunnerImplementationsRemainSourceCompatible()
    {
        ISandboxRunner runner = new ExistingRunnerFake();

        Assert.Equal("fake", runner.NativeVersion);
    }

    [Fact]
    public void LifecyclePtyCapabilityHasDefaultImplementation()
    {
        var method = typeof(ISandboxLifecycle).GetMethod(
            nameof(ISandboxLifecycle.SpawnInContainerWithPty));

        Assert.NotNull(method?.GetMethodBody());
    }

    [Fact]
    public void LifecycleAdapterDelegatesStaticValidation()
    {
        ISandboxLifecycle lifecycle = new MxcSandboxLifecycle();

        var exception = Assert.Throws<MxcException>(
            () => lifecycle.DryRunStopSandbox(new ContainerId("missing-prefix")));

        Assert.Equal(ErrorCode.MalformedId, exception.Code);
    }

    [Theory]
    [InlineData(typeof(MxcSandbox), typeof(ISandboxRunner))]
    [InlineData(typeof(MxcLifecycle), typeof(ISandboxLifecycle))]
    public void InjectableContractsMirrorStaticFacadeMethods(
        Type staticFacade,
        Type contract)
    {
        var contractMethods = contract.GetMethods();
        foreach (var facadeMethod in staticFacade
            .GetMethods(BindingFlags.Public | BindingFlags.Static | BindingFlags.DeclaredOnly)
            .Where(method => !method.IsSpecialName)
            .Where(method => staticFacade != typeof(MxcSandbox) || method.Name != nameof(MxcSandbox.Probe)))
        {
            var parameterTypes = facadeMethod.GetParameters()
                .Select(parameter => parameter.ParameterType)
                .ToArray();
            var contractMethod = contractMethods.SingleOrDefault(
                method => method.Name == facadeMethod.Name
                    && method.GetParameters()
                        .Select(parameter => parameter.ParameterType)
                        .SequenceEqual(parameterTypes));

            Assert.NotNull(contractMethod);
            Assert.True(
                contractMethod.ReturnType.IsAssignableFrom(facadeMethod.ReturnType),
                $"{contractMethod} cannot represent {facadeMethod.ReturnType}");
        }

        foreach (var facadeProperty in staticFacade.GetProperties(
            BindingFlags.Public | BindingFlags.Static | BindingFlags.DeclaredOnly))
        {
            var contractProperty = contract.GetProperty(facadeProperty.Name);

            Assert.NotNull(contractProperty);
            Assert.True(
                contractProperty.PropertyType.IsAssignableFrom(facadeProperty.PropertyType),
                $"{contractProperty} cannot represent {facadeProperty.PropertyType}");
        }
    }

    [Fact]
    public async Task SandboxProcessContractSupportsInMemoryFakes()
    {
        using var fake = new FakeSandboxProcess("fake output");
        IMxcProcess process = fake;

        using var reader = new StreamReader(process.StandardOutput!);
        using var closer = process.StandardOutputCloser;
        Assert.NotNull(closer);
        closer.Close();
        var output = await reader.ReadToEndAsync(TestContext.Current.CancellationToken);
        var result = await process.WaitAsync(TestContext.Current.CancellationToken);

        Assert.True(fake.OutputCloseRequested);
        Assert.Equal("fake output", output);
        Assert.Equal(0, result.ExitCode);
        Assert.False(result.TimedOut);
    }

    [Fact]
    public void BlockingNativeWaitIsNotPublic()
    {
        var method = typeof(MxcProcess).GetMethod(
            "WaitBlocking",
            BindingFlags.Public | BindingFlags.Instance);

        Assert.Null(method);
    }

    private sealed class ExistingRunnerFake : ISandboxRunner
    {
        public string NativeVersion => "fake";

        public IReadOnlyList<AvailableBackend> GetAvailableBackends() => [];

        public PlatformSupport GetPlatformSupport() => new();

        public Output Run(ContainerRequest request) =>
            throw new NotSupportedException();

        public Task<Output> RunAsync(
            ContainerRequest request,
            CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();

        public IMxcProcess Spawn(ContainerRequest request) =>
            throw new NotSupportedException();
    }

    private sealed class FakeSandboxProcess(string output) : IMxcProcess
    {
        private readonly MemoryStream _stdout =
            new(System.Text.Encoding.UTF8.GetBytes(output));

        public uint Id => 42;
        public Stream? StandardInput => Stream.Null;
        public Stream? StandardOutput => _stdout;
        public Stream? StandardError => Stream.Null;
        public bool OutputCloseRequested { get; private set; }
        public IMxcStreamCloser? StandardOutputCloser =>
            new FakeSandboxStreamCloser(() => OutputCloseRequested = true);
        public IMxcStreamCloser? StandardErrorCloser => null;
        public IReadOnlyList<string> Warnings => Array.Empty<string>();
        public SandboxOutputMetadata? OutputMetadata => null;

        public WaitOutcome Wait() => new() { ExitCode = 0 };

        public Task<WaitOutcome> WaitAsync(
            CancellationToken cancellationToken = default) =>
            Task.FromResult(Wait());

        public bool TryGetExitCode(out int exitCode)
        {
            exitCode = 0;
            return true;
        }

        public Task<(WaitOutcome Result, byte[] Stdout, byte[] Stderr)>
            WaitForExitWithOutputAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult((Wait(), _stdout.ToArray(), Array.Empty<byte>()));

        public void Kill()
        {
        }

        public void Dispose() => _stdout.Dispose();
    }

    private sealed class FakeSandboxStreamCloser(Action close) : IMxcStreamCloser
    {
        public void Close() => close();

        public void Dispose()
        {
        }
    }
}
