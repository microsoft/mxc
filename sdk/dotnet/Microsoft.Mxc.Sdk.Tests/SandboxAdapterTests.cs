// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Reflection;
using Microsoft.Mxc.Sdk;
using Xunit;

namespace Microsoft.Mxc.Sdk.Tests;

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
            () => runner.Run((SandboxRequest)null!));
        Assert.Throws<ArgumentNullException>(
            () => runner.Spawn((SandboxPolicy)null!, "echo hi"));
    }

    [Fact]
    public void LifecycleAdapterDelegatesStaticValidation()
    {
        ISandboxLifecycle lifecycle = new MxcSandboxLifecycle();

        var exception = Assert.Throws<MxcException>(
            () => lifecycle.DryRunStopSandbox(new SandboxId("missing-prefix")));

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
            .Where(method => !method.IsSpecialName))
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
        ISandboxProcess process = fake;

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
        var method = typeof(MxcSandboxProcess).GetMethod(
            "WaitBlocking",
            BindingFlags.Public | BindingFlags.Instance);

        Assert.Null(method);
    }

    private sealed class FakeSandboxProcess(string output) : ISandboxProcess
    {
        private readonly MemoryStream _stdout =
            new(System.Text.Encoding.UTF8.GetBytes(output));

        public uint Id => 42;
        public Stream? StandardInput => Stream.Null;
        public Stream? StandardOutput => _stdout;
        public Stream? StandardError => Stream.Null;
        public bool OutputCloseRequested { get; private set; }
        public ISandboxStreamCloser? StandardOutputCloser =>
            new FakeSandboxStreamCloser(() => OutputCloseRequested = true);
        public ISandboxStreamCloser? StandardErrorCloser => null;
        public IReadOnlyList<string> Warnings => Array.Empty<string>();
        public SandboxOutputMetadata? OutputMetadata => null;

        public SandboxWaitResult Wait() => new() { ExitCode = 0 };

        public Task<SandboxWaitResult> WaitAsync(
            CancellationToken cancellationToken = default) =>
            Task.FromResult(Wait());

        public bool TryGetExitCode(out int exitCode)
        {
            exitCode = 0;
            return true;
        }

        public Task<(SandboxWaitResult Result, byte[] Stdout, byte[] Stderr)>
            WaitForExitWithOutputAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult((Wait(), _stdout.ToArray(), Array.Empty<byte>()));

        public void Kill()
        {
        }

        public void Dispose() => _stdout.Dispose();
    }

    private sealed class FakeSandboxStreamCloser(Action close) : ISandboxStreamCloser
    {
        public void Close() => close();

        public void Dispose()
        {
        }
    }
}
