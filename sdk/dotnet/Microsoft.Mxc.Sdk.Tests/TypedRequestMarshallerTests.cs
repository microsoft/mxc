// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using Microsoft.Mxc.Sdk.Native;
using Xunit;

namespace Microsoft.Mxc.Sdk.Tests;

public unsafe class TypedRequestMarshallerTests
{
    [Fact]
    public void OneShotMarshaller_MapsPresenceSensitivePolicyAndProcessContainerFields()
    {
        var request = new SandboxRequest(
            new SandboxPolicy
            {
                Filesystem = new FilesystemPolicy
                {
                    ReadwritePaths = [@"C:\work"],
                    ReadonlyPaths = [@"C:\input"],
                    DeniedPaths = [@"C:\secret"],
                    ClearPolicyOnExit = false,
                },
                Network = new NetworkPolicy
                {
                    Egress = new NetworkEgressPolicy
                    {
                        Default = NetworkAction.Deny,
                        Allow =
                        [
                            new NetworkRulePolicy
                            {
                                To =
                                [
                                    new NetworkPeerPolicy("10.20.0.0/16")
                                    {
                                        Except = ["10.20.30.0/24"],
                                    },
                                ],
                                Ports =
                                [
                                    new NetworkPortPolicy
                                    {
                                        Protocol = NetworkProtocol.Tcp,
                                        Port = 443,
                                        EndPort = 444,
                                    },
                                ],
                            },
                        ],
                    },
                    Ingress = new NetworkIngressPolicy
                    {
                        Default = NetworkAction.Allow,
                        HostLoopback = NetworkAction.Deny,
                    },
                    RuntimeConfig = new NetworkRuntimeConfig
                    {
                        NetworkProxy = "http://127.0.0.1:8080",
                    },
                },
                Ui = new UiPolicy
                {
                    AllowWindows = true,
                    Clipboard = ClipboardPolicy.Write,
                    AllowInputInjection = true,
                },
                TimeoutMs = 123,
                Telemetry = new TelemetrySettings { Enabled = false },
            },
            "cmd /c echo typed")
        {
            Containment = new ProcessContainerContainment
            {
                LeastPrivilege = true,
                LearningMode = true,
                Capabilities = ["internetClient"],
                CaptureDenials = new CaptureDenialsPolicy
                {
                    Mode = CaptureDenialsMode.Allow,
                    OutputPath = @"C:\logs\denials.json",
                    RetainEtl = true,
                },
                Ui = new ProcessContainerUiPolicy
                {
                    Isolation = ProcessContainerUiIsolation.Handles,
                    DesktopSystemControl = true,
                    SystemSettings = ProcessContainerSystemSettings.Parameters,
                    Ime = true,
                },
                Filesystem = new ProcessContainerFilesystemPolicy
                {
                    EnumeratePaths = [@"C:\enum"],
                },
                Network = new ProcessContainerNetworkPolicy
                {
                    AllowedProxyPeer = "Contoso.App_123",
                },
            },
            ContainerName = "typed-container",
            WorkingDirectory = @"C:\work",
            Environment = [],
            InheritDefaultEnvironment = true,
            Experimental = true,
        };

        using var marshaller = TypedRequestMarshaller.ForOneShot(request);
        var native = marshaller.OneShotRequest;

        Assert.Equal(TypedRequestMarshaller.TypedAbiVersion, native->abi_version);
        Assert.Equal((nuint)sizeof(MxcTypedOneShotRequest), native->struct_size);
        Assert.Equal("cmd /c echo typed", String(native->command));
        Assert.Equal(TypedRequestMarshaller.ContainmentProcessContainer, native->containment);
        Assert.Equal("typed-container", OptionalString(native->container_name));
        Assert.Equal(@"C:\work", OptionalString(native->working_directory));
        Assert.Equal(1, native->environment.is_set);
        Assert.Equal((nuint)0, native->environment.len);
        Assert.Equal(1, native->inherit_default_env);
        Assert.Equal(1, native->experimental);

        var policy = native->policy;
        Assert.Equal(@"C:\work", SingleString(policy->filesystem->readwrite_paths));
        Assert.Equal(1, policy->filesystem->clear_policy_on_exit.is_set);
        Assert.Equal(0, policy->filesystem->clear_policy_on_exit.value);
        Assert.Equal(1, policy->network->egress->default_action.is_set);
        Assert.Equal(0, policy->network->egress->default_action.value);
        Assert.Equal(1, policy->network->egress->allow_is_set);
        Assert.Equal((nuint)1, policy->network->egress->allow_len);
        var rule = &policy->network->egress->allow[0];
        Assert.Equal(1, rule->to_is_set);
        Assert.Equal("10.20.0.0/16", String(rule->to[0].cidr));
        Assert.Equal(1, rule->to[0].except_is_set);
        Assert.Equal("10.20.30.0/24", SingleString(rule->to[0].except));
        Assert.Equal(1, rule->ports_is_set);
        Assert.Equal(0, rule->ports[0].protocol.value);
        Assert.Equal((ushort)443, rule->ports[0].port.value);
        Assert.Equal((ushort)444, rule->ports[0].end_port.value);
        Assert.Equal(1, policy->network->ingress->default_action.value);
        Assert.Equal(0, policy->network->ingress->host_loopback.value);
        Assert.Equal("http://127.0.0.1:8080", OptionalString(policy->network->network_proxy));
        Assert.Equal(1, policy->ui->allow_windows);
        Assert.Equal((int)ClipboardPolicy.Write, policy->ui->clipboard);
        Assert.Equal(1, policy->timeout_ms.is_set);
        Assert.Equal((uint)123, policy->timeout_ms.value);
        Assert.Equal(1, policy->telemetry_enabled.is_set);
        Assert.Equal(0, policy->telemetry_enabled.value);

        var processContainer = native->process_container;
        Assert.Equal(1, processContainer->least_privilege);
        Assert.Equal(1, processContainer->learning_mode);
        Assert.Equal("internetClient", SingleString(processContainer->capabilities));
        Assert.Equal((int)CaptureDenialsMode.Allow, processContainer->capture_denials->mode);
        Assert.Equal(@"C:\logs\denials.json", OptionalString(processContainer->capture_denials->output_path));
        Assert.Equal(1, processContainer->capture_denials->retain_etl);
        Assert.Equal((int)ProcessContainerUiIsolation.Handles, processContainer->ui->isolation);
        Assert.Equal(1, processContainer->ui->desktop_system_control);
        Assert.Equal((int)ProcessContainerSystemSettings.Parameters, processContainer->ui->system_settings);
        Assert.Equal(1, processContainer->ui->ime);
        Assert.Equal(@"C:\enum", SingleString(processContainer->enumerate_paths));
        Assert.Equal("Contoso.App_123", OptionalString(processContainer->allowed_proxy_peer));
    }

    [Fact]
    public void OneShotMarshaller_DistinguishesAbsentAndPresentEmptyEnvironment()
    {
        using var absent = TypedRequestMarshaller.ForOneShot(
            new SandboxRequest(new SandboxPolicy(), "echo absent"));
        Assert.Equal(0, absent.OneShotRequest->environment.is_set);

        using var empty = TypedRequestMarshaller.ForOneShot(
            new SandboxRequest(new SandboxPolicy(), "echo empty")
            {
                Environment = [],
            });
        Assert.Equal(1, empty.OneShotRequest->environment.is_set);
        Assert.Equal((nuint)0, empty.OneShotRequest->environment.len);
    }

    [Fact]
    public void OneShotMarshaller_MapsBackendSpecificContainmentOptions()
    {
        using var seatbelt = TypedRequestMarshaller.ForOneShot(new SandboxRequest(
            new SandboxPolicy(),
            "echo seatbelt")
        {
            Containment = new SeatbeltContainment
            {
                ProfileOverride = "(version 1)",
                GuiAccess = true,
                NestedPty = false,
                KeychainAccess = true,
                ExtraMachLookups = ["com.apple.windowserver.active"],
            },
        });
        Assert.Equal(TypedRequestMarshaller.ContainmentSeatbelt, seatbelt.OneShotRequest->containment);
        Assert.Equal("(version 1)", OptionalString(seatbelt.OneShotRequest->seatbelt->profile_override));
        Assert.Equal(1, seatbelt.OneShotRequest->seatbelt->gui_access);
        Assert.Equal(0, seatbelt.OneShotRequest->seatbelt->nested_pty);
        Assert.Equal(1, seatbelt.OneShotRequest->seatbelt->keychain_access);
        Assert.Equal("com.apple.windowserver.active", SingleString(seatbelt.OneShotRequest->seatbelt->extra_mach_lookups));

        using var lxc = TypedRequestMarshaller.ForOneShot(new SandboxRequest(
            new SandboxPolicy(),
            "echo lxc")
        {
            Containment = new LxcContainment { Distribution = "ubuntu", Release = "24.04" },
        });
        Assert.Equal(TypedRequestMarshaller.ContainmentLxc, lxc.OneShotRequest->containment);
        Assert.Equal("ubuntu", OptionalString(lxc.OneShotRequest->lxc->distribution));
        Assert.Equal("24.04", OptionalString(lxc.OneShotRequest->lxc->release));

        using var wslc = TypedRequestMarshaller.ForOneShot(new SandboxRequest(
            new SandboxPolicy(),
            "echo wslc")
        {
            Containment = new WslcContainment
            {
                Image = "alpine:3.20",
                ImageTarPath = @"C:\images\alpine.tar",
                CpuCount = 2,
                MemoryMb = 1024,
                Gpu = true,
                StoragePath = @"C:\wslc",
                PortMappings = [new WslcPortMapping(8080, 80)],
            },
        });
        Assert.Equal(TypedRequestMarshaller.ContainmentWslc, wslc.OneShotRequest->containment);
        Assert.Equal("alpine:3.20", OptionalString(wslc.OneShotRequest->wslc->image));
        Assert.Equal(@"C:\images\alpine.tar", OptionalString(wslc.OneShotRequest->wslc->image_tar_path));
        Assert.Equal((uint)2, wslc.OneShotRequest->wslc->cpu_count.value);
        Assert.Equal((ulong)1024, wslc.OneShotRequest->wslc->memory_mb.value);
        Assert.Equal(1, wslc.OneShotRequest->wslc->gpu);
        Assert.Equal(@"C:\wslc", OptionalString(wslc.OneShotRequest->wslc->storage_path));
        Assert.Equal((ushort)8080, wslc.OneShotRequest->wslc->port_mappings[0].windows_port);
        Assert.Equal((ushort)80, wslc.OneShotRequest->wslc->port_mappings[0].container_port);
    }

    [Fact]
    public void LifecycleMarshaller_MapsProvisionAndExecPresence()
    {
        using var provision = TypedRequestMarshaller.ForProvision(
            StateAwareContainment.Wslc,
            new WslcProvisionOptions
            {
                Filesystem = new StateAwareFilesystemPolicy
                {
                    ReadwritePaths = ["/work"],
                },
                Network = new StateAwareNetworkPolicy
                {
                    Ingress = new NetworkIngressPolicy { HostLoopback = NetworkAction.Allow },
                },
                Image = "alpine:latest",
                ImageTarPath = @"C:\images\alpine.tar",
                Telemetry = new TelemetrySettings { Enabled = true },
            });

        var provisionRequest = provision.StateAwareRequest;
        Assert.Equal(TypedRequestMarshaller.StateAwareProvision, provisionRequest->operation);
        Assert.Equal(TypedRequestMarshaller.StateAwareWslc, provisionRequest->provision->backend);
        Assert.Equal("alpine:latest", OptionalString(provisionRequest->provision->image));
        Assert.Equal(@"C:\images\alpine.tar", OptionalString(provisionRequest->provision->image_tar_path));
        Assert.Equal("/work", SingleString(provisionRequest->provision->filesystem->readwrite_paths));
        Assert.Equal(1, provisionRequest->provision->network->ingress->host_loopback.value);
        Assert.Equal(1, provisionRequest->telemetry_enabled.value);

        using var absentEnv = TypedRequestMarshaller.ForExec(
            new SandboxId("wslc:0123456789abcdef0123456789abcdef"),
            "echo absent",
            null);
        Assert.Equal(0, absentEnv.StateAwareRequest->exec->environment.is_set);
        Assert.Equal(0, absentEnv.StateAwareRequest->exec->inherit_default_env.is_set);

        using var emptyEnv = TypedRequestMarshaller.ForExec(
            new SandboxId("wslc:0123456789abcdef0123456789abcdef"),
            "echo empty",
            new WslcExecOptions
            {
                Environment = [],
                InheritDefaultEnvironment = false,
                RuntimeConfig = new NetworkRuntimeConfig
                {
                    NetworkProxy = "http://proxy.example:8080",
                },
            });
        Assert.Equal(1, emptyEnv.StateAwareRequest->exec->environment.is_set);
        Assert.Equal((nuint)0, emptyEnv.StateAwareRequest->exec->environment.len);
        Assert.Equal(1, emptyEnv.StateAwareRequest->exec->inherit_default_env.is_set);
        Assert.Equal(0, emptyEnv.StateAwareRequest->exec->inherit_default_env.value);
        Assert.Equal("http://proxy.example:8080", OptionalString(emptyEnv.StateAwareRequest->exec->network_proxy));
    }

    [Fact]
    public void Run_InvalidEnvironmentName_ReturnsNativeMalformedRequest()
    {
        var ex = Assert.Throws<MxcException>(() => MxcSandbox.Run(
            new SandboxRequest(new SandboxPolicy(), "echo bad")
            {
                Environment = new() { ["BAD=KEY"] = "value" },
            }));

        Assert.Equal(ErrorCode.MalformedRequest, ex.Code);
        Assert.Contains("environment", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void TypedLifecycleMetadata_ParsesIsolationSessionFields()
    {
        var name = Marshal.StringToCoTaskMemUTF8("agent-user");
        var sid = Marshal.StringToCoTaskMemUTF8("S-1-5-21-1");
        var workspace = Marshal.StringToCoTaskMemUTF8(@"C:\mxc\workspace");
        try
        {
            var result = new MxcTypedStateAwareResult
            {
                metadata_kind = TypedRequestMarshaller.ProvisionMetadataIsolationSession,
                agent_user_name_utf8 = (byte*)name,
                agent_user_sid_utf8 = (byte*)sid,
                ephemeral_workspace_path_utf8 = (byte*)workspace,
            };

            var metadata = MxcLifecycle.ParseTypedMetadata(result);

            Assert.NotNull(metadata.Json);
            using var document = JsonDocument.Parse(metadata.Json);
            Assert.Equal("agent-user", document.RootElement.GetProperty("agentUserName").GetString());
            Assert.Equal("S-1-5-21-1", metadata.IsolationSession!.AgentUserSid);
            Assert.Equal(@"C:\mxc\workspace", metadata.IsolationSession.EphemeralWorkspacePath);
        }
        finally
        {
            Marshal.FreeCoTaskMem(name);
            Marshal.FreeCoTaskMem(sid);
            Marshal.FreeCoTaskMem(workspace);
        }
    }

    [Fact]
    public void WindowsSandboxLifecycle_BuildsRawJsonEnvelopeOnDevelopmentContract()
    {
        var json = MxcLifecycle
            .BuildExecEnvelope(new SandboxId("wsb:01234567"), "cmd /c echo hi")
            .ToJsonString();
        using var document = JsonDocument.Parse(json);

        Assert.Equal(SchemaVersions.MaximumSupported, document.RootElement.GetProperty("version").GetString());
        Assert.Equal("exec", document.RootElement.GetProperty("phase").GetString());
        Assert.Equal("wsb:01234567", document.RootElement.GetProperty("sandboxId").GetString());
    }

    private static string SingleString(MxcUtf8SliceList list)
    {
        Assert.Equal((nuint)1, list.len);
        return String(list.items[0]);
    }

    private static string OptionalString(MxcUtf8Slice* value)
    {
        Assert.True(value is not null);
        return String(*value);
    }

    private static string String(MxcUtf8Slice value)
    {
        if (value.len == 0)
        {
            return string.Empty;
        }
        return Encoding.UTF8.GetString(new ReadOnlySpan<byte>(value.data, checked((int)value.len)));
    }
}
