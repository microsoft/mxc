// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Mxc.Sdk;

namespace Microsoft.Mxc.Sdk.Native;

internal unsafe sealed class TypedRequestMarshaller : IDisposable
{
    internal const uint TypedAbiVersion = 1;

    internal const int ContainmentProcess = 0;
    internal const int ContainmentProcessContainer = 1;
    internal const int ContainmentBubblewrap = 2;
    internal const int ContainmentLxc = 3;
    internal const int ContainmentSeatbelt = 4;
    internal const int ContainmentWslc = 5;
    internal const int ContainmentIsolationSession = 6;

    internal const int StateAwareProvision = 0;
    internal const int StateAwareStart = 1;
    internal const int StateAwareExec = 2;
    internal const int StateAwareStop = 3;
    internal const int StateAwareDeprovision = 4;

    internal const int StateAwareIsolationSession = 0;
    internal const int StateAwareWslc = 1;

    internal const int ProvisionMetadataNone = 0;
    internal const int ProvisionMetadataIsolationSession = 1;

    private readonly List<nint> allocations = new();
    private bool disposed;

    private TypedRequestMarshaller()
    {
    }

    internal MxcTypedOneShotRequest* OneShotRequest { get; private set; }

    internal MxcTypedStateAwareRequest* StateAwareRequest { get; private set; }

    internal static TypedRequestMarshaller ForOneShot(SandboxRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        var marshaller = new TypedRequestMarshaller();
        try
        {
            marshaller.OneShotRequest = marshaller.BuildOneShotRequest(request);
            return marshaller;
        }
        catch
        {
            marshaller.Dispose();
            throw;
        }
    }

    internal static TypedRequestMarshaller ForProvision(
        StateAwareContainment containment,
        StateAwareProvisionOptions? options)
    {
        var marshaller = new TypedRequestMarshaller();
        try
        {
            var provision = marshaller.BuildProvisionRequest(containment, options);
            marshaller.StateAwareRequest = marshaller.BuildStateAwareRequest(
                StateAwareProvision,
                sandboxId: null,
                provision,
                exec: null,
                Telemetry(options?.Telemetry),
                experimental: false);
            return marshaller;
        }
        catch
        {
            marshaller.Dispose();
            throw;
        }
    }

    internal static TypedRequestMarshaller ForLifecycleId(
        int operation,
        SandboxId id,
        StateAwarePhaseOptions? options)
    {
        var marshaller = new TypedRequestMarshaller();
        try
        {
            marshaller.StateAwareRequest = marshaller.BuildStateAwareRequest(
                operation,
                id.Value,
                provision: null,
                exec: null,
                Telemetry(options?.Telemetry),
                experimental: false);
            return marshaller;
        }
        catch
        {
            marshaller.Dispose();
            throw;
        }
    }

    internal static TypedRequestMarshaller ForExec(
        SandboxId id,
        string command,
        StateAwareExecOptions? options)
    {
        ArgumentNullException.ThrowIfNull(command);
        var marshaller = new TypedRequestMarshaller();
        try
        {
            var exec = marshaller.BuildExecRequest(command, options);
            marshaller.StateAwareRequest = marshaller.BuildStateAwareRequest(
                StateAwareExec,
                id.Value,
                provision: null,
                exec,
                Telemetry(options?.Telemetry),
                experimental: false);
            return marshaller;
        }
        catch
        {
            marshaller.Dispose();
            throw;
        }
    }

    public void Dispose()
    {
        if (disposed)
        {
            return;
        }
        disposed = true;
        for (var i = allocations.Count - 1; i >= 0; i--)
        {
            NativeMemory.Free((void*)allocations[i]);
        }
        allocations.Clear();
    }

    private MxcTypedOneShotRequest* BuildOneShotRequest(SandboxRequest request)
    {
        var containment = BuildContainment(request.Containment);
        return AllocateStruct(new MxcTypedOneShotRequest
        {
            abi_version = TypedAbiVersion,
            struct_size = (nuint)sizeof(MxcTypedOneShotRequest),
            policy = BuildSandboxPolicy(request.Policy),
            command = Slice(request.Command),
            containment = containment.Discriminant,
            process_container = containment.ProcessContainer,
            seatbelt = containment.Seatbelt,
            lxc = containment.Lxc,
            wslc = containment.Wslc,
            container_name = OptionalString(request.ContainerName),
            working_directory = OptionalString(request.WorkingDirectory),
            environment = BuildEnvironment(request.Environment),
            inherit_default_env = Flag(
                request.InheritDefaultEnvironment && request.Environment is not null),
            experimental = Flag(request.Experimental),
        });
    }

    private readonly struct ContainmentPointers
    {
        internal ContainmentPointers(
            int discriminant,
            MxcTypedProcessContainer* processContainer,
            MxcTypedSeatbelt* seatbelt,
            MxcTypedLxc* lxc,
            MxcTypedWslc* wslc)
        {
            Discriminant = discriminant;
            ProcessContainer = processContainer;
            Seatbelt = seatbelt;
            Lxc = lxc;
            Wslc = wslc;
        }

        internal int Discriminant { get; }

        internal MxcTypedProcessContainer* ProcessContainer { get; }

        internal MxcTypedSeatbelt* Seatbelt { get; }

        internal MxcTypedLxc* Lxc { get; }

        internal MxcTypedWslc* Wslc { get; }
    }

    private ContainmentPointers BuildContainment(SandboxContainment containment) => containment switch
        {
            ProcessContainment => new(ContainmentProcess, null, null, null, null),
            ProcessContainerContainment processContainer =>
                new(ContainmentProcessContainer, BuildProcessContainer(processContainer), null, null, null),
            BubblewrapContainment => new(ContainmentBubblewrap, null, null, null, null),
            LxcContainment lxc => new(ContainmentLxc, null, null, BuildLxc(lxc), null),
            SeatbeltContainment seatbelt =>
                new(ContainmentSeatbelt, null, BuildSeatbelt(seatbelt), null, null),
            WslcContainment wslc => new(ContainmentWslc, null, null, null, BuildWslc(wslc)),
            IsolationSessionContainment => new(ContainmentIsolationSession, null, null, null, null),
            _ => throw new MxcException(
                ErrorCode.UnsupportedContainment,
                $"unknown containment type '{containment.GetType().Name}'"),
        };

    private MxcTypedSandboxPolicy* BuildSandboxPolicy(SandboxPolicy policy) =>
        AllocateStruct(new MxcTypedSandboxPolicy
        {
            filesystem = BuildFilesystem(policy.Filesystem),
            network = BuildNetwork(policy.Network),
            ui = BuildUi(policy.Ui),
            timeout_ms = OptionalU32(policy.TimeoutMs),
            telemetry_enabled = Telemetry(policy.Telemetry),
        });

    private MxcTypedFilesystemPolicy* BuildFilesystem(FilesystemPolicy? policy) =>
        policy is null
            ? null
            : AllocateStruct(new MxcTypedFilesystemPolicy
            {
                readwrite_paths = StringList(policy.ReadwritePaths),
                readonly_paths = StringList(policy.ReadonlyPaths),
                denied_paths = StringList(policy.DeniedPaths),
                clear_policy_on_exit = OptionalBool(policy.ClearPolicyOnExit),
            });

    private MxcTypedFilesystemPolicy* BuildFilesystem(StateAwareFilesystemPolicy? policy) =>
        policy is null
            ? null
            : AllocateStruct(new MxcTypedFilesystemPolicy
            {
                readwrite_paths = StringList(policy.ReadwritePaths),
                readonly_paths = StringList(policy.ReadonlyPaths),
                denied_paths = StringList(policy.DeniedPaths),
                clear_policy_on_exit = default,
            });

    private MxcTypedNetworkPolicy* BuildNetwork(NetworkPolicy? policy) =>
        policy is null
            ? null
            : AllocateStruct(new MxcTypedNetworkPolicy
            {
                egress = BuildEgress(policy.Egress),
                ingress = BuildIngress(policy.Ingress),
                network_proxy = OptionalString(policy.RuntimeConfig?.NetworkProxy),
            });

    private MxcTypedNetworkPolicy* BuildNetwork(StateAwareNetworkPolicy? policy) =>
        policy is null
            ? null
            : AllocateStruct(new MxcTypedNetworkPolicy
            {
                egress = BuildEgress(policy.Egress),
                ingress = BuildIngress(policy.Ingress),
                network_proxy = null,
            });

    private MxcTypedNetworkEgress* BuildEgress(NetworkEgressPolicy? policy) =>
        policy is null
            ? null
            : AllocateStruct(new MxcTypedNetworkEgress
            {
                default_action = OptionalNetworkAction(policy.Default),
                allow_is_set = Flag(policy.Allow is not null),
                allow = BuildRules(policy.Allow),
                allow_len = (nuint)(policy.Allow?.Count ?? 0),
                deny_is_set = Flag(policy.Deny is not null),
                deny = BuildRules(policy.Deny),
                deny_len = (nuint)(policy.Deny?.Count ?? 0),
            });

    private MxcTypedNetworkIngress* BuildIngress(NetworkIngressPolicy? policy) =>
        policy is null
            ? null
            : AllocateStruct(new MxcTypedNetworkIngress
            {
                default_action = OptionalNetworkAction(policy.Default),
                host_loopback = OptionalNetworkAction(policy.HostLoopback),
            });

    private MxcTypedNetworkRule* BuildRules(IReadOnlyList<NetworkRulePolicy>? rules)
    {
        if (rules is null || rules.Count == 0)
        {
            return null;
        }
        var native = new MxcTypedNetworkRule[rules.Count];
        for (var i = 0; i < rules.Count; i++)
        {
            var rule = rules[i];
            native[i] = new MxcTypedNetworkRule
            {
                to_is_set = Flag(rule.To is not null),
                to = BuildPeers(rule.To),
                to_len = (nuint)(rule.To?.Count ?? 0),
                ports_is_set = Flag(rule.Ports is not null),
                ports = BuildPorts(rule.Ports),
                ports_len = (nuint)(rule.Ports?.Count ?? 0),
            };
        }
        return AllocateArray(native);
    }

    private MxcTypedNetworkPeer* BuildPeers(IReadOnlyList<NetworkPeerPolicy>? peers)
    {
        if (peers is null || peers.Count == 0)
        {
            return null;
        }
        var native = new MxcTypedNetworkPeer[peers.Count];
        for (var i = 0; i < peers.Count; i++)
        {
            var peer = peers[i];
            native[i] = new MxcTypedNetworkPeer
            {
                cidr = Slice(peer.Cidr),
                except_is_set = Flag(peer.Except is not null),
                except = StringList(peer.Except ?? []),
            };
        }
        return AllocateArray(native);
    }

    private MxcTypedNetworkPort* BuildPorts(IReadOnlyList<NetworkPortPolicy>? ports)
    {
        if (ports is null || ports.Count == 0)
        {
            return null;
        }
        var native = new MxcTypedNetworkPort[ports.Count];
        for (var i = 0; i < ports.Count; i++)
        {
            var port = ports[i];
            native[i] = new MxcTypedNetworkPort
            {
                protocol = OptionalProtocol(port.Protocol),
                port = OptionalU16(port.Port),
                end_port = OptionalU16(port.EndPort),
            };
        }
        return AllocateArray(native);
    }

    private MxcTypedUiPolicy* BuildUi(UiPolicy? policy) =>
        policy is null
            ? null
            : AllocateStruct(new MxcTypedUiPolicy
            {
                allow_windows = Flag(policy.AllowWindows),
                clipboard = (int)policy.Clipboard,
                allow_input_injection = Flag(policy.AllowInputInjection),
            });

    private MxcTypedProcessContainer* BuildProcessContainer(ProcessContainerContainment containment) =>
        AllocateStruct(new MxcTypedProcessContainer
        {
            least_privilege = Flag(containment.LeastPrivilege),
            learning_mode = Flag(containment.LearningMode),
            capabilities = StringList(containment.Capabilities),
            capture_denials = BuildCaptureDenials(containment.CaptureDenials),
            ui = BuildProcessContainerUi(containment.Ui),
            enumerate_paths = StringList(containment.Filesystem?.EnumeratePaths ?? []),
            allowed_proxy_peer = OptionalString(containment.Network?.AllowedProxyPeer),
        });

    private MxcTypedCaptureDenials* BuildCaptureDenials(CaptureDenialsPolicy? policy) =>
        policy is null
            ? null
            : AllocateStruct(new MxcTypedCaptureDenials
            {
                mode = (int)policy.Mode,
                output_path = OptionalString(policy.OutputPath),
                retain_etl = Flag(policy.RetainEtl),
            });

    private MxcTypedProcessContainerUi* BuildProcessContainerUi(ProcessContainerUiPolicy? policy) =>
        policy is null
            ? null
            : AllocateStruct(new MxcTypedProcessContainerUi
            {
                isolation = (int)policy.Isolation,
                desktop_system_control = Flag(policy.DesktopSystemControl),
                system_settings = (int)policy.SystemSettings,
                ime = Flag(policy.Ime),
            });

    private MxcTypedSeatbelt* BuildSeatbelt(SeatbeltContainment containment) =>
        AllocateStruct(new MxcTypedSeatbelt
        {
            profile_override = OptionalString(containment.ProfileOverride),
            gui_access = Flag(containment.GuiAccess),
            nested_pty = Flag(containment.NestedPty),
            keychain_access = Flag(containment.KeychainAccess),
            extra_mach_lookups = StringList(containment.ExtraMachLookups),
        });

    private MxcTypedLxc* BuildLxc(LxcContainment containment) =>
        AllocateStruct(new MxcTypedLxc
        {
            distribution = OptionalString(containment.Distribution),
            release = OptionalString(containment.Release),
        });

    private MxcTypedWslc* BuildWslc(WslcContainment containment)
    {
        var mappings = containment.PortMappings
            .Select(mapping => new MxcTypedWslcPortMapping
            {
                windows_port = mapping.WindowsPort,
                container_port = mapping.ContainerPort,
            })
            .ToArray();
        return AllocateStruct(new MxcTypedWslc
        {
            image = OptionalString(containment.Image),
            image_tar_path = OptionalString(containment.ImageTarPath),
            cpu_count = OptionalU32(containment.CpuCount),
            memory_mb = OptionalU64(containment.MemoryMb),
            gpu = Flag(containment.Gpu),
            storage_path = OptionalString(containment.StoragePath),
            port_mappings = AllocateArray(mappings),
            port_mappings_len = (nuint)mappings.Length,
        });
    }

    private MxcTypedProvisionRequest* BuildProvisionRequest(
        StateAwareContainment containment,
        StateAwareProvisionOptions? options) => options switch
        {
            IsolationSessionProvisionOptions isolation => AllocateStruct(new MxcTypedProvisionRequest
            {
                backend = StateAwareIsolationSession,
                app_id = OptionalString(isolation.AppId),
                image = null,
                image_tar_path = null,
                filesystem = null,
                network = BuildNetwork(isolation.Network),
            }),
            WslcProvisionOptions wslc => AllocateStruct(new MxcTypedProvisionRequest
            {
                backend = StateAwareWslc,
                app_id = null,
                image = OptionalString(wslc.Image),
                image_tar_path = OptionalString(wslc.ImageTarPath),
                filesystem = BuildFilesystem(wslc.Filesystem),
                network = BuildNetwork(wslc.Network),
            }),
            null when containment == StateAwareContainment.Wslc => AllocateStruct(new MxcTypedProvisionRequest
            {
                backend = StateAwareWslc,
                app_id = null,
                image = null,
                image_tar_path = null,
                filesystem = null,
                network = null,
            }),
            _ => throw new ArgumentException(
                options is null
                    ? $"{containment} requires backend-specific provision options"
                    : $"{options.GetType().Name} cannot configure {containment}",
                nameof(options)),
        };

    private MxcTypedExecRequest* BuildExecRequest(string command, StateAwareExecOptions? options) =>
        AllocateStruct(new MxcTypedExecRequest
        {
            command = Slice(command),
            working_directory = OptionalString(options?.WorkingDirectory),
            environment = BuildExecEnvironment(options?.Environment),
            inherit_default_env = OptionalBool(options?.InheritDefaultEnvironment),
            timeout_ms = OptionalU32(options?.TimeoutMs),
            network_proxy = OptionalString(
                options is WslcExecOptions wslc ? wslc.RuntimeConfig?.NetworkProxy : null),
        });

    private MxcTypedStateAwareRequest* BuildStateAwareRequest(
        int operation,
        string? sandboxId,
        MxcTypedProvisionRequest* provision,
        MxcTypedExecRequest* exec,
        MxcOptionalBool telemetry,
        bool experimental) => AllocateStruct(new MxcTypedStateAwareRequest
        {
            abi_version = TypedAbiVersion,
            struct_size = (nuint)sizeof(MxcTypedStateAwareRequest),
            operation = operation,
            sandbox_id = OptionalString(sandboxId),
            provision = provision,
            exec = exec,
            telemetry_enabled = telemetry,
            experimental = Flag(experimental),
        });

    private MxcEnvironment BuildEnvironment(Dictionary<string, string>? environment)
    {
        if (environment is null)
        {
            return default;
        }
        var entries = environment
            .OrderBy(pair => pair.Key, StringComparer.Ordinal)
            .Select(pair => new MxcEnvironmentEntry
            {
                key = Slice(pair.Key),
                value = Slice(pair.Value),
            })
            .ToArray();
        return new MxcEnvironment
        {
            is_set = 1,
            entries = AllocateArray(entries),
            len = (nuint)entries.Length,
        };
    }

    private MxcEnvironment BuildExecEnvironment(IReadOnlyList<string>? environment)
    {
        if (environment is null)
        {
            return default;
        }
        var entries = new MxcEnvironmentEntry[environment.Count];
        for (var i = 0; i < environment.Count; i++)
        {
            var item = environment[i];
            var separator = item.IndexOf('=', StringComparison.Ordinal);
            var key = separator < 0 ? item : item[..separator];
            var value = separator < 0 ? string.Empty : item[(separator + 1)..];
            entries[i] = new MxcEnvironmentEntry
            {
                key = Slice(key),
                value = Slice(value),
            };
        }
        return new MxcEnvironment
        {
            is_set = 1,
            entries = AllocateArray(entries),
            len = (nuint)entries.Length,
        };
    }

    private MxcUtf8Slice* OptionalString(string? value) =>
        value is null ? null : AllocateStruct(Slice(value));

    private MxcUtf8Slice Slice(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        var bytes = Encoding.UTF8.GetBytes(value);
        var data = AllocateBytes(bytes);
        return new MxcUtf8Slice
        {
            data = data,
            len = (nuint)bytes.Length,
        };
    }

    private MxcUtf8SliceList StringList(IEnumerable<string> values)
    {
        var slices = values.Select(Slice).ToArray();
        return new MxcUtf8SliceList
        {
            items = AllocateArray(slices),
            len = (nuint)slices.Length,
        };
    }

    private byte* AllocateBytes(byte[] bytes)
    {
        if (bytes.Length == 0)
        {
            return null;
        }
        var destination = (byte*)Allocate((nuint)bytes.Length);
        fixed (byte* source = bytes)
        {
            Buffer.MemoryCopy(source, destination, bytes.Length, bytes.Length);
        }
        return destination;
    }

    private T* AllocateStruct<T>(T value)
        where T : unmanaged
    {
        var pointer = (T*)Allocate((nuint)sizeof(T));
        *pointer = value;
        return pointer;
    }

    private T* AllocateArray<T>(IReadOnlyList<T> values)
        where T : unmanaged
    {
        if (values.Count == 0)
        {
            return null;
        }
        var pointer = (T*)Allocate((nuint)(sizeof(T) * values.Count));
        for (var i = 0; i < values.Count; i++)
        {
            pointer[i] = values[i];
        }
        return pointer;
    }

    private void* Allocate(nuint bytes)
    {
        var pointer = NativeMemory.Alloc(bytes);
        allocations.Add((nint)pointer);
        return pointer;
    }

    private static MxcOptionalBool Telemetry(TelemetrySettings? telemetry) =>
        telemetry is null ? default : OptionalBool(telemetry.Enabled);

    private static MxcOptionalBool OptionalBool(bool? value) => new()
    {
        is_set = value.HasValue ? 1 : 0,
        value = Flag(value.GetValueOrDefault()),
    };

    private static MxcOptionalU16 OptionalU16(ushort? value) => new()
    {
        is_set = value.HasValue ? 1 : 0,
        value = value.GetValueOrDefault(),
    };

    private static MxcOptionalU32 OptionalU32(uint? value) => new()
    {
        is_set = value.HasValue ? 1 : 0,
        value = value.GetValueOrDefault(),
    };

    private static MxcOptionalU64 OptionalU64(ulong? value) => new()
    {
        is_set = value.HasValue ? 1 : 0,
        value = value.GetValueOrDefault(),
    };

    private static MxcOptionalI32 OptionalNetworkAction(NetworkAction? value) => new()
    {
        is_set = value.HasValue ? 1 : 0,
        value = value switch
        {
            NetworkAction.Allow => 1,
            NetworkAction.Deny => 0,
            _ => 0,
        },
    };

    private static MxcOptionalI32 OptionalProtocol(NetworkProtocol? value) => new()
    {
        is_set = value.HasValue ? 1 : 0,
        value = value.HasValue ? (int)value.Value : 0,
    };

    private static int Flag(bool value) => value ? 1 : 0;
}
