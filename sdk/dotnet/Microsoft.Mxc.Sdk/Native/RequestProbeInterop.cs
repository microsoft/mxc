// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace Microsoft.Mxc.Sdk.Native;

internal unsafe interface IRequestProbeInterop
{
    bool IsSupportedOnCurrentPlatform { get; }

    int Probe(byte* requestJsonUtf8, byte** outputJsonUtf8, MxcErrorDetail* error);

    void FreeString(byte* value);

    void FreeError(MxcErrorDetail* error);
}

internal sealed unsafe class PInvokeRequestProbeInterop : IRequestProbeInterop
{
    internal static PInvokeRequestProbeInterop Instance { get; } = new();

    private PInvokeRequestProbeInterop()
    {
    }

    public bool IsSupportedOnCurrentPlatform => OperatingSystem.IsWindows();

    public int Probe(
        byte* requestJsonUtf8,
        byte** outputJsonUtf8,
        MxcErrorDetail* error) =>
        NativeMethods.mxc_probe_sandbox_request_json_with_error(
            requestJsonUtf8,
            outputJsonUtf8,
            error);

    public void FreeString(byte* value) =>
        NativeMethods.mxc_string_free(value);

    public void FreeError(MxcErrorDetail* error) =>
        NativeMethods.mxc_error_detail_free(error);
}
