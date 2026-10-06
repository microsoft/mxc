// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Diagnostics;
using Microsoft.Mxc.Sdk;
using Microsoft.Mxc.Sdk.V1;

static TelemetryConsentDecision PresentConsent(TelemetryConsentPrompt prompt)
{
    Console.WriteLine(prompt.Title.Text);
    Console.WriteLine();
    Console.WriteLine(prompt.Body.Text);
    Console.WriteLine();
    Console.WriteLine($"{prompt.LearnMoreLabel.Text}: {prompt.LearnMoreUrl}");

    while (true)
    {
        Console.Write(
            $"{prompt.AffirmativeLabel.Text} [y], {prompt.NegativeLabel.Text} [n], "
            + $"{prompt.LearnMoreLabel.Text} [l]: ");
        var response = Console.ReadLine();
        if (response is null)
        {
            return TelemetryConsentDecision.Dismissed;
        }

        switch (response.Trim().ToLowerInvariant())
        {
            case "y":
            case "yes":
                return TelemetryConsentDecision.Yes;
            case "n":
            case "no":
                return TelemetryConsentDecision.No;
            case "l":
                Process.Start(new ProcessStartInfo(prompt.LearnMoreUrl)
                {
                    UseShellExecute = true,
                });
                break;
            default:
                Console.Error.WriteLine("Enter y, n, or l.");
                break;
        }
    }
}

var support = MxcPlatform.GetPlatformSupport();
if (!support.IsSupported)
{
    Console.Error.WriteLine($"MXC is not supported: {support.Reason ?? "unknown reason"}");
    return 1;
}

try
{
    if (MxcTelemetry.NeedsConsentPrompt())
    {
        var outcome = MxcTelemetry.RequestConsent(PresentConsent, "en-US");
        Console.Error.WriteLine($"telemetry consent result: {outcome.Result}");
    }

    var consent = MxcTelemetry.GetConsent();
    if (consent != TelemetryConsentState.Granted)
    {
        Console.Error.WriteLine($"telemetry is not authorized ({consent}) and will remain off");
    }

    var sampleCommand = OperatingSystem.IsWindows()
        ? "cmd.exe /d /s /c \"echo hello from telemetry\""
        : "sh -c \"printf 'hello from telemetry\\n'\"";
    var request = new ContainerRequest(sampleCommand)
    {
        Containment = new Containment.Process(),
        TimeoutMs = 30_000,
    };

    // This opts only this invocation into optional diagnostic telemetry. In a
    // Microsoft telemetry-routed build, authorized diagnostics may be sent to
    // Microsoft. Commands, output, credentials, and customer content are excluded.
    var options = new RunOptions
    {
        Telemetry = new TelemetryConfig
        {
            Enabled = true,
        },
    };
    await MxcContainer.RunAsync(request, options);
    return 0;
}
catch (MxcException error)
{
    Console.Error.WriteLine($"MXC error [{error.Code}]: {error.Message}");
    return 1;
}
