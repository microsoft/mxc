// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;
using Dev = Microsoft.Mxc.Sdk.V1.Dev;
using Microsoft.Mxc.Sdk.V1;
using Xunit;

namespace Microsoft.Mxc.Sdk.Tests;

public class DevEntryPointTests
{
    private static bool HostCanPreparePolicy =>
        OperatingSystem.IsWindows()
        && Environment.GetEnvironmentVariable("MXC_E2E_PSEC_CAPABLE_HOST") == "1";

    [Fact]
    public async Task DevEntryPointsRejectInvalidDocumentsWithoutLaunching()
    {
        var synchronous = Assert.Throws<MxcException>(
            () => Dev.MxcContainer.SpawnWithPtyJson("{}"));
        Assert.Equal(ErrorCode.MalformedRequest, synchronous.Code);

        var asynchronous = await Assert.ThrowsAsync<MxcException>(
            () => Dev.MxcLifecycle.ProvisionContainerJsonAsync("{}"));
        Assert.Equal(ErrorCode.MalformedRequest, asynchronous.Code);
    }

    [Fact]
    public async Task PhaseSpecificMethodsRejectMismatchesBeforeDispatch()
    {
        const string start = """{"version":"1.0.0","phase":"start","sandboxId":"iso:unused"}""";
        var sync = Assert.Throws<MxcException>(() => Dev.MxcLifecycle.StopContainerJson(start));
        Assert.Equal(ErrorCode.MalformedRequest, sync.Code);
        Assert.Contains("requires phase 'stop'", sync.Message);

        var asynchronous = await Assert.ThrowsAsync<MxcException>(
            () => Dev.MxcLifecycle.ValidateProcessJsonAsync(start));
        Assert.Equal(ErrorCode.MalformedRequest, asynchronous.Code);

        var exec = Assert.Throws<MxcException>(
            () => Dev.MxcLifecycle.SpawnInContainerJson(start));
        Assert.Equal(ErrorCode.MalformedRequest, exec.Code);

        const string duplicate =
            """{"version":"1.0.0","phase":"start","phase":"stop","sandboxId":"iso:unused"}""";
        var repeated = Assert.Throws<MxcException>(
            () => Dev.MxcLifecycle.StartContainerJson(duplicate));
        Assert.Equal(ErrorCode.MalformedRequest, repeated.Code);
    }

    [Fact]
    public async Task CapturedExecValidatesBeforeCanceledSpawn()
    {
        const string start = """{"version":"1.0.0","phase":"start","sandboxId":"iso:unused"}""";
        var error = await Assert.ThrowsAsync<MxcException>(
            () => Dev.MxcLifecycle.RunInContainerJsonAsync(
                start, cancellationToken: new CancellationToken(true)));
        Assert.Equal(ErrorCode.MalformedRequest, error.Code);
        Assert.Contains("RunInContainerJson requires phase 'exec'", error.Message);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("exec")]
    public void PreparationPreservesUnicodeJsonAndExtractsTimeout(string? phase)
    {
        var json =
            " {\"version\":\"1.1.0-alpha\",\"_comment\":\"caf\u00e9 \ud83d\ude00\"," +
            (phase is null ? "" : "\"phase\":\"exec\",\"sandboxId\":\"iso:unused\",") +
            "\"process\":{\"commandLine\":\"echo\",\"timeout\":250}} ";
        var (request, timeout) = Dev.DevJsonRequest.Prepare(
            json, nameof(PreparationPreservesUnicodeJsonAndExtractsTimeout), phase);
        Assert.Equal((uint?)250, timeout);
        Assert.Equal((byte)0, request[^1]);
        Assert.Equal(json, Encoding.UTF8.GetString(request.AsSpan(0, request.Length - 1)));
    }

    [Fact]
    public void ExactContractErrorsReachPublicDevFacade()
    {
        const string unregistered =
            """{"version":"999.0.0","process":{"commandLine":"echo must-not-run"}}""";
        var error = Assert.Throws<MxcException>(() => Dev.MxcContainer.RunJson(unregistered));
        Assert.Equal(ErrorCode.MalformedRequest, error.Code);

        const string unknownField =
            """{"version":"1.0.0","phase":"start","sandboxId":"iso:unused","extra":true}""";
        error = Assert.Throws<MxcException>(
            () => Dev.MxcLifecycle.ValidateStartJson(unknownField));
        Assert.Equal(ErrorCode.MalformedRequest, error.Code);
    }

    [Fact]
    public void ExperimentalAuthorizationIsSeparateFromTheDevelopmentContract()
    {
        const string json =
            """{"version":"1.1.0-alpha","phase":"provision","containment":"windows_sandbox"}""";
        var error = Assert.Throws<MxcException>(
            () => Dev.MxcLifecycle.ValidateProvisionJson(json));
        Assert.Equal(ErrorCode.BackendUnavailable, error.Code);
        Assert.Contains("experimental", error.Message);

        try
        {
            Dev.MxcLifecycle.ValidateProvisionJson(json, new Dev.JsonOptions { Experimental = true });
        }
        catch (MxcException authorized)
        {
            Assert.NotEqual(ErrorCode.BackendUnavailable, authorized.Code);
        }
    }

    [Fact]
    public void EmbeddedNullCannotChangeTheNativeDocument()
    {
        const string json = """{"version":"1.0.0","process":{"commandLine":"echo"}}""" + "\0";
        var error = Assert.Throws<MxcException>(() => Dev.MxcContainer.RunJson(json));
        Assert.Equal(ErrorCode.MalformedRequest, error.Code);
    }

    [Theory]
    [InlineData('\uD800')]
    [InlineData('\uDC00')]
    public async Task LoneSurrogatesAreMalformedRequests(char surrogate)
    {
        var creation = """{"version":"1.0.0","process":{"commandLine":"echo"}}""" + surrogate;
        var start = """{"version":"1.0.0","phase":"start","sandboxId":"iso:unused"}""" + surrogate;
        var sync = Assert.Throws<MxcException>(() => Dev.MxcContainer.RunJson(creation));
        Assert.Equal(ErrorCode.MalformedRequest, sync.Code);
        sync = Assert.Throws<MxcException>(() => Dev.MxcLifecycle.StartContainerJson(start));
        Assert.Equal(ErrorCode.MalformedRequest, sync.Code);

        var asynchronous = await Assert.ThrowsAsync<MxcException>(
            () => Dev.MxcContainer.RunJsonAsync(
                creation, cancellationToken: TestContext.Current.CancellationToken));
        Assert.Equal(ErrorCode.MalformedRequest, asynchronous.Code);
        asynchronous = await Assert.ThrowsAsync<MxcException>(
            () => Dev.MxcLifecycle.StartContainerJsonAsync(start));
        Assert.Equal(ErrorCode.MalformedRequest, asynchronous.Code);
    }

    [Fact]
    public void DeepCommentReachesNativeExactParser()
    {
        static string Request(int depth) =>
            "{\"version\":\"1.0.0\",\"phase\":\"start\",\"sandboxId\":\"nosuchbackend:abc123\",\"_comment\":" +
            new string('[', depth) + "0" + new string(']', depth) + "}";

        var accepted = Assert.Throws<MxcException>(
            () => Dev.MxcLifecycle.ValidateStartJson(Request(70)));
        Assert.Equal(ErrorCode.UnsupportedContainment, accepted.Code);

        var tooDeep = Assert.Throws<MxcException>(
            () => Dev.MxcLifecycle.ValidateStartJson(Request(130)));
        Assert.Equal(ErrorCode.MalformedRequest, tooDeep.Code);
    }

    [Fact]
    public void ExistingContainerExecReachesNativeBackendValidation()
    {
        const string json =
            """{"version":"1.0.0","phase":"exec","sandboxId":"nosuchbackend:abc123","process":{"commandLine":"echo hi"}}""";
        var error = Assert.Throws<MxcException>(
            () => Dev.MxcLifecycle.SpawnInContainerJson(json));
        Assert.Equal(ErrorCode.UnsupportedContainment, error.Code);
    }

    [Fact]
    public void PtyEntryPointsHaveNoAsyncOverloads()
    {
        Assert.Null(typeof(Dev.MxcContainer).GetMethod("SpawnWithPtyJsonAsync"));
        Assert.Null(typeof(Dev.MxcLifecycle).GetMethod("SpawnInContainerWithPtyJsonAsync"));
    }

    [Fact]
    public void DevOptionsAreClosedAndTerminalControlsStayWithPtyOperations()
    {
        Assert.True(typeof(Dev.JsonOptions).IsSealed);
        Assert.True(typeof(Dev.PtyJsonOptions).IsSealed);
        Assert.False(typeof(Dev.JsonOptions).IsAssignableFrom(typeof(Dev.PtyJsonOptions)));
        Assert.Null(typeof(Dev.PtyJsonOptions).GetProperty("PolicyFailures"));
    }

    [Fact]
    public void PolicyFailureStoragePreservesUnknownValuesBatchBoundariesAndResourcePresence()
    {
        ushort[] malformedResource = [0xD800, 0, 0xDC00];
        var failures = new Dev.PolicyFailures
        {
            Results =
            [
                new()
                {
                    Version = 99,
                    MinimumReaderVersion = 98,
                    Outcome = uint.MaxValue,
                    Details =
                    [
                        new()
                        {
                            FailureClass = uint.MaxValue,
                            FailureReason = uint.MaxValue - 1,
                            RequiredAction = uint.MaxValue - 2,
                            ResourceKind = uint.MaxValue - 3,
                            ValueKind = uint.MaxValue - 4,
                            Flags = uint.MaxValue,
                            RequestedValue = ulong.MaxValue,
                            RequiredValue = 9_007_199_254_740_993,
                            Resource = malformedResource,
                        },
                        new() { Resource = [] },
                        new(),
                        new() { Resource = [0xD83D, 0xDE00] },
                    ],
                },
                new()
                {
                    Outcome = Dev.PolicyFailureOutcomes.Blocked,
                    Details =
                    [
                        new()
                        {
                            FailureClass = Dev.PolicyFailureClasses.Filesystem,
                            FailureReason = Dev.PolicyFailureReasons.AccessExceedsCeiling,
                            RequiredAction = Dev.PolicyFailureActions.RestrictFilesystemAccess,
                            ResourceKind = Dev.PolicyFailureResourceKinds.Path,
                            ValueKind = Dev.PolicyFailureValueKinds.Access,
                            Flags = Dev.PolicyFailureFlags.HasActionableDetails | Dev.PolicyFailureFlags.ResourceComplete,
                            RequestedValue = Dev.PolicyFailureAccessValues.ReadWrite,
                            RequiredValue = Dev.PolicyFailureAccessValues.ReadOnly,
                        },
                    ],
                },
            ],
        };

        var stored = failures.ToJson();
        var restored = Dev.PolicyFailures.FromJson(stored);
        Assert.Equal(stored, restored.ToJson());
        Assert.Equal(2, restored.Results.Length);
        Assert.Equal((uint)99, restored.Results[0].Version);
        Assert.Equal((uint)98, restored.Results[0].MinimumReaderVersion);
        Assert.Equal(uint.MaxValue, restored.Results[0].Outcome);
        var first = restored.Results[0].Details[0];
        Assert.Equal(ulong.MaxValue, first.RequestedValue);
        Assert.Equal(9_007_199_254_740_993UL, first.RequiredValue);
        Assert.Equal(uint.MaxValue, first.Flags);
        Assert.Equal(malformedResource, first.Resource);
        var decoding = Assert.Throws<DecoderFallbackException>(() => first.GetResourceText());
        Assert.Equal("policy resource is not valid UTF-16", decoding.Message);
        Assert.Null(decoding.InnerException);
        Assert.Equal(string.Empty, restored.Results[0].Details[1].GetResourceText());
        Assert.Null(restored.Results[0].Details[2].GetResourceText());
        Assert.Equal("\uD83D\uDE00", restored.Results[0].Details[3].GetResourceText());
        using var document = JsonDocument.Parse(stored);
        var known = document.RootElement.GetProperty("results")[1];
        Assert.Equal(1u, known.GetProperty("outcome").GetUInt32());
        Assert.True(JsonNode.DeepEquals(
            JsonNode.Parse("""
                {"failureClass":2,"failureReason":2,"requiredAction":2,"resourceKind":1,
                 "valueKind":1,"flags":3,"requestedValue":"2","requiredValue":"1"}
                """),
            JsonNode.Parse(known.GetProperty("details")[0].GetRawText())));
        var details = document.RootElement.GetProperty("results")[0].GetProperty("details");
        Assert.Equal("18446744073709551615", details[0].GetProperty("requestedValue").GetString());
        Assert.Equal("9007199254740993", details[0].GetProperty("requiredValue").GetString());
        Assert.Equal(0, details[1].GetProperty("resource").GetArrayLength());
        Assert.False(details[2].TryGetProperty("resource", out _));
        Assert.Equal(new ushort[] { 0xD800, 0, 0xDC00 }, malformedResource);
        Assert.Equal(stored, failures.ToJson());
        var nullable = JsonNode.Parse(stored)!;
        nullable["results"]![0]!["details"]![2]!["resource"] = null;
        var normalized = Dev.PolicyFailures.FromJson(nullable.ToJsonString());
        Assert.Null(normalized.Results[0].Details[2].Resource);
        Assert.Equal(stored, normalized.ToJson());
    }

    [Fact]
    public void PolicyFailureStorageRejectsInvalidShapeVersionAndLossyValues()
    {
        foreach (var json in new[]
        {
            "null", "[]", "{}",
            """{"formatVersion":2,"results":[]}""",
            """{"formatVersion":1,"results":null}""",
            """{"formatVersion":1,"results":[null]}""",
            """{"formatVersion":1,"results":[],"extra":true}""",
            """{"formatVersion":1,"formatVersion":1,"results":[]}""",
            """{"formatVersion":1,"results":[{"version":1,"minimumReaderVersion":1,"outcome":1,"details":null}]}""",
        })
        {
            Assert.Throws<JsonException>(() => Dev.PolicyFailures.FromJson(json));
        }

        var valid = new Dev.PolicyFailures
        {
            Results = [new() { Details = [new() { RequestedValue = ulong.MaxValue }] }],
        }.ToJson();
        foreach (var invalid in new[] { "2", "\"18446744073709551616\"", "\"-1\"", "\"+1\"", "\"1\\u0000\"" })
        {
            var json = JsonNode.Parse(valid)!;
            json["results"]![0]!["details"]![0]!["requestedValue"] = JsonNode.Parse(invalid);
            Assert.Throws<JsonException>(() => Dev.PolicyFailures.FromJson(json.ToJsonString()));
        }
        foreach (var invalid in new[] { """{"extra":true}""", """{"resource":[65536]}""", """{"flags":-1}""" })
        {
            var json = JsonNode.Parse(valid)!;
            foreach (var property in JsonNode.Parse(invalid)!.AsObject())
            {
                json["results"]![0]!["details"]![0]![property.Key] = property.Value?.DeepClone();
            }
            Assert.Throws<JsonException>(() => Dev.PolicyFailures.FromJson(json.ToJsonString()));
        }
    }

    [Fact]
    public void MalformedPolicyFailuresDoNotLeakInputIntoValidationErrors()
    {
        const string marker = "MXC_MALFORMED_POLICY_STRUCTURED_ONLY_9D133E1B";
        var unknown = $$$"""{"formatVersion":1,"results":[],"{{{marker}}}":"private resource"}""";
        var duplicate = $$$"""{"formatVersion":1,"results":[],"{{{marker}}}":true,"{{{marker}}}":false}""";
        foreach (var json in new[] { unknown, duplicate })
        {
            AssertGenericValidationError(Assert.Throws<JsonException>(
                () => Dev.PolicyFailures.FromJson(json)));
            using var document = JsonDocument.Parse(
                $$$"""{"policyFailures":{{{json}}},"backend":"preserved"}""");
            var original = new MxcException(ErrorCode.BackendError, "creation refused",
                "PSEC.Create", "0x80070005", null, document.RootElement);
            var extraction = Assert.Throws<MxcException>(
                () => Dev.PolicyFailures.FromException(original));
            Assert.Equal(ErrorCode.BackendError, extraction.Code);
            Assert.Equal("native policy failures are malformed", extraction.Message);
            Assert.DoesNotContain(marker, extraction.ToString());
            Assert.Null(extraction.InnerException);
            Assert.Null(extraction.Details);
            Assert.Contains(marker, original.Details!.Value.GetRawText());
            Assert.Equal("preserved", original.Details.Value.GetProperty("backend").GetString());
            Assert.Equal("creation refused", original.Message);
            Assert.Equal("PSEC.Create", original.Operation);
            Assert.Equal("0x80070005", original.NativeCode);
        }
        AssertGenericValidationError(Assert.Throws<JsonException>(
            () => Dev.PolicyFailures.FromJson(unknown[..^1])));

        static void AssertGenericValidationError(JsonException error)
        {
            Assert.Equal("invalid stored policy failures", error.Message);
            Assert.DoesNotContain(marker, error.Message);
            Assert.DoesNotContain(marker, error.ToString());
            Assert.Null(error.InnerException);
        }
    }

    [Fact]
    public async Task StoredTerminalPolicyFailuresReachNativePreparationLimitsWithoutMutatingInputs()
    {
        var terminal = new Dev.PolicyFailures
        {
            Results = Enumerable.Range(0, 65)
                .Select(index => new Dev.PolicyFailureResult { Outcome = (uint)index }).ToArray(),
        };
        var stored = terminal.ToJson();
        var failures = Dev.PolicyFailures.FromJson(stored);
        const string request =
            """{"version":"1.0.0","containment":"process","process":{"commandLine":"must-not-run","timeout":1000}}""";

        var sync = Assert.Throws<MxcException>(
            () => Dev.MxcContainer.PreparePolicyJson(request, failures));
        var asynchronous = await Assert.ThrowsAsync<MxcException>(
            () => Dev.MxcContainer.PreparePolicyJsonAsync(
                request, failures, cancellationToken: TestContext.Current.CancellationToken));
        Assert.All(new[] { sync, asynchronous }, error =>
        {
            Assert.Equal(ErrorCode.MalformedRequest, error.Code);
            Assert.Contains("result limit", error.Message);
        });
        Assert.Equal(stored, failures.ToJson());
        Assert.Equal(stored, terminal.ToJson());

        var tooMany = new Dev.PolicyFailures
        {
            Results = Enumerable.Repeat(new Dev.PolicyFailureResult(), 66).ToArray(),
        };
        Assert.Throws<JsonException>(() => tooMany.ToJson());
        var tooManyDetails = new Dev.PolicyFailures
        {
            Results = [new() { Details = Enumerable.Repeat(new Dev.PolicyFailureDetail(), 65).ToArray() }],
        };
        Assert.Throws<JsonException>(() => tooManyDetails.ToJson());
    }

    [Fact]
    public void TerminalPolicyFailureStorageKeepsTheCompleteExtraNativeBatch()
    {
        var results = Enumerable.Range(0, 17)
            .Select(index => new Dev.PolicyFailureResult
            {
                Outcome = (uint)index,
                Details = Enumerable.Range(0, 64)
                    .Select(detail => new Dev.PolicyFailureDetail
                    {
                        Resource = index < 9 && detail == 0 ? new ushort[32_767] : null,
                    }).ToArray(),
            }).ToArray();
        var terminal = new Dev.PolicyFailures { Results = results };
        var restored = Dev.PolicyFailures.FromJson(terminal.ToJson());
        Assert.Equal(1088, restored.Results.Sum(result => result.Details.Length));
        Assert.Equal(294_912, restored.Results.Sum(result =>
            result.Details.Sum(detail => detail.Resource is null ? 0 : detail.Resource.Length + 1)));

        var tooManyDetails = new Dev.PolicyFailures
        {
            Results = [.. results, new() { Details = [new()] }],
        };
        Assert.Throws<JsonException>(() => tooManyDetails.ToJson());
        var tooManyUnits = new Dev.PolicyFailures
        {
            Results = [
                .. Enumerable.Range(0, 9).Select(_ => new Dev.PolicyFailureResult
                {
                    Details = [new() { Resource = new ushort[32_767] }],
                }),
                new() { Details = [new() { Resource = [] }] },
            ],
        };
        Assert.Equal(10, tooManyUnits.Results.Sum(result => result.Details.Length));
        Assert.Throws<JsonException>(() => tooManyUnits.ToJson());
        Assert.Throws<JsonException>(() => new Dev.PolicyFailures
        {
            Results = [new() { Details = [new() { Resource = new ushort[32_768] }] }],
        }.ToJson());
        Assert.Throws<JsonException>(() => Dev.PolicyFailures.FromJson(
            new string(' ', 4 * 1024 * 1024 + 512 * 1024) + "{}"));
        Assert.Equal(1088, terminal.Results.Sum(result => result.Details.Length));
    }

    [Fact]
    public async Task PolicyPreparationReturnsOwnedNativeRequestsWithoutLaunching()
    {
        Assert.SkipUnless(HostCanPreparePolicy, "policy preparation requires a PSEC-capable host");
        const string request =
            """{"version":"1.1.0-alpha","containment":"processcontainer","process":{"commandLine":"MXC_PREPARATION_MUST_NOT_EXECUTE_0A7C5DF1.exe","timeout":1000}}""";
        var failures = new Dev.PolicyFailures();
        var stored = failures.ToJson();
        var sync = Dev.MxcContainer.PreparePolicyJson(request, failures);
        var asynchronous = await Dev.MxcContainer.PreparePolicyJsonAsync(
            request, failures, cancellationToken: TestContext.Current.CancellationToken);
        foreach (var prepared in new[] { sync, asynchronous })
        {
            Assert.Empty(prepared.Changes);
            Assert.True(JsonNode.DeepEquals(JsonNode.Parse(request), JsonNode.Parse(prepared.RequestJson)));
            Assert.Equal(prepared.RequestJson,
                Dev.PreparedPolicyRequest.FromJson(prepared.ToJson()).RequestJson);
        }
        Assert.Equal(stored, failures.ToJson());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void PolicyPreparationStoragePreservesLargeTextWithoutHtmlExpansion(bool nativePreparation)
    {
        Assert.SkipUnless(!nativePreparation || HostCanPreparePolicy,
            "policy preparation requires a PSEC-capable host");
        var request =
            "{\"version\":\"1.1.0-alpha\",\"containment\":\"processcontainer\",\"_comment\":\""
            + new string('<', 6 * 1024 * 1024)
            + "\",\"process\":{\"commandLine\":\"MXC_PREPARATION_MUST_NOT_EXECUTE_0A7C5DF1.exe\"}}";
        var nativeCompatible = "{\"requestJson\":\""
            + JsonEncodedText.Encode(request, JavaScriptEncoder.UnsafeRelaxedJsonEscaping)
            + "\",\"changes\":[]}";
        var prepared = nativePreparation
            ? Dev.MxcContainer.PreparePolicyJson(request, new())
            : Dev.PreparedPolicyRequest.FromJson(nativeCompatible);
        Assert.Equal(request, prepared.RequestJson);
        Assert.Empty(prepared.Changes);
        var stored = prepared.ToJson();
        Assert.Equal(Encoding.UTF8.GetByteCount(nativeCompatible), Encoding.UTF8.GetByteCount(stored));
        Assert.Equal(request, Dev.PreparedPolicyRequest.FromJson(stored).RequestJson);
        Assert.Contains("\\u003C", MxcJson.Serialize("<", MxcJson.Options));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void PolicyPreparationStoragePreservesDuplicateCommentMembers(bool nativePreparation)
    {
        Assert.SkipUnless(!nativePreparation || HostCanPreparePolicy,
            "policy preparation requires a PSEC-capable host");
        const string request =
            """ {"version":"1.1.0-alpha","containment":"processcontainer","_comment":{"x":1,"x":2},"process":{"commandLine":"MXC_PREPARATION_MUST_NOT_EXECUTE_0A7C5DF1.exe"}} """;
        var nativeCompatible = "{\"requestJson\":\""
            + JsonEncodedText.Encode(request, JavaScriptEncoder.UnsafeRelaxedJsonEscaping)
            + "\",\"changes\":[]}";
        var prepared = nativePreparation
            ? Dev.MxcContainer.PreparePolicyJson(request, new())
            : Dev.PreparedPolicyRequest.FromJson(nativeCompatible);
        Assert.Equal(request, prepared.RequestJson);
        Assert.Empty(prepared.Changes);
        Assert.Equal(request, Dev.PreparedPolicyRequest.FromJson(prepared.ToJson()).RequestJson);
    }

    [Fact]
    public void PolicyFailureMergeDeduplicatesWholeBatchesAndOwnsEveryResource()
    {
        var firstDetail = new Dev.PolicyFailureDetail
        {
            FailureClass = uint.MaxValue,
            RequestedValue = ulong.MaxValue,
            Resource = [0xD800, 0],
        };
        var secondDetail = new Dev.PolicyFailureDetail { Resource = [] };
        var first = new Dev.PolicyFailures
        {
            Results =
            [
                new() { Outcome = uint.MaxValue, Details = [firstDetail, secondDetail] },
                new() { Outcome = 1, Details = [firstDetail] },
            ],
        };
        var second = Dev.PolicyFailures.FromJson(first.ToJson());
        second = new Dev.PolicyFailures
        {
            Results = [.. second.Results, new() { Outcome = uint.MaxValue, Details = [secondDetail, firstDetail] }],
        };
        var originalFirst = first.ToJson();
        var originalSecond = second.ToJson();
        var merged = first.MergedWith(second);
        Assert.Equal(3, merged.Results.Length);
        Assert.Equal(new[] { uint.MaxValue, 1u, uint.MaxValue },
            merged.Results.Select(result => result.Outcome));
        Assert.Equal(ulong.MaxValue, merged.Results[0].Details[0].RequestedValue);
        Assert.Equal(new ushort[] { 0xD800, 0 }, merged.Results[0].Details[0].Resource);
        Assert.Equal(2, merged.Results[2].Details.Length);
        Assert.Empty(merged.Results[2].Details[0].Resource!);
        merged.Results[0].Details[0].Resource![0] = 42;
        merged.Results[1].Details[0] = new();
        merged.Results[2] = new();
        Assert.Equal(originalFirst, first.ToJson());
        Assert.Equal(originalSecond, second.ToJson());
    }

    [Fact]
    public void PolicyFailureMergeRejectsInvalidInputsAndCompleteOverflowWithoutTruncation()
    {
        var first = new Dev.PolicyFailures
        {
            Results = Enumerable.Range(0, 65)
                .Select(index => new Dev.PolicyFailureResult { Outcome = (uint)index }).ToArray(),
        };
        var second = new Dev.PolicyFailures { Results = [new() { Outcome = 65 }] };
        var originalFirst = first.ToJson();
        var originalSecond = second.ToJson();
        Assert.Throws<JsonException>(() => first.MergedWith(second));
        Assert.Equal(originalFirst, first.ToJson());
        Assert.Equal(originalSecond, second.ToJson());
        var invalid = new Dev.PolicyFailures { FormatVersion = 2 };
        Assert.Throws<JsonException>(() => invalid.MergedWith(second));
        Assert.Throws<JsonException>(() => second.MergedWith(invalid));
        var invalidDuplicates = new Dev.PolicyFailures
        {
            Results = Enumerable.Repeat(new Dev.PolicyFailureResult(), 66).ToArray(),
        };
        Assert.Throws<JsonException>(() => second.MergedWith(invalidDuplicates));
        Assert.Equal(originalSecond, second.ToJson());
    }

    [Fact]
    public void PreparedPolicyStorageRetainsRequiredNullValuesAndOwnsJsonElements()
    {
        Dev.PreparedPolicyRequest prepared;
        using (var document = JsonDocument.Parse(
            """{"null":null,"old":{"nested":[true,18446744073709551615]},"new":"caf\u00e9 \ud83d\ude00"}"""))
        {
            var root = document.RootElement;
            prepared = new Dev.PreparedPolicyRequest
            {
                RequestJson = """{"version":"1.1.0-alpha","process":{"commandLine":"echo"}}""",
                Changes =
                [
                    new()
                    {
                        Operation = Dev.PolicyChangeOperation.Add, Path = "/a~1b/~0field",
                        Before = root.GetProperty("null"), After = root.GetProperty("old"),
                    },
                    new()
                    {
                        Operation = Dev.PolicyChangeOperation.Remove, Path = "/old",
                        Before = root.GetProperty("old"), After = root.GetProperty("null"),
                    },
                    new()
                    {
                        Operation = Dev.PolicyChangeOperation.Replace, Path = "/value",
                        Before = root.GetProperty("null"), After = root.GetProperty("new"),
                    },
                ],
            };
        }
        var stored = prepared.ToJson();
        var restored = Dev.PreparedPolicyRequest.FromJson(stored);
        Assert.Equal(stored, restored.ToJson());
        Assert.Equal(JsonValueKind.Null, restored.Changes[0].Before.ValueKind);
        Assert.Equal(JsonValueKind.Null, restored.Changes[1].After.ValueKind);
        Assert.Equal(JsonValueKind.Null, restored.Changes[2].Before.ValueKind);
        Assert.Equal("caf\u00e9 \ud83d\ude00", restored.Changes[2].After.GetString());
        Assert.Equal(ulong.MaxValue,
            restored.Changes[0].After.GetProperty("nested")[1].GetUInt64());
        using var saved = JsonDocument.Parse(stored);
        Assert.Equal(new[] { "add", "remove", "replace" },
            saved.RootElement.GetProperty("changes").EnumerateArray()
                .Select(change => change.GetProperty("operation").GetString()));
        Assert.All(saved.RootElement.GetProperty("changes").EnumerateArray(), change =>
        {
            Assert.True(change.TryGetProperty("before", out _));
            Assert.True(change.TryGetProperty("after", out _));
        });
        restored.Changes[0] = new();
        Assert.Equal(stored, prepared.ToJson());
    }

    [Fact]
    public void PreparedPolicyStorageRejectsMalformedShapesPointersAndOperationsWithoutInputLeaks()
    {
        const string marker = "MXC_PRIVATE_PREPARATION_INPUT_5F26AC94";
        const string valid =
            """{"requestJson":"{}","changes":[{"operation":"add","path":"/x","before":null,"after":1}]}""";
        var invalid = new List<string>
        {
            "null", "[]", "{}", """{"requestJson":null,"changes":[]}""",
            """{"requestJson":"[]","changes":[]}""", """{"requestJson":"{}","changes":null}""",
            """{"requestJson":"{}","changes":[null]}""",
            $$$"""{"requestJson":"{}","changes":[],"{{{marker}}}":true}""",
            valid.Replace("\"before\":null,", "", StringComparison.Ordinal),
            valid.Replace(",\"after\":1", "", StringComparison.Ordinal),
            valid.Replace("\"before\":null", "\"before\":true", StringComparison.Ordinal),
            valid.Replace("\"add\"", "\"remove\"", StringComparison.Ordinal),
            valid.Replace("\"add\"", "0", StringComparison.Ordinal),
            valid.Replace("\"add\"", "\"Add\"", StringComparison.Ordinal),
            valid.Replace("\"add\"", $"\"{marker}\"", StringComparison.Ordinal),
            valid.Replace("\"/x\"", "\"x\"", StringComparison.Ordinal),
            valid.Replace("\"/x\"", "\"/~2\"", StringComparison.Ordinal),
            valid.Replace("\"/x\"", "\"/~\"", StringComparison.Ordinal),
            valid.Replace("\"after\":1", $"\"after\":{{\"{marker}\":true,\"{marker}\":false}}", StringComparison.Ordinal),
            valid[..^1],
        };
        foreach (var json in invalid)
        {
            var error = Assert.Throws<JsonException>(() => Dev.PreparedPolicyRequest.FromJson(json));
            Assert.Equal("invalid prepared policy request", error.Message);
            Assert.DoesNotContain(marker, error.ToString());
            Assert.Null(error.InnerException);
        }
        Assert.Throws<JsonException>(() => new Dev.PreparedPolicyRequest
        {
            RequestJson = "{}",
            Changes = [new() { Operation = Dev.PolicyChangeOperation.Replace, Path = "/x" }],
        }.ToJson());
    }

    [Fact]
    public void PreparedPolicyStorageBoundsResultsAndChangesButAllowsExpandedRequests()
    {
        var nullValue = MxcJson.Deserialize<JsonElement>("null");
        var change = new Dev.PolicyChange
        {
            Operation = Dev.PolicyChangeOperation.Replace, Path = "",
            Before = nullValue, After = nullValue,
        };
        var bounded = new Dev.PreparedPolicyRequest
        {
            RequestJson = "{}",
            Changes = Enumerable.Repeat(change, 4096).ToArray(),
        };
        Assert.Equal(4096, Dev.PreparedPolicyRequest.FromJson(bounded.ToJson()).Changes.Length);
        Assert.Throws<JsonException>(() => new Dev.PreparedPolicyRequest
        {
            RequestJson = "{}",
            Changes = [.. bounded.Changes, change],
        }.ToJson());
        var expandedRequest = "{\"_comment\":\"" + new string('x', 8 * 1024 * 1024) + "\"}";
        var expanded = new Dev.PreparedPolicyRequest { RequestJson = expandedRequest };
        Assert.Equal(expandedRequest, Dev.PreparedPolicyRequest.FromJson(expanded.ToJson()).RequestJson);
        Assert.Throws<JsonException>(() => new Dev.PreparedPolicyRequest
        {
            RequestJson = "{\"_comment\":\"" + new string('x', 32 * 1024 * 1024) + "\"}",
        }.ToJson());
        Assert.Throws<JsonException>(() => Dev.PreparedPolicyRequest.FromJson(
            new string(' ', 32 * 1024 * 1024) + """{"requestJson":"{}","changes":[]}"""));
    }

    [Fact]
    public unsafe void NativePreparedPolicyDataIsBoundedOwnedAndStrictUtf8()
    {
        const string valid =
            """{"requestJson":"{}","changes":[{"operation":"replace","path":"/x","before":null,"after":{"large":18446744073709551615}}]}""";
        var bytes = Encoding.UTF8.GetBytes(valid + "\0");
        Dev.PreparedPolicyRequest prepared;
        fixed (byte* pointer = bytes)
        {
            prepared = Dev.MxcContainer.ReadPreparedPolicyRequest(pointer);
        }
        Array.Fill(bytes, (byte)0);
        Assert.Equal(ulong.MaxValue, prepared.Changes[0].After.GetProperty("large").GetUInt64());
        Assert.Equal(ErrorCode.BackendError,
            Assert.Throws<MxcException>(() => Dev.MxcContainer.ReadPreparedPolicyRequest(null)).Code);
        foreach (var malformed in new[] { new byte[] { 0xFF, 0 }, Encoding.UTF8.GetBytes("private input\0") })
        {
            fixed (byte* pointer = malformed)
            {
                try
                {
                    Dev.MxcContainer.ReadPreparedPolicyRequest(pointer);
                    Assert.Fail("malformed native preparation data was accepted");
                }
                catch (MxcException error)
                {
                    Assert.Equal(ErrorCode.BackendError, error.Code);
                    Assert.Equal("native policy preparation returned invalid JSON", error.Message);
                    Assert.DoesNotContain("private input", error.ToString());
                    Assert.Null(error.InnerException);
                }
            }
        }
        var oversized = new byte[32 * 1024 * 1024 + 2];
        Array.Fill(oversized, (byte)' ');
        oversized[^1] = 0;
        fixed (byte* pointer = oversized)
        {
            try
            {
                Dev.MxcContainer.ReadPreparedPolicyRequest(pointer);
                Assert.Fail("oversized native preparation data was accepted");
            }
            catch (MxcException error)
            {
                Assert.Equal(ErrorCode.BackendError, error.Code);
                Assert.Contains("byte limit", error.Message);
            }
        }
    }

    [Fact]
    public async Task PolicyPreparationRejectsInvalidInputsWithoutLeaksAndHonorsPreCancellation()
    {
        const string marker = "MXC_PRIVATE_PREPARATION_INPUT_5F26AC94";
        foreach (var json in new[]
        {
            "{\"" + marker + "\":", "{}\0" + marker,
            "{\"_comment\":\"" + marker + "\ud800\"}",
            "{\"_comment\":\"" + new string('\u00e9', 4 * 1024 * 1024) + "\"}",
        })
        {
            var error = Assert.Throws<MxcException>(
                () => Dev.MxcContainer.PreparePolicyJson(json, new()));
            Assert.Equal(ErrorCode.MalformedRequest, error.Code);
            Assert.Equal("invalid MXC request JSON for policy preparation", error.Message);
            Assert.DoesNotContain(marker, error.ToString());
            Assert.Null(error.InnerException);
        }
        var invalidFailures = Assert.Throws<MxcException>(
            () => Dev.MxcContainer.PreparePolicyJson("{}", new() { FormatVersion = 2 }));
        Assert.Equal(ErrorCode.MalformedRequest, invalidFailures.Code);
        Assert.Null(invalidFailures.InnerException);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => Dev.MxcContainer.PreparePolicyJsonAsync(
                "{}", new(), cancellationToken: new CancellationToken(true)));
    }
}
