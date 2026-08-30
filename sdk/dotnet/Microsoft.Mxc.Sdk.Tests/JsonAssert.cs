// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Text.Json;
using Xunit;

namespace Microsoft.Mxc.Sdk.Tests;

internal static class JsonAssert
{
    internal static void MatchesGolden(string actualJson, string fixtureName)
    {
        var assembly = typeof(JsonAssert).Assembly;
        var resourceName = assembly.GetManifestResourceNames()
            .Single(name => name.EndsWith(fixtureName, StringComparison.Ordinal));
        using var stream = assembly.GetManifestResourceStream(resourceName)
            ?? throw new InvalidOperationException($"Missing embedded fixture {resourceName}.");
        using var reader = new StreamReader(stream);
        using var expected = JsonDocument.Parse(reader.ReadToEnd());
        using var actual = JsonDocument.Parse(actualJson);

        Equivalent(expected.RootElement, actual.RootElement, fixtureName);
    }

    private static void Equivalent(JsonElement expected, JsonElement actual, string path)
    {
        Assert.True(
            expected.ValueKind == actual.ValueKind,
            $"{path}: expected {expected.ValueKind}, actual {actual.ValueKind}");

        switch (expected.ValueKind)
        {
            case JsonValueKind.Object:
                var expectedProperties = expected.EnumerateObject().ToArray();
                var actualProperties = actual.EnumerateObject().ToArray();
                Assert.True(
                    expectedProperties.Length == actualProperties.Length,
                    $"{path}: expected {expectedProperties.Length} properties, " +
                    $"actual {actualProperties.Length}");
                foreach (var property in expectedProperties)
                {
                    Assert.True(
                        actual.TryGetProperty(property.Name, out var actualValue),
                        $"{path}: missing property '{property.Name}'");
                    Equivalent(property.Value, actualValue, $"{path}.{property.Name}");
                }
                break;

            case JsonValueKind.Array:
                var expectedItems = expected.EnumerateArray().ToArray();
                var actualItems = actual.EnumerateArray().ToArray();
                Assert.True(
                    expectedItems.Length == actualItems.Length,
                    $"{path}: expected {expectedItems.Length} items, actual {actualItems.Length}");
                for (var index = 0; index < expectedItems.Length; index++)
                {
                    Equivalent(expectedItems[index], actualItems[index], $"{path}[{index}]");
                }
                break;

            case JsonValueKind.String:
                Assert.Equal(expected.GetString(), actual.GetString());
                break;

            default:
                Assert.Equal(expected.GetRawText(), actual.GetRawText());
                break;
        }
    }
}
