// Copyright (c) 2026 Ellosoft Limited. All rights reserved.

using System.Text.RegularExpressions;

namespace Ellosoft.AwsCredentialsManager.Services.Okta.Idx;

/// <summary>
///     Reads the HTML / Ion body Okta returns from a FastPass <c>redirect-idp</c> GET
///     (<c>/sso/idps/{id}</c> is a browser navigation, not an IDX POST).
/// </summary>
public static partial class OktaFastPassRedirectParser
{
    public const string OktaVerifyDeviceChallengePrefix = "com-okta-authenticator:/deviceChallenge?challengeRequest=";

    public static string? TryGetDeepLink(string? location, string content)
    {
        return OktaVerifyAppLauncher.ExtractOktaVerifyDeepLink(location)
               ?? OktaVerifyAppLauncher.ExtractOktaVerifyDeepLink(content)
               ?? TryBuildDeepLinkFromChallengeRequest(content);
    }

    public static IdxResponse? TryGetEmbeddedIdx(string content)
    {
        if (string.IsNullOrWhiteSpace(content))
            return null;

        if (LooksLikeIdxJson(content))
            return TryParseIdx(content);

        foreach (var marker in new[] { "\"remediation\"", "\"authenticatorChallenge\"", "\"stateHandle\"" })
        {
            var index = 0;

            while ((index = content.IndexOf(marker, index, StringComparison.Ordinal)) >= 0)
            {
                var start = content.LastIndexOf('{', index);

                if (start >= 0 && TryReadJsonObject(content, start, out var json) && TryParseIdx(json) is { } parsed
                    && (parsed.PollRemediation is not null || parsed.IsSuccess || parsed.HasErrors || parsed.RemediationNames.Count > 0))
                {
                    return parsed;
                }

                index += marker.Length;
            }
        }

        return null;
    }

    public static bool LooksLikeIdxJson(string content)
    {
        var trimmed = content.TrimStart();

        return trimmed.StartsWith('{') &&
               (trimmed.Contains("\"remediation\"", StringComparison.Ordinal) ||
                trimmed.Contains("\"success\"", StringComparison.Ordinal) ||
                trimmed.Contains("\"stateHandle\"", StringComparison.Ordinal));
    }

    private static string? TryBuildDeepLinkFromChallengeRequest(string content)
    {
        var match = ChallengeRequestRegex().Match(content);

        if (!match.Success)
            return null;

        var jwt = match.Groups["jwt"].Value;

        return jwt.Length > 0 ? OktaVerifyDeviceChallengePrefix + jwt : null;
    }

    private static IdxResponse? TryParseIdx(string json)
    {
        try
        {
            return IdxResponse.Parse(json);
        }
        catch (Exception e) when (e is InvalidOperationException or System.Text.Json.JsonException)
        {
            return null;
        }
    }

    private static bool TryReadJsonObject(string content, int start, out string json)
    {
        json = string.Empty;

        if ((uint)start >= (uint)content.Length || content[start] != '{')
            return false;

        var depth = 0;
        var inString = false;
        var escape = false;

        for (var i = start; i < content.Length; i++)
        {
            var c = content[i];

            if (inString)
            {
                if (escape)
                    escape = false;
                else if (c == '\\')
                    escape = true;
                else if (c == '"')
                    inString = false;

                continue;
            }

            switch (c)
            {
                case '"':
                    inString = true;
                    break;
                case '{':
                    depth++;
                    break;
                case '}':
                    depth--;

                    if (depth == 0)
                    {
                        json = content[start..(i + 1)];

                        return true;
                    }

                    break;
            }
        }

        return false;
    }

    [GeneratedRegex("""challengeRequest\s*"?\s*[=:]\s*(?:"(?<jwt>eyJ[^"\\]+)"|'(?<jwt>eyJ[^'\\]+)')""", RegexOptions.CultureInvariant)]
    private static partial Regex ChallengeRequestRegex();
}
