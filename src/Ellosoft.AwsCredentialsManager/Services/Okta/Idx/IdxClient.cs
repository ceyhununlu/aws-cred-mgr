// Copyright (c) 2026 Ellosoft Limited. All rights reserved.

using System.Net.Http.Headers;
using System.Text;
using System.Text.Json.Nodes;
using Ellosoft.AwsCredentialsManager.Services.Okta.Exceptions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Ellosoft.AwsCredentialsManager.Services.Okta.Idx;

/// <summary>
///     Minimal Okta Identity Engine (IDX) API client bound to one sign-in transaction (cookie aware HttpClient)
/// </summary>
public sealed class IdxClient(HttpClient httpClient, ILogger? logger = null) : IDisposable
{
    private const string ION_JSON_MEDIA_TYPE = "application/ion+json";
    private const string OKTA_VERSION = "1.0.0";

    private readonly ILogger _logger = logger ?? NullLogger.Instance;

    public HttpClient HttpClient { get; } = httpClient;

    public Task<IdxResponse> PostAsync(string href, string stateHandle, CancellationToken cancellationToken = default) =>
        PostAsync(href, new JsonObject { ["stateHandle"] = stateHandle }, cancellationToken);

    public async Task<IdxResponse> PostAsync(string href, JsonObject body, CancellationToken cancellationToken = default)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, href);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue(ION_JSON_MEDIA_TYPE) { Parameters = { OktaVersionParameter() } });
        request.Content = new StringContent(body.ToJsonString(), Encoding.UTF8);
        request.Content.Headers.ContentType = new MediaTypeHeaderValue(ION_JSON_MEDIA_TYPE) { Parameters = { OktaVersionParameter() } };

        var path = request.RequestUri?.AbsolutePath;

        using var response = await HttpClient.SendAsync(request, cancellationToken);

        var content = await response.Content.ReadAsStringAsync(cancellationToken);

        if (!content.TrimStart().StartsWith('{'))
        {
            _logger.LogError("Okta Identity Engine returned a non JSON response ({StatusCode}) from {Path}", (int)response.StatusCode, path);

            throw new OktaFastPassException(
                $"Unexpected response from Okta Identity Engine ({(int)response.StatusCode} {response.StatusCode}) when calling {path}");
        }

        var idxResponse = IdxResponse.Parse(content);

        LogResponse(path, (int)response.StatusCode, idxResponse);

        return idxResponse;
    }

    public void Dispose() => HttpClient.Dispose();

    /// <summary>
    ///     The one-line summary is what a bug report needs (which step Okta asked for, which IdP it redirected to);
    ///     the full document carries the live state handle, so it is only written to the log file at debug level
    /// </summary>
    private void LogResponse(string? path, int statusCode, IdxResponse response)
    {
        if (!_logger.IsEnabled(LogLevel.Debug))
            return;

        string outcome;

        if (response.IsSuccess)
            outcome = "success";
        else if (response.HasErrors)
            outcome = $"errors: {string.Join(" | ", response.ErrorMessages.Select(m => m.Message))}";
        else
            outcome = $"remediations: {string.Join(", ", response.RemediationNames)}";

        var challenge = response.DeviceChallenge is { } deviceChallenge ? $", device challenge: {deviceChallenge.Method}" : string.Empty;
        var idps = response.IdpRedirects.Count > 0 ? $", idp redirects: {string.Join(", ", response.IdpRedirects.Select(i => i.Description))}" : string.Empty;

        _logger.LogDebug("IDX POST {Path} -> {StatusCode} ({Outcome}{Challenge}{Idps})", path, statusCode, outcome, challenge, idps);
        _logger.LogDebug("IDX response from {Path}: {Response}", path, response);
    }

    private static NameValueHeaderValue OktaVersionParameter() => new("okta-version", OKTA_VERSION);
}
