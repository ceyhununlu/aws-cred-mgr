// Copyright (c) 2026 Ellosoft Limited. All rights reserved.

using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Text.Json.Nodes;
using Ellosoft.AwsCredentialsManager.Services.Okta.Models;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Ellosoft.AwsCredentialsManager.Services.Okta.Sessions;

public record OktaSessionInfo(string Id, DateTimeOffset? ExpiresAt);

public interface IOktaSessionClient
{
    /// <summary>
    ///     Returns the Okta session identified by the session cookies (or session id) of the authentication result,
    ///     or null if Okta no longer considers the session active
    /// </summary>
    Task<OktaSessionInfo?> GetActiveSessionAsync(AuthenticationResult session, CancellationToken cancellationToken = default);

    /// <summary>
    ///     Ends the Okta session (sign out)
    /// </summary>
    /// <returns>true if Okta closed the session</returns>
    Task<bool> CloseSessionAsync(AuthenticationResult session, CancellationToken cancellationToken = default);
}

public class OktaSessionClient(IHttpClientFactory httpClientFactory, ILogger<OktaSessionClient> logger) : IOktaSessionClient
{
    public const string HttpClientName = nameof(OktaSessionClient);

    private const string CURRENT_SESSION_PATH = "/api/v1/sessions/me";

    public static void ConfigureHttpClient(IHttpClientBuilder builder) =>
        builder
            .ConfigureHttpClient(client => client.Timeout = TimeSpan.FromSeconds(30))
            .ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler { UseCookies = false, AllowAutoRedirect = false });

    public async Task<OktaSessionInfo?> GetActiveSessionAsync(AuthenticationResult session, CancellationToken cancellationToken = default)
    {
        using var request = CreateRequest(HttpMethod.Get, session);
        using var response = await SendAsync(request, cancellationToken);

        if (response.StatusCode != HttpStatusCode.OK)
        {
            logger.LogDebug("Okta session is not active (HTTP {StatusCode})", (int)response.StatusCode);

            return null;
        }

        var body = JsonNode.Parse(await response.Content.ReadAsStringAsync(cancellationToken));

        if (body?["status"]?.GetValue<string>() != "ACTIVE" || body["id"]?.GetValue<string>() is not { } sessionId)
        {
            logger.LogDebug("Okta session is not active (status: {Status})", body?["status"]);

            return null;
        }

        var expiresAt = DateTimeOffset.TryParse(body["expiresAt"]?.GetValue<string>(), CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal,
            out var parsedExpiresAt)
            ? parsedExpiresAt
            : (DateTimeOffset?)null;

        return new OktaSessionInfo(sessionId, expiresAt);
    }

    public async Task<bool> CloseSessionAsync(AuthenticationResult session, CancellationToken cancellationToken = default)
    {
        using var request = CreateRequest(HttpMethod.Delete, session);
        using var response = await SendAsync(request, cancellationToken);

        logger.LogDebug("Okta session close response: HTTP {StatusCode}", (int)response.StatusCode);

        return response.IsSuccessStatusCode;
    }

    private Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var httpClient = httpClientFactory.CreateClient(HttpClientName);

        return httpClient.SendAsync(request, cancellationToken);
    }

    private static HttpRequestMessage CreateRequest(HttpMethod method, AuthenticationResult session)
    {
        var requestUri = new Uri(session.OktaDomain, CURRENT_SESSION_PATH);
        var request = new HttpRequestMessage(method, requestUri);

        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        request.Headers.TryAddWithoutValidation("Cookie", GetCookieHeader(session, requestUri));

        if (session.UserAgent is not null)
            request.Headers.TryAddWithoutValidation("User-Agent", session.UserAgent);

        return request;
    }

    private static string GetCookieHeader(AuthenticationResult session, Uri requestUri)
    {
        var cookieHeader = session.SessionCookies?.GetCookieHeader(requestUri);

        if (!string.IsNullOrEmpty(cookieHeader))
            return cookieHeader;

        return session.SessionId is not null ? $"sid={session.SessionId}" : string.Empty;
    }
}
