// Copyright (c) 2023 Ellosoft Limited. All rights reserved.

using System.Net;
using AngleSharp.Html.Parser;
using Ellosoft.AwsCredentialsManager.Services.Okta.Exceptions;
using Ellosoft.AwsCredentialsManager.Services.Okta.Idx;
using Ellosoft.AwsCredentialsManager.Services.Okta.Models;

namespace Ellosoft.AwsCredentialsManager.Services.Okta;

public record SamlData(string SamlAssertion, string SignInUrl, string RelayState);

public interface IOktaSamlService
{
    /// <summary>
    ///     Retrieves the SAML assertion for an Okta app using the session carried by the authentication result
    ///     (session cookies or session id for Identity Engine / FastPass / browser authentication, session token for classic authentication)
    /// </summary>
    /// <exception cref="OktaAppReauthenticationRequiredException">Okta requires the user to sign in again to access the app</exception>
    Task<SamlData> GetAppSamlDataAsync(AuthenticationResult authenticationResult, string oktaAppUrl);
}

public class OktaSamlService(Func<HttpMessageHandler> httpMessageHandlerFactory) : IOktaSamlService
{
    public OktaSamlService() : this(() => new HttpClientHandler())
    {
    }

    public async Task<SamlData> GetAppSamlDataAsync(AuthenticationResult authenticationResult, string oktaAppUrl)
    {
        if (authenticationResult.CapturedSaml is { } capturedSaml && IsSameApp(capturedSaml.OktaAppUrl, oktaAppUrl))
            return capturedSaml.SamlData;

        using var response = await GetAppPageAsync(authenticationResult, oktaAppUrl);

        if (!response.IsSuccessStatusCode)
            throw new InvalidOperationException($"Failed to retrieve SAML assertion. HTTP Status: {response.StatusCode}");

        var responseBody = await response.Content.ReadAsStringAsync();

        var parser = new HtmlParser();
        using var document = await parser.ParseDocumentAsync(responseBody);

        var samlAssertion = document.QuerySelector("input[name=SAMLResponse]")?.GetAttribute("value");

        if (samlAssertion is null)
            throw CreateMissingSamlAssertionException(responseBody, response);

        var signInUrl = document.QuerySelector("form")?.GetAttribute("action")
                        ?? throw new InvalidOperationException("Sign-in URL not found in the Okta SAML response");

        return new SamlData
        (
            SamlAssertion: samlAssertion,
            SignInUrl: signInUrl,
            RelayState: document.QuerySelector("input[name=RelayState]")?.GetAttribute("value") ?? String.Empty
        );
    }

    private static bool IsSameApp(string capturedAppUrl, string oktaAppUrl) =>
        string.Equals(capturedAppUrl.TrimEnd('/'), oktaAppUrl.TrimEnd('/'), StringComparison.OrdinalIgnoreCase);

    private static InvalidOperationException CreateMissingSamlAssertionException(string responseBody, HttpResponseMessage response)
    {
        // Okta answered with its sign-in page: the session was not accepted for this app (e.g. the app sign-on policy requires re-verification)
        if (OktaLoginPageStateTokenExtractor.Extract(responseBody) is not null)
        {
            return new OktaAppReauthenticationRequiredException(
                "Okta requires additional verification to access this app (the Okta session was not accepted for the app sign-on policy). " +
                $"Please try again. Okta responded at: {response.RequestMessage?.RequestUri}");
        }

        return new InvalidOperationException(
            $"SAML assertion not found in the Okta response. Please check the Okta app URL and try again (Okta responded at: {response.RequestMessage?.RequestUri})");
    }

    private Task<HttpResponseMessage> GetAppPageAsync(AuthenticationResult authenticationResult, string oktaAppUrl)
    {
        // a classic session token can only be redeemed once, when the session was already created from it the session cookies/id must be used
        if (authenticationResult.SessionCookies is not null)
            return GetUsingSessionCookies(oktaAppUrl, authenticationResult.SessionCookies, authenticationResult.UserAgent);

        if (authenticationResult.SessionId is not null)
            return GetUsingSessionId(oktaAppUrl, authenticationResult.SessionId, authenticationResult.UserAgent);

        if (authenticationResult.SessionToken is not null)
            return RedirectUsingSessionCookie(authenticationResult.OktaDomain, oktaAppUrl, authenticationResult.SessionToken, authenticationResult.UserAgent);

        throw new InvalidOperationException("Authentication result does not contain an Okta session");
    }

    private async Task<HttpResponseMessage> GetUsingSessionCookies(string oktaAppUrl, CookieContainer sessionCookies, string? userAgent)
    {
        // Identity Engine sessions are carried by several cookies (sid, idx, device token...), replay the whole sign-in cookie jar.
        // Cookies refreshed by Okta during the request are written back to the jar, so they are kept when the session is saved again
        var handler = httpMessageHandlerFactory();

        if (handler is HttpClientHandler clientHandler)
        {
            clientHandler.UseCookies = true;
            clientHandler.CookieContainer = sessionCookies;
        }

        using var httpClient = new HttpClient(handler);
        using var request = CreateRequest(oktaAppUrl, userAgent);

        if (handler is not HttpClientHandler)
            request.Headers.Add("Cookie", sessionCookies.GetCookieHeader(new Uri(oktaAppUrl)));

        return await httpClient.SendAsync(request);
    }

    private async Task<HttpResponseMessage> RedirectUsingSessionCookie(Uri oktaDomain, string redirectUrl, string sessionToken, string? userAgent)
    {
        // see: https://developer.okta.com/docs/guides/session-cookie/main/#retrieve-a-session-cookie-by-visiting-a-session-redirect-link
        const string OKTA_SESSION_REDIRECT_URL_TEMPLATE = "/login/sessionCookieRedirect?token=${sessionToken}&redirectUrl=${redirectUrl}";

        var sessionRedirectUrl = OKTA_SESSION_REDIRECT_URL_TEMPLATE
            .Replace("${sessionToken}", sessionToken)
            .Replace("${redirectUrl}", redirectUrl);

        using var httpClient = CreateHttpClient();
        using var request = CreateRequest(new Uri(oktaDomain, sessionRedirectUrl).ToString(), userAgent);

        return await httpClient.SendAsync(request);
    }

    private async Task<HttpResponseMessage> GetUsingSessionId(string oktaAppUrl, string sessionId, string? userAgent)
    {
        // see: https://developer.okta.com/docs/guides/session-cookie/main/#use-the-session-cookie
        using var httpClient = CreateHttpClient();
        using var request = CreateRequest(oktaAppUrl, userAgent);
        request.Headers.Add("Cookie", $"sid={sessionId}");

        return await httpClient.SendAsync(request);
    }

    private static HttpRequestMessage CreateRequest(string url, string? userAgent)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, url);

        if (userAgent is not null)
            request.Headers.TryAddWithoutValidation("User-Agent", userAgent);

        return request;
    }

    private HttpClient CreateHttpClient() => new(httpMessageHandlerFactory());
}
