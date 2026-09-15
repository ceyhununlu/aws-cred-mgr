// Copyright (c) 2026 Ellosoft Limited. All rights reserved.

using System.Net;
using System.Net.Http.Headers;
using System.Text.RegularExpressions;
using Ellosoft.AwsCredentialsManager.Services.Okta.Exceptions;
using Microsoft.Extensions.Logging;

namespace Ellosoft.AwsCredentialsManager.Services.Okta.Idx;

public interface IOktaAgentlessDssoHandler
{
    /// <summary>
    ///     Completes an "AgentlessDSSO" identity provider redirect the way a browser does: follows it to the org Kerberos
    ///     endpoint (https://{org}.kerberos.okta.com/login/agentlessDsso) and answers the Negotiate challenge with the
    ///     Kerberos ticket of the OS user, then follows Okta back to the sign-in transaction / dashboard
    /// </summary>
    /// <param name="oktaDomain">Okta org domain</param>
    /// <param name="redirect">The "redirect-idp" remediation returned by Okta</param>
    /// <param name="sessionCookies">Cookie jar of the sign-in transaction (the Okta session cookie ends up here)</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Where the redirect chain ended (URL, status code and body)</returns>
    Task<AgentlessDssoResult> ExecuteAsync(Uri oktaDomain, IdxIdpRedirect redirect, CookieContainer sessionCookies, CancellationToken cancellationToken);
}

/// <summary>
///     Outcome of the Desktop SSO redirect chain
/// </summary>
/// <param name="FinalUrl">URL of the last (non redirect) response</param>
/// <param name="StatusCode">Status code of the last response</param>
/// <param name="Content">Body of the last response (Okta sign-in page or dashboard HTML)</param>
/// <param name="KerberosHost">Host that issued the Negotiate challenge, if any</param>
/// <param name="NegotiateChallengeSeen">Whether any hop actually asked for a Kerberos (Negotiate) ticket</param>
public sealed record AgentlessDssoResult(Uri FinalUrl, HttpStatusCode StatusCode, string Content, string? KerberosHost, bool NegotiateChallengeSeen)
{
    /// <summary>
    ///     The Kerberos endpoint refused the sign-in (no ticket, NTLM instead of Kerberos, clock skew...)
    /// </summary>
    public bool KerberosRejected => StatusCode == HttpStatusCode.Unauthorized;
}

/// <summary>
///     Okta Agentless Desktop Single Sign-on: Okta answers with a 401 "WWW-Authenticate: Negotiate" on the org Kerberos
///     host, the client presents the Kerberos ticket of the signed-in OS user (SPN HTTP/{org}.kerberos.okta.com) and Okta
///     signs the user in. On Windows .NET uses SSPI for this, so the CLI can complete the flow without a browser.
/// </summary>
public partial class OktaAgentlessDssoHandler(IOktaIdxHttpClientFactory httpClientFactory, IAnsiConsole console, ILogger<OktaAgentlessDssoHandler> logger)
    : IOktaAgentlessDssoHandler
{
    public const string IdpType = "AgentlessDSSO";

    private const string NegotiateScheme = "Negotiate";
    private const int MaxRedirects = 15;
    private const int LoggedBodySnippetLength = 800;

    private static readonly string[] OktaKerberosDomains = [".kerberos.okta.com", ".kerberos.oktapreview.com", ".kerberos.okta-emea.com"];

    public static bool IsAgentlessDsso(IdxIdpRedirect redirect) => string.Equals(redirect.Type, IdpType, StringComparison.OrdinalIgnoreCase);

    public async Task<AgentlessDssoResult> ExecuteAsync(Uri oktaDomain, IdxIdpRedirect redirect, CookieContainer sessionCookies, CancellationToken cancellationToken)
    {
        console.MarkupLine($"Okta routed the sign-in to Desktop Single Sign-on ([green]{Markup.Escape(redirect.IdpName ?? IdpType)}[/]), signing in with your Windows (Kerberos) account...");

        // the OS user's Kerberos ticket is only ever presented to Okta hosts (the org and its *.kerberos.okta.com endpoint)
        var credentials = new CredentialCache();

        using var httpClient = httpClientFactory.CreateDesktopSsoClient(sessionCookies, credentials);

        var url = new Uri(oktaDomain, redirect.Href);
        string? kerberosHost = null;
        var negotiateChallengeSeen = false;

        for (var hop = 0; hop <= MaxRedirects; hop++)
        {
            PrepareCredentials(credentials, url, oktaDomain);

            using var response = await SendAsync(httpClient, url, hop, cancellationToken);

            // .NET answers the 401 Negotiate internally, so a challenge shows up either as a lingering 401 (rejected) or as
            // the WWW-Authenticate header echoed on the final response; either way it proves Okta asked for the Kerberos ticket
            if (response.StatusCode == HttpStatusCode.Unauthorized || response.Headers.WwwAuthenticate.Any(h => h.Scheme == NegotiateScheme))
            {
                negotiateChallengeSeen = true;
                kerberosHost ??= url.Host;
            }

            if (GetRedirectLocation(response, url) is { } location)
            {
                url = location;

                continue;
            }

            var content = await response.Content.ReadAsStringAsync(cancellationToken);

            LogFinalResponse(hop, url, response, content);

            // Okta serves the agentless DSSO step as a 200 HTML page that bounces to the Kerberos challenge URL via
            // meta-refresh / script; a browser follows it, so must we (otherwise Kerberos is never actually attempted)
            if (GetHtmlRedirect(response, content, url, oktaDomain) is { } htmlRedirect)
            {
                logger.LogDebug("Desktop SSO hop {Hop}: following in-page redirect to {Url}", hop, htmlRedirect);
                url = htmlRedirect;

                continue;
            }

            if (response.StatusCode == HttpStatusCode.Unauthorized)
                logger.LogError("Desktop SSO: {Host} rejected the Kerberos sign-in (401). WWW-Authenticate: {Challenge}", url.Host, response.Headers.WwwAuthenticate);

            return new AgentlessDssoResult(url, response.StatusCode, content, kerberosHost, negotiateChallengeSeen);
        }

        throw new OktaFastPassException($"Desktop Single Sign-on did not complete: Okta kept redirecting (more than {MaxRedirects} redirects), last URL: {url}");
    }

    private void PrepareCredentials(CredentialCache credentials, Uri url, Uri oktaDomain)
    {
        if (IsTrustedOktaHost(url, oktaDomain))
            TrustHost(credentials, url);
        else
            logger.LogWarning("Desktop SSO redirected to {Host}, which is not an Okta host: the Kerberos ticket will not be presented to it", url.Host);
    }

    private static Uri? GetRedirectLocation(HttpResponseMessage response, Uri currentUrl)
    {
        if (!IsRedirect(response.StatusCode) || response.Headers.Location is not { } location)
            return null;

        return location.IsAbsoluteUri ? location : new Uri(currentUrl, location);
    }

    private static Uri? GetHtmlRedirect(HttpResponseMessage response, string content, Uri currentUrl, Uri oktaDomain)
    {
        if (response.StatusCode != HttpStatusCode.OK)
            return null;

        return ExtractHtmlRedirect(content, currentUrl) is { } htmlRedirect && IsTrustedOktaHost(htmlRedirect, oktaDomain) ? htmlRedirect : null;
    }

    private async Task<HttpResponseMessage> SendAsync(HttpClient httpClient, Uri url, int hop, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, url);

        // the Kerberos SPN Okta registers is HTTP/{org}.kerberos.okta.com; with an explicit Host header .NET builds the SPN
        // from it instead of canonicalising the host through DNS (which would follow the CNAME and produce the wrong SPN)
        request.Headers.Host = url.IsDefaultPort ? url.Host : $"{url.Host}:{url.Port}";
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("text/html"));
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/xhtml+xml"));
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("*/*", 0.8));

        try
        {
            var response = await httpClient.SendAsync(request, cancellationToken);

            var wwwAuthenticate = response.Headers.WwwAuthenticate.Count > 0
                ? string.Join(", ", response.Headers.WwwAuthenticate.Select(h => h.Scheme))
                : "none";

            logger.LogDebug("Desktop SSO hop {Hop}: GET {Url} -> {StatusCode} (WWW-Authenticate: {WwwAuthenticate}, Location: {Location}, Content-Type: {ContentType})",
                hop, url, (int)response.StatusCode, wwwAuthenticate, response.Headers.Location?.ToString() ?? "none", response.Content.Headers.ContentType?.ToString() ?? "none");

            return response;
        }
        catch (HttpRequestException e)
        {
            logger.LogError(e, "Desktop SSO request to {Url} failed", url);

            throw new OktaFastPassException(
                $"Desktop Single Sign-on failed while contacting {url.Host}: {e.Message}. " +
                "This device must be able to reach Okta's Kerberos endpoint and a domain controller (corporate network or VPN)");
        }
    }

    private void LogFinalResponse(int hop, Uri url, HttpResponseMessage response, string content)
    {
        if (!logger.IsEnabled(LogLevel.Debug))
            return;

        var snippet = content.Length > LoggedBodySnippetLength ? content[..LoggedBodySnippetLength] + "..." : content;

        logger.LogDebug("Desktop SSO hop {Hop}: {Url} settled at HTTP {StatusCode} ({Length} bytes). Body: {Body}",
            hop, url, (int)response.StatusCode, content.Length, snippet);
    }

    /// <summary>
    ///     Finds the URL an HTML page bounces to without a real HTTP redirect: meta-refresh or a plain
    ///     <c>window.location = '...'</c> / <c>location.replace('...')</c> assignment
    /// </summary>
    public static Uri? ExtractHtmlRedirect(string html, Uri baseUrl)
    {
        if (string.IsNullOrWhiteSpace(html))
            return null;

        var match = MetaRefreshRegex().Match(html);

        if (!match.Success)
            match = JsLocationRegex().Match(html);

        if (!match.Success)
            return null;

        var target = WebUtility.HtmlDecode(match.Groups["url"].Value).Trim();

        return Uri.TryCreate(baseUrl, target, out var uri) ? uri : null;
    }

    [GeneratedRegex("""<meta[^>]+http-equiv\s*=\s*["']?refresh["']?[^>]+content\s*=\s*["'][^"']*url\s*=\s*(?<url>[^"']+)["']""",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex MetaRefreshRegex();

    [GeneratedRegex("""(?:window\.)?location(?:\.href)?\s*=\s*["'](?<url>[^"']+)["']|location\.replace\(\s*["'](?<url>[^"']+)["']""",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex JsLocationRegex();

    /// <summary>
    ///     Only Okta's own hosts may challenge for the Kerberos ticket: the org (including custom domains), the org's
    ///     parent Okta domain and the *.kerberos.okta.com endpoints Agentless DSSO uses
    /// </summary>
    public static bool IsTrustedOktaHost(Uri url, Uri oktaDomain)
    {
        if (url.Scheme != Uri.UriSchemeHttps)
            return false;

        var host = url.Host;

        if (string.Equals(host, oktaDomain.Host, StringComparison.OrdinalIgnoreCase))
            return true;

        if (OktaKerberosDomains.Any(d => host.EndsWith(d, StringComparison.OrdinalIgnoreCase)))
            return true;

        // xyz.okta.com -> anything under okta.com (e.g. xyz.kerberos.okta.com on preview/EMEA cells with other suffixes)
        var firstDot = oktaDomain.Host.IndexOf('.');

        return firstDot > 0 && host.EndsWith(oktaDomain.Host[firstDot..], StringComparison.OrdinalIgnoreCase);
    }

    private static void TrustHost(CredentialCache credentials, Uri url)
    {
        var prefix = new Uri(url.GetLeftPart(UriPartial.Authority));

        if (credentials.GetCredential(prefix, NegotiateScheme) is null)
            credentials.Add(prefix, NegotiateScheme, CredentialCache.DefaultNetworkCredentials);
    }

    private static bool IsRedirect(HttpStatusCode statusCode) =>
        statusCode is HttpStatusCode.MovedPermanently or HttpStatusCode.Found or HttpStatusCode.SeeOther
            or HttpStatusCode.TemporaryRedirect or HttpStatusCode.PermanentRedirect;
}
