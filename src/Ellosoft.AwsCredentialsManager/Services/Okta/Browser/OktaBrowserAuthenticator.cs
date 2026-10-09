// Copyright (c) 2026 Ellosoft Limited. All rights reserved.

using System.Net;
using System.Text;
using System.Text.Json.Nodes;
using Ellosoft.AwsCredentialsManager.Services.Configuration;
using Ellosoft.AwsCredentialsManager.Services.Okta.Exceptions;
using Ellosoft.AwsCredentialsManager.Services.Okta.Interactive;
using Ellosoft.AwsCredentialsManager.Services.Okta.Models;
using Ellosoft.AwsCredentialsManager.Services.Okta.Sessions;
using Microsoft.Extensions.Logging;

namespace Ellosoft.AwsCredentialsManager.Services.Okta.Browser;

/// <param name="OktaDomain">Okta org URL</param>
/// <param name="OktaAppUrl">Okta app to open, its SAML response is captured. When null the sign-in completes once Okta has a session</param>
/// <param name="Username">Pre-fills the Okta username field</param>
/// <param name="Password">Pre-fills the Okta password field</param>
/// <param name="MfaType">MFA type configured for the profile (reported back as the MFA used)</param>
public sealed record OktaBrowserSignInRequest(Uri OktaDomain, string? OktaAppUrl, string? Username, string? Password, string? MfaType);

public interface IOktaBrowserAuthenticator
{
    /// <summary>
    ///     Signs in to Okta in a browser window (Microsoft Edge or Google Chrome). The browser completes every step Okta asks for
    ///     (Okta FastPass through Okta Verify, Desktop SSO, passwords, push...), the resulting Okta session cookies and the SAML
    ///     response posted to AWS are captured through the DevTools protocol
    /// </summary>
    Task<AuthenticationResult> AuthenticateAsync(OktaBrowserSignInRequest request, CancellationToken cancellationToken = default);
}

public class OktaBrowserAuthenticator(
    IAnsiConsole console,
    IConfigManager configManager,
    IBrowserLocator browserLocator,
    IOktaSessionClient sessionClient,
    ILogger<OktaBrowserAuthenticator> logger) : IOktaBrowserAuthenticator
{
    public BrowserLaunchOptions LaunchOptions { get; init; } = new();

    public TimeSpan SignInTimeout { get; init; } = TimeSpan.FromMinutes(5);

    /// <summary>
    ///     Dedicated browser profile: keeps the Okta cookies (device token, session) and the "open Okta Verify" choice between sign-ins
    /// </summary>
    public string ProfileDirectory { get; init; } = Path.Combine(AppDataDirectory.Path, "browser-profile");

    public async Task<AuthenticationResult> AuthenticateAsync(OktaBrowserSignInRequest request, CancellationToken cancellationToken = default)
    {
        var browsers = GetBrowsers();

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(SignInTimeout);

        var (browser, browserPath) = await LaunchBrowserAsync(browsers, timeout.Token);

        await using (browser)
        {
            console.MarkupLineInterpolated($"Signing in to Okta in [green]{GetBrowserName(browserPath)}[/], please complete the sign-in in the browser window...");

            if (OktaMfaFactorSelector.IsFastPass(request.MfaType))
                console.MarkupLine("[grey]Okta Verify opens when Okta asks for Okta FastPass, allow the browser to open it if prompted[/]");

            try
            {
                var signIn = new SignInFlow(browser, request, sessionClient, logger);
                var result = await signIn.RunAsync(timeout.Token);

                await signIn.CloseSignInTabAsync();

                console.MarkupLine("\r\n[bold green]Authenticated![/]\r\n");

                return result;
            }
            catch (OperationCanceledException) when (timeout.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
            {
                throw new OktaBrowserSignInException(
                    $"The Okta sign-in in the browser did not complete within {SignInTimeout.TotalMinutes:0} minutes, please try again");
            }
            catch (CdpConnectionClosedException)
            {
                throw SignInFlow.BrowserClosed();
            }
        }
    }

    /// <summary>
    ///     Starts the first browser that can be controlled, remote debugging may be disabled by policy for one browser but not for another
    /// </summary>
    private async Task<(ChromiumBrowser Browser, string BrowserPath)> LaunchBrowserAsync(List<string> browsers, CancellationToken cancellationToken)
    {
        foreach (var browserPath in browsers.SkipLast(1))
        {
            try
            {
                return (await ChromiumBrowser.LaunchAsync(browserPath, ProfileDirectory, LaunchOptions, logger, cancellationToken), browserPath);
            }
            catch (BrowserDevToolsUnavailableException e)
            {
                logger.LogWarning(e, "Unable to control {BrowserPath}, trying the next browser", browserPath);
            }
        }

        var lastBrowserPath = browsers[^1];

        return (await ChromiumBrowser.LaunchAsync(lastBrowserPath, ProfileDirectory, LaunchOptions, logger, cancellationToken), lastBrowserPath);
    }

    private List<string> GetBrowsers()
    {
        if (configManager.ToolConfig.BrowserPath is { } configuredBrowser)
        {
            if (!File.Exists(configuredBrowser))
                throw new OktaBrowserSignInException($"The browser configured in 'browser_path' was not found: {configuredBrowser}");

            return [configuredBrowser];
        }

        var browsers = browserLocator.FindBrowsers();

        if (browsers.Count == 0)
        {
            throw new OktaBrowserSignInException(
                "Okta sign-in requires Microsoft Edge or Google Chrome, but neither was found. " +
                "Install one of them or set 'browser_path' in the 'config' section of the aws-cred-mgr configuration");
        }

        return [.. browsers];
    }

    private static string GetBrowserName(string browserPath) =>
        Path.GetFileNameWithoutExtension(browserPath).ToLowerInvariant() switch
        {
            "msedge" or "microsoft edge" or "microsoft-edge" => "Microsoft Edge",
            "chrome" or "google chrome" or "google-chrome" or "google-chrome-stable" => "Google Chrome",
            var name => name
        };

    /// <summary>
    ///     A single sign-in in one browser tab: opens Okta, pre-fills the sign-in form, then waits for the SAML response posted
    ///     to AWS (app sign-in) or for an active Okta session (Okta profile sign-in)
    /// </summary>
    private sealed class SignInFlow(ChromiumBrowser browser, OktaBrowserSignInRequest request, IOktaSessionClient sessionClient, ILogger logger)
    {
        private const string SIGNED_IN_PAGE =
            """
            <!doctype html>
            <html><head><meta charset="utf-8"><title>aws-cred-mgr</title></head>
            <body style="font-family: sans-serif; margin: 3em">
              <h2>You are signed in</h2>
              <p>aws-cred-mgr received your AWS sign-in, this tab is closing.</p>
            </body></html>
            """;

        /// <summary>
        ///     Shared helpers for the page scripts: visible, editable Okta sign-in widget inputs (Identity Engine and Classic widgets)
        /// </summary>
        private const string SCRIPT_HELPERS =
            """
            const isVisible = input => !!input && !input.disabled && !input.readOnly && input.getClientRects().length > 0;
            const findInput = selectors => selectors.map(selector => document.querySelector(selector)).find(isVisible) || null;
            const findUsername = () => findInput(['input[name="identifier"]', 'input[name="username"]', '#okta-signin-username']);
            const findPassword = () => findInput(['input[name="credentials.passcode"]', 'input[name="password"]', '#okta-signin-password']);
            """;

        private const string PROBE_SCRIPT =
            $$"""
              (() => {
                {{SCRIPT_HELPERS}}
                const username = findUsername();
                const password = findPassword();
                return { origin: location.origin, username: !!username && !username.value, password: !!password && !password.value };
              })()
              """;

        private const string FILL_FUNCTION =
            $$"""
              function (expectedOrigin, username, password) {
                if (location.origin !== expectedOrigin)
                  return { username: false, password: false };

                {{SCRIPT_HELPERS}}
                const setValue = (input, value) => {
                  const valueSetter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set;
                  input.focus();
                  valueSetter.call(input, value);
                  input.dispatchEvent(new Event('input', { bubbles: true }));
                  input.dispatchEvent(new Event('change', { bubbles: true }));
                };

                const usernameInput = username == null ? null : findUsername();
                const passwordInput = password == null ? null : findPassword();

                if (usernameInput && !usernameInput.value) setValue(usernameInput, username);
                if (passwordInput && !passwordInput.value) setValue(passwordInput, password);

                const form = (passwordInput || usernameInput || {}).form;
                const missingPassword = !!form && Array.from(form.querySelectorAll('input[type="password"]')).some(input => isVisible(input) && !input.value);

                if (form && !missingPassword) {
                  const submit = form.querySelector('[type="submit"]');
                  if (submit) submit.click(); else form.requestSubmit();
                }

                return { username: !!usernameInput, password: !!passwordInput };
              }
              """;

        // AWS sign-in endpoints (regional endpoints are subdomains), see: https://docs.aws.amazon.com/general/latest/gr/signin-service.html
        private static readonly string[] AwsSamlSignInUrlPatterns =
            new[] { "signin.aws.amazon.com", "signin.amazonaws-us-gov.com", "signin.amazonaws.cn" }
                .Select(host => $"{Uri.UriSchemeHttps}://*{host}/saml*")
                .ToArray();

        private static readonly TimeSpan PollInterval = TimeSpan.FromSeconds(1);

        private readonly CdpConnection _cdp = browser.Connection;
        private readonly string _oktaOrigin = request.OktaDomain.GetLeftPart(UriPartial.Authority);
        private string _targetId = string.Empty;
        private string _sessionId = string.Empty;
        private string? _userAgent;
        private bool _usernameFilled;
        private bool _passwordFilled;
        private string? _lastCheckedSessionCookies;

        public static OktaBrowserSignInException BrowserClosed() =>
            new("The browser window was closed before the Okta sign-in completed, please try again");

        public async Task<AuthenticationResult> RunAsync(CancellationToken cancellationToken)
        {
            var version = await _cdp.SendAsync("Browser.getVersion", cancellationToken: cancellationToken);
            _userAgent = GetString(version["userAgent"]);

            await AttachToPageAsync(cancellationToken);

            await SendToPageAsync("Network.enable", null, cancellationToken);
            await SendToPageAsync("Page.enable", null, cancellationToken);

            if (request.OktaAppUrl is not null)
            {
                var patterns = new JsonArray(AwsSamlSignInUrlPatterns.Select(pattern => (JsonNode)new JsonObject { ["urlPattern"] = pattern }).ToArray());
                await SendToPageAsync("Fetch.enable", new JsonObject { ["patterns"] = patterns }, cancellationToken);
            }

            await SendToPageAsync("Page.bringToFront", null, cancellationToken);
            await SendToPageAsync("Page.navigate", new JsonObject { ["url"] = request.OktaAppUrl ?? request.OktaDomain.ToString() }, cancellationToken);

            while (true)
            {
                if (!await WaitForEventsAsync(cancellationToken))
                    throw BrowserClosed();

                while (_cdp.Events.TryRead(out var cdpEvent))
                {
                    if (await HandleEventAsync(cdpEvent, cancellationToken) is { } result)
                        return result;
                }

                await TryFillSignInFormAsync(cancellationToken);

                if (request.OktaAppUrl is null && await TryGetActiveSessionAsync(cancellationToken) is { } sessionResult)
                    return sessionResult;
            }
        }

        public async Task CloseSignInTabAsync()
        {
            if (_targetId.Length == 0 || _cdp.IsClosed)
                return;

            try
            {
                using var closeTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(3));
                await _cdp.SendAsync("Target.closeTarget", new JsonObject { ["targetId"] = _targetId }, cancellationToken: closeTimeout.Token);
            }
            catch (Exception e) when (e is CdpException or OperationCanceledException)
            {
                logger.LogDebug(e, "Unable to close the Okta sign-in tab");
            }
        }

        private async Task AttachToPageAsync(CancellationToken cancellationToken)
        {
            string? targetId = null;

            // reuse the about:blank tab of a new browser, or the leftover tab of a browser still running with this profile
            for (var attempt = 0; targetId is null && attempt < 20; attempt++)
            {
                var targets = await _cdp.SendAsync("Target.getTargets", cancellationToken: cancellationToken);

                targetId = (targets["targetInfos"] as JsonArray)?
                    .OfType<JsonObject>()
                    .Where(target => GetString(target["type"]) == "page")
                    .Select(target => GetString(target["targetId"]))
                    .FirstOrDefault(id => id is not null);

                if (targetId is null)
                    await Task.Delay(TimeSpan.FromMilliseconds(100), cancellationToken);
            }

            if (targetId is null)
            {
                var newTarget = await _cdp.SendAsync("Target.createTarget",
                    new JsonObject { ["url"] = "about:blank", ["newWindow"] = false }, cancellationToken: cancellationToken);

                targetId = GetString(newTarget["targetId"]) ?? throw new OktaBrowserSignInException("Unable to open a browser tab for the Okta sign-in");
            }

            var attachResult = await _cdp.SendAsync("Target.attachToTarget",
                new JsonObject { ["targetId"] = targetId, ["flatten"] = true }, cancellationToken: cancellationToken);

            _targetId = targetId;
            _sessionId = GetString(attachResult["sessionId"]) ?? throw new OktaBrowserSignInException("Unable to attach to the browser tab");
        }

        private async Task<bool> WaitForEventsAsync(CancellationToken cancellationToken)
        {
            using var poll = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            poll.CancelAfter(PollInterval);

            try
            {
                return await _cdp.Events.WaitToReadAsync(poll.Token);
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                return true;
            }
        }

        private async Task<AuthenticationResult?> HandleEventAsync(CdpEvent cdpEvent, CancellationToken cancellationToken)
        {
            switch (cdpEvent.Method)
            {
                case "Fetch.requestPaused" when cdpEvent.SessionId == _sessionId:
                    return await HandlePausedRequestAsync(cdpEvent.Params, cancellationToken);

                case "Target.detachedFromTarget" when GetString(cdpEvent.Params["sessionId"]) == _sessionId
                                                     || GetString(cdpEvent.Params["targetId"]) == _targetId:
                case "Inspector.detached" when cdpEvent.SessionId == _sessionId:
                    throw BrowserClosed();

                default:
                    return null;
            }
        }

        private async Task<AuthenticationResult?> HandlePausedRequestAsync(JsonObject parameters, CancellationToken cancellationToken)
        {
            var requestId = GetString(parameters["requestId"]) ?? string.Empty;
            var pausedRequest = parameters["request"] as JsonObject;
            var form = GetString(pausedRequest?["method"]) == "POST"
                ? ParseForm(await GetPostDataAsync(parameters, pausedRequest!, cancellationToken))
                : [];

            if (!form.TryGetValue("SAMLResponse", out var samlResponse) || string.IsNullOrEmpty(samlResponse))
            {
                await SendToPageAsync("Fetch.continueRequest", new JsonObject { ["requestId"] = requestId }, cancellationToken);

                return null;
            }

            await FulfillWithSignedInPageAsync(requestId, cancellationToken);

            var samlData = new SamlData(samlResponse, GetString(pausedRequest!["url"]) ?? string.Empty, form.GetValueOrDefault("RelayState") ?? string.Empty);
            var cookies = await GetOktaCookiesAsync(cancellationToken);

            return CreateResult(cookies, sessionId: null, new CapturedSamlResponse(request.OktaAppUrl!, samlData));
        }

        private async Task<string> GetPostDataAsync(JsonObject parameters, JsonObject pausedRequest, CancellationToken cancellationToken)
        {
            if (GetString(pausedRequest["postData"]) is { Length: > 0 } postData)
                return postData;

            if (pausedRequest["postDataEntries"] is JsonArray { Count: > 0 } entries)
            {
                var bytes = entries
                    .Select(entry => GetString(entry?["bytes"]))
                    .Where(entry => entry is not null)
                    .SelectMany(entry => Convert.FromBase64String(entry!))
                    .ToArray();

                return Encoding.UTF8.GetString(bytes);
            }

            // large request bodies are left out of the paused request, they can still be read through the network domain
            if (GetString(parameters["networkId"]) is { } networkId)
            {
                try
                {
                    var result = await SendToPageAsync("Network.getRequestPostData", new JsonObject { ["requestId"] = networkId }, cancellationToken);

                    return GetString(result["postData"]) ?? string.Empty;
                }
                catch (CdpException e) when (e is not CdpConnectionClosedException)
                {
                    logger.LogDebug(e, "Unable to read the AWS sign-in request body");
                }
            }

            return string.Empty;
        }

        private async Task FulfillWithSignedInPageAsync(string requestId, CancellationToken cancellationToken)
        {
            var parameters = new JsonObject
            {
                ["requestId"] = requestId,
                ["responseCode"] = 200,
                ["responseHeaders"] = new JsonArray(new JsonObject { ["name"] = "Content-Type", ["value"] = "text/html; charset=utf-8" }),
                ["body"] = Convert.ToBase64String(Encoding.UTF8.GetBytes(SIGNED_IN_PAGE))
            };

            try
            {
                await SendToPageAsync("Fetch.fulfillRequest", parameters, cancellationToken);
            }
            catch (CdpException e) when (e is not CdpConnectionClosedException)
            {
                logger.LogDebug(e, "Unable to answer the AWS sign-in request in the browser");
            }
        }

        private async Task TryFillSignInFormAsync(CancellationToken cancellationToken)
        {
            var usernamePending = request.Username is not null && !_usernameFilled;
            var passwordPending = request.Password is not null && !_passwordFilled;

            if (!usernamePending && !passwordPending)
                return;

            try
            {
                // look at the page without handing over any credential first: only the Okta sign-in page may receive them
                var probe = await EvaluateAsync(PROBE_SCRIPT, cancellationToken);

                if (probe is null || !string.Equals(GetString(probe["origin"]), _oktaOrigin, StringComparison.OrdinalIgnoreCase))
                    return;

                var fillUsername = usernamePending && GetBool(probe["username"]);
                var fillPassword = passwordPending && GetBool(probe["password"]);

                if (!fillUsername && !fillPassword)
                    return;

                var filled = await FillSignInFormAsync(fillUsername ? request.Username : null, fillPassword ? request.Password : null, cancellationToken);

                // every field is filled at most once per sign-in, a rejected saved password is never submitted again
                _usernameFilled |= GetBool(filled?["username"]);
                _passwordFilled |= GetBool(filled?["password"]);
            }
            catch (CdpException e) when (e is not CdpConnectionClosedException)
            {
                // the page navigated while the script was running
                logger.LogTrace(e, "Okta sign-in form pre-fill skipped");
            }
        }

        private async Task<JsonObject?> FillSignInFormAsync(string? username, string? password, CancellationToken cancellationToken)
        {
            var globalObject = await SendToPageAsync("Runtime.evaluate", new JsonObject { ["expression"] = "globalThis" }, cancellationToken);

            if (GetString(globalObject["result"]?["objectId"]) is not { } objectId)
                return null;

            var parameters = new JsonObject
            {
                ["functionDeclaration"] = FILL_FUNCTION,
                ["objectId"] = objectId,
                ["arguments"] = new JsonArray(
                    new JsonObject { ["value"] = _oktaOrigin },
                    new JsonObject { ["value"] = username },
                    new JsonObject { ["value"] = password }),
                ["returnByValue"] = true
            };

            var result = await SendToPageAsync("Runtime.callFunctionOn", parameters, cancellationToken);

            return result["result"]?["value"] as JsonObject;
        }

        private async Task<JsonObject?> EvaluateAsync(string expression, CancellationToken cancellationToken)
        {
            var result = await SendToPageAsync("Runtime.evaluate", new JsonObject { ["expression"] = expression, ["returnByValue"] = true }, cancellationToken);

            return result["exceptionDetails"] is null ? result["result"]?["value"] as JsonObject : null;
        }

        /// <summary>
        ///     Okta profile sign-in (no app): completes once the browser cookies carry an Okta session that Okta reports as active
        /// </summary>
        private async Task<AuthenticationResult?> TryGetActiveSessionAsync(CancellationToken cancellationToken)
        {
            var cookies = await GetOktaCookiesAsync(cancellationToken);

            var sessionCookies = string.Join(';', cookies.Where(c => c.Name is "sid" or "idx").OrderBy(c => c.Name).Select(c => $"{c.Name}={c.Value}"));

            // only ask Okta again once the session cookies change (e.g. after the next sign-in step)
            if (sessionCookies.Length == 0 || sessionCookies == _lastCheckedSessionCookies)
                return null;

            _lastCheckedSessionCookies = sessionCookies;

            var result = CreateResult(cookies, sessionId: null, capturedSaml: null);

            try
            {
                var activeSession = await sessionClient.GetActiveSessionAsync(result, cancellationToken);

                return activeSession is not null ? result with { SessionId = activeSession.Id } : null;
            }
            catch (HttpRequestException e)
            {
                logger.LogDebug(e, "Unable to check the Okta session");
                _lastCheckedSessionCookies = null;

                return null;
            }
        }

        private async Task<List<BrowserCookie>> GetOktaCookiesAsync(CancellationToken cancellationToken)
        {
            JsonObject result;

            try
            {
                result = await SendToPageAsync("Network.getCookies", new JsonObject { ["urls"] = new JsonArray(_oktaOrigin + "/") }, cancellationToken);
            }
            catch (CdpException e) when (e is not CdpConnectionClosedException)
            {
                logger.LogDebug(e, "Unable to read the Okta cookies from the browser");

                return [];
            }

            return (result["cookies"] as JsonArray ?? [])
                .OfType<JsonObject>()
                .Select(cookie => new BrowserCookie(
                    Name: GetString(cookie["name"]) ?? string.Empty,
                    Value: GetString(cookie["value"]) ?? string.Empty,
                    Domain: GetString(cookie["domain"]) ?? request.OktaDomain.Host,
                    Path: GetString(cookie["path"]) ?? "/",
                    Expires: cookie["expires"] is JsonValue expires && expires.TryGetValue<double>(out var seconds) ? seconds : -1,
                    Secure: GetBool(cookie["secure"]),
                    HttpOnly: GetBool(cookie["httpOnly"])))
                .Where(cookie => cookie.Name.Length > 0)
                .ToList();
        }

        private AuthenticationResult CreateResult(List<BrowserCookie> cookies, string? sessionId, CapturedSamlResponse? capturedSaml)
        {
            var cookieContainer = new CookieContainer();

            foreach (var cookie in cookies)
            {
                try
                {
                    cookieContainer.Add(new Cookie(cookie.Name, cookie.Value, cookie.Path, cookie.Domain)
                    {
                        Secure = cookie.Secure,
                        HttpOnly = cookie.HttpOnly,
                        Expires = cookie.Expires > 0 ? DateTimeOffset.FromUnixTimeMilliseconds((long)(cookie.Expires * 1000)).LocalDateTime : DateTime.MinValue
                    });
                }
                catch (CookieException e)
                {
                    logger.LogDebug(e, "Ignoring Okta cookie {CookieName}", cookie.Name);
                }
            }

            return new AuthenticationResult
            {
                OktaDomain = request.OktaDomain,
                Authenticated = true,
                MfaUsed = request.MfaType,
                SessionId = sessionId,
                SessionCookies = cookieContainer.Count > 0 ? cookieContainer : null,
                UserAgent = _userAgent,
                CapturedSaml = capturedSaml
            };
        }

        private Task<JsonObject> SendToPageAsync(string method, JsonObject? parameters, CancellationToken cancellationToken) =>
            _cdp.SendAsync(method, parameters, _sessionId, cancellationToken);

        private static Dictionary<string, string> ParseForm(string body)
        {
            var form = new Dictionary<string, string>(StringComparer.Ordinal);

            foreach (var pair in body.Split('&', StringSplitOptions.RemoveEmptyEntries))
            {
                var separatorIndex = pair.IndexOf('=');
                var name = DecodeFormValue(separatorIndex < 0 ? pair : pair[..separatorIndex]);
                var value = separatorIndex < 0 ? string.Empty : DecodeFormValue(pair[(separatorIndex + 1)..]);

                form.TryAdd(name, value);
            }

            return form;
        }

        private static string DecodeFormValue(string value) => Uri.UnescapeDataString(value.Replace('+', ' '));

        private static string? GetString(JsonNode? node) => node is JsonValue value && value.TryGetValue<string>(out var text) ? text : null;

        private static bool GetBool(JsonNode? node) => node is JsonValue value && value.TryGetValue<bool>(out var flag) && flag;

        private sealed record BrowserCookie(string Name, string Value, string Domain, string Path, double Expires, bool Secure, bool HttpOnly);
    }
}
