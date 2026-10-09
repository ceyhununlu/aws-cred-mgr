// Copyright (c) 2026 Ellosoft Limited. All rights reserved.

using System.Collections.Concurrent;
using System.Net;
using Ellosoft.AwsCredentialsManager.Services.Configuration;
using Ellosoft.AwsCredentialsManager.Services.Configuration.Models;
using Ellosoft.AwsCredentialsManager.Services.Okta.Browser;
using Ellosoft.AwsCredentialsManager.Services.Okta.Exceptions;
using Ellosoft.AwsCredentialsManager.Services.Okta.Sessions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;
using Spectre.Console.Testing;

namespace Ellosoft.AwsCredentialsManager.Tests.Services.Okta.Browser;

/// <summary>
///     Signs in through a real headless browser (Edge, Chrome or Chromium installed on the machine) against a fake Okta site
/// </summary>
public sealed class OktaBrowserAuthenticatorTests : IAsyncLifetime
{
    private const string Username = "john@xyz.com";
    private const string Password = "P@ssw0rd";
    private const string AppPath = "/home/amazon_aws/abc/272";

    private static readonly string? BrowserPath = new BrowserLocator().FindBrowsers().FirstOrDefault();

    private readonly string _profileDirectory = Path.Combine(Path.GetTempPath(), $"aws-cred-mgr-tests-{Guid.NewGuid():N}");
    private readonly TestConsole _console = new();
    private FakeOktaSite _oktaSite = null!;

    public async ValueTask InitializeAsync()
    {
        Assert.SkipWhen(BrowserPath is null, "Microsoft Edge, Google Chrome or Chromium is required for browser sign-in tests");

        _oktaSite = await FakeOktaSite.StartAsync();
    }

    public async ValueTask DisposeAsync()
    {
        if (_oktaSite is not null)
            await _oktaSite.DisposeAsync();

        try
        {
            if (Directory.Exists(_profileDirectory))
                Directory.Delete(_profileDirectory, recursive: true);
        }
        catch (IOException)
        {
            // the browser may still be releasing its profile files
        }
    }

    [Fact]
    public async Task AuthenticateAsync_WithOktaApp_ShouldPreFillSignInFormAndCaptureSamlResponsePostedToAws()
    {
        var authenticator = CreateAuthenticator(TimeSpan.FromMinutes(1));
        var request = new OktaBrowserSignInRequest(_oktaSite.OktaDomain, $"{_oktaSite.Origin}{AppPath}", Username, Password, MfaType: "push");

        var result = await authenticator.AuthenticateAsync(request, TestContext.Current.CancellationToken);

        result.Authenticated.ShouldBeTrue();
        result.MfaUsed.ShouldBe("push");
        result.UserAgent.ShouldNotBeNullOrWhiteSpace();

        var capturedSaml = result.CapturedSaml.ShouldNotBeNull();
        capturedSaml.OktaAppUrl.ShouldBe(request.OktaAppUrl);
        capturedSaml.SamlData.SamlAssertion.ShouldBe(FakeOktaSite.SamlAssertion);
        capturedSaml.SamlData.RelayState.ShouldBe("relay+state");
        capturedSaml.SamlData.SignInUrl.ShouldBe("https://signin.aws.amazon.com/saml");

        result.SessionCookies.ShouldNotBeNull().GetCookieHeader(_oktaSite.OktaDomain).ShouldContain($"sid={FakeOktaSite.SessionId}");

        _oktaSite.SignIns.ShouldBe([(Username, Password)]);
        _console.Output.ShouldContain("Authenticated!");

        await ShouldHaveClosedTheBrowserAsync();
    }

    [Fact]
    public async Task AuthenticateAsync_WithoutOktaApp_ShouldCompleteOnceOktaReportsAnActiveSession()
    {
        var authenticator = CreateAuthenticator(TimeSpan.FromMinutes(1));
        var request = new OktaBrowserSignInRequest(_oktaSite.OktaDomain, OktaAppUrl: null, Username, Password, MfaType: null);

        var result = await authenticator.AuthenticateAsync(request, TestContext.Current.CancellationToken);

        result.Authenticated.ShouldBeTrue();
        result.SessionId.ShouldBe(FakeOktaSite.SessionId);
        result.CapturedSaml.ShouldBeNull();
        result.SessionCookies.ShouldNotBeNull().GetCookieHeader(_oktaSite.OktaDomain).ShouldContain($"sid={FakeOktaSite.SessionId}");

        _oktaSite.SignIns.ShouldBe([(Username, Password)]);

        await ShouldHaveClosedTheBrowserAsync();
    }

    [Fact]
    public async Task AuthenticateAsync_WhenSignInPageIsNotOnTheOktaDomain_ShouldNotFillCredentials()
    {
        var authenticator = CreateAuthenticator(TimeSpan.FromSeconds(8));

        // same fake site, but reached through another origin than the configured Okta domain
        var otherOrigin = _oktaSite.Origin.Replace("127.0.0.1", "localhost", StringComparison.Ordinal);
        var request = new OktaBrowserSignInRequest(_oktaSite.OktaDomain, $"{otherOrigin}{AppPath}", Username, Password, MfaType: null);

        await Should.ThrowAsync<OktaBrowserSignInException>(() => authenticator.AuthenticateAsync(request, TestContext.Current.CancellationToken));

        _oktaSite.SignInPageViews.ShouldBeGreaterThan(0);
        _oktaSite.SignIns.ShouldBeEmpty();
    }

    private OktaBrowserAuthenticator CreateAuthenticator(TimeSpan signInTimeout)
    {
        var configManager = Substitute.For<IConfigManager>();
        configManager.ToolConfig.Returns(new ActiveToolConfiguration(new ToolConfiguration { BrowserPath = BrowserPath }));

        var httpClientFactory = Substitute.For<IHttpClientFactory>();
        httpClientFactory.CreateClient(OktaSessionClient.HttpClientName).Returns(_ => new HttpClient(new HttpClientHandler { UseCookies = false }));

        var sessionClient = new OktaSessionClient(httpClientFactory, NullLogger<OktaSessionClient>.Instance);

        return new OktaBrowserAuthenticator(_console, configManager, Substitute.For<IBrowserLocator>(), sessionClient,
            NullLogger<OktaBrowserAuthenticator>.Instance)
        {
            LaunchOptions = new BrowserLaunchOptions { Headless = true, ExtraArguments = GetTestBrowserArguments() },
            SignInTimeout = signInTimeout,
            ProfileDirectory = _profileDirectory
        };
    }

    private async Task ShouldHaveClosedTheBrowserAsync()
    {
        // a leftover browser would be reused (IsNewInstance == false); a closed one starts a new process
        await using var leftover = await ChromiumBrowser.LaunchAsync(BrowserPath!, _profileDirectory,
            new BrowserLaunchOptions { Headless = true, ExtraArguments = GetTestBrowserArguments() },
            NullLogger.Instance, TestContext.Current.CancellationToken);

        leftover.IsNewInstance.ShouldBeTrue("the sign-in browser should have been closed after authentication");
    }

    private static List<string> GetTestBrowserArguments()
    {
        var arguments = new List<string> { "--use-mock-keychain", "--password-store=basic", "--disable-gpu" };

        // containers and CI agents usually lack the user namespaces needed by the Chromium sandbox
        if (OperatingSystem.IsLinux())
            arguments.Add("--no-sandbox");

        return arguments;
    }

    /// <summary>
    ///     Okta sign-in page, dashboard, AWS app (auto-posting its SAML response to AWS) and session API on a loopback port
    /// </summary>
    private sealed class FakeOktaSite : IAsyncDisposable
    {
        public const string SessionId = "102browser";
        public const string SamlAssertion = "PHNhbWxwOlJlc3BvbnNlPg==";

        private const string SIGN_IN_PAGE =
            """
            <!doctype html>
            <html><body>
              <form method="post" action="/signin">
                <input type="hidden" name="fromURI" value="{fromURI}">
                <input type="text" name="identifier">
                <input type="password" name="credentials.passcode">
                <input type="submit" value="Sign in">
              </form>
            </body></html>
            """;

        private const string APP_PAGE =
            """
            <!doctype html>
            <html><body onload="document.forms[0].submit()">
              <form method="post" action="https://signin.aws.amazon.com/saml">
                <input type="hidden" name="SAMLResponse" value="{saml}">
                <input type="hidden" name="RelayState" value="relay+state">
              </form>
            </body></html>
            """;

        private readonly WebApplication _app;
        private readonly ConcurrentQueue<(string Username, string Password)> _signIns = new();
        private int _signInPageViews;

        private FakeOktaSite(WebApplication app)
        {
            _app = app;
        }

        public string Origin { get; private set; } = string.Empty;

        public Uri OktaDomain => new($"{Origin}/");

        public List<(string Username, string Password)> SignIns => [.. _signIns];

        public int SignInPageViews => _signInPageViews;

        public static async Task<FakeOktaSite> StartAsync()
        {
            var builder = WebApplication.CreateSlimBuilder();
            builder.WebHost.UseUrls("http://127.0.0.1:0");
            builder.Logging.ClearProviders();

            var site = new FakeOktaSite(builder.Build());
            site.MapEndpoints();

            await site._app.StartAsync();

            var address = site._app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses.First();
            site.Origin = new Uri(address).GetLeftPart(UriPartial.Authority);

            return site;
        }

        public async ValueTask DisposeAsync() => await _app.DisposeAsync();

        private void MapEndpoints()
        {
            _app.MapGet("/", (HttpContext context) => HasSession(context)
                ? Results.Content("<html><body>Okta dashboard</body></html>", "text/html")
                : Results.Redirect("/signin?fromURI=/"));

            _app.MapGet(AppPath, (HttpContext context) => HasSession(context)
                ? Results.Content(APP_PAGE.Replace("{saml}", SamlAssertion, StringComparison.Ordinal), "text/html")
                : Results.Redirect($"/signin?fromURI={Uri.EscapeDataString(AppPath)}"));

            _app.MapGet("/signin", (string? fromURI) =>
            {
                Interlocked.Increment(ref _signInPageViews);

                return Results.Content(SIGN_IN_PAGE.Replace("{fromURI}", WebUtility.HtmlEncode(fromURI ?? "/"), StringComparison.Ordinal), "text/html");
            });

            _app.MapPost("/signin", async (HttpContext context) =>
            {
                var form = await context.Request.ReadFormAsync();
                _signIns.Enqueue((form["identifier"].ToString(), form["credentials.passcode"].ToString()));

                context.Response.Cookies.Append("sid", SessionId, new CookieOptions { HttpOnly = true, Path = "/" });

                var fromUri = form["fromURI"].ToString();

                return Results.Redirect(fromUri.StartsWith('/') ? fromUri : "/");
            }).DisableAntiforgery();

            _app.MapGet("/api/v1/sessions/me", (HttpContext context) => HasSession(context)
                ? Results.Json(new { id = SessionId, status = "ACTIVE", expiresAt = DateTime.UtcNow.AddHours(2) })
                : Results.NotFound(new { errorCode = "E0000007" }));
        }

        private static bool HasSession(HttpContext context) => context.Request.Cookies["sid"] == SessionId;
    }
}
