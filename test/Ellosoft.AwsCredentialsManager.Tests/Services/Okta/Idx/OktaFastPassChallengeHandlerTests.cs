// Copyright (c) 2026 Ellosoft Limited. All rights reserved.

using System.Net;
using System.Text.Json.Nodes;
using Ellosoft.AwsCredentialsManager.Services.Okta.Exceptions;
using Ellosoft.AwsCredentialsManager.Services.Okta.Idx;
using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;
using Spectre.Console.Testing;

namespace Ellosoft.AwsCredentialsManager.Tests.Services.Okta.Idx;

public class OktaFastPassChallengeHandlerTests
{
    private const string OktaDomain = "https://xyz.okta.com/";
    private const string PollUrl = "https://xyz.okta.com/idp/idx/authenticators/poll";
    private const string CancelUrl = "https://xyz.okta.com/idp/idx/authenticators/poll/cancel";

    private readonly FakeHttpMessageHandler _oktaHandler = new();
    private readonly FakeHttpMessageHandler _loopbackHandler = new();
    private readonly IOktaVerifyAppLauncher _appLauncher = Substitute.For<IOktaVerifyAppLauncher>();
    private readonly TestConsole _console = new();
    private readonly OktaFastPassChallengeHandler _handler;
    private readonly IdxClient _idxClient;

    public OktaFastPassChallengeHandlerTests()
    {
        var httpClientFactory = Substitute.For<IOktaIdxHttpClientFactory>();
        httpClientFactory.CreateLoopbackClient().Returns(_ => new HttpClient(_loopbackHandler));

        _idxClient = new IdxClient(new HttpClient(_oktaHandler));

        // the platform defaults are covered by ExecuteAsync_PlatformDefaults_*, every test states the strategy it exercises
        _handler = new OktaFastPassChallengeHandler(httpClientFactory, _appLauncher, _console, NullLogger<OktaFastPassChallengeHandler>.Instance)
        {
            Timeout = TimeSpan.FromSeconds(5),
            PreferAppLaunch = true,
            StartOktaVerifyWhenUnreachable = false,
            AppStartupTimeout = TimeSpan.FromMilliseconds(400),
            AppStartupProbeInterval = TimeSpan.FromMilliseconds(20)
        };
    }

    [Fact]
    public void PlatformDefaults_ShouldOpenTheAppThroughOktaOnMacOsAndUseLoopbackWithAppStartupOnWindows()
    {
        var handler = new OktaFastPassChallengeHandler(Substitute.For<IOktaIdxHttpClientFactory>(), _appLauncher, _console, NullLogger<OktaFastPassChallengeHandler>.Instance);

        // cancelling the loopback challenge on Windows commonly ends in "redirect-idp" (IdP routing rule), the Sign-In Widget path (loopback) is used there
        handler.PreferAppLaunch.ShouldBe(!OperatingSystem.IsWindows());
        handler.StartOktaVerifyWhenUnreachable.ShouldBe(OperatingSystem.IsWindows());
    }

    [Fact]
    public async Task ExecuteAsync_Loopback_WhenAppLaunchIsPreferred_ShouldAskOktaToOpenTheAppInsteadOfProbingLoopbackPorts()
    {
        // Okta answers the cancellation with the "launch-authenticator" remediation (Okta Verify deep link)
        _oktaHandler.OnJson(HttpMethod.Post, CancelUrl, IdxPayloads.IdentifyWithoutPassword);

        var result = await _handler.ExecuteAsync(_idxClient, new Uri(OktaDomain), IdxResponse.Parse(IdxPayloads.LoopbackChallenge()), CancellationToken.None);

        result.HasRemediation("launch-authenticator").ShouldBeTrue();

        var body = JsonNode.Parse(_oktaHandler.RequestsTo(HttpMethod.Post, CancelUrl).ShouldHaveSingleItem().Body!)!;
        body["stateHandle"]!.GetValue<string>().ShouldBe(IdxPayloads.StateHandle);
        body["reason"]!.GetValue<string>().ShouldBe("OV_UNREACHABLE_BY_LOOPBACK");

        _loopbackHandler.Requests.ShouldBeEmpty();
        _oktaHandler.RequestsTo(HttpMethod.Post, PollUrl).ShouldBeEmpty();
        _console.Output.ShouldContain("Okta Verify");
    }

    [Fact]
    public async Task ExecuteAsync_Loopback_WhenAppLaunchIsPreferred_WhenOktaDoesNotOfferToOpenTheApp_ShouldFallBackToLoopback()
    {
        _loopbackHandler
            .OnStatus(HttpMethod.Get, "http://localhost:8769/probe", HttpStatusCode.OK)
            .OnStatus(HttpMethod.Post, "http://localhost:8769/challenge", HttpStatusCode.OK);

        _oktaHandler
            .OnJson(HttpMethod.Post, CancelUrl, IdxPayloads.LoopbackChallenge())
            .OnJson(HttpMethod.Post, PollUrl, IdxPayloads.LoopbackChallenge(), IdxPayloads.Success);

        var result = await _handler.ExecuteAsync(_idxClient, new Uri(OktaDomain), IdxResponse.Parse(IdxPayloads.LoopbackChallenge()), CancellationToken.None);

        result.IsSuccess.ShouldBeTrue();
        _oktaHandler.RequestsTo(HttpMethod.Post, CancelUrl).ShouldHaveSingleItem();
        _loopbackHandler.RequestsTo(HttpMethod.Post, "http://localhost:8769/challenge").ShouldHaveSingleItem();
        _appLauncher.DidNotReceiveWithAnyArgs().TryLaunch(default!);
    }

    [Fact]
    public async Task ExecuteAsync_Loopback_ShouldProbePortsAndPostChallengeToFirstListeningPort()
    {
        _handler.PreferAppLaunch = false;

        _loopbackHandler
            .OnUnreachable(HttpMethod.Get, "http://localhost:8769/probe")
            .OnStatus(HttpMethod.Get, "http://localhost:65111/probe", HttpStatusCode.OK)
            .OnStatus(HttpMethod.Post, "http://localhost:65111/challenge", HttpStatusCode.OK);

        _oktaHandler.OnJson(HttpMethod.Post, PollUrl, IdxPayloads.LoopbackChallenge(), IdxPayloads.Success);

        var result = await _handler.ExecuteAsync(_idxClient, new Uri(OktaDomain), IdxResponse.Parse(IdxPayloads.LoopbackChallenge()), CancellationToken.None);

        result.IsSuccess.ShouldBeTrue();

        var challengeRequest = _loopbackHandler.RequestsTo(HttpMethod.Post, "http://localhost:65111/challenge").ShouldHaveSingleItem();
        JsonNode.Parse(challengeRequest.Body!)!["challengeRequest"]!.GetValue<string>().ShouldBe("eyJraWQ.challenge.jwt");
        challengeRequest.Request.Headers.GetValues("Origin").ShouldBe(["https://xyz.okta.com"]);

        _loopbackHandler.RequestsTo(HttpMethod.Post, "http://localhost:8769/challenge").ShouldBeEmpty();
        _oktaHandler.RequestsTo(HttpMethod.Post, PollUrl).ShouldAllBe(r => JsonNode.Parse(r.Body!)!["stateHandle"]!.GetValue<string>() == IdxPayloads.StateHandle);
        _appLauncher.DidNotReceiveWithAnyArgs().TryLaunch(default!);
    }

    [Fact]
    public async Task ExecuteAsync_Loopback_WhenChallengeReturns503_ShouldTryNextPort()
    {
        _handler.PreferAppLaunch = false;

        _loopbackHandler
            .OnStatus(HttpMethod.Get, "http://localhost:8769/probe", HttpStatusCode.OK)
            .OnStatus(HttpMethod.Post, "http://localhost:8769/challenge", HttpStatusCode.ServiceUnavailable)
            .OnStatus(HttpMethod.Get, "http://localhost:65111/probe", HttpStatusCode.OK)
            .OnStatus(HttpMethod.Post, "http://localhost:65111/challenge", HttpStatusCode.OK);

        _oktaHandler.OnJson(HttpMethod.Post, PollUrl, IdxPayloads.Success);

        var result = await _handler.ExecuteAsync(_idxClient, new Uri(OktaDomain), IdxResponse.Parse(IdxPayloads.LoopbackChallenge()), CancellationToken.None);

        result.IsSuccess.ShouldBeTrue();
        _loopbackHandler.RequestsTo(HttpMethod.Post, "http://localhost:65111/challenge").ShouldHaveSingleItem();
    }

    [Fact]
    public async Task ExecuteAsync_Loopback_WhenNoPortIsListening_ShouldCancelPollingWithUnreachableReason()
    {
        _handler.PreferAppLaunch = false;

        _loopbackHandler
            .OnUnreachable(HttpMethod.Get, "http://localhost:8769/probe")
            .OnUnreachable(HttpMethod.Get, "http://localhost:65111/probe");

        _oktaHandler
            .OnJson(HttpMethod.Post, PollUrl, IdxPayloads.LoopbackChallenge())
            .OnJson(HttpMethod.Post, CancelUrl, IdxPayloads.IdentifyWithoutPassword);

        var result = await _handler.ExecuteAsync(_idxClient, new Uri(OktaDomain), IdxResponse.Parse(IdxPayloads.LoopbackChallenge()), CancellationToken.None);

        result.HasRemediation("launch-authenticator").ShouldBeTrue();

        var cancel = _oktaHandler.RequestsTo(HttpMethod.Post, CancelUrl).ShouldHaveSingleItem();
        var body = JsonNode.Parse(cancel.Body!)!;
        body["stateHandle"]!.GetValue<string>().ShouldBe(IdxPayloads.StateHandle);
        body["reason"]!.GetValue<string>().ShouldBe("OV_UNREACHABLE_BY_LOOPBACK");
        body["statusCode"].ShouldBeNull();
    }

    [Theory]
    [InlineData("http://evil.example.com")]
    [InlineData("https://localhost")]
    [InlineData("not a url")]
    public async Task ExecuteAsync_Loopback_WhenChallengeDomainIsNotHttpLoopback_ShouldNotContactItAndCancelPolling(string domain)
    {
        _handler.PreferAppLaunch = false;

        var payload = IdxPayloads.LoopbackChallenge().Replace("\"domain\": \"http://localhost\"", $"\"domain\": \"{domain}\"");

        _oktaHandler
            .OnJson(HttpMethod.Post, PollUrl, payload)
            .OnJson(HttpMethod.Post, CancelUrl, IdxPayloads.IdentifyWithoutPassword);

        var result = await _handler.ExecuteAsync(_idxClient, new Uri(OktaDomain), IdxResponse.Parse(payload), CancellationToken.None);

        result.HasRemediation("launch-authenticator").ShouldBeTrue();
        _loopbackHandler.Requests.ShouldBeEmpty();
        JsonNode.Parse(_oktaHandler.RequestsTo(HttpMethod.Post, CancelUrl).ShouldHaveSingleItem().Body!)!["reason"]!.GetValue<string>().ShouldBe("OV_UNREACHABLE_BY_LOOPBACK");
    }

    [Fact]
    public async Task ExecuteAsync_Loopback_WhenOktaVerifyReturnsError_ShouldCancelPollingWithErrorReason()
    {
        _handler.PreferAppLaunch = false;

        _loopbackHandler
            .OnStatus(HttpMethod.Get, "http://localhost:8769/probe", HttpStatusCode.OK)
            .OnStatus(HttpMethod.Post, "http://localhost:8769/challenge", HttpStatusCode.BadRequest);

        _oktaHandler
            .OnJson(HttpMethod.Post, PollUrl, IdxPayloads.LoopbackChallenge())
            .OnJson(HttpMethod.Post, CancelUrl, IdxPayloads.SelectAuthenticator);

        var result = await _handler.ExecuteAsync(_idxClient, new Uri(OktaDomain), IdxResponse.Parse(IdxPayloads.LoopbackChallenge()), CancellationToken.None);

        result.HasRemediation("select-authenticator-authenticate").ShouldBeTrue();

        var body = JsonNode.Parse(_oktaHandler.RequestsTo(HttpMethod.Post, CancelUrl).ShouldHaveSingleItem().Body!)!;
        body["reason"]!.GetValue<string>().ShouldBe("OV_RETURNED_ERROR");
        body["statusCode"]!.GetValue<int>().ShouldBe(400);
        _loopbackHandler.RequestsTo(HttpMethod.Get, "http://localhost:65111/probe").ShouldBeEmpty();
    }

    [Fact]
    public async Task ExecuteAsync_Loopback_WhenOktaIssuesSecondChallenge_ShouldSendNewChallengeRequest()
    {
        _handler.PreferAppLaunch = false;

        _loopbackHandler
            .OnStatus(HttpMethod.Get, "http://localhost:8769/probe", HttpStatusCode.OK)
            .OnStatus(HttpMethod.Post, "http://localhost:8769/challenge", HttpStatusCode.OK);

        _oktaHandler.OnJson(HttpMethod.Post, PollUrl,
            IdxPayloads.LoopbackChallenge("eyJraWQ.second.jwt"),
            IdxPayloads.LoopbackChallenge("eyJraWQ.second.jwt"),
            IdxPayloads.Success);

        var result = await _handler.ExecuteAsync(_idxClient, new Uri(OktaDomain), IdxResponse.Parse(IdxPayloads.LoopbackChallenge("eyJraWQ.first.jwt")), CancellationToken.None);

        result.IsSuccess.ShouldBeTrue();

        var challenges = _loopbackHandler.RequestsTo(HttpMethod.Post, "http://localhost:8769/challenge")
            .Select(r => JsonNode.Parse(r.Body!)!["challengeRequest"]!.GetValue<string>())
            .ToList();

        challenges.ShouldBe(["eyJraWQ.first.jwt", "eyJraWQ.second.jwt"]);
    }

    [Fact]
    public async Task ExecuteAsync_Loopback_WhenOktaVerifyIsNotRunning_ShouldStartTheAppAndDeliverTheChallengeOnceItListens()
    {
        // Windows strategy: never abandon the loopback challenge while Okta Verify can be brought up
        _handler.PreferAppLaunch = false;
        _handler.StartOktaVerifyWhenUnreachable = true;
        _appLauncher.TryStartApp().Returns(true);

        // first probe round: nothing listens; once the app has been started the first port answers
        _loopbackHandler
            .On(HttpMethod.Get, "http://localhost:8769/probe",
                _ => throw new HttpRequestException("Connection refused"),
                _ => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)))
            .OnUnreachable(HttpMethod.Get, "http://localhost:65111/probe")
            .OnStatus(HttpMethod.Post, "http://localhost:8769/challenge", HttpStatusCode.OK);

        // like the real service, Okta keeps asking to poll until Okta Verify has answered the challenge
        _oktaHandler.On(HttpMethod.Post, PollUrl, _ => Task.FromResult(FakeHttpMessageHandler.Json(
            _loopbackHandler.RequestsTo(HttpMethod.Post, "http://localhost:8769/challenge").Any() ? IdxPayloads.Success : IdxPayloads.LoopbackChallenge())));

        var result = await _handler.ExecuteAsync(_idxClient, new Uri(OktaDomain), IdxResponse.Parse(IdxPayloads.LoopbackChallenge()), CancellationToken.None);

        result.IsSuccess.ShouldBeTrue();

        _appLauncher.Received(1).TryStartApp();
        _appLauncher.DidNotReceiveWithAnyArgs().TryLaunch(default!);

        var challengeRequest = _loopbackHandler.RequestsTo(HttpMethod.Post, "http://localhost:8769/challenge").ShouldHaveSingleItem();
        JsonNode.Parse(challengeRequest.Body!)!["challengeRequest"]!.GetValue<string>().ShouldBe("eyJraWQ.challenge.jwt");
        _loopbackHandler.RequestsTo(HttpMethod.Get, "http://localhost:8769/probe").Count().ShouldBe(2);

        // the challenge was never cancelled, so Okta never got the chance to route the sign-in elsewhere
        _oktaHandler.RequestsTo(HttpMethod.Post, CancelUrl).ShouldBeEmpty();
        _console.Output.ShouldContain("starting Okta Verify");
    }

    [Fact]
    public async Task ExecuteAsync_Loopback_WhenOktaVerifyIsNotRunning_ShouldKeepPollingOktaWhileWaitingForTheApp()
    {
        _handler.PreferAppLaunch = false;
        _handler.StartOktaVerifyWhenUnreachable = true;
        _handler.AppStartupTimeout = TimeSpan.FromMilliseconds(300);
        _handler.AppStartupProbeInterval = TimeSpan.FromMilliseconds(50);
        _appLauncher.TryStartApp().Returns(true);

        _loopbackHandler
            .OnUnreachable(HttpMethod.Get, "http://localhost:8769/probe")
            .OnUnreachable(HttpMethod.Get, "http://localhost:65111/probe");

        _oktaHandler
            .OnJson(HttpMethod.Post, PollUrl, IdxPayloads.LoopbackChallenge())
            .OnJson(HttpMethod.Post, CancelUrl, IdxPayloads.IdentifyWithoutPassword);

        var result = await _handler.ExecuteAsync(_idxClient, new Uri(OktaDomain), IdxResponse.Parse(IdxPayloads.LoopbackChallenge()), CancellationToken.None);

        // the app never came up: Okta is asked for another way to open it (existing fallback)
        result.HasRemediation("launch-authenticator").ShouldBeTrue();
        _appLauncher.Received(1).TryStartApp();

        // several probe rounds happened while the transaction was kept alive with polls
        _loopbackHandler.RequestsTo(HttpMethod.Get, "http://localhost:8769/probe").Count().ShouldBeGreaterThan(2);
        _oktaHandler.RequestsTo(HttpMethod.Post, PollUrl).Count().ShouldBeGreaterThan(1);

        var body = JsonNode.Parse(_oktaHandler.RequestsTo(HttpMethod.Post, CancelUrl).ShouldHaveSingleItem().Body!)!;
        body["reason"]!.GetValue<string>().ShouldBe("OV_UNREACHABLE_BY_LOOPBACK");
    }

    [Fact]
    public async Task ExecuteAsync_Loopback_WhenOktaVerifyCannotBeStarted_ShouldCancelPollingWithUnreachableReason()
    {
        _handler.PreferAppLaunch = false;
        _handler.StartOktaVerifyWhenUnreachable = true;
        _appLauncher.TryStartApp().Returns(false);

        _loopbackHandler
            .OnUnreachable(HttpMethod.Get, "http://localhost:8769/probe")
            .OnUnreachable(HttpMethod.Get, "http://localhost:65111/probe");

        _oktaHandler
            .OnJson(HttpMethod.Post, PollUrl, IdxPayloads.LoopbackChallenge())
            .OnJson(HttpMethod.Post, CancelUrl, IdxPayloads.IdentifyWithoutPassword);

        var result = await _handler.ExecuteAsync(_idxClient, new Uri(OktaDomain), IdxResponse.Parse(IdxPayloads.LoopbackChallenge()), CancellationToken.None);

        result.HasRemediation("launch-authenticator").ShouldBeTrue();
        _appLauncher.Received(1).TryStartApp();
        _loopbackHandler.RequestsTo(HttpMethod.Get, "http://localhost:8769/probe").ShouldHaveSingleItem();
        _oktaHandler.RequestsTo(HttpMethod.Post, CancelUrl).ShouldHaveSingleItem();
        _console.Output.ShouldContain("could not be started");
    }

    [Fact]
    public async Task ExecuteAsync_Loopback_WhenOktaVerifyIsUnreachableAndOktaOnlyOffersAnIdpRedirect_ShouldThrowExplainingTheDeadEnd()
    {
        _handler.PreferAppLaunch = false;
        _handler.StartOktaVerifyWhenUnreachable = true;
        _appLauncher.TryStartApp().Returns(false);

        _loopbackHandler
            .OnUnreachable(HttpMethod.Get, "http://localhost:8769/probe")
            .OnUnreachable(HttpMethod.Get, "http://localhost:65111/probe");

        _oktaHandler
            .OnJson(HttpMethod.Post, PollUrl, IdxPayloads.LoopbackChallenge())
            .OnJson(HttpMethod.Post, CancelUrl, IdxPayloads.RedirectIdpOnly);

        var act = () => _handler.ExecuteAsync(_idxClient, new Uri(OktaDomain), IdxResponse.Parse(IdxPayloads.LoopbackChallenge()), CancellationToken.None);

        var exception = await Should.ThrowAsync<OktaFastPassException>(act);

        exception.Message.ShouldContain("could not be reached on this device");
        exception.Message.ShouldContain("Contoso Entra ID");
        exception.Message.ShouldContain("MICROSOFT");
        exception.Message.ShouldContain("system tray");
        exception.Message.ShouldNotContain("not supported by this tool");

        // the IdP redirect is a browser navigation, it must never be followed by the tool
        _oktaHandler.RequestsTo(HttpMethod.Get, "https://xyz.okta.com/sso/idps/0oa1idpazure?stateToken=02state-handle").ShouldBeEmpty();
    }

    [Fact]
    public async Task ExecuteAsync_Loopback_WhenOktaVerifyRejectsTheChallengeAndOktaOnlyOffersAnIdpRedirect_ShouldThrowWithTheOktaVerifyStatus()
    {
        _handler.PreferAppLaunch = false;

        _loopbackHandler
            .OnStatus(HttpMethod.Get, "http://localhost:8769/probe", HttpStatusCode.OK)
            .OnStatus(HttpMethod.Post, "http://localhost:8769/challenge", HttpStatusCode.Unauthorized);

        _oktaHandler
            .OnJson(HttpMethod.Post, PollUrl, IdxPayloads.LoopbackChallenge())
            .OnJson(HttpMethod.Post, CancelUrl, IdxPayloads.RedirectIdpOnly);

        var act = () => _handler.ExecuteAsync(_idxClient, new Uri(OktaDomain), IdxResponse.Parse(IdxPayloads.LoopbackChallenge()), CancellationToken.None);

        var exception = await Should.ThrowAsync<OktaFastPassException>(act);

        exception.Message.ShouldContain("HTTP 401");
        exception.Message.ShouldContain("Contoso Entra ID");

        var body = JsonNode.Parse(_oktaHandler.RequestsTo(HttpMethod.Post, CancelUrl).ShouldHaveSingleItem().Body!)!;
        body["reason"]!.GetValue<string>().ShouldBe("OV_RETURNED_ERROR");
        body["statusCode"]!.GetValue<int>().ShouldBe(401);
    }

    [Fact]
    public async Task ExecuteAsync_Loopback_WhenOktaIssuesSecondChallengeWhileWaitingForTheApp_ShouldDeliverOnlyTheNewChallenge()
    {
        _handler.PreferAppLaunch = false;
        _handler.StartOktaVerifyWhenUnreachable = true;
        _handler.AppStartupTimeout = TimeSpan.FromSeconds(2);
        _handler.AppStartupProbeInterval = TimeSpan.FromMilliseconds(200);
        _appLauncher.TryStartApp().Returns(true);

        // nothing listens on the first probe (before the app is started), then Okta Verify comes up
        _loopbackHandler
            .On(HttpMethod.Get, "http://localhost:8769/probe",
                _ => throw new HttpRequestException("Connection refused"),
                _ => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)))
            .OnUnreachable(HttpMethod.Get, "http://localhost:65111/probe")
            .OnStatus(HttpMethod.Post, "http://localhost:8769/challenge", HttpStatusCode.OK);

        // the first poll (interval 20ms, well before the 200ms retry) replaces the challenge, Okta succeeds once the new one is delivered
        _oktaHandler.On(HttpMethod.Post, PollUrl, _ => Task.FromResult(FakeHttpMessageHandler.Json(
            _loopbackHandler.RequestsTo(HttpMethod.Post, "http://localhost:8769/challenge").Any(r => r.Body!.Contains("eyJraWQ.second.jwt"))
                ? IdxPayloads.Success
                : IdxPayloads.LoopbackChallenge("eyJraWQ.second.jwt"))));

        var result = await _handler.ExecuteAsync(_idxClient, new Uri(OktaDomain), IdxResponse.Parse(IdxPayloads.LoopbackChallenge("eyJraWQ.first.jwt")), CancellationToken.None);

        result.IsSuccess.ShouldBeTrue();

        var challenges = _loopbackHandler.RequestsTo(HttpMethod.Post, "http://localhost:8769/challenge")
            .Select(r => JsonNode.Parse(r.Body!)!["challengeRequest"]!.GetValue<string>())
            .ToList();

        // the superseded first challenge must not be delivered by the pending retry
        challenges.ShouldBe(["eyJraWQ.second.jwt"]);
    }

    [Fact]
    public async Task ExecuteAsync_CustomUri_ShouldLaunchOktaVerifyAndPollUntilSuccess()
    {
        _appLauncher.TryLaunch(Arg.Any<string>()).Returns(true);
        _oktaHandler.OnJson(HttpMethod.Post, PollUrl, IdxPayloads.CustomUriChallenge(), IdxPayloads.Success);

        var result = await _handler.ExecuteAsync(_idxClient, new Uri(OktaDomain), IdxResponse.Parse(IdxPayloads.CustomUriChallenge()), CancellationToken.None);

        result.IsSuccess.ShouldBeTrue();
        _appLauncher.Received(1).TryLaunch("com-okta-authenticator:/deviceChallenge?challengeRequest=eyJraWQ.custom.jwt");
        _loopbackHandler.Requests.ShouldBeEmpty();
        _oktaHandler.RequestsTo(HttpMethod.Post, PollUrl).Count().ShouldBe(2);
    }

    [Fact]
    public async Task ExecuteAsync_CustomUri_WhenAppCannotBeLaunched_ShouldThrow()
    {
        _appLauncher.TryLaunch(Arg.Any<string>()).Returns(false);
        _oktaHandler.OnJson(HttpMethod.Post, CancelUrl, IdxPayloads.SelectAuthenticator);

        var act = () => _handler.ExecuteAsync(_idxClient, new Uri(OktaDomain), IdxResponse.Parse(IdxPayloads.CustomUriChallenge()), CancellationToken.None);

        var exception = await Should.ThrowAsync<OktaFastPassException>(act);
        exception.Message.ShouldContain("Okta Verify");
        _oktaHandler.RequestsTo(HttpMethod.Post, CancelUrl).ShouldHaveSingleItem();
    }

    [Fact]
    public async Task ExecuteAsync_WhenPollReturnsError_ShouldReturnErrorResponse()
    {
        _appLauncher.TryLaunch(Arg.Any<string>()).Returns(true);
        _oktaHandler.OnJson(HttpMethod.Post, PollUrl, IdxPayloads.InvalidCredentialsError);

        var result = await _handler.ExecuteAsync(_idxClient, new Uri(OktaDomain), IdxResponse.Parse(IdxPayloads.CustomUriChallenge()), CancellationToken.None);

        result.HasErrors.ShouldBeTrue();
    }

    [Fact]
    public async Task ExecuteAsync_WhenUserNeverApproves_ShouldCancelPollingAndThrowTimeout()
    {
        _handler.Timeout = TimeSpan.FromMilliseconds(150);
        _appLauncher.TryLaunch(Arg.Any<string>()).Returns(true);

        _oktaHandler
            .OnJson(HttpMethod.Post, PollUrl, IdxPayloads.CustomUriChallenge())
            .OnJson(HttpMethod.Post, CancelUrl, IdxPayloads.SelectAuthenticator);

        var act = () => _handler.ExecuteAsync(_idxClient, new Uri(OktaDomain), IdxResponse.Parse(IdxPayloads.CustomUriChallenge()), CancellationToken.None);

        var exception = await Should.ThrowAsync<OktaFastPassException>(act);
        exception.Message.ShouldContain("Timed out");

        var body = JsonNode.Parse(_oktaHandler.RequestsTo(HttpMethod.Post, CancelUrl).ShouldHaveSingleItem().Body!)!;
        body["reason"]!.GetValue<string>().ShouldBe("USER_CANCELED");
    }
}
