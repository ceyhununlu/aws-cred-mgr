// Copyright (c) 2026 Ellosoft Limited. All rights reserved.

using Ellosoft.AwsCredentialsManager.Services.Okta.Models;
using Ellosoft.AwsCredentialsManager.Services.Okta.Sessions;
using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;
using NSubstitute.ExceptionExtensions;
using Spectre.Console.Testing;

namespace Ellosoft.AwsCredentialsManager.Tests.Services.Okta.Sessions;

public class OktaSessionServiceTests
{
    private const string Profile = "default";
    private static readonly Uri OktaDomain = new("https://xyz.okta.com/");

    private static readonly AuthenticationResult SavedSession =
        new() { OktaDomain = OktaDomain, Authenticated = true, SessionId = "102sid", IsResumedSession = true };

    private readonly IOktaSessionStore _sessionStore = Substitute.For<IOktaSessionStore>();
    private readonly IOktaSessionClient _sessionClient = Substitute.For<IOktaSessionClient>();
    private readonly TestConsole _console = new();
    private readonly OktaSessionService _sessionService;

    public OktaSessionServiceTests()
    {
        _sessionService = new OktaSessionService(_sessionStore, _sessionClient, _console, NullLogger<OktaSessionService>.Instance);
    }

    [Fact]
    public async Task ResumeAsync_WhenNoSessionWasSaved_ShouldReturnNullWithoutCallingOkta()
    {
        _sessionStore.Load(Profile, OktaDomain).Returns((AuthenticationResult?)null);

        var session = await _sessionService.ResumeAsync(Profile, OktaDomain, TestContext.Current.CancellationToken);

        session.ShouldBeNull();
        await _sessionClient.DidNotReceiveWithAnyArgs().GetActiveSessionAsync(default!, TestContext.Current.CancellationToken);
    }

    [Fact]
    public async Task ResumeAsync_WhenSavedSessionIsActive_ShouldReturnItWithTheCurrentSessionId()
    {
        _sessionStore.Load(Profile, OktaDomain).Returns(SavedSession with { SessionId = null });
        _sessionClient.GetActiveSessionAsync(Arg.Any<AuthenticationResult>(), Arg.Any<CancellationToken>())
            .Returns(new OktaSessionInfo("102active", DateTimeOffset.UtcNow.AddHours(1)));

        var session = await _sessionService.ResumeAsync(Profile, OktaDomain, TestContext.Current.CancellationToken);

        session.ShouldNotBeNull();
        session.SessionId.ShouldBe("102active");
        session.IsResumedSession.ShouldBeTrue();
        _sessionStore.DidNotReceiveWithAnyArgs().Delete(default!);
    }

    [Fact]
    public async Task ResumeAsync_WhenSavedSessionExpired_ShouldRemoveIt()
    {
        _sessionStore.Load(Profile, OktaDomain).Returns(SavedSession);
        _sessionClient.GetActiveSessionAsync(SavedSession, Arg.Any<CancellationToken>()).Returns((OktaSessionInfo?)null);

        var session = await _sessionService.ResumeAsync(Profile, OktaDomain, TestContext.Current.CancellationToken);

        session.ShouldBeNull();
        _sessionStore.Received(1).Delete(Profile);
        _console.Output.ShouldContain("Your saved Okta session has expired");
    }

    [Fact]
    public async Task ResumeAsync_WhenOktaIsUnreachable_ShouldKeepSavedSession()
    {
        _sessionStore.Load(Profile, OktaDomain).Returns(SavedSession);
        _sessionClient.GetActiveSessionAsync(SavedSession, Arg.Any<CancellationToken>()).ThrowsAsync(new HttpRequestException("Connection refused"));

        var session = await _sessionService.ResumeAsync(Profile, OktaDomain, TestContext.Current.CancellationToken);

        session.ShouldBeNull();
        _sessionStore.DidNotReceiveWithAnyArgs().Delete(default!);
    }

    [Fact]
    public async Task EndAsync_WithSavedSession_ShouldEndItInOktaAndRemoveIt()
    {
        _sessionStore.Load(Profile, OktaDomain).Returns(SavedSession);

        var ended = await _sessionService.EndAsync(Profile, OktaDomain, TestContext.Current.CancellationToken);

        ended.ShouldBeTrue();
        _sessionStore.Received(1).Delete(Profile);
        await _sessionClient.Received(1).CloseSessionAsync(SavedSession, Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task EndAsync_WhenOktaIsUnreachable_ShouldStillRemoveSavedSession()
    {
        _sessionStore.Load(Profile, OktaDomain).Returns(SavedSession);
        _sessionClient.CloseSessionAsync(SavedSession, Arg.Any<CancellationToken>()).ThrowsAsync(new HttpRequestException("Connection refused"));

        var ended = await _sessionService.EndAsync(Profile, OktaDomain, TestContext.Current.CancellationToken);

        ended.ShouldBeTrue();
        _sessionStore.Received(1).Delete(Profile);
    }

    [Fact]
    public async Task EndAsync_WithoutSavedSession_ShouldReturnFalse()
    {
        _sessionStore.Load(Profile, OktaDomain).Returns((AuthenticationResult?)null);

        var ended = await _sessionService.EndAsync(Profile, OktaDomain, TestContext.Current.CancellationToken);

        ended.ShouldBeFalse();
        await _sessionClient.DidNotReceiveWithAnyArgs().CloseSessionAsync(default!, TestContext.Current.CancellationToken);
    }

    [Fact]
    public void Save_ShouldSaveSessionInTheStore()
    {
        _sessionStore.Save(Profile, SavedSession).Returns(true);

        _sessionService.Save(Profile, SavedSession).ShouldBeTrue();
    }
}
