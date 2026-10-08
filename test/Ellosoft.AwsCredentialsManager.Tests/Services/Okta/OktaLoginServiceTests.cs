// Copyright (c) 2026 Ellosoft Limited. All rights reserved.

using Ellosoft.AwsCredentialsManager.Services.Configuration;
using Ellosoft.AwsCredentialsManager.Services.Configuration.Models;
using Ellosoft.AwsCredentialsManager.Services.Okta;
using Ellosoft.AwsCredentialsManager.Services.Okta.Exceptions;
using Ellosoft.AwsCredentialsManager.Services.Okta.Idx;
using Ellosoft.AwsCredentialsManager.Services.Okta.Interactive;
using Ellosoft.AwsCredentialsManager.Services.Okta.Models;
using Ellosoft.AwsCredentialsManager.Services.Okta.Models.HttpModels;
using Ellosoft.AwsCredentialsManager.Services.Okta.Sessions;
using Ellosoft.AwsCredentialsManager.Services.Security;
using NSubstitute;
using NSubstitute.ExceptionExtensions;
using Spectre.Console.Testing;

namespace Ellosoft.AwsCredentialsManager.Tests.Services.Okta;

public class OktaLoginServiceTests
{
    private const string Profile = "default";
    private static readonly Uri OktaDomain = new("https://xyz.okta.com/");
    private static readonly UserCredentials Credentials = new("john@xyz.com", "P@ssw0rd");

    private readonly IConfigManager _configManager = Substitute.For<IConfigManager>();
    private readonly IUserCredentialsManager _userCredentialsManager = Substitute.For<IUserCredentialsManager>();
    private readonly IOktaClassicAuthenticator _classicAuthenticator = Substitute.For<IOktaClassicAuthenticator>();
    private readonly IOktaIdxAuthenticator _idxAuthenticator = Substitute.For<IOktaIdxAuthenticator>();
    private readonly IOktaSessionService _sessionService = Substitute.For<IOktaSessionService>();
    private readonly OktaLoginService _loginService;

    public OktaLoginServiceTests()
    {
        _userCredentialsManager.GetUserCredentials(Profile).Returns(Credentials);

        _loginService = new OktaLoginService(new TestConsole(), _configManager, _userCredentialsManager, _classicAuthenticator, _idxAuthenticator,
            _sessionService);
    }

    [Fact]
    public async Task InteractiveLogin_WhenPreferredMfaIsFastPass_ShouldUseIdentityEngineAuthenticator()
    {
        ConfigureProfile("fastpass");

        var idxResult = new AuthenticationResult { OktaDomain = OktaDomain, Authenticated = true, SessionId = "102sid", MfaUsed = "signed_nonce" };
        _idxAuthenticator.AuthenticateAsync(OktaDomain, Credentials.Username, Credentials.Password, Arg.Any<CancellationToken>()).Returns(idxResult);

        var result = await _loginService.InteractiveLogin(Profile, createSession: true);

        result.ShouldBe(idxResult);

        await _classicAuthenticator.DidNotReceiveWithAnyArgs().AuthenticateAsync(default!, default!, default!, default);
        await _classicAuthenticator.DidNotReceiveWithAnyArgs().CreateSessionAsync(default!, default!);
    }

    [Theory]
    [InlineData("push")]
    [InlineData(null)]
    public async Task InteractiveLogin_WhenPreferredMfaIsNotFastPass_ShouldUseClassicAuthenticator(string? preferredMfa)
    {
        ConfigureProfile(preferredMfa);

        var classicResult = new AuthenticationResult { OktaDomain = OktaDomain, Authenticated = true, SessionToken = "session-token" };
        _classicAuthenticator.AuthenticateAsync(OktaDomain, Credentials.Username, Credentials.Password, preferredMfa).Returns(classicResult);
        _classicAuthenticator.CreateSessionAsync(OktaDomain, "session-token").Returns(new CreateSessionResult { Id = "102sid", Status = "ACTIVE" });

        var result = await _loginService.InteractiveLogin(Profile, createSession: true);

        result.ShouldNotBeNull();
        result.SessionToken.ShouldBe("session-token");
        result.SessionId.ShouldBe("102sid");

        await _classicAuthenticator.Received(1).CreateSessionAsync(OktaDomain, "session-token");
        await _idxAuthenticator.DidNotReceiveWithAnyArgs().AuthenticateAsync(default!, default!, default!, TestContext.Current.CancellationToken);
    }

    [Fact]
    public async Task InteractiveLogin_WithClassicAuthentication_ShouldCreateAndSaveOktaSession()
    {
        ConfigureProfile("push");

        var classicResult = new AuthenticationResult { OktaDomain = OktaDomain, Authenticated = true, SessionToken = "session-token" };
        _classicAuthenticator.AuthenticateAsync(OktaDomain, Credentials.Username, Credentials.Password, "push").Returns(classicResult);
        _classicAuthenticator.CreateSessionAsync(OktaDomain, "session-token").Returns(new CreateSessionResult { Id = "102sid", Status = "ACTIVE" });

        var result = await _loginService.InteractiveLogin(Profile);

        result.ShouldNotBeNull();
        result.SessionId.ShouldBe("102sid");

        _sessionService.Received(1).Save(Profile, Arg.Is<AuthenticationResult>(r => r.SessionId == "102sid"));
    }

    [Fact]
    public async Task InteractiveLogin_WhenSessionIsNotRemembered_ShouldNotCreateOrSaveOktaSession()
    {
        ConfigureProfile("push", rememberSession: false);

        var classicResult = new AuthenticationResult { OktaDomain = OktaDomain, Authenticated = true, SessionToken = "session-token" };
        _classicAuthenticator.AuthenticateAsync(OktaDomain, Credentials.Username, Credentials.Password, "push").Returns(classicResult);

        var result = await _loginService.InteractiveLogin(Profile);

        result.ShouldBe(classicResult);

        await _classicAuthenticator.DidNotReceiveWithAnyArgs().CreateSessionAsync(default!, default!);
        _sessionService.DidNotReceiveWithAnyArgs().Save(default!, default!);
    }

    [Fact]
    public async Task InteractiveLogin_WhenAuthenticationFails_ShouldNotSaveOktaSession()
    {
        ConfigureProfile("push");

        _classicAuthenticator.AuthenticateAsync(OktaDomain, Credentials.Username, Credentials.Password, "push")
            .Returns(new AuthenticationResult { OktaDomain = OktaDomain, Authenticated = false });

        var result = await _loginService.InteractiveLogin(Profile);

        result.ShouldNotBeNull();
        result.Authenticated.ShouldBeFalse();

        _sessionService.DidNotReceiveWithAnyArgs().Save(default!, default!);
    }

    [Fact]
    public async Task ResumeSessionAsync_ShouldReturnSavedSession()
    {
        ConfigureProfile("push");

        var savedSession = new AuthenticationResult { OktaDomain = OktaDomain, Authenticated = true, SessionId = "102sid", IsResumedSession = true };
        _sessionService.ResumeAsync(Profile, OktaDomain, Arg.Any<CancellationToken>()).Returns(savedSession);

        var result = await _loginService.ResumeSessionAsync(Profile);

        result.ShouldBe(savedSession);
    }

    [Fact]
    public async Task ResumeSessionAsync_WhenSessionIsNotRemembered_ShouldNotUseSavedSession()
    {
        ConfigureProfile("push", rememberSession: false);

        var result = await _loginService.ResumeSessionAsync(Profile);

        result.ShouldBeNull();
        await _sessionService.DidNotReceiveWithAnyArgs().ResumeAsync(default!, default!, TestContext.Current.CancellationToken);
    }

    [Fact]
    public async Task LogoutAsync_ShouldEndSavedSession()
    {
        ConfigureProfile("push");
        _sessionService.EndAsync(Profile, OktaDomain, Arg.Any<CancellationToken>()).Returns(true);

        var result = await _loginService.LogoutAsync(Profile);

        result.ShouldBeTrue();
    }

    [Fact]
    public async Task Login_WhenFastPassAuthenticatorRejectsCredentials_ShouldClearStoredPasswordAndReturnUnauthenticated()
    {
        _idxAuthenticator.AuthenticateAsync(OktaDomain, Credentials.Username, Credentials.Password, Arg.Any<CancellationToken>())
            .ThrowsAsync(new InvalidUsernameOrPasswordException());

        var result = await _loginService.Login(OktaDomain, Credentials, OktaMfaFactorSelector.FastPassFactorCode, savedCredentials: true, Profile);

        result.Authenticated.ShouldBeFalse();
        _userCredentialsManager.Received(1).SaveUserCredentials(Profile, Arg.Is<UserCredentials>(c => c.Username == Credentials.Username && c.Password == string.Empty));
    }

    private void ConfigureProfile(string? preferredMfa, bool? rememberSession = null)
    {
        var config = new AppConfig
        {
            Authentication = new AppConfig.AuthenticationSection
            {
                Okta = new Dictionary<string, OktaConfiguration>
                {
                    [Profile] = new() { OktaDomain = OktaDomain.ToString(), PreferredMfaType = preferredMfa, RememberSession = rememberSession }
                }
            }
        };

        _configManager.AppConfig.Returns(config);
    }
}
