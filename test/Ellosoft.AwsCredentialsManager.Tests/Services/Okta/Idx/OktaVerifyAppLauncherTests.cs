// Copyright (c) 2026 Ellosoft Limited. All rights reserved.

using Ellosoft.AwsCredentialsManager.Services.Okta.Idx;
using Microsoft.Extensions.Logging.Abstractions;

namespace Ellosoft.AwsCredentialsManager.Tests.Services.Okta.Idx;

public class OktaVerifyAppLauncherTests
{
    private readonly OktaVerifyAppLauncher _launcher = new(NullLogger<OktaVerifyAppLauncher>.Instance);

    [Theory]
    [InlineData("https://evil.example.com/")]
    [InlineData("file:///etc/passwd")]
    [InlineData("javascript:alert(1)")]
    [InlineData("com-okta-authenticator-evil:/deviceChallenge")]
    [InlineData("not a uri")]
    [InlineData("")]
    public void TryLaunch_WhenUriIsNotAnOktaVerifyDeepLink_ShouldRefuseToHandItToTheOs(string uri)
    {
        // the URI comes from the IDX response, only the Okta Verify scheme may be handed to the OS URI handler
        _launcher.TryLaunch(uri).ShouldBeFalse();
    }

    [Theory]
    [InlineData("com-okta-authenticator:/deviceChallenge?challengeRequest=eyJraWQ.jwt")]
    [InlineData("COM-OKTA-AUTHENTICATOR://deviceChallenge?challengeRequest=eyJraWQ.jwt")]
    public void IsOktaVerifyDeepLink_ShouldAcceptTheOktaVerifyScheme(string uri)
    {
        OktaVerifyAppLauncher.IsOktaVerifyDeepLink(uri).ShouldBeTrue();
    }

    [Theory]
    [InlineData(@"""C:\Program Files\Okta\Okta Verify\OktaVerify.exe"" --URI ""%1""", @"C:\Program Files\Okta\Okta Verify\OktaVerify.exe")]
    [InlineData(@"""C:\Program Files\Okta\Okta Verify\OktaVerify.exe""", @"C:\Program Files\Okta\Okta Verify\OktaVerify.exe")]
    [InlineData(@"C:\Okta\OktaVerify.exe ""%1""", @"C:\Okta\OktaVerify.exe")]
    [InlineData(@"C:\Okta\oktaverify.EXE", @"C:\Okta\oktaverify.EXE")]
    public void ExtractExecutablePath_ShouldReadTheOktaVerifyExecutableFromTheUriHandlerCommand(string command, string expected)
    {
        OktaVerifyAppLauncher.ExtractExecutablePath(command).ShouldBe(expected);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData(@"""C:\Program Files\Okta\Okta Verify\OktaVerify.exe")]
    [InlineData(@"""C:\Windows\System32\cmd.exe"" /c evil ""%1""")]
    [InlineData(@"C:\Tools\SomethingElse.exe ""%1""")]
    public void ExtractExecutablePath_WhenTheCommandIsNotOktaVerify_ShouldReturnNull(string? command)
    {
        // the registry value is not trusted blindly: only Okta Verify's own executable is ever started
        OktaVerifyAppLauncher.ExtractExecutablePath(command).ShouldBeNull();
    }

    [Fact]
    public void TryStartApp_OnUnsupportedPlatform_ShouldReturnFalse()
    {
        if (OperatingSystem.IsWindows() || OperatingSystem.IsMacOS())
            return;

        _launcher.TryStartApp().ShouldBeFalse();
    }
}
