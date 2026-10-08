// Copyright (c) 2026 Ellosoft Limited. All rights reserved.

using Ellosoft.AwsCredentialsManager.Services.Okta.Browser;

namespace Ellosoft.AwsCredentialsManager.Tests.Services.Okta.Browser;

public class OktaBrowserSignInTests
{
    [Theory]
    [InlineData("signed_nonce", "classic", true, true)]
    [InlineData("signed_nonce", "classic", false, false)]
    [InlineData("signed_nonce", null, true, true)]
    [InlineData("push", "classic", true, false)]
    [InlineData(null, "classic", true, false)]
    [InlineData("push", "browser", false, true)]
    [InlineData(null, "BROWSER", true, true)]
    public void IsRequired_ShouldUseBrowserForBrowserProfilesAndFastPassOnWindows(string? preferredMfa, string? authType, bool isWindows, bool expected)
    {
        OktaBrowserSignIn.IsRequired(preferredMfa, authType, isWindows).ShouldBe(expected);
    }
}
