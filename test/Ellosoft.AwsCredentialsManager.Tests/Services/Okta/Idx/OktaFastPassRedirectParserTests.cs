// Copyright (c) 2026 Ellosoft Limited. All rights reserved.

using Ellosoft.AwsCredentialsManager.Services.Okta.Idx;

namespace Ellosoft.AwsCredentialsManager.Tests.Services.Okta.Idx;

public class OktaFastPassRedirectParserTests
{
    [Fact]
    public void TryGetDeepLink_WhenHtmlHasCustomUri_ShouldReturnIt()
    {
        const string Html = """<html><a href="com-okta-authenticator:/deviceChallenge?challengeRequest=eyJraWQ.jwt">Open</a></html>""";

        OktaFastPassRedirectParser.TryGetDeepLink(location: null, Html)
            .ShouldBe("com-okta-authenticator:/deviceChallenge?challengeRequest=eyJraWQ.jwt");
    }

    [Fact]
    public void TryGetDeepLink_WhenHtmlHasChallengeRequestJwt_ShouldBuildOktaVerifyUri()
    {
        // Windows FastPass /sso/idps often returns the Sign-In Widget shell with the JWT, not the custom URI
        const string Html = """<html><script>var okta = {"authenticatorChallenge":{"challengeRequest":"eyJraWQ.html.jwt","challengeMethod":"CUSTOM_URI"}};</script></html>""";

        OktaFastPassRedirectParser.TryGetDeepLink(location: null, Html)
            .ShouldBe("com-okta-authenticator:/deviceChallenge?challengeRequest=eyJraWQ.html.jwt");
    }

    [Fact]
    public void BuildDeviceChallengeDeepLink_ShouldUrlEncodeTheJwt()
    {
        OktaFastPassRedirectParser.BuildDeviceChallengeDeepLink("eyJ+abc=/")
            .ShouldBe("com-okta-authenticator:/deviceChallenge?challengeRequest=eyJ%2Babc%3D%2F");
    }

    [Fact]
    public void TryGetEmbeddedIdx_WhenHtmlWrapsIonJson_ShouldParseRemediation()
    {
        var html = $"<html><script>window.__oktaIdxResponse = {IdxPayloads.DeviceChallengePollCustomUri};</script></html>";

        var response = OktaFastPassRedirectParser.TryGetEmbeddedIdx(html);

        response.ShouldNotBeNull();
        response.PollRemediation.ShouldNotBeNull();
        response.DeviceChallenge!.Href.ShouldBe("com-okta-authenticator:/deviceChallenge?challengeRequest=eyJraWQ.custom.jwt");
    }

    [Fact]
    public void TryGetEmbeddedIdx_WhenBodyIsPlainIdxJson_ShouldParseIt()
    {
        var response = OktaFastPassRedirectParser.TryGetEmbeddedIdx(IdxPayloads.DeviceChallengePollCustomUri);

        response.ShouldNotBeNull();
        response.HasRemediation(IdxResponse.DeviceChallengePollRemediation).ShouldBeTrue();
    }

    [Fact]
    public void TryGetEmbeddedIdx_WhenHtmlHasNoIdx_ShouldReturnNull()
    {
        OktaFastPassRedirectParser.TryGetEmbeddedIdx("<html><body>Opening Okta Verify...</body></html>").ShouldBeNull();
    }
}
