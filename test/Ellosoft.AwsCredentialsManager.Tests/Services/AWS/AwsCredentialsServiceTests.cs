// Copyright (c) 2026 Ellosoft Limited. All rights reserved.

using Amazon.SecurityToken;
using Amazon.SecurityToken.Model;
using Ellosoft.AwsCredentialsManager.Services.AWS;
using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;
using NSubstitute.ExceptionExtensions;

namespace Ellosoft.AwsCredentialsManager.Tests.Services.AWS;

public class AwsCredentialsServiceTests
{
    private const string RoleArn = "arn:aws:iam::123:role/TestRole";
    private const string IdpArn = "arn:aws:iam::123:saml-provider/okta";

    private readonly IAmazonSecurityTokenService _stsClient = Substitute.For<IAmazonSecurityTokenService>();
    private readonly AwsCredentialsService _credentialsService;

    public AwsCredentialsServiceTests()
    {
        _credentialsService = new AwsCredentialsService(NullLogger<AwsCredentialsService>.Instance, () => _stsClient);
    }

    [Fact]
    public async Task GetAwsCredentials_ShouldRequestTheSessionDuration()
    {
        _stsClient.AssumeRoleWithSAMLAsync(Arg.Any<AssumeRoleWithSAMLRequest>(), Arg.Any<CancellationToken>()).Returns(CreateResponse());

        var credentials = await _credentialsService.GetAwsCredentials("saml", RoleArn, IdpArn, expirationInMinutes: 480);

        credentials.AccessKeyId.ShouldBe("ASIAEXAMPLEACCESSKEY");
        credentials.RoleArn.ShouldBe(RoleArn);

        await _stsClient.Received(1).AssumeRoleWithSAMLAsync(
            Arg.Is<AssumeRoleWithSAMLRequest>(r => r.DurationSeconds == 480 * 60 && r.RoleArn == RoleArn && r.PrincipalArn == IdpArn && r.SAMLAssertion == "saml"),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task GetAwsCredentials_WhenRoleDoesNotAllowTheSessionDuration_ShouldRequestOneHour()
    {
        _stsClient.AssumeRoleWithSAMLAsync(Arg.Is<AssumeRoleWithSAMLRequest>(r => r.DurationSeconds == 7200), Arg.Any<CancellationToken>())
            .ThrowsAsync(CreateStsException("ValidationError", "The requested DurationSeconds exceeds the MaxSessionDuration set for this role."));

        _stsClient.AssumeRoleWithSAMLAsync(Arg.Is<AssumeRoleWithSAMLRequest>(r => r.DurationSeconds == 3600), Arg.Any<CancellationToken>())
            .Returns(CreateResponse());

        var credentials = await _credentialsService.GetAwsCredentials("saml", RoleArn, IdpArn);

        credentials.AccessKeyId.ShouldBe("ASIAEXAMPLEACCESSKEY");
        await _stsClient.Received(2).AssumeRoleWithSAMLAsync(Arg.Any<AssumeRoleWithSAMLRequest>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task GetAwsCredentials_WhenStsRejectsTheSamlAssertion_ShouldNotRetry()
    {
        _stsClient.AssumeRoleWithSAMLAsync(Arg.Any<AssumeRoleWithSAMLRequest>(), Arg.Any<CancellationToken>())
            .ThrowsAsync(CreateStsException("InvalidIdentityToken", "The SAML assertion is expired"));

        await Should.ThrowAsync<InvalidOperationException>(() => _credentialsService.GetAwsCredentials("saml", RoleArn, IdpArn));

        await _stsClient.Received(1).AssumeRoleWithSAMLAsync(Arg.Any<AssumeRoleWithSAMLRequest>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task GetAwsCredentials_WhenOneHourExceedsTheRoleMaximum_ShouldNotRetry()
    {
        _stsClient.AssumeRoleWithSAMLAsync(Arg.Any<AssumeRoleWithSAMLRequest>(), Arg.Any<CancellationToken>())
            .ThrowsAsync(CreateStsException("ValidationError", "The requested DurationSeconds exceeds the MaxSessionDuration set for this role."));

        await Should.ThrowAsync<InvalidOperationException>(() => _credentialsService.GetAwsCredentials("saml", RoleArn, IdpArn, expirationInMinutes: 60));

        await _stsClient.Received(1).AssumeRoleWithSAMLAsync(Arg.Any<AssumeRoleWithSAMLRequest>(), Arg.Any<CancellationToken>());
    }

    private static AmazonSecurityTokenServiceException CreateStsException(string errorCode, string message) =>
        new(message) { ErrorCode = errorCode };

    private static AssumeRoleWithSAMLResponse CreateResponse() =>
        new()
        {
            Credentials = new Credentials
            {
                AccessKeyId = "ASIAEXAMPLEACCESSKEY",
                SecretAccessKey = "secret",
                SessionToken = "token",
                Expiration = DateTime.UtcNow.AddHours(1)
            }
        };
}
