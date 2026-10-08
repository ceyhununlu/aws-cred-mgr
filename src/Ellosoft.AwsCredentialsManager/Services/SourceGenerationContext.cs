// Copyright (c) 2023 Ellosoft Limited. All rights reserved.

using System.Text.Json.Serialization;
using Ellosoft.AwsCredentialsManager.Services.AWS;
using Ellosoft.AwsCredentialsManager.Services.Configuration.Models;
using Ellosoft.AwsCredentialsManager.Services.Okta.Sessions;

namespace Ellosoft.AwsCredentialsManager.Services;

[JsonSourceGenerationOptions]
[JsonSerializable(typeof(AwsCredentialsService.ProfileMetadata))]
[JsonSerializable(typeof(UserCredentials))]
[JsonSerializable(typeof(StoredOktaSession))]
internal partial class SourceGenerationContext : JsonSerializerContext
{
}
