// Copyright (c) 2023 Ellosoft Limited. All rights reserved.

using Ellosoft.AwsCredentialsManager.Services.Configuration;
using Ellosoft.AwsCredentialsManager.Services.Configuration.Models;
using Ellosoft.AwsCredentialsManager.Services.Okta.Browser;
using Ellosoft.AwsCredentialsManager.Services.Okta.Interactive;

namespace Ellosoft.AwsCredentialsManager.Commands.Okta;

[Name("setup")]
[Description("Setup Okta authentication (All parameters are optional)")]
[Examples(
    "setup",
    "setup -d https://xyz.okta.com -u john --mfa push",
    "setup xyz_profile -d https://xyz.okta.com -u john --mfa push",
    "setup -d https://xyz.okta.com -u john --mfa fastpass",
    "setup -d https://xyz.okta.com -u john --browser")]
public class SetupOkta(IOktaLoginService loginService, IConfigManager configManager) : AsyncCommand<SetupOkta.Settings>
{
    public class Settings : CommonSettings
    {
        [CommandArgument(0, "[PROFILE]")]
        [DefaultValue(OktaConfiguration.DefaultProfileName)]
        [Description("Local Okta profile name (Useful if you need to authenticate in multiple Okta domains)")]
        public string Profile { get; set; } = OktaConfiguration.DefaultProfileName;

        [CommandOption("-d|--domain")]
        [Description("Your organization Okta domain URL (e.g. https://xyz.okta.com)")]
        public string? OktaDomain { get; set; }

        [CommandOption("-u|--user")]
        [Description("Your Okta username")]
        public string? Username { get; set; }

        [CommandOption("--mfa")]
        [Description("Your preferred MFA type <push|totp|code|fastpass> (fastpass uses the Okta Verify desktop app and requires Okta Identity Engine, " +
                     "on Windows it signs in through the browser)")]
        public string? PreferredMfaType { get; set; }

        [CommandOption("--browser")]
        [Description("Sign in to Okta in a browser window (Microsoft Edge or Google Chrome), Okta asks for MFA in the browser")]
        public bool Browser { get; set; }
    }

    protected override async Task<int> ExecuteAsync(CommandContext context, Settings settings, CancellationToken cancellationToken)
    {
        AnsiConsole.MarkupLine("Okta Setup");

        var oktaDomain = GetOktaDomainUrl(settings);
        var username = settings.Username ?? await AnsiConsole.AskAsync<string>("Enter your [green]Okta[/] username:", cancellationToken);
        var preferredMfaType = settings.PreferredMfaType is not null ? OktaMfaFactorSelector.GetOktaMfaFactorCode(settings.PreferredMfaType) : null;
        var authType = settings.Browser ? OktaConfiguration.BrowserAuthType : OktaConfiguration.ClassicAuthType;

        // the password is typed on the Okta page when signing in through the browser
        var password = OktaBrowserSignIn.IsRequired(preferredMfaType, authType)
            ? string.Empty
            : await AnsiConsole.PromptAsync(new TextPrompt<string>("Enter your [green]Okta[/] password:").Secret(), cancellationToken);

        AnsiConsole.WriteLine();

        var credentials = new UserCredentials(username, password);

        var authResult = await loginService.Login(oktaDomain, credentials, preferredMfaType, userProfileKey: settings.Profile, authType: authType);

        if (!authResult.Authenticated)
            throw new CommandException("Unable to create profile, please try again");

        CreateOktaProfile(settings.Profile, oktaDomain.ToString(), authResult.MfaUsed, authType);

        await loginService.SaveSessionAsync(settings.Profile, authResult);

        AnsiConsole.MarkupLine($"[bold green]All good, '{settings.Profile}' Okta profile created[/]");

        return 0;
    }

    private static Uri GetOktaDomainUrl(Settings settings)
    {
        const string URL_MESSAGE = "Enter your [green]Okta[/] domain URL (e.g. https://xyz.okta.com): [grey85][[https://]][/]";

        var oktaDomain = settings.OktaDomain ?? AnsiConsole.Ask<string>(URL_MESSAGE);

        if (!oktaDomain.StartsWith("https://"))
            oktaDomain = $"https://{oktaDomain}";

        while (!Uri.TryCreate(oktaDomain, UriKind.Absolute, out _))
        {
            AnsiConsole.MarkupLine("[red]Invalid URL, please try again[/]");
            oktaDomain = AnsiConsole.Ask<string>(URL_MESSAGE);
        }

        return new Uri(oktaDomain);
    }

    private void CreateOktaProfile(string profileName, string oktaDomain, string? preferredMfaType, string authType)
    {
        var appConfig = configManager.AppConfig;
        appConfig.Authentication ??= new AppConfig.AuthenticationSection();

        appConfig.Authentication.Okta[profileName] = new OktaConfiguration
        {
            OktaDomain = oktaDomain,
            PreferredMfaType = preferredMfaType,
            AuthType = authType
        };

        configManager.SaveConfig();
    }
}
