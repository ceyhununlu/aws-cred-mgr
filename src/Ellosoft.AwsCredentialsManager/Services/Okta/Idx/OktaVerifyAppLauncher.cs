// Copyright (c) 2026 Ellosoft Limited. All rights reserved.

using System.Diagnostics;
using System.Net;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;

namespace Ellosoft.AwsCredentialsManager.Services.Okta.Idx;

public interface IOktaVerifyAppLauncher
{
    /// <summary>
    ///     Opens an Okta Verify deep link (e.g. com-okta-authenticator:/deviceChallenge?challengeRequest=...) with the OS,
    ///     launching the Okta Verify desktop app
    /// </summary>
    /// <returns>true if the OS accepted the request</returns>
    bool TryLaunch(string uri);
}

public partial class OktaVerifyAppLauncher(ILogger<OktaVerifyAppLauncher> logger) : IOktaVerifyAppLauncher
{
    /// <summary>
    ///     URI scheme registered by the Okta Verify desktop app (CUSTOM_URI challenge method)
    /// </summary>
    public const string OktaVerifyScheme = "com-okta-authenticator";

    public bool TryLaunch(string uri)
    {
        // the URI comes from the Okta response: only the Okta Verify scheme may be handed to the OS URI handler
        if (!IsOktaVerifyDeepLink(uri))
        {
            logger.LogWarning("Refusing to open Okta Verify: unexpected URI scheme '{Scheme}'", uri.Split(':')[0]);

            return false;
        }

        try
        {
            if (OperatingSystem.IsWindows() && TryLaunchWindowsExecutable(uri))
                return true;

            var startInfo = CreateStartInfo(uri);

            using var process = Process.Start(startInfo);

            if (DidProtocolLaunch(process, OperatingSystem.IsWindows()))
                return true;

            if (OperatingSystem.IsWindows() && TryLaunchViaCmdStart(uri))
                return true;

            return false;
        }
        catch (Exception e) when (e is Win32Exception or InvalidOperationException or IOException or PlatformNotSupportedException)
        {
            logger.LogWarning(e, "Unable to launch Okta Verify using URI scheme {Scheme}", uri.Split(':')[0]);

            return OperatingSystem.IsWindows() && TryLaunchViaCmdStart(uri);
        }
    }

    public static bool IsOktaVerifyDeepLink(string uri) =>
        Uri.TryCreate(uri, UriKind.Absolute, out var parsed)
        && string.Equals(parsed.Scheme, OktaVerifyScheme, StringComparison.OrdinalIgnoreCase);

    /// <summary>
    ///     ShellExecute of a custom URI often returns null when the handler is an already-running
    ///     process (Okta Verify lives in the Windows tray). That is success, not failure.
    /// </summary>
    public static bool DidProtocolLaunch(Process? process, bool windows) =>
        process is not null || windows;

    /// <summary>
    ///     Finds an Okta Verify custom-URI deep link in a redirect Location header or in HTML returned by
    ///     the Windows FastPass <c>redirect-idp</c> step
    /// </summary>
    public static string? ExtractOktaVerifyDeepLink(string? content)
    {
        if (string.IsNullOrWhiteSpace(content))
            return null;

        var trimmed = content.Trim();

        if (IsOktaVerifyDeepLink(trimmed))
            return trimmed;

        var match = OktaVerifyDeepLinkRegex().Match(content);

        return match.Success ? WebUtility.HtmlDecode(match.Value) : null;
    }

    [GeneratedRegex(@"com-okta-authenticator:[^\s""'<>\\]+", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex OktaVerifyDeepLinkRegex();

    private static ProcessStartInfo CreateStartInfo(string uri)
    {
        if (OperatingSystem.IsWindows())
            return new ProcessStartInfo { FileName = uri, UseShellExecute = true };

        var launcher = OperatingSystem.IsMacOS() ? "open" : "xdg-open";

        return new ProcessStartInfo(launcher, [uri])
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };
    }

    /// <summary>
    ///     Okta Verify on Windows is started as <c>Okta Verify.exe --URI com-okta-authenticator:...</c>.
    ///     That accepts a long challenge JWT; ShellExecute of the raw URI often does not.
    /// </summary>
    private bool TryLaunchWindowsExecutable(string uri)
    {
        foreach (var exe in EnumerateOktaVerifyExecutables())
        {
            try
            {
                var startInfo = new ProcessStartInfo(exe, ["--URI", uri])
                {
                    UseShellExecute = false
                };

                using var process = Process.Start(startInfo);

                if (process is not null)
                {
                    logger.LogDebug("Launched Okta Verify executable {Path}", exe);

                    return true;
                }
            }
            catch (Exception e) when (e is Win32Exception or InvalidOperationException or IOException)
            {
                logger.LogDebug(e, "Could not start Okta Verify at {Path}", exe);
            }
        }

        return false;
    }

    private static bool TryLaunchViaCmdStart(string uri)
    {
        try
        {
            using var process = Process.Start(new ProcessStartInfo("cmd.exe", ["/c", "start", "", uri])
            {
                UseShellExecute = false,
                CreateNoWindow = true
            });

            return DidProtocolLaunch(process, windows: true);
        }
        catch (Exception)
        {
            return false;
        }
    }

    private static IEnumerable<string> EnumerateOktaVerifyExecutables()
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var candidate in WellKnownOktaVerifyPaths().Concat(OktaVerifyPathsFromRegistry()))
        {
            if (seen.Add(candidate) && File.Exists(candidate))
                yield return candidate;
        }
    }

    private static IEnumerable<string> WellKnownOktaVerifyPaths()
    {
        yield return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Okta", "Okta Verify", "Okta Verify.exe");
        yield return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "Okta", "Okta Verify", "Okta Verify.exe");
        yield return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Programs", "Okta", "Okta Verify", "Okta Verify.exe");
    }

    private static IEnumerable<string> OktaVerifyPathsFromRegistry()
    {
        if (!OperatingSystem.IsWindows())
            yield break;

        foreach (var command in ReadOktaVerifyProtocolCommands())
        {
            var exe = TryParseExecutableFromCommand(command);

            if (exe is not null)
                yield return exe;
        }
    }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static IEnumerable<string> ReadOktaVerifyProtocolCommands()
    {
        string[] keys =
        [
            @"Software\Classes\com-okta-authenticator\shell\open\command",
            @"com-okta-authenticator\shell\open\command"
        ];

        foreach (var hive in new[] { Microsoft.Win32.Registry.CurrentUser, Microsoft.Win32.Registry.LocalMachine, Microsoft.Win32.Registry.ClassesRoot })
        {
            foreach (var key in keys)
            {
                using var subKey = hive.OpenSubKey(key);

                if (subKey?.GetValue(null) is string command && command.Length > 0)
                    yield return command;
            }
        }
    }

    public static string? TryParseExecutableFromCommand(string command)
    {
        var match = QuotedPathRegex().Match(command);

        if (match.Success)
            return match.Groups["path"].Value;

        var first = command.Trim().Split(' ', 2)[0];

        return first.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ? first : null;
    }

    [GeneratedRegex("""^"(?<path>[^"]+\.exe)" """, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex QuotedPathRegex();
}
