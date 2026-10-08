// Copyright (c) 2026 Ellosoft Limited. All rights reserved.

namespace Ellosoft.AwsCredentialsManager.Services.Okta.Browser;

public interface IBrowserLocator
{
    /// <summary>
    ///     Chromium based browsers installed on this machine, in order of preference (Microsoft Edge first on Windows)
    /// </summary>
    IReadOnlyList<string> FindBrowsers();
}

public class BrowserLocator : IBrowserLocator
{
    public IReadOnlyList<string> FindBrowsers() =>
        GetCandidatePaths()
            .Where(File.Exists)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

    private static IEnumerable<string> GetCandidatePaths()
    {
        if (OperatingSystem.IsWindows())
            return GetWindowsCandidates();

        if (OperatingSystem.IsMacOS())
            return GetMacOSCandidates();

        return GetPathCandidates();
    }

    private static IEnumerable<string> GetWindowsCandidates()
    {
        var installRoots = new[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData)
            }
            .Where(root => !string.IsNullOrEmpty(root))
            .ToList();

        string[][] browsers =
        [
            ["Microsoft", "Edge", "Application", "msedge.exe"],
            ["Google", "Chrome", "Application", "chrome.exe"]
        ];

        return browsers.SelectMany(browser => installRoots.Select(root => Path.Combine([root, .. browser])));
    }

    private static IEnumerable<string> GetMacOSCandidates()
    {
        string[] applicationDirectories = ["/Applications", Path.Combine(AppDataDirectory.UserProfileDirectory, "Applications")];

        string[] browsers =
        [
            "Google Chrome.app/Contents/MacOS/Google Chrome",
            "Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
            "Chromium.app/Contents/MacOS/Chromium"
        ];

        return browsers.SelectMany(browser => applicationDirectories.Select(directory => Path.Combine(directory, browser)));
    }

    private static IEnumerable<string> GetPathCandidates()
    {
        string[] executables = ["google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "microsoft-edge"];

        var pathDirectories = (Environment.GetEnvironmentVariable("PATH") ?? string.Empty)
            .Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries);

        return executables.SelectMany(executable => pathDirectories.Select(directory => Path.Combine(directory, executable)));
    }
}
