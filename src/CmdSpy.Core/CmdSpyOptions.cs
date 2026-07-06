using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace CmdSpy.Core;

/// <summary>Runtime configuration for the capture engine.</summary>
public sealed class CmdSpyOptions
{
    /// <summary>
    /// Executable names that count as a "cmd popup". Compared case-insensitively
    /// and with/without the ".exe" suffix. Defaults to cmd.exe only.
    /// </summary>
    public HashSet<string> TargetProcessNames { get; set; } =
        new(StringComparer.OrdinalIgnoreCase) { "cmd.exe" };

    public bool CaptureNetwork { get; set; } = true;
    public bool CaptureChildren { get; set; } = true;
    public bool CaptureParentDetails { get; set; } = true;

    /// <summary>Where JSON-lines and human-readable logs are written.</summary>
    public string LogDirectory { get; set; } = DefaultLogDirectory();

    /// <summary>Cap on in-memory retained events (the GUI's live list).</summary>
    public int MaxInMemoryEvents { get; set; } = 10_000;

    public static string DefaultLogDirectory() => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "CmdSpy", "logs");

    /// <summary>
    /// Console-host and script-host executables that commonly produce a flashing
    /// window. Useful when the user wants broader coverage than cmd.exe alone.
    /// </summary>
    public static IReadOnlyCollection<string> ExtendedTargets { get; } = new[]
    {
        "cmd.exe", "powershell.exe", "pwsh.exe", "conhost.exe",
        "wscript.exe", "cscript.exe", "mshta.exe"
    };

    /// <summary>Returns the configured targets reduced to lower-case stems (no extension).</summary>
    public HashSet<string> TargetStems()
    {
        var stems = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var name in TargetProcessNames)
            stems.Add(Stem(name));
        return stems;
    }

    /// <summary>"C:\\Windows\\System32\\cmd.exe" or "CMD.EXE" -> "cmd".</summary>
    public static string Stem(string nameOrPath)
    {
        if (string.IsNullOrWhiteSpace(nameOrPath)) return "";
        var file = nameOrPath;
        int slash = file.LastIndexOfAny(new[] { '\\', '/' });
        if (slash >= 0) file = file[(slash + 1)..];
        if (file.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
            file = file[..^4];
        return file.Trim();
    }
}
