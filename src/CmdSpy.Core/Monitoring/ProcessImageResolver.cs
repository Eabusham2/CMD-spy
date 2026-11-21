using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using CmdSpy.Core.Analysis;

namespace CmdSpy.Core.Monitoring;

/// <summary>
/// Works out the full path of a process's executable — even after the process
/// has exited — so it can be signature-checked and hashed. Tries, in order: a
/// path already known, the live process (only if its start time matches, so a
/// recycled PID isn't misattributed), the command line, then standard Windows
/// folders and the PATH.
/// </summary>
public static class ProcessImageResolver
{
    private const uint ProcessQueryLimitedInformation = 0x1000;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint access, bool inheritHandle, int processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool QueryFullProcessImageNameW(IntPtr process, int flags, StringBuilder exeName, ref int size);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetProcessTimes(IntPtr process, out long creation, out long exit, out long kernel, out long user);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern uint QueryDosDeviceW(string deviceName, StringBuilder targetPath, int max);

    private static readonly Lazy<List<(string Device, string Drive)>> DeviceMap = new(BuildDeviceMap);

    /// <summary>Full image path and start time of a running process, or nulls.</summary>
    public static (string? Path, DateTimeOffset? StartedUtc) TryQueryLive(int processId)
    {
        if (processId <= 4 || !OperatingSystem.IsWindows()) return (null, null);
        IntPtr handle = IntPtr.Zero;
        try
        {
            handle = OpenProcess(ProcessQueryLimitedInformation, false, processId);
            if (handle == IntPtr.Zero) return (null, null);

            string? path = null;
            var sb = new StringBuilder(1024);
            int size = sb.Capacity;
            if (QueryFullProcessImageNameW(handle, 0, sb, ref size)) path = sb.ToString(0, size);

            DateTimeOffset? started = null;
            if (GetProcessTimes(handle, out var creation, out _, out _, out _) && creation > 0)
                started = DateTimeOffset.FromFileTime(creation).ToUniversalTime();

            return (path, started);
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException or PlatformNotSupportedException)
        {
            return (null, null);
        }
        finally
        {
            if (handle != IntPtr.Zero) CloseHandle(handle);
        }
    }

    /// <summary>
    /// Converts kernel-style paths to normal ones:
    /// <c>\Device\HarddiskVolume3\Windows\x.exe</c> → <c>C:\Windows\x.exe</c>,
    /// <c>\SystemRoot\System32\x.exe</c> → <c>C:\Windows\System32\x.exe</c>,
    /// <c>\??\C:\x.exe</c> → <c>C:\x.exe</c>.
    /// </summary>
    public static string? NormalizeKernelPath(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return path;
        var p = path.Trim().Trim('"');

        if (p.StartsWith(@"\??\", StringComparison.Ordinal)) p = p[4..];
        if (p.StartsWith(@"\\?\", StringComparison.Ordinal) && p.Length > 6 && p[5] == ':') p = p[4..];

        if (p.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase))
        {
            var root = Environment.GetEnvironmentVariable("SystemRoot") ?? @"C:\Windows";
            p = root + p[@"\SystemRoot".Length..];
        }
        else if (p.StartsWith(@"\Device\", StringComparison.OrdinalIgnoreCase))
        {
            foreach (var (device, drive) in DeviceMap.Value)
            {
                if (p.StartsWith(device + @"\", StringComparison.OrdinalIgnoreCase))
                {
                    p = drive + p[device.Length..];
                    break;
                }
            }
        }
        return p;
    }

    /// <summary>The executable named at the start of a command line, if it can be located.</summary>
    public static string? FromCommandLine(string? commandLine)
    {
        if (string.IsNullOrWhiteSpace(commandLine)) return null;
        var tokens = CommandLineTokenizer.Tokenize(commandLine);
        if (tokens.Count == 0) return null;
        var first = NormalizeKernelPath(tokens[0].Value);
        if (string.IsNullOrEmpty(first)) return null;

        if (IsRooted(first))
        {
            if (FileExists(first)) return first;
            if (!first.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) && FileExists(first + ".exe")) return first + ".exe";

            // Unquoted path containing spaces: C:\Program Files\x\y.exe --arg
            var raw = commandLine.TrimStart();
            for (int end = raw.IndexOf(' '); end > 0; end = raw.IndexOf(' ', end + 1))
            {
                var candidate = raw[..end];
                if (candidate.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) && FileExists(candidate)) return candidate;
            }
            return first;
        }
        return FindByName(first);
    }

    /// <summary>Looks for an executable by name in the Windows folders and on the PATH.</summary>
    public static string? FindByName(string? name)
    {
        if (string.IsNullOrWhiteSpace(name) || !OperatingSystem.IsWindows()) return null;
        var file = CommandLineTokenizer.FileNameOf(name);
        if (!Path.HasExtension(file)) file += ".exe";

        var windows = Environment.GetEnvironmentVariable("SystemRoot") ?? @"C:\Windows";
        var candidates = new List<string>
        {
            Path.Combine(windows, "System32"),
            Path.Combine(windows, "System32", "WindowsPowerShell", "v1.0"),
            Path.Combine(windows, "SysWOW64"),
            windows,
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "PowerShell", "7"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Microsoft", "WindowsApps")
        };
        candidates.AddRange((Environment.GetEnvironmentVariable("PATH") ?? "")
            .Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));

        foreach (var dir in candidates)
        {
            try
            {
                var full = Path.Combine(dir.Trim('"'), file);
                if (FileExists(full)) return full;
            }
            catch (ArgumentException)
            {
            }
        }
        return null;
    }

    /// <summary>
    /// Best full path for a process. <paramref name="startedUtc"/> guards the
    /// live lookup against recycled PIDs.
    /// </summary>
    public static string? Resolve(int processId, string? knownPath, string? name, string? commandLine, DateTimeOffset? startedUtc)
    {
        var known = NormalizeKernelPath(knownPath);
        if (!string.IsNullOrEmpty(known) && IsRooted(known) && FileExists(known)) return known;

        var (livePath, liveStart) = TryQueryLive(processId);
        if (livePath is not null)
        {
            bool sameIncarnation = startedUtc is null || startedUtc == DateTimeOffset.MinValue || liveStart is null ||
                                   (liveStart.Value - startedUtc.Value).Duration() <= ProcessCache.Skew;
            if (sameIncarnation) return NormalizeKernelPath(livePath);
        }

        var fromCommand = FromCommandLine(commandLine);
        if (fromCommand is not null && IsRooted(fromCommand) && FileExists(fromCommand)) return fromCommand;

        var byName = FindByName(name ?? known);
        if (byName is not null) return byName;

        return fromCommand ?? known;
    }

    public static bool IsRooted(string? path) =>
        !string.IsNullOrEmpty(path) && path.Length > 2 &&
        ((path[1] == ':' && (path[2] == '\\' || path[2] == '/')) || path.StartsWith(@"\\", StringComparison.Ordinal));

    private static bool FileExists(string path)
    {
        try { return File.Exists(path); }
        catch { return false; }
    }

    private static List<(string, string)> BuildDeviceMap()
    {
        var map = new List<(string, string)>();
        if (!OperatingSystem.IsWindows()) return map;
        try
        {
            for (char letter = 'A'; letter <= 'Z'; letter++)
            {
                var drive = $"{letter}:";
                var sb = new StringBuilder(512);
                if (QueryDosDeviceW(drive, sb, sb.Capacity) > 0)
                {
                    var device = sb.ToString();
                    var nul = device.IndexOf('\0');
                    if (nul >= 0) device = device[..nul];
                    if (device.Length > 0) map.Add((device, drive));
                }
            }
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException)
        {
        }
        return map;
    }
}
