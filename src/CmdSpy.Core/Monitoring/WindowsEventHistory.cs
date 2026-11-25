using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.Linq;
using System.Text.RegularExpressions;
using CmdSpy.Core.Analysis;
using CmdSpy.Core.Models;

namespace CmdSpy.Core.Monitoring;

/// <summary>Whether one Windows log source is usable.</summary>
public sealed class LogSourceStatus
{
    public string Name { get; init; } = "";
    public string LogName { get; init; } = "";
    public bool Available { get; init; }
    public bool Enabled { get; init; }
    public long? RecordCount { get; init; }
    public string Detail { get; init; } = "";

    /// <summary>Available, switched on, and actually recording what CMD-spy needs.</summary>
    public bool Active { get; init; }
}

/// <summary>A Task Scheduler "created task process" record (event 129).</summary>
public sealed class TaskLaunch
{
    public string TaskName { get; init; } = "";
    public string? ImagePath { get; init; }
    public int ProcessId { get; init; }
    public DateTimeOffset TimeUtc { get; init; }
}

/// <summary>
/// Reads the Windows event logs that can explain a launch — including launches
/// that happened before CMD-spy was running:
/// Security 4688 (process creation, needs auditing enabled), Sysmon event 1
/// (if Sysmon is installed), Windows PowerShell 400 (engine start, records the
/// exact command line, on by default), PowerShell 4104 (script blocks) and
/// Task Scheduler 129 (which task launched which PID). Every query is bounded
/// and failure-tolerant: a missing or disabled log just yields nothing.
/// </summary>
public sealed class WindowsEventHistory
{
    public const string SecurityLog = "Security";
    public const string SysmonLog = "Microsoft-Windows-Sysmon/Operational";
    public const string PowerShellClassicLog = "Windows PowerShell";
    public const string PowerShellOperationalLog = "Microsoft-Windows-PowerShell/Operational";
    public const string PowerShellCoreLog = "PowerShellCore/Operational";
    public const string TaskSchedulerLog = "Microsoft-Windows-TaskScheduler/Operational";

    private const int ScanLimit = 5_000;

    // Logs that recently failed (missing, disabled, access denied) are skipped for a while.
    private readonly ConcurrentDictionary<string, DateTime> _unavailableUntil = new(StringComparer.OrdinalIgnoreCase);
    private List<LogSourceStatus>? _status;
    private DateTime _statusAt;

    // ------------------------------------------------------------ queries --

    /// <summary>Task Scheduler event 129 records ("created task process") in a time window.</summary>
    public List<TaskLaunch> FindTaskLaunches(DateTimeOffset fromUtc, DateTimeOffset toUtc, int max = 500)
    {
        var selector = Selector("TaskName", "Path", "ProcessID");
        return Query(TaskSchedulerLog, $"*[System[(EventID=129) and {TimeWindow(fromUtc, toUtc)}]]", max, record =>
        {
            var v = Values(record, selector);
            var pid = ToPid(v[2]);
            if (pid is null) return null;
            return new TaskLaunch
            {
                TaskName = v[0] as string ?? "",
                ImagePath = v[1] as string,
                ProcessId = pid.Value,
                TimeUtc = TimeOf(record)
            };
        });
    }

    /// <summary>
    /// The creation record of <paramref name="processId"/> from Sysmon (preferred)
    /// or Security 4688, looking back from <paramref name="aroundUtc"/>.
    /// </summary>
    public HistoricalEvent? FindProcessCreation(int processId, DateTimeOffset aroundUtc, TimeSpan lookback)
    {
        var from = aroundUtc - lookback;
        var to = aroundUtc + TimeSpan.FromSeconds(5);

        var sysmon = Query(SysmonLog, $"*[System[(EventID=1) and {TimeWindow(from, to)}]]", 1, r =>
        {
            var e = ParseSysmon(r);
            return e?.ProcessId == processId ? e : null;
        });
        if (sysmon.Count > 0) return sysmon[0];

        var security = Query(SecurityLog, $"*[System[(EventID=4688) and {TimeWindow(from, to)}]]", 1, r =>
        {
            var e = ParseSecurity4688(r);
            return e?.ProcessId == processId ? e : null;
        });
        return security.Count > 0 ? security[0] : null;
    }

    /// <summary>PowerShell activity of one process: engine start (400) and script blocks (4104).</summary>
    public List<HistoricalEvent> FindPowerShellActivity(int processId, DateTimeOffset startUtc, DateTimeOffset? endUtc, string? commandLine)
    {
        var results = new List<HistoricalEvent>();
        var to = (endUtc ?? startUtc + TimeSpan.FromMinutes(10)) + TimeSpan.FromSeconds(10);
        var from = startUtc - TimeSpan.FromSeconds(5);

        // 4104 records the PowerShell process ID in System/Execution.
        var scriptSelector = Selector("ScriptBlockText", "Path");
        foreach (var log in new[] { PowerShellOperationalLog, PowerShellCoreLog })
        {
            results.AddRange(Query(log,
                $"*[System[(EventID=4104) and Execution[@ProcessID={processId}] and {TimeWindow(from, to)}]]", 10, r =>
                {
                    var v = Values(r, scriptSelector);
                    var text = v[0] as string;
                    if (string.IsNullOrWhiteSpace(text)) return null;
                    return new HistoricalEvent
                    {
                        TimeUtc = TimeOf(r),
                        Source = log == PowerShellCoreLog ? "PowerShell 7 4104" : "PowerShell 4104",
                        EventId = 4104,
                        ProcessId = processId,
                        Detail = CommandExplainer.Shorten(text, 2000),
                        CommandLine = v[1] as string,
                        RelatedTo = "script block run by this process"
                    };
                }, newestFirst: false));
        }

        // 400 (classic log) has no process ID, so match on time and command line.
        var start400 = Query(PowerShellClassicLog, $"*[System[(EventID=400) and {TimeWindow(from, startUtc + TimeSpan.FromSeconds(30))}]]", 5, r =>
        {
            var host = HostApplicationOf(r);
            if (host is null || !SameCommand(host, commandLine)) return null;
            return new HistoricalEvent
            {
                TimeUtc = TimeOf(r),
                Source = "PowerShell 400",
                EventId = 400,
                CommandLine = host,
                Detail = "PowerShell engine started with this exact command line.",
                RelatedTo = "this process"
            };
        }, newestFirst: false);
        results.AddRange(start400.Take(1));

        return results.OrderBy(e => e.TimeUtc).ToList();
    }

    /// <summary>
    /// Launches of target programs since <paramref name="sinceUtc"/>, from
    /// Sysmon 1, Security 4688 and PowerShell 400 — including ones that
    /// happened before CMD-spy was running.
    /// </summary>
    public List<HistoricalEvent> ReadProcessHistory(DateTimeOffset sinceUtc, Func<string?, bool> isTarget, int max = 2_000)
    {
        var now = DateTimeOffset.UtcNow;
        var all = new List<HistoricalEvent>();
        all.AddRange(Query(SysmonLog, $"*[System[(EventID=1) and {TimeWindow(sinceUtc, now)}]]", max, r =>
        {
            var e = ParseSysmon(r);
            return e is not null && isTarget(e.Image) ? e : null;
        }, newestFirst: false, scanLimit: 50_000));
        all.AddRange(Query(SecurityLog, $"*[System[(EventID=4688) and {TimeWindow(sinceUtc, now)}]]", max, r =>
        {
            var e = ParseSecurity4688(r);
            return e is not null && isTarget(e.Image) ? e : null;
        }, newestFirst: false, scanLimit: 50_000));
        all.AddRange(Query(PowerShellClassicLog, $"*[System[(EventID=400) and {TimeWindow(sinceUtc, now)}]]", max, r =>
        {
            var host = HostApplicationOf(r);
            if (host is null) return null;
            var tokens = CommandLineTokenizer.Tokenize(host);
            return new HistoricalEvent
            {
                TimeUtc = TimeOf(r),
                Source = "PowerShell 400",
                EventId = 400,
                CommandLine = host,
                Image = tokens.Count > 0 ? tokens[0].Value : "powershell.exe",
                Detail = "PowerShell engine start"
            };
        }, newestFirst: false, scanLimit: 20_000));

        // The same launch can appear in several logs: prefer Sysmon, then 4688, then 400.
        var ordered = all.OrderBy(e => e.TimeUtc).ToList();
        var result = new List<HistoricalEvent>();
        foreach (var e in ordered)
        {
            bool duplicate = result.Any(x =>
                Math.Abs((x.TimeUtc - e.TimeUtc).TotalSeconds) < 2 &&
                (x.ProcessId is not null && x.ProcessId == e.ProcessId ||
                 SameCommand(x.CommandLine, e.CommandLine)));
            if (!duplicate) result.Add(e);
        }
        return result.Take(max).ToList();
    }

    /// <summary>
    /// When the machine booted before <paramref name="timeUtc"/> (System log,
    /// Kernel-General event 12). Used to give imported launches from earlier
    /// boots a meaningful "time since boot".
    /// </summary>
    public DateTimeOffset? FindBootBefore(DateTimeOffset timeUtc)
    {
        var xpath = "*[System[Provider[@Name='Microsoft-Windows-Kernel-General'] and (EventID=12) and " +
                    $"TimeCreated[@SystemTime<='{timeUtc.UtcDateTime:yyyy-MM-ddTHH:mm:ss.fffZ}']]]";
        var boots = Query("System", xpath, 1, r => new HistoricalEvent { TimeUtc = TimeOf(r) }, newestFirst: true, scanLimit: 10);
        return boots.Count > 0 ? boots[0].TimeUtc : null;
    }

    /// <summary>Which log sources are available and switched on (cached for 10 minutes).</summary>
    public List<LogSourceStatus> GetSourceStatus(bool refresh = false)
    {
        if (!refresh && _status is not null && DateTime.UtcNow - _statusAt < TimeSpan.FromMinutes(10)) return _status;
        var list = new List<LogSourceStatus>();
        if (!OperatingSystem.IsWindows())
        {
            list.Add(new LogSourceStatus { Name = "Windows event logs", Detail = "Only available on Windows." });
            return list;
        }

        list.Add(Status("Process creation (Security 4688)", SecurityLog, () =>
        {
            var recent = Query(SecurityLog, $"*[System[(EventID=4688) and {TimeWindow(DateTimeOffset.UtcNow - TimeSpan.FromDays(7), DateTimeOffset.UtcNow)}]]", 1, r => r.Id.ToString(CultureInfo.InvariantCulture));
            bool cmdline = RegistryDword(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit", "ProcessCreationIncludeCmdLine_Enabled") == 1;
            return recent.Count == 0
                ? ("Auditing appears to be OFF (no 4688 events in the last 7 days) — launches before CMD-spy started can't be traced.", false)
                : ($"Auditing is on{(cmdline ? ", with command lines" : " but command lines are NOT recorded")}.", true);
        }));
        list.Add(Status("Sysmon (event 1)", SysmonLog, () => ("Sysmon is installed — the richest process history source.", true)));
        list.Add(Status("PowerShell engine start (400)", PowerShellClassicLog, () => ("Records every PowerShell start with its exact command line (on by default).", true)));
        list.Add(Status("PowerShell script blocks (4104)", PowerShellOperationalLog, () =>
            RegistryDword(@"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging", "EnableScriptBlockLogging") == 1
                ? ("Script block logging is ON — full script contents are recorded.", true)
                : ("Only suspicious script blocks are recorded automatically (full logging is off).", true)));
        list.Add(Status("Task Scheduler history (129)", TaskSchedulerLog, () => ("Records which task launched which process ID.", true)));

        _status = list;
        _statusAt = DateTime.UtcNow;
        return list;
    }

    // ------------------------------------------------------------ parsing --

    private static readonly EventLogPropertySelector SysmonSelector = Selector(
        "ProcessId", "Image", "CommandLine", "ParentProcessId", "ParentImage", "ParentCommandLine", "User", "Hashes");

    private static HistoricalEvent? ParseSysmon(EventLogRecord record)
    {
        var v = Values(record, SysmonSelector);
        var pid = ToPid(v[0]);
        if (pid is null) return null;
        return new HistoricalEvent
        {
            TimeUtc = TimeOf(record),
            Source = "Sysmon 1",
            EventId = 1,
            ProcessId = pid,
            Image = v[1] as string,
            CommandLine = v[2] as string,
            ParentProcessId = ToPid(v[3]),
            ParentImage = v[4] as string,
            User = v[6] as string,
            Detail = v[7] is string hashes && hashes.Length > 0 ? $"Hashes: {hashes}" : (v[5] is string pc ? $"Parent command line: {pc}" : null)
        };
    }

    private static readonly EventLogPropertySelector SecuritySelector = Selector(
        "NewProcessId", "NewProcessName", "CommandLine", "ProcessId", "ParentProcessName", "SubjectUserName", "SubjectDomainName");

    private static HistoricalEvent? ParseSecurity4688(EventLogRecord record)
    {
        var v = Values(record, SecuritySelector);
        var pid = ToPid(v[0]);
        if (pid is null) return null;
        var user = v[5] as string;
        if (v[6] is string domain && domain.Length > 0 && user is not null) user = $"{domain}\\{user}";
        return new HistoricalEvent
        {
            TimeUtc = TimeOf(record),
            Source = "Security 4688",
            EventId = 4688,
            ProcessId = pid,
            Image = v[1] as string,
            CommandLine = v[2] is string c && c.Length > 0 ? c : null,
            ParentProcessId = ToPid(v[3]),
            ParentImage = v[4] as string,
            User = user
        };
    }

    private static readonly Regex HostApplication = new(@"HostApplication=(?<cmd>[^\r\n]*)", RegexOptions.CultureInvariant);

    private static string? HostApplicationOf(EventLogRecord record)
    {
        try
        {
            foreach (var p in record.Properties)
            {
                if (p.Value is string s && HostApplication.Match(s) is { Success: true } m)
                    return m.Groups["cmd"].Value.Trim();
            }
        }
        catch
        {
        }
        return null;
    }

    /// <summary>True when two command lines are the same apart from quoting, spacing and the program's path.</summary>
    public static bool SameCommand(string? a, string? b)
    {
        if (string.IsNullOrWhiteSpace(a) || string.IsNullOrWhiteSpace(b)) return false;
        static string Tail(string s)
        {
            var tokens = CommandLineTokenizer.Tokenize(s);
            var rest = tokens.Count > 1 ? string.Join(" ", tokens.Skip(1).Select(t => t.Value)) : "";
            var exe = tokens.Count > 0 ? CmdSpyOptions.Stem(CommandLineTokenizer.FileNameOf(tokens[0].Value)) : "";
            return (exe + " " + Regex.Replace(rest, @"\s+", " ")).Trim().ToLowerInvariant();
        }
        return Tail(a) == Tail(b);
    }

    // ------------------------------------------------------------ helpers --

    private List<T> Query<T>(string log, string xpath, int max, Func<EventLogRecord, T?> map,
        bool newestFirst = true, int scanLimit = ScanLimit) where T : class
    {
        var results = new List<T>();
        if (!OperatingSystem.IsWindows()) return results;
        if (_unavailableUntil.TryGetValue(log, out var until) && DateTime.UtcNow < until) return results;

        try
        {
            var query = new EventLogQuery(log, PathType.LogName, xpath) { ReverseDirection = newestFirst };
            using var reader = new EventLogReader(query);
            for (int scanned = 0; scanned < scanLimit && results.Count < max; scanned++)
            {
                using var record = reader.ReadEvent();
                if (record is null) break;
                if (record is EventLogRecord r && map(r) is { } item) results.Add(item);
            }
        }
        catch (Exception ex) when (ex is EventLogException or UnauthorizedAccessException or PlatformNotSupportedException or InvalidOperationException)
        {
            // Missing log, disabled channel or no access: try again in five minutes.
            _unavailableUntil[log] = DateTime.UtcNow + TimeSpan.FromMinutes(5);
        }
        return results;
    }

    private LogSourceStatus Status(string name, string logName, Func<(string Detail, bool Active)> describe)
    {
        try
        {
            using var config = new EventLogConfiguration(logName);
            long? count = null;
            try { count = EventLogSession.GlobalSession.GetLogInformation(logName, PathType.LogName).RecordCount; } catch { }
            var (detail, active) = config.IsEnabled ? describe() : ("This log is turned off.", false);
            return new LogSourceStatus
            {
                Name = name,
                LogName = logName,
                Available = true,
                Enabled = config.IsEnabled,
                RecordCount = count,
                Detail = detail,
                Active = config.IsEnabled && active
            };
        }
        catch (Exception ex)
        {
            return new LogSourceStatus
            {
                Name = name,
                LogName = logName,
                Available = false,
                Detail = ex is EventLogNotFoundException ? "Not installed on this PC." : ex.Message
            };
        }
    }

    private static int? RegistryDword(string subKey, string value)
    {
        if (!OperatingSystem.IsWindows()) return null;
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(subKey);
            return key?.GetValue(value) is int i ? i : null;
        }
        catch
        {
            return null;
        }
    }

    private static EventLogPropertySelector Selector(params string[] names) =>
        new(names.Select(n => $"Event/EventData/Data[@Name='{n}']").ToArray());

    private static IList<object?> Values(EventLogRecord record, EventLogPropertySelector selector)
    {
        try
        {
            return record.GetPropertyValues(selector).Cast<object?>().ToList();
        }
        catch
        {
            // Every parser indexes at most 8 values; return "all missing" instead of throwing.
            return new object?[16];
        }
    }

    private static DateTimeOffset TimeOf(EventRecord record) =>
        record.TimeCreated is { } t ? new DateTimeOffset(t.ToUniversalTime(), TimeSpan.Zero) : DateTimeOffset.UtcNow;

    private static string TimeWindow(DateTimeOffset fromUtc, DateTimeOffset toUtc) =>
        $"TimeCreated[@SystemTime>='{fromUtc.UtcDateTime:yyyy-MM-ddTHH:mm:ss.fffZ}' and @SystemTime<='{toUtc.UtcDateTime:yyyy-MM-ddTHH:mm:ss.fffZ}']";

    /// <summary>Process IDs appear as numbers, pointers or hex strings ("0x1a4") depending on the log.</summary>
    public static int? ToPid(object? value)
    {
        try
        {
            switch (value)
            {
                case null: return null;
                case int i: return i;
                case uint u: return (int)u;
                case long l: return (int)l;
                case ulong ul: return (int)ul;
                case IntPtr p: return (int)p.ToInt64();
                case UIntPtr up: return (int)up.ToUInt64();
                case string s:
                    s = s.Trim();
                    if (s.StartsWith("0x", StringComparison.OrdinalIgnoreCase) &&
                        long.TryParse(s[2..], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var hex))
                        return (int)hex;
                    return int.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out var dec) ? dec : null;
                default:
                    return Convert.ToInt32(value, CultureInfo.InvariantCulture);
            }
        }
        catch
        {
            return null;
        }
    }
}

/// <summary>Turns on the Windows logging that makes launch history traceable.</summary>
public static class WindowsLoggingSetup
{
    private const string AuditPolicyExecutable = "auditpol.exe";

    /// <summary>The "Process Creation" audit subcategory (locale-independent GUID).</summary>
    public const string ProcessCreationAuditGuid = "{0CCE922B-69AE-11D9-BED3-505054503030}";

    /// <summary>What <see cref="EnableRecommended"/> will change, for a confirmation prompt.</summary>
    public static readonly string[] Changes =
    {
        "Audit Process Creation (Security event 4688) — records every program start",
        "Include command lines in event 4688",
        "Task Scheduler history — records which task launched which process",
        "PowerShell script block logging — records the scripts PowerShell runs"
    };

    public static List<string> EnableRecommended()
    {
        var results = new List<string>();
        if (!OperatingSystem.IsWindows())
        {
            results.Add("✗ Only available on Windows.");
            return results;
        }

        try
        {
            var auditPolicyPath = GetTrustedAuditPolicyPath();
            using var p = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
            {
                FileName = auditPolicyPath,
                Arguments = $"/set /subcategory:{ProcessCreationAuditGuid} /success:enable",
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            });
            p!.WaitForExit(15_000);
            results.Add(p.ExitCode == 0 ? "✓ Process-creation auditing (4688) enabled." : $"✗ auditpol failed (exit code {p.ExitCode}).");
        }
        catch (Exception ex)
        {
            results.Add($"✗ Could not enable process-creation auditing: {ex.Message}");
        }

        results.Add(SetDword(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit",
            "ProcessCreationIncludeCmdLine_Enabled", "Command lines included in event 4688"));
        results.Add(SetDword(@"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging",
            "EnableScriptBlockLogging", "PowerShell script block logging enabled"));

        try
        {
            using var config = new EventLogConfiguration(WindowsEventHistory.TaskSchedulerLog);
            config.IsEnabled = true;
            config.SaveChanges();
            results.Add("✓ Task Scheduler history enabled.");
        }
        catch (Exception ex)
        {
            results.Add($"✗ Could not enable Task Scheduler history: {ex.Message}");
        }
        return results;
    }

    private static string GetTrustedAuditPolicyPath()
    {
        var systemDirectory = Path.TrimEndingDirectorySeparator(Path.GetFullPath(Environment.SystemDirectory));
        var executablePath = Path.GetFullPath(Path.Combine(systemDirectory, AuditPolicyExecutable));

        if (!Path.IsPathFullyQualified(executablePath) ||
            !string.Equals(Path.GetDirectoryName(executablePath), systemDirectory, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("The Windows audit policy utility is outside the system directory.");

        if ((File.GetAttributes(systemDirectory) & FileAttributes.ReparsePoint) != 0 ||
            (File.GetAttributes(executablePath) & FileAttributes.ReparsePoint) != 0)
            throw new InvalidOperationException("The Windows audit policy utility resolves through a reparse point.");

        return executablePath;
    }

    private static string SetDword(string subKey, string name, string description)
    {
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(subKey, writable: true);
            key.SetValue(name, 1, Microsoft.Win32.RegistryValueKind.DWord);
            return $"✓ {description}.";
        }
        catch (Exception ex)
        {
            return $"✗ {description} failed: {ex.Message}";
        }
    }
}
