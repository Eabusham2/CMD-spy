using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using System.Xml;
using CmdSpy.Core.Analysis;

namespace CmdSpy.Core.Monitoring;

/// <summary>One action of a scheduled task.</summary>
public sealed class TaskAction
{
    /// <summary>"Exec" (runs a program) or "ComHandler".</summary>
    public string Kind { get; init; } = "Exec";
    public string? Command { get; init; }
    public string? Arguments { get; init; }
    public string? WorkingDirectory { get; init; }
    public string? ClassId { get; init; }
}

/// <summary>A registered scheduled task, read from its definition file.</summary>
public sealed class ScheduledTaskInfo
{
    /// <summary>Full task path, e.g. "\Microsoft\Windows\Defrag\ScheduledDefrag".</summary>
    public string Path { get; init; } = "";
    public string? Author { get; init; }
    public string? Description { get; init; }
    public string? UserId { get; init; }
    public string? RunLevel { get; init; }
    public bool Enabled { get; init; } = true;
    public bool Hidden { get; init; }
    public List<string> Triggers { get; init; } = new();
    public List<TaskAction> Actions { get; init; } = new();

    public string TriggerSummary => Triggers.Count == 0 ? "(no triggers)" : string.Join("; ", Triggers);
}

/// <summary>
/// Reads the scheduled-task definitions Windows keeps under
/// <c>%SystemRoot%\System32\Tasks</c> (requires administrator rights) and
/// matches task actions against processes.
/// </summary>
public sealed class ScheduledTaskCatalog
{
    private readonly object _gate = new();
    private readonly TimeSpan _refreshAfter;
    private List<ScheduledTaskInfo>? _tasks;
    private DateTime _loadedAt;

    public ScheduledTaskCatalog(string? root = null, TimeSpan? refreshAfter = null)
    {
        Root = root ?? DefaultRoot();
        _refreshAfter = refreshAfter ?? TimeSpan.FromMinutes(10);
    }

    public string Root { get; }

    /// <summary>Why loading failed, if it did (e.g. access denied).</summary>
    public string? LastError { get; private set; }

    public static string DefaultRoot()
    {
        if (!OperatingSystem.IsWindows()) return "";
        var windows = Environment.GetEnvironmentVariable("SystemRoot") ?? @"C:\Windows";
        return System.IO.Path.Combine(windows, "System32", "Tasks");
    }

    public IReadOnlyList<ScheduledTaskInfo> GetTasks()
    {
        lock (_gate)
        {
            if (_tasks is null || DateTime.UtcNow - _loadedAt > _refreshAfter)
            {
                _tasks = Load();
                _loadedAt = DateTime.UtcNow;
            }
            return _tasks;
        }
    }

    public ScheduledTaskInfo? FindByPath(string? taskPath)
    {
        if (string.IsNullOrWhiteSpace(taskPath)) return null;
        var normalized = taskPath.StartsWith('\\') ? taskPath : "\\" + taskPath;
        return GetTasks().FirstOrDefault(t => t.Path.Equals(normalized, StringComparison.OrdinalIgnoreCase));
    }

    private List<ScheduledTaskInfo> Load()
    {
        var tasks = new List<ScheduledTaskInfo>();
        LastError = null;
        if (string.IsNullOrEmpty(Root) || !Directory.Exists(Root))
        {
            LastError = string.IsNullOrEmpty(Root) ? "Scheduled tasks are only available on Windows." : $"{Root} not found.";
            return tasks;
        }

        IEnumerable<string> files;
        try
        {
            files = Directory.EnumerateFiles(Root, "*", new EnumerationOptions
            {
                RecurseSubdirectories = true,
                IgnoreInaccessible = true,
                AttributesToSkip = FileAttributes.ReparsePoint
            }).ToList();
        }
        catch (Exception ex)
        {
            LastError = ex.Message;
            return tasks;
        }

        foreach (var file in files)
        {
            try
            {
                var relative = file[Root.Length..].Replace('/', '\\');
                if (!relative.StartsWith('\\')) relative = "\\" + relative;
                var xml = File.ReadAllText(file);
                var task = Parse(relative, xml);
                if (task is not null) tasks.Add(task);
            }
            catch
            {
                // Unreadable or malformed task file — skip it.
            }
        }
        return tasks;
    }

    /// <summary>Parses one task definition (Task Scheduler 2.0 XML schema).</summary>
    public static ScheduledTaskInfo? Parse(string taskPath, string xml)
    {
        var doc = new XmlDocument { XmlResolver = null };
        try
        {
            doc.LoadXml(xml.TrimStart('\uFEFF'));
        }
        catch (XmlException)
        {
            return null;
        }
        var root = doc.DocumentElement;
        if (root is null || root.LocalName != "Task") return null;

        string? Text(XmlNode? parent, params string[] path)
        {
            var node = parent;
            foreach (var name in path)
            {
                node = node?.ChildNodes.Cast<XmlNode>().FirstOrDefault(n => n.LocalName == name);
                if (node is null) return null;
            }
            var value = node?.InnerText?.Trim();
            return string.IsNullOrEmpty(value) ? null : value;
        }

        var actions = new List<TaskAction>();
        var actionsNode = root.ChildNodes.Cast<XmlNode>().FirstOrDefault(n => n.LocalName == "Actions");
        if (actionsNode is not null)
        {
            foreach (XmlNode a in actionsNode.ChildNodes)
            {
                if (a.LocalName == "Exec")
                    actions.Add(new TaskAction { Kind = "Exec", Command = Text(a, "Command"), Arguments = Text(a, "Arguments"), WorkingDirectory = Text(a, "WorkingDirectory") });
                else if (a.LocalName == "ComHandler")
                    actions.Add(new TaskAction { Kind = "ComHandler", ClassId = Text(a, "ClassId") });
            }
        }

        var triggers = new List<string>();
        var triggersNode = root.ChildNodes.Cast<XmlNode>().FirstOrDefault(n => n.LocalName == "Triggers");
        if (triggersNode is not null)
        {
            foreach (XmlNode t in triggersNode.ChildNodes)
            {
                if (t.NodeType != XmlNodeType.Element) continue;
                if (Text(t, "Enabled")?.Equals("false", StringComparison.OrdinalIgnoreCase) == true) continue;
                var description = t.LocalName switch
                {
                    "BootTrigger" => "At system start-up",
                    "LogonTrigger" => Text(t, "UserId") is { } u ? $"At log on of {u}" : "At log on of any user",
                    "IdleTrigger" => "When the computer is idle",
                    "EventTrigger" => "When a specific event is logged",
                    "RegistrationTrigger" => "When the task is created or changed",
                    "SessionStateChangeTrigger" => $"On session change ({Text(t, "StateChange") ?? "?"})",
                    "TimeTrigger" => $"Once at {Text(t, "StartBoundary") ?? "?"}",
                    "CalendarTrigger" => CalendarDescription(t, Text(t, "StartBoundary")),
                    "WnfStateChangeTrigger" => "On a system state change",
                    _ => t.LocalName
                };
                var interval = Text(t, "Repetition", "Interval");
                if (interval is not null) description += $", repeating every {FriendlyDuration(interval)}";
                triggers.Add(description);
            }
        }

        var principal = root.ChildNodes.Cast<XmlNode>().FirstOrDefault(n => n.LocalName == "Principals")?
            .ChildNodes.Cast<XmlNode>().FirstOrDefault(n => n.LocalName == "Principal");

        return new ScheduledTaskInfo
        {
            Path = taskPath,
            Author = Text(root, "RegistrationInfo", "Author"),
            Description = Text(root, "RegistrationInfo", "Description"),
            UserId = Text(principal, "UserId") ?? Text(principal, "GroupId"),
            RunLevel = Text(principal, "RunLevel"),
            Enabled = !string.Equals(Text(root, "Settings", "Enabled"), "false", StringComparison.OrdinalIgnoreCase),
            Hidden = string.Equals(Text(root, "Settings", "Hidden"), "true", StringComparison.OrdinalIgnoreCase),
            Triggers = triggers,
            Actions = actions
        };
    }

    private static string CalendarDescription(XmlNode trigger, string? start)
    {
        var kinds = trigger.ChildNodes.Cast<XmlNode>().Select(n => n.LocalName).ToList();
        var when = start is not null && start.Length >= 16 ? $" at {start[11..16]}" : "";
        if (kinds.Contains("ScheduleByDay")) return $"Daily{when}";
        if (kinds.Contains("ScheduleByWeek")) return $"Weekly{when}";
        if (kinds.Contains("ScheduleByMonth") || kinds.Contains("ScheduleByMonthDayOfWeek")) return $"Monthly{when}";
        return $"On a schedule{when}";
    }

    /// <summary>"PT1H30M" → "1 h 30 min".</summary>
    public static string FriendlyDuration(string iso)
    {
        var m = Regex.Match(iso, @"^P(?:(?<d>\d+)D)?(?:T(?:(?<h>\d+)H)?(?:(?<m>\d+)M)?(?:(?<s>\d+)S)?)?$");
        if (!m.Success) return iso;
        var parts = new List<string>();
        if (m.Groups["d"].Success) parts.Add($"{m.Groups["d"].Value} d");
        if (m.Groups["h"].Success) parts.Add($"{m.Groups["h"].Value} h");
        if (m.Groups["m"].Success) parts.Add($"{m.Groups["m"].Value} min");
        if (m.Groups["s"].Success) parts.Add($"{m.Groups["s"].Value} s");
        return parts.Count == 0 ? iso : string.Join(" ", parts);
    }

    /// <summary>
    /// Registered tasks whose action would start this program with these
    /// arguments, best match first. A score of 95 means path and arguments match.
    /// </summary>
    public List<(ScheduledTaskInfo Task, TaskAction Action, int Score)> Match(string? imagePath, string? commandLine) =>
        Match(GetTasks(), imagePath, commandLine);

    public static List<(ScheduledTaskInfo Task, TaskAction Action, int Score)> Match(
        IEnumerable<ScheduledTaskInfo> tasks, string? imagePath, string? commandLine)
    {
        var results = new List<(ScheduledTaskInfo, TaskAction, int)>();
        var processFile = CommandLineTokenizer.FileNameOf(imagePath ?? FirstToken(commandLine) ?? "");
        if (processFile.Length == 0) return results;
        var normalizedCommand = NormalizeSpace(commandLine);

        foreach (var task in tasks.Where(t => t.Enabled))
        {
            foreach (var action in task.Actions.Where(a => a.Kind == "Exec" && !string.IsNullOrWhiteSpace(a.Command)))
            {
                var actionPath = Expand(action.Command!).Trim().Trim('"');
                var actionFile = CommandLineTokenizer.FileNameOf(actionPath);
                int score;
                if (imagePath is not null && ProcessImageResolver.IsRooted(actionPath) &&
                    actionPath.Equals(imagePath, StringComparison.OrdinalIgnoreCase))
                    score = 50;
                else if (CmdSpyOptions.Stem(actionFile).Equals(CmdSpyOptions.Stem(processFile), StringComparison.OrdinalIgnoreCase))
                    score = 25;
                else
                    continue;

                var args = NormalizeSpace(Expand(action.Arguments ?? ""));
                if (args.Length > 0 && normalizedCommand.Length > 0)
                {
                    if (normalizedCommand.Contains(args, StringComparison.OrdinalIgnoreCase)) score += 45;
                    else if (TokenOverlap(args, normalizedCommand) >= 0.6) score += 20;
                }
                else if (args.Length == 0)
                {
                    score += 5;
                }

                if (score >= 30) results.Add((task, action, score));
            }
        }
        return results.OrderByDescending(r => r.Item3).ToList();
    }

    private static string Expand(string value)
    {
        try { return Environment.ExpandEnvironmentVariables(value); }
        catch { return value; }
    }

    private static string? FirstToken(string? commandLine)
    {
        var tokens = CommandLineTokenizer.Tokenize(commandLine);
        return tokens.Count > 0 ? tokens[0].Value : null;
    }

    private static string NormalizeSpace(string? s) =>
        string.IsNullOrWhiteSpace(s) ? "" : Regex.Replace(s.Replace("\"", ""), @"\s+", " ").Trim();

    private static double TokenOverlap(string a, string b)
    {
        var at = a.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (at.Length == 0) return 0;
        var bt = new HashSet<string>(b.Split(' ', StringSplitOptions.RemoveEmptyEntries), StringComparer.OrdinalIgnoreCase);
        return at.Count(bt.Contains) / (double)at.Length;
    }
}
