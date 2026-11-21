using System;
using System.Collections.Generic;

namespace CmdSpy.Core.Analysis;

/// <summary>
/// What well-known Windows processes are for. Used to describe each step of a
/// launch chain in plain words, to decide where a chain legitimately ends, and
/// to look past Windows "plumbing" (service hosts, the service manager...) to
/// find the program that actually caused a launch.
/// </summary>
public static class ProcessRoles
{
    private static readonly Dictionary<string, string> Descriptions = new(StringComparer.OrdinalIgnoreCase)
    {
        ["System"] = "Windows kernel",
        ["Idle"] = "System idle process",
        ["Registry"] = "Windows registry process",
        ["smss"] = "Session Manager (Windows start-up)",
        ["csrss"] = "Client/Server Runtime (Windows core)",
        ["wininit"] = "Windows start-up process",
        ["winlogon"] = "Windows logon",
        ["services"] = "Service Control Manager (starts Windows services)",
        ["lsass"] = "Local Security Authority",
        ["svchost"] = "Windows service host",
        ["userinit"] = "User logon initialisation",
        ["explorer"] = "Windows desktop / File Explorer (the logged-in user)",
        ["taskhostw"] = "Task Scheduler task host",
        ["taskeng"] = "Task Scheduler engine",
        ["taskhost"] = "Task Scheduler task host",
        ["WmiPrvSE"] = "WMI provider host (runs WMI requests, local or remote)",
        ["dllhost"] = "COM surrogate",
        ["RuntimeBroker"] = "Runtime Broker (Store-app permissions)",
        ["sihost"] = "Shell infrastructure host",
        ["ctfmon"] = "Text input service",
        ["conhost"] = "Console window host",
        ["OpenConsole"] = "Windows Terminal console host",
        ["WindowsTerminal"] = "Windows Terminal",
        ["wt"] = "Windows Terminal launcher",
        ["cmd"] = "Command Prompt",
        ["powershell"] = "Windows PowerShell",
        ["pwsh"] = "PowerShell 7",
        ["wscript"] = "Windows Script Host",
        ["cscript"] = "Windows Script Host (console)",
        ["mshta"] = "HTML Application host",
        ["msiexec"] = "Windows Installer",
        ["TrustedInstaller"] = "Windows Modules Installer",
        ["MsMpEng"] = "Microsoft Defender Antivirus",
        ["SearchIndexer"] = "Windows Search indexer",
        ["spoolsv"] = "Print Spooler",
    };

    /// <summary>
    /// Processes where a launch chain legitimately ends: the kernel, Windows
    /// start-up/logon processes (whose own parents exit during boot), and the
    /// user's desktop shell.
    /// </summary>
    private static readonly HashSet<string> Roots = new(StringComparer.OrdinalIgnoreCase)
    {
        "System", "Idle", "Registry", "smss", "csrss", "wininit", "winlogon", "userinit", "explorer"
    };

    /// <summary>
    /// Windows infrastructure that starts things on behalf of something else.
    /// The "original launcher" is the outermost process that is NOT one of these.
    /// </summary>
    private static readonly HashSet<string> Plumbing = new(StringComparer.OrdinalIgnoreCase)
    {
        "System", "Idle", "Registry", "smss", "csrss", "wininit", "winlogon", "userinit", "explorer",
        "services", "svchost", "taskhostw", "taskeng", "taskhost", "WmiPrvSE", "dllhost", "sihost",
        "RuntimeBroker", "lsass"
    };

    public static string Stem(string? nameOrPath) => CmdSpyOptions.Stem(nameOrPath ?? "");

    public static bool IsRoot(string? name, int processId) =>
        processId is 0 or 4 || Roots.Contains(Stem(name));

    public static bool IsPlumbing(string? name, int processId) =>
        processId is 0 or 4 || Plumbing.Contains(Stem(name));

    /// <summary>svchost hosting the Schedule service, or a Task Scheduler task host.</summary>
    public static bool IsSchedulerHost(string? name, string? commandLine)
    {
        var stem = Stem(name);
        if (stem.Equals("taskhostw", StringComparison.OrdinalIgnoreCase) ||
            stem.Equals("taskeng", StringComparison.OrdinalIgnoreCase) ||
            stem.Equals("taskhost", StringComparison.OrdinalIgnoreCase))
            return true;
        return stem.Equals("svchost", StringComparison.OrdinalIgnoreCase) &&
               commandLine is not null &&
               commandLine.Contains("Schedule", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>svchost in the shared "netsvcs" group, which may host the Task Scheduler.</summary>
    public static bool IsSharedNetsvcsHost(string? name, string? commandLine) =>
        Stem(name).Equals("svchost", StringComparison.OrdinalIgnoreCase) &&
        commandLine is not null &&
        commandLine.Contains("netsvcs", StringComparison.OrdinalIgnoreCase) &&
        !commandLine.Contains("-s ", StringComparison.OrdinalIgnoreCase);

    /// <summary>Plain-English role for a process, or null if it isn't a well-known one.</summary>
    public static string? Describe(string? name, string? commandLine = null, int processId = -1)
    {
        if (processId == 4) return Descriptions["System"];
        if (processId == 0) return Descriptions["Idle"];
        var stem = Stem(name);
        if (stem.Length == 0) return null;

        if (stem.Equals("svchost", StringComparison.OrdinalIgnoreCase) && commandLine is not null)
        {
            if (IsSchedulerHost(name, commandLine)) return "Task Scheduler service (runs scheduled tasks)";
            var service = ServiceNameFromSvchost(commandLine);
            if (service is not null) return $"Windows service host ({service})";
        }
        return Descriptions.TryGetValue(stem, out var d) ? d : null;
    }

    /// <summary>"svchost.exe -k netsvcs -p -s Schedule" → "Schedule".</summary>
    public static string? ServiceNameFromSvchost(string commandLine)
    {
        var idx = commandLine.IndexOf(" -s ", StringComparison.OrdinalIgnoreCase);
        if (idx >= 0)
        {
            var rest = commandLine[(idx + 4)..].Trim();
            var end = rest.IndexOf(' ');
            return end > 0 ? rest[..end] : rest;
        }
        idx = commandLine.IndexOf(" -k ", StringComparison.OrdinalIgnoreCase);
        if (idx >= 0)
        {
            var rest = commandLine[(idx + 4)..].Trim();
            var end = rest.IndexOf(' ');
            return (end > 0 ? rest[..end] : rest) + " group";
        }
        return null;
    }

    /// <summary>Why a chain ending at this root is considered complete.</summary>
    public static string RootNote(string? name, int processId)
    {
        var stem = Stem(name);
        if (processId is 0 or 4) return "Reached the Windows kernel — the chain is complete.";
        if (stem.Equals("explorer", StringComparison.OrdinalIgnoreCase))
            return "Reached the Windows desktop (explorer.exe): started by the logged-in user or a program they ran.";
        if (stem.Equals("userinit", StringComparison.OrdinalIgnoreCase) || stem.Equals("winlogon", StringComparison.OrdinalIgnoreCase))
            return "Reached Windows logon — started as part of signing in.";
        return $"Reached {stem}.exe, a Windows start-up process — the chain is complete.";
    }

    /// <summary>
    /// How the launch happened, judged from the closest Windows plumbing in the
    /// chain (parent first): service, scheduled task, WMI, user desktop, logon.
    /// </summary>
    public static string? LaunchContextFor(string? name, string? commandLine, int processId)
    {
        var stem = Stem(name);
        if (IsSchedulerHost(name, commandLine)) return "Scheduled task (Task Scheduler)";
        if (IsSharedNetsvcsHost(name, commandLine)) return "Windows service host (may be the Task Scheduler)";
        return stem.ToLowerInvariant() switch
        {
            "services" => "Windows service",
            "svchost" => "Windows service host",
            "wmiprvse" => "WMI (Win32_Process.Create or a remote WMI request)",
            "explorer" => "User desktop (explorer.exe)",
            "userinit" or "winlogon" => "Logon",
            "dllhost" => "COM object",
            "wininit" or "smss" or "csrss" => "Windows start-up",
            _ when processId is 0 or 4 => "Windows kernel",
            _ => null
        };
    }
}
