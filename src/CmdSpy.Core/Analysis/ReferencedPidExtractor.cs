using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;

namespace CmdSpy.Core.Analysis;

/// <summary>A process ID mentioned inside a command, with the text that mentioned it.</summary>
public readonly record struct PidReference(int ProcessId, string Context);

/// <summary>A process referred to by executable name (taskkill /IM, Get-Process -Name...).</summary>
public readonly record struct NameReference(string Name, string Context);

/// <summary>
/// Finds the process IDs (and process names) a command talks about — e.g. the
/// five PIDs in <c>gwmi win32_process -Filter 'ProcessId=37868 or ProcessId=39508 ...'</c>
/// — so they can be resolved to the programs they actually were. Only explicit
/// process contexts are matched, so numbers like <c>ping -n 4</c> or event IDs
/// (<c>Get-WinEvent -Id 4688</c>) are not mistaken for PIDs.
/// </summary>
public static class ReferencedPidExtractor
{
    private const RegexOptions Opts = RegexOptions.IgnoreCase | RegexOptions.CultureInvariant;
    private const int MaxReferences = 64;

    // ProcessId=123, ProcessId = '123', ParentProcessId=1, Handle='123', PID eq 5 (WQL / Where-Object / wmic)
    private static readonly Regex WqlPid = new(
        @"\b(?<key>ParentProcessId|ProcessId|Handle|PID)\b\s*(?:=|==|-eq|\beq\b)\s*['""]?(?<pid>\d{1,7})\b", Opts);

    // Get-Process -Id 1,2 / Stop-Process -Id 5 / kill -Id 3 / Wait-Process -Id 9
    private static readonly Regex ProcessCmdletIds = new(
        @"\b(?:Get-Process|gps|ps|Stop-Process|spps|kill|Wait-Process|Debug-Process|Get-ProcessMitigation|Set-ProcessMitigation)\b" +
        @"[^;|&\r\n]*?-(?:Id|PID|ProcessId)\b\s*[:=]?\s*(?<ids>\d{1,7}(?:\s*,\s*\d{1,7})*)", Opts);

    // taskkill /PID 123 /PID 456
    private static readonly Regex SlashPid = new(@"/PID\s+(?<pid>\d{1,7})\b", Opts);

    // [Diagnostics.Process]::GetProcessById(123)
    private static readonly Regex GetProcessById = new(@"GetProcessById\s*\(\s*(?<pid>\d{1,7})\s*\)", Opts);

    // rundll32 comsvcs.dll, MiniDump 123 out.dmp full  (process memory dump)
    private static readonly Regex MiniDump = new(@"\bMiniDump(?:W)?\b\s*,?\s*(?<pid>\d{1,7})\b", Opts);

    // procdump -ma 123 / procdump64 -accepteula -mp 456
    private static readonly Regex ProcDump = new(
        @"\bprocdump(?:64)?(?:\.exe)?\b[^&|\r\n]*?\s-m[apm]\s+(?<pid>\d{1,7})\b", Opts);

    // ntsd/cdb/windbg -p 123
    private static readonly Regex Debugger = new(
        @"\b(?:ntsd|cdb|windbg)(?:\.exe)?\b[^&|\r\n]*?\s-p\s+(?<pid>\d{1,7})\b", Opts);

    // taskkill /IM name.exe, tasklist /FI "IMAGENAME eq name.exe"
    private static readonly Regex ImageName = new(
        @"(?:/IM\s+|IMAGENAME\s+eq\s+)[""']?(?<name>[\w.\-]+?\.exe|[\w.\-]+?)(?=[""'\s]|$)", Opts);

    // Get-Process -Name x,y / Stop-Process -Name x
    private static readonly Regex ProcessCmdletNames = new(
        @"\b(?:Get-Process|gps|ps|Stop-Process|spps|kill|Wait-Process)\b[^;|&\r\n]*?-(?:Name|ProcessName)\b\s*[:=]?\s*(?<names>[""']?[\w.\-*]+[""']?(?:\s*,\s*[""']?[\w.\-*]+[""']?)*)", Opts);

    // WQL Name='x.exe' (Win32_Process filters)
    private static readonly Regex WqlName = new(
        @"\bName\s*(?:=|-eq|\blike\b)\s*['""](?<name>[\w.\-%]+?\.exe)['""]", Opts);

    public static List<PidReference> ExtractPids(string? text)
    {
        var found = new List<PidReference>();
        if (string.IsNullOrWhiteSpace(text)) return found;
        var seen = new HashSet<int>();

        void Add(string pidText, string context)
        {
            if (found.Count >= MaxReferences) return;
            if (!int.TryParse(pidText, out var pid) || pid < 0) return;
            if (seen.Add(pid)) found.Add(new PidReference(pid, context.Trim()));
        }

        foreach (Match m in WqlPid.Matches(text))
            Add(m.Groups["pid"].Value, m.Value);

        foreach (Match m in ProcessCmdletIds.Matches(text))
        {
            var ids = m.Groups["ids"].Value;
            foreach (var id in ids.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                Add(id, $"-Id {id}");
        }

        foreach (Match m in SlashPid.Matches(text)) Add(m.Groups["pid"].Value, m.Value);
        foreach (Match m in GetProcessById.Matches(text)) Add(m.Groups["pid"].Value, m.Value);
        foreach (Match m in MiniDump.Matches(text)) Add(m.Groups["pid"].Value, m.Value);
        foreach (Match m in ProcDump.Matches(text)) Add(m.Groups["pid"].Value, $"procdump {m.Groups["pid"].Value}");
        foreach (Match m in Debugger.Matches(text)) Add(m.Groups["pid"].Value, $"-p {m.Groups["pid"].Value}");

        return found;
    }

    public static List<NameReference> ExtractNames(string? text)
    {
        var found = new List<NameReference>();
        if (string.IsNullOrWhiteSpace(text)) return found;
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        void Add(string name, string context)
        {
            name = name.Trim().Trim('"', '\'');
            if (name.Length == 0 || name.Contains('*') || name.Contains('%')) return;
            if (found.Count < MaxReferences && seen.Add(CmdSpyOptions.Stem(name)))
                found.Add(new NameReference(name, context.Trim()));
        }

        foreach (Match m in ImageName.Matches(text)) Add(m.Groups["name"].Value, m.Value);
        foreach (Match m in WqlName.Matches(text)) Add(m.Groups["name"].Value, m.Value);
        foreach (Match m in ProcessCmdletNames.Matches(text))
            foreach (var n in m.Groups["names"].Value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                Add(n, $"-Name {n.Trim('"', '\'')}");

        return found;
    }

    /// <summary>All PIDs referenced across several texts (raw + decoded + nested), first context wins.</summary>
    public static List<PidReference> ExtractPids(IEnumerable<string> texts)
    {
        var all = new List<PidReference>();
        var seen = new HashSet<int>();
        foreach (var text in texts)
            foreach (var r in ExtractPids(text))
                if (seen.Add(r.ProcessId)) all.Add(r);
        return all.Take(MaxReferences).ToList();
    }

    public static List<NameReference> ExtractNames(IEnumerable<string> texts)
    {
        var all = new List<NameReference>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var text in texts)
            foreach (var r in ExtractNames(text))
                if (seen.Add(CmdSpyOptions.Stem(r.Name))) all.Add(r);
        return all.Take(MaxReferences).ToList();
    }
}
