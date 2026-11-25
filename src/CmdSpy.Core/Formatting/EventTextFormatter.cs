using System;
using System.Linq;
using System.Text;
using CmdSpy.Core.Models;

namespace CmdSpy.Core.Formatting;

/// <summary>Renders a <see cref="CmdEvent"/> as a readable text block.</summary>
public static class EventTextFormatter
{
    /// <summary>Title of the block written when the user re-runs an analysis.</summary>
    public const string ReanalysisTitle = "CMD POPUP — UPDATED ANALYSIS";

    public static string Format(CmdEvent ev, bool finalized = false)
    {
        // The engine mutates ChildProcesses/NetworkConnections under lock(ev)
        // from watcher threads; take the same lock so our enumeration is safe.
        lock (ev)
        {
            return FormatLocked(ev, finalized ? "CMD POPUP — FINAL RECORD" : "CMD POPUP CAPTURED", finalized);
        }
    }

    /// <summary>Formats with a custom block title (e.g. <see cref="ReanalysisTitle"/>).</summary>
    public static string Format(CmdEvent ev, string title)
    {
        lock (ev)
        {
            return FormatLocked(ev, title, finalized: true);
        }
    }

    private static string FormatLocked(CmdEvent ev, string title, bool finalized)
    {
        var sb = new LogTextBuilder();
        sb.AppendLine("============================================================");
        sb.AppendLine($"#{ev.SequenceNumber}  {title}   (id {ev.Id})");
        sb.AppendLine("============================================================");

        sb.AppendLine("-- Time --------------------------------------------------");
        sb.AppendLine($"  Local time        : {ev.TimestampLocal:yyyy-MM-dd HH:mm:ss.fff zzz}");
        sb.AppendLine($"  UTC time          : {ev.TimestampUtc:yyyy-MM-dd HH:mm:ss.fff}");
        sb.AppendLine($"  System boot time  : {ev.SystemBootTimeLocal:yyyy-MM-dd HH:mm:ss}");
        sb.AppendLine($"  Since bootup      : {ev.SinceBootDisplay}");
        sb.AppendLine($"  System uptime     : {ev.SystemUptimeSeconds:0.0} s");

        sb.AppendLine("-- Task info ---------------------------------------------");
        sb.AppendLine($"  Process           : {ev.ProcessName}  (PID {ev.ProcessId})");
        sb.AppendLine($"  Image path        : {ev.ImagePath ?? "(unknown)"}");
        sb.AppendLine($"  User              : {ev.UserName ?? "(unknown)"}");
        sb.AppendLine($"  Session           : {ev.SessionId}");
        sb.AppendLine($"  Detected via      : {ev.CaptureSource}");

        sb.AppendLine("-- Command line ------------------------------------------");
        sb.AppendLine($"  {ev.CommandLine ?? "(not available)"}");

        sb.AppendLine("-- Cause (parent process) --------------------------------");
        sb.AppendLine($"  Parent            : {ev.ParentProcessName ?? "(unknown)"}  (PID {ev.ParentProcessId})");
        sb.AppendLine($"  Parent image      : {ev.ParentImagePath ?? "(unknown)"}");
        sb.AppendLine($"  Parent cmdline    : {ev.ParentCommandLine ?? "(unknown)"}");

        sb.AppendLine("-- Lifetime ----------------------------------------------");
        if (ev.LifetimeMilliseconds is not null)
        {
            sb.AppendLine($"  Exited at (UTC)   : {ev.ExitedAtUtc:yyyy-MM-dd HH:mm:ss.fff}");
            sb.AppendLine($"  Lived for         : {ev.LifetimeDisplay}");
            sb.AppendLine($"  Exit code         : {ev.ExitCode?.ToString() ?? "(unknown)"}");
        }
        else
        {
            sb.AppendLine("  Still alive / exit not observed.");
        }

        sb.AppendLine("-- Actions (child processes) -----------------------------");
        if (ev.ChildProcesses.Count == 0)
        {
            sb.AppendLine("  (none observed)");
        }
        else
        {
            foreach (var child in ev.ChildProcesses)
            {
                var indent = new string(' ', 2 * Math.Max(0, child.Depth - 1));
                var level = child.Depth > 1 ? $"  (level {child.Depth}, started by PID {child.ParentProcessId})" : "";
                var exit = child.ExitedAtUtc is { } exited && child.StartTimeUtc is { } started
                    ? $"  — exited after {Duration(exited - started)}, code {child.ExitCode?.ToString() ?? "?"}"
                    : "";
                sb.AppendLine($"  {indent}* [{child.ProcessId}] {child.ProcessName}{level}{exit}");
                if (!string.IsNullOrWhiteSpace(child.CommandLine))
                    sb.AppendLine($"      {indent}{child.CommandLine}");
            }
        }

        sb.AppendLine("-- Networking --------------------------------------------");
        if (ev.NetworkConnections.Count == 0)
        {
            sb.AppendLine("  (no connections captured)");
        }
        else
        {
            foreach (var conn in ev.NetworkConnections)
            {
                var owner = conn.OwningPid > 0 && conn.OwningPid != ev.ProcessId ? $"  (by action PID {conn.OwningPid})" : "";
                var live = conn.Source == "ETW" ? "  — seen live" : "";
                sb.AppendLine($"  * {conn}{owner}{live}");
            }
        }

        AppendInvestigation(sb, ev, finalized);

        if (!string.IsNullOrWhiteSpace(ev.Notes))
        {
            sb.AppendLine("-- Notes -------------------------------------------------");
            sb.AppendLine($"  {ev.Notes}");
        }

        return sb.ToString();
    }

    // ------------------------------------------------------- investigation --

    private static void AppendInvestigation(LogTextBuilder sb, CmdEvent ev, bool finalized)
    {
        var inv = ev.Investigation;
        sb.AppendLine("-- Investigation -----------------------------------------");
        if (inv is null)
        {
            sb.AppendLine(finalized
                ? "  (not analysed — investigation was off or did not finish)"
                : "  (analysis running in the background — it is added to the final record)");
            return;
        }

        var ex = inv.Explanation;
        if (ex is not null)
            sb.AppendLine($"  {ex.Interpreter} detected — {ex.Classification}");
        sb.AppendLine(inv.Launcher is null
            ? "  Launcher          : Not yet identified — requires parent-process evidence."
            : $"  Launcher          : {inv.Launcher}{(inv.LaunchContext is null ? "" : $" ({inv.LaunchContext})")}");
        if (inv.ScheduledTask is { } quickTask)
            sb.AppendLine($"  Scheduled task    : {(quickTask.TaskPath.Length > 0 ? quickTask.TaskPath : "(task not identified)")} — {quickTask.Confidence}");
        if (inv.Risk is { } quickRisk)
            sb.AppendLine($"  Verdict           : {quickRisk.Level}  (score {quickRisk.Score}/100, confidence {quickRisk.Confidence})");

        // Launch chain ------------------------------------------------------
        sb.AppendLine("-- Launch chain (what started it) ------------------------");
        sb.AppendLine($"  this process  {Pid(ev.ProcessId)} {Pad(ev.ProcessName, 26)} {inv.ResolvedImagePath ?? ev.ImagePath ?? ""}");
        if (inv.Ancestry.Count == 0)
        {
            sb.AppendLine("  (no parent-process evidence)");
        }
        foreach (var a in inv.Ancestry)
        {
            var label = a.Depth == 1 ? "parent" : $"level {a.Depth}";
            var where = a.ImagePath ?? "";
            sb.AppendLine($"  {Pad(label, 13)} {Pid(a.ProcessId)} {Pad(a.ProcessName, 26)} {where}");
            if (a.Description is not null)
                sb.AppendLine($"  {"",13} {"",8} ↳ {a.Description}");
            if (!string.IsNullOrWhiteSpace(a.CommandLine) && a.Depth <= 3)
                sb.AppendLine($"  {"",13} {"",8}   {Shorten(a.CommandLine, 180)}");
            if (a.Source is "Security 4688" or "Sysmon 1")
                sb.AppendLine($"  {"",13} {"",8}   (recovered from the {a.Source} event log — it had already exited)");
        }
        sb.AppendLine($"  Chain             : {(inv.AncestryComplete ? "complete" : "incomplete")}{(inv.AncestryNote is null ? "" : " — " + inv.AncestryNote)}");

        // Scheduled task ----------------------------------------------------
        sb.AppendLine("-- Scheduled task ----------------------------------------");
        if (inv.ScheduledTask is { } task)
        {
            sb.AppendLine($"  Task              : {(task.TaskPath.Length > 0 ? task.TaskPath : "(not identified)")}");
            sb.AppendLine($"  Confidence        : {task.Confidence}");
            sb.AppendLine($"  Evidence          : {task.Evidence}");
            if (task.Command is not null) sb.AppendLine($"  Action            : {task.Command} {task.Arguments}".TrimEnd());
            if (task.Triggers is not null) sb.AppendLine($"  Runs              : {task.Triggers}");
            if (task.Author is not null) sb.AppendLine($"  Author            : {task.Author}");
            if (task.RunAs is not null) sb.AppendLine($"  Runs as           : {task.RunAs}");
        }
        else
        {
            sb.AppendLine("  (no scheduled task involved, as far as the evidence shows)");
        }

        // Referenced processes ------------------------------------------------
        sb.AppendLine("-- Processes referenced by the command -------------------");
        if (inv.ReferencedProcesses.Count == 0)
        {
            sb.AppendLine("  (the command doesn't refer to other processes)");
        }
        else
        {
            sb.AppendLine($"  {"PID",-8} {Pad("Process", 26)} {Pad("Status", 18)} Vendor / path");
            foreach (var r in inv.ReferencedProcesses)
            {
                var pid = r.ProcessId > 0 ? r.ProcessId.ToString() : "-";
                sb.AppendLine($"  {pid,-8} {Pad(r.ProcessName ?? "?", 26)} {Pad(r.Status, 18)} {r.Company ?? r.Product ?? ""}");
                if (r.ImagePath is not null) sb.AppendLine($"  {"",8} {r.ImagePath}");
                sb.AppendLine($"  {"",8} referenced as: {r.Context}");
            }
        }

        // Command analysis ----------------------------------------------------
        sb.AppendLine("-- Command analysis --------------------------------------");
        if (ex is null)
        {
            sb.AppendLine("  (not analysed)");
        }
        else
        {
            sb.AppendLine($"  Analysis          : {ex.Summary}");
            if (ex.InnerCommand is not null) sb.AppendLine($"  Command           : {Shorten(ex.InnerCommand, 400)}");
            if (ex.DecodedCommand is not null) sb.AppendLine($"  Decoded           : {Shorten(ex.DecodedCommand, 800)}");
            if (ex.ScriptPath is not null) sb.AppendLine($"  Script file       : {ex.ScriptPath}");
            if (ex.Effects.Count > 0) sb.AppendLine($"  Effects           : {string.Join(", ", ex.Effects)}");
            foreach (var sw in ex.Switches) sb.AppendLine($"  Switch            : {sw}");
            if (ex.Details.Count > 0)
            {
                sb.AppendLine("  Step by step      :");
                foreach (var d in ex.Details) sb.AppendLine($"    • {d}");
            }
        }

        // Suspicious indicators -----------------------------------------------
        sb.AppendLine("-- Suspicious indicators ---------------------------------");
        var shown = inv.Findings.Where(f => f.Severity != Severity.Info || f.RuleId.StartsWith("INFO", StringComparison.Ordinal) || f.RuleId.StartsWith("LINEAGE", StringComparison.Ordinal)).ToList();
        if (shown.Count == 0)
        {
            sb.AppendLine("  (none found in the command, its actions or its launch chain)");
        }
        foreach (var f in shown)
        {
            sb.AppendLine($"  [{f.Severity.ToUpperInvariant()}] {f.Title}{(f.Technique is null ? "" : $"  (MITRE ATT&CK {f.Technique})")}");
            sb.AppendLine($"         {f.Detail}");
            if (f.Evidence is not null) sb.AppendLine($"         evidence: {Shorten(f.Evidence, 200)}{(f.Subject is null ? "" : $"   in: {f.Subject}")}");
        }

        // Signatures -----------------------------------------------------------
        sb.AppendLine("-- Authenticity (digital signatures & hashes) -------------");
        if (inv.Signatures.Count == 0)
        {
            sb.AppendLine("  (no signatures checked)");
        }
        foreach (var sig in inv.Signatures)
        {
            var file = sig.Path[(sig.Path.LastIndexOfAny(new[] { '\\', '/' }) + 1)..];
            sb.AppendLine($"  {Pad(sig.Role, 22)} {Pad(file, 26)} {Pad(sig.StatusDisplay, 18)} {sig.Publisher ?? ""}");
            if (sig.CompanyName is not null || sig.ProductName is not null)
                sb.AppendLine($"  {"",22} {sig.CompanyName}{(sig.ProductName is null ? "" : " — " + sig.ProductName)}{(sig.FileVersion is null ? "" : " " + sig.FileVersion)}");
            if (sig.Sha256 is not null) sb.AppendLine($"  {"",22} SHA-256 {sig.Sha256}");
            if (sig.Detail is not null && !sig.IsValid) sb.AppendLine($"  {"",22} {sig.Detail}");
            sb.AppendLine($"  {"",22} {sig.Path}");
        }

        // History ----------------------------------------------------------------
        sb.AppendLine("-- Windows event history ---------------------------------");
        if (inv.History.Count == 0)
        {
            sb.AppendLine("  (no related records found in the Windows event logs)");
        }
        foreach (var h in inv.History)
        {
            sb.AppendLine($"  {h.TimeUtc.ToLocalTime():yyyy-MM-dd HH:mm:ss}  {Pad(h.Source, 18)} {h.RelatedTo}");
            if (h.Image is not null || h.ProcessId is not null)
                sb.AppendLine($"  {"",21}{(h.ProcessId is null ? "" : $"PID {h.ProcessId} ")}{h.Image}{(h.ParentProcessId is null ? "" : $"  (parent PID {h.ParentProcessId})")}");
            if (h.CommandLine is not null) sb.AppendLine($"  {"",21}{Shorten(h.CommandLine, 300)}");
            if (h.Detail is not null) sb.AppendLine($"  {"",21}{Shorten(h.Detail, 600)}");
        }

        // Risk -----------------------------------------------------------------------
        sb.AppendLine("-- Risk assessment ---------------------------------------");
        if (inv.Risk is { } risk)
        {
            sb.AppendLine($"  Verdict           : {risk.Level}  (score {risk.Score}/100, confidence {risk.Confidence})");
            sb.AppendLine($"  Summary           : {risk.Summary}");
            foreach (var r in risk.RaisingFactors) sb.AppendLine($"  Raises risk       : {r}");
            foreach (var r in risk.LoweringFactors) sb.AppendLine($"  Lowers risk       : {r}");
            foreach (var r in risk.Unknowns) sb.AppendLine($"  Still unknown     : {r}");
            sb.AppendLine($"  Note              : {risk.Disclaimer}");
        }
        else
        {
            sb.AppendLine("  (no assessment)");
        }

        if (inv.Notes.Count > 0 || inv.Errors.Count > 0)
        {
            sb.AppendLine("-- Investigation notes -----------------------------------");
            foreach (var n in inv.Notes) sb.AppendLine($"  • {n}");
            foreach (var e in inv.Errors) sb.AppendLine($"  ! {e}");
        }
        sb.AppendLine($"  (analysed {inv.AnalyzedAtUtc.ToLocalTime():yyyy-MM-dd HH:mm:ss}, pass {inv.Revision})");
    }

    private static string Pid(int pid) => $"[{pid,6}]";

    private static string Pad(string? s, int width)
    {
        s ??= "";
        return s.Length >= width ? s + " " : s.PadRight(width);
    }

    private static string Shorten(string? s, int max)
    {
        if (string.IsNullOrEmpty(s)) return "";
        s = s.Replace("\r", " ").Replace("\n", " ");
        return s.Length <= max ? s : s[..(max - 1)] + "…";
    }

    private static string Duration(TimeSpan span) =>
        span.TotalMilliseconds < 1000 ? $"{span.TotalMilliseconds:0.#} ms" : $"{span.TotalSeconds:0.###} s";

    /// <summary>
    /// Builds the human-readable report one logical line at a time. Captured and
    /// derived values can contain controls, so render them visibly before adding
    /// the formatter-owned line ending.
    /// </summary>
    private sealed class LogTextBuilder
    {
        private readonly StringBuilder _builder = new();

        public void AppendLine(string? value)
        {
            if (value is not null)
            {
                foreach (var ch in value)
                {
                    switch (ch)
                    {
                        case '\r':
                            _builder.Append(@"\r");
                            break;
                        case '\n':
                            _builder.Append(@"\n");
                            break;
                        case '\t':
                            _builder.Append(@"\t");
                            break;
                        default:
                            if (char.IsControl(ch) || ch is '\u2028' or '\u2029')
                                _builder.Append(@"\u").Append(((int)ch).ToString("X4"));
                            else
                                _builder.Append(ch);
                            break;
                    }
                }
            }

            _builder.AppendLine();
        }

        public override string ToString() => _builder.ToString();
    }
}
