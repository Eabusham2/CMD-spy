using System.Text;
using CmdSpy.Core.Models;

namespace CmdSpy.Core.Formatting;

/// <summary>Renders a <see cref="CmdEvent"/> as a readable text block.</summary>
public static class EventTextFormatter
{
    public static string Format(CmdEvent ev)
    {
        // The engine mutates ChildProcesses/NetworkConnections under lock(ev)
        // from watcher threads; take the same lock so our enumeration is safe.
        lock (ev)
        {
            return FormatLocked(ev);
        }
    }

    private static string FormatLocked(CmdEvent ev)
    {
        var sb = new StringBuilder();
        sb.AppendLine("============================================================");
        sb.AppendLine($"#{ev.SequenceNumber}  CMD POPUP CAPTURED   (id {ev.Id})");
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
                sb.AppendLine($"  * [{child.ProcessId}] {child.ProcessName}");
                if (!string.IsNullOrWhiteSpace(child.CommandLine))
                    sb.AppendLine($"      {child.CommandLine}");
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
                sb.AppendLine($"  * {conn}");
        }

        if (!string.IsNullOrWhiteSpace(ev.Notes))
        {
            sb.AppendLine("-- Notes -------------------------------------------------");
            sb.AppendLine($"  {ev.Notes}");
        }

        return sb.ToString();
    }
}
