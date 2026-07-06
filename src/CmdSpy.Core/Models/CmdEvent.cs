using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Serialization;

namespace CmdSpy.Core.Models;

/// <summary>
/// A fully captured "cmd popup" sighting. Everything CMD-spy knows about a
/// command-prompt (or other console-host) process that appeared on the machine,
/// even if that window only existed for a fraction of a second.
/// </summary>
public sealed class CmdEvent
{
    /// <summary>Monotonically increasing capture number within this session.</summary>
    public long SequenceNumber { get; set; }

    public Guid Id { get; set; } = Guid.NewGuid();

    // ---- Timing -----------------------------------------------------------
    public DateTimeOffset TimestampUtc { get; set; }
    public DateTimeOffset TimestampLocal { get; set; }

    /// <summary>When the machine last booted (local time).</summary>
    public DateTimeOffset SystemBootTimeLocal { get; set; }

    /// <summary>Elapsed time between system boot and this event ("from bootup time").</summary>
    public TimeSpan TimeSinceBoot { get; set; }

    public double SystemUptimeSeconds { get; set; }

    // ---- The spied process (the cmd popup) --------------------------------
    public int ProcessId { get; set; }
    public string ProcessName { get; set; } = "";
    public string? ImagePath { get; set; }
    public string? CommandLine { get; set; }
    public string? UserName { get; set; }
    public int SessionId { get; set; } = -1;

    // ---- Cause (the parent process that spawned it) -----------------------
    public int ParentProcessId { get; set; }
    public string? ParentProcessName { get; set; }
    public string? ParentImagePath { get; set; }
    public string? ParentCommandLine { get; set; }

    // ---- Lifetime ("even for a millisecond") ------------------------------
    public DateTimeOffset? ExitedAtUtc { get; set; }
    public double? LifetimeMilliseconds { get; set; }
    public int? ExitCode { get; set; }

    // ---- Actions & networking ---------------------------------------------
    /// <summary>Processes launched by this cmd popup while it was alive.</summary>
    public List<ProcessInfo> ChildProcesses { get; set; } = new();

    /// <summary>Network endpoints owned by this process (best effort snapshot).</summary>
    public List<NetworkConnectionInfo> NetworkConnections { get; set; } = new();

    // ---- Capture metadata -------------------------------------------------
    /// <summary>ETW or WMI — how this sighting was detected.</summary>
    public string CaptureSource { get; set; } = "";
    public string? Notes { get; set; }

    // ---- Computed display helpers (not persisted to JSON) ------------------
    [JsonIgnore]
    public string TimeLocalDisplay => TimestampLocal.ToString("yyyy-MM-dd HH:mm:ss.fff");

    [JsonIgnore]
    public string SinceBootDisplay => FormatSpan(TimeSinceBoot);

    [JsonIgnore]
    public string CauseDisplay =>
        ParentProcessId <= 0
            ? "(unknown)"
            : $"[{ParentProcessId}] {ParentProcessName ?? "?"}";

    [JsonIgnore]
    public string LifetimeDisplay =>
        LifetimeMilliseconds is null
            ? "(alive)"
            : LifetimeMilliseconds.Value < 1000
                ? $"{LifetimeMilliseconds.Value:0.#} ms"
                : $"{LifetimeMilliseconds.Value / 1000.0:0.###} s";

    [JsonIgnore]
    public int NetworkCount => NetworkConnections.Count;

    [JsonIgnore]
    public int ChildCount => ChildProcesses.Count;

    [JsonIgnore]
    public string CommandLineShort
    {
        get
        {
            var c = string.IsNullOrWhiteSpace(CommandLine) ? (ImagePath ?? ProcessName) : CommandLine;
            c = c.Replace("\r", " ").Replace("\n", " ");
            return c.Length > 160 ? c[..157] + "..." : c;
        }
    }

    private static string FormatSpan(TimeSpan span)
    {
        if (span.TotalDays >= 1)
            return $"{(int)span.TotalDays}d {span.Hours:D2}:{span.Minutes:D2}:{span.Seconds:D2}";
        return $"{span.Hours:D2}:{span.Minutes:D2}:{span.Seconds:D2}.{span.Milliseconds:D3}";
    }
}
