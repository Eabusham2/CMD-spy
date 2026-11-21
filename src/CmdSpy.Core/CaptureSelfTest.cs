using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;
using CmdSpy.Core.Analysis;
using CmdSpy.Core.Models;

namespace CmdSpy.Core;

/// <summary>Outcome of a <see cref="CaptureSelfTest"/> run.</summary>
public sealed class SelfTestResult
{
    public int Launched { get; set; }
    public int Captured { get; set; }

    /// <summary>Captures whose command line arrived complete (the unique marker at its very end was intact).</summary>
    public int WithFullCommandLine { get; set; }

    public int ExitObserved { get; set; }
    public double? ShortestLifetimeMs { get; set; }
    public double? LongestLifetimeMs { get; set; }
    public TimeSpan Elapsed { get; set; }
    public string? CaptureSource { get; set; }
    public List<string> Problems { get; } = new();

    public bool Passed => Launched > 0 && Captured == Launched && WithFullCommandLine == Launched;

    public string Summary
    {
        get
        {
            var verdict = Passed ? "PASSED" : "FAILED";
            var life = ShortestLifetimeMs is null ? "" :
                $" Shortest-lived window: {ShortestLifetimeMs:0.#} ms (longest {LongestLifetimeMs:0.#} ms).";
            return $"Self-test {verdict}: {Captured}/{Launched} short-lived windows captured, " +
                   $"{WithFullCommandLine}/{Launched} with the full command line, {ExitObserved}/{Launched} exits seen" +
                   $"{(CaptureSource is null ? "" : $" (via {CaptureSource})")}, in {Elapsed.TotalSeconds:0.0} s.{life}";
        }
    }
}

/// <summary>
/// Verifies capture reliability on this machine: launches a burst of
/// command-prompt processes that exit within milliseconds, each tagged with a
/// unique marker at the very end of its command line, and checks that every
/// one was captured with its complete command line and exit.
/// </summary>
public static class CaptureSelfTest
{
    /// <summary>Same marker the detector recognizes; only genuine CMD-spy launches are labelled self-test.</summary>
    public const string Marker = SuspiciousCommandDetector.SelfTestMarker;

    public static SelfTestResult Run(ICaptureFeed feed, int count = 25, TimeSpan? timeout = null,
        CancellationToken cancellationToken = default)
    {
        var result = new SelfTestResult();
        var runId = Guid.NewGuid().ToString("N")[..12];
        var markers = Enumerable.Range(0, Math.Max(1, count)).Select(i => $"{Marker}-{runId}-{i:D4}").ToList();
        var markerSet = new HashSet<string>(markers, StringComparer.OrdinalIgnoreCase);
        var seen = new ConcurrentDictionary<string, CmdEvent>(StringComparer.OrdinalIgnoreCase);

        void OnEvent(object? sender, CmdEvent ev)
        {
            string? cmd;
            lock (ev) cmd = ev.CommandLine;
            var marker = ExtractMarker(cmd, runId);
            if (marker is not null && markerSet.Contains(marker)) seen[marker] = ev;
        }

        feed.EventCaptured += OnEvent;
        feed.EventUpdated += OnEvent;
        var clock = Stopwatch.StartNew();
        try
        {
            var cmdExe = Path.Combine(Environment.SystemDirectory, "cmd.exe");
            foreach (var marker in markers)
            {
                cancellationToken.ThrowIfCancellationRequested();
                try
                {
                    using var p = Process.Start(new ProcessStartInfo(cmdExe, $"/d /c rem {marker}")
                    {
                        UseShellExecute = false,
                        CreateNoWindow = true
                    });
                    result.Launched++;
                }
                catch (Exception ex)
                {
                    result.Problems.Add($"Could not start a test window: {ex.Message}");
                    break;
                }
            }

            // Wait for every capture and exit (or the timeout).
            var deadline = DateTime.UtcNow + (timeout ?? TimeSpan.FromSeconds(20));
            while (DateTime.UtcNow < deadline && !cancellationToken.IsCancellationRequested)
            {
                if (seen.Count >= result.Launched && seen.Values.All(e => e.ExitedAtUtc is not null)) break;
                Thread.Sleep(50);
            }
        }
        finally
        {
            feed.EventCaptured -= OnEvent;
            feed.EventUpdated -= OnEvent;
            clock.Stop();
        }

        result.Elapsed = clock.Elapsed;
        result.Captured = seen.Count;
        var lifetimes = new List<double>();
        foreach (var marker in markers.Take(result.Launched))
        {
            if (!seen.TryGetValue(marker, out var ev))
            {
                if (result.Problems.Count < 10) result.Problems.Add($"Not captured: {marker}");
                continue;
            }
            string? cmd; double? life; string source;
            lock (ev) { cmd = ev.CommandLine; life = ev.LifetimeMilliseconds; source = ev.CaptureSource; }
            result.CaptureSource ??= source;
            if (cmd is not null && cmd.TrimEnd().EndsWith(marker, StringComparison.OrdinalIgnoreCase))
                result.WithFullCommandLine++;
            else if (result.Problems.Count < 10)
                result.Problems.Add($"Command line incomplete for {marker}: {cmd ?? "(none)"}");
            if (life is not null)
            {
                result.ExitObserved++;
                lifetimes.Add(life.Value);
            }
        }
        if (lifetimes.Count > 0)
        {
            result.ShortestLifetimeMs = lifetimes.Min();
            result.LongestLifetimeMs = lifetimes.Max();
        }
        return result;
    }

    private static string? ExtractMarker(string? commandLine, string runId)
    {
        if (string.IsNullOrEmpty(commandLine)) return null;
        var prefix = $"{Marker}-{runId}-";
        int at = commandLine.IndexOf(prefix, StringComparison.OrdinalIgnoreCase);
        if (at < 0) return null;
        int end = at + prefix.Length;
        while (end < commandLine.Length && char.IsDigit(commandLine[end])) end++;
        return commandLine[at..end];
    }

    // ------------------------------------------------------- genuineness --

    /// <summary>
    /// True when a process carrying the self-test marker (or the console host
    /// of one) was really started by CMD-spy — this process, or the same
    /// CmdSpy.exe running as the background service. A command that merely
    /// contains the marker text does not count, so malware can't hide behind it.
    /// </summary>
    public static bool IsGenuine(string? commandLine, IReadOnlyList<ProcessInfo> ancestry)
    {
        int launcherIndex;
        if (ContainsMarker(commandLine)) launcherIndex = 0;
        else if (ancestry.Count > 0 && ContainsMarker(ancestry[0].CommandLine)) launcherIndex = 1;   // its conhost
        else return false;

        return launcherIndex < ancestry.Count && IsCmdSpyProcess(ancestry[launcherIndex]);
    }

    public static bool ContainsMarker(string? text) =>
        !string.IsNullOrEmpty(text) && text.Contains(Marker, StringComparison.OrdinalIgnoreCase);

    private static readonly Lazy<(string? Path, DateTimeOffset? Start)> Self = new(() =>
    {
        try
        {
            using var me = Process.GetCurrentProcess();
            return (Environment.ProcessPath, new DateTimeOffset(me.StartTime.ToUniversalTime(), TimeSpan.Zero));
        }
        catch
        {
            return (Environment.ProcessPath, null);
        }
    });

    private static bool IsCmdSpyProcess(ProcessInfo p)
    {
        var (ownPath, ownStart) = Self.Value;

        // This very process (the GUI, or a test host running the engine).
        if (p.ProcessId == Environment.ProcessId &&
            (p.StartTimeUtc is null || ownStart is null || (p.StartTimeUtc.Value - ownStart.Value).Duration() < TimeSpan.FromSeconds(5)))
            return true;

        // The same CmdSpy.exe in another process (GUI ↔ background service).
        if (string.IsNullOrEmpty(ownPath) || string.IsNullOrEmpty(p.ImagePath)) return false;
        var ownName = Path.GetFileName(ownPath);
        if (ownName.Equals("dotnet.exe", StringComparison.OrdinalIgnoreCase) ||
            ownName.Equals("dotnet", StringComparison.OrdinalIgnoreCase))
            return false;   // a generic host proves nothing
        try
        {
            if (string.Equals(Path.GetFullPath(ownPath), Path.GetFullPath(p.ImagePath), StringComparison.OrdinalIgnoreCase))
                return true;

            // A copy of the very same CmdSpy.exe (e.g. the GUI run from its download
            // folder while the service runs the installed copy): compare contents.
            var own = HashOf(ownPath);
            return own is not null && string.Equals(own, HashOf(p.ImagePath), StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }

    private static readonly ConcurrentDictionary<string, string?> Hashes = new(StringComparer.OrdinalIgnoreCase);

    private static string? HashOf(string path) => Hashes.GetOrAdd(path, static p =>
    {
        try
        {
            using var stream = File.OpenRead(p);
            return Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(stream));
        }
        catch
        {
            return null;
        }
    });
}
