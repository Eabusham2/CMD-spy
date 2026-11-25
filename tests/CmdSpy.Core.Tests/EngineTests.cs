using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using CmdSpy.Core.Models;
using Xunit;

namespace CmdSpy.Core.Tests;

/// <summary>
/// End-to-end behaviour of the capture engine, driven by a fake process
/// watcher: the cause survives its parent exiting, descendants are tracked
/// with their depth and validated against recycled PIDs, live network events
/// attach to the right popup, and the finalized log record waits for the
/// investigation so it includes it.
/// </summary>
public class EngineTests : IDisposable
{
    // PIDs far above anything Windows hands out, so a live lookup on a real
    // machine can never confuse them with an actual process.
    private const int Explorer = 900_004, Updater = 900_008, Cmd = 900_012, Ping = 900_016, Grandchild = 900_020, Reused = 900_024;

    private readonly TempDir _dir = new();
    private readonly FakeWatcher _watcher = new();

    public void Dispose() => _dir.Dispose();

    private CmdSpyEngine NewEngine(bool investigate = false, bool network = false)
    {
        var options = new CmdSpyOptions
        {
            LogDirectory = _dir.Path,
            SeedProcessCache = false,
            InvestigateEvents = investigate,
            CaptureNetwork = network,
            CaptureNetworkEvents = network,
            VerifySignatures = false,
            CorrelateEventLogs = false,
            CorrelateScheduledTasks = false
        };
        var engine = new CmdSpyEngine(options, () => _watcher);
        engine.Start();
        return engine;
    }

    private void LaunchChain(DateTimeOffset t)
    {
        _watcher.Started(Explorer, 4, "explorer.exe", @"C:\Windows\Explorer.EXE", t.AddMinutes(-30), @"C:\Windows\explorer.exe");
        _watcher.Started(Updater, Explorer, "updater.exe", "\"C:\\Program Files\\Vendor\\updater.exe\" --run", t, @"C:\Program Files\Vendor\updater.exe");
    }

    [Fact]
    public void ParentDetailsArePreservedEvenThoughTheParentAlreadyExited()
    {
        using var engine = NewEngine();
        CmdEvent? captured = null;
        engine.EventCaptured += (_, ev) => captured = ev;
        var t = DateTimeOffset.UtcNow;

        LaunchChain(t);
        // The launcher exits immediately; the popup's start is handled after that.
        _watcher.Stopped(Updater, t.AddMilliseconds(4));
        _watcher.Started(Cmd, Updater, "cmd.exe", "cmd.exe /c ping -n 2 127.0.0.1", t.AddMilliseconds(2), @"C:\Windows\System32\cmd.exe");

        Assert.NotNull(captured);
        Assert.Equal("updater.exe", captured!.ParentProcessName);
        Assert.Equal(@"C:\Program Files\Vendor\updater.exe", captured.ParentImagePath);
        Assert.Contains("--run", captured.ParentCommandLine);
    }

    [Fact]
    public void ChildrenAndGrandchildrenAreRecordedWithDepthAndExit()
    {
        using var engine = NewEngine();
        CmdEvent? captured = null;
        engine.EventCaptured += (_, ev) => captured = ev;
        var t = DateTimeOffset.UtcNow;

        LaunchChain(t);
        _watcher.Started(Cmd, Updater, "cmd.exe", "cmd.exe /c tool.bat", t.AddMilliseconds(1));
        _watcher.Started(Ping, Cmd, "PING.EXE", "ping -n 1 127.0.0.1", t.AddMilliseconds(5));
        _watcher.Started(Grandchild, Ping, "helper.exe", "helper.exe --child", t.AddMilliseconds(8));
        _watcher.Stopped(Grandchild, t.AddMilliseconds(20), exitCode: 3);

        Assert.NotNull(captured);
        var child = Assert.Single(captured!.ChildProcesses, c => c.ProcessId == Ping);
        Assert.Equal(1, child.Depth);
        var grandchild = Assert.Single(captured.ChildProcesses, c => c.ProcessId == Grandchild);
        Assert.Equal(2, grandchild.Depth);
        Assert.Equal(Ping, grandchild.ParentProcessId);
        Assert.Equal(3, grandchild.ExitCode);
        Assert.NotNull(grandchild.ExitedAtUtc);
    }

    [Fact]
    public void ARecycledPidDoesNotAttachProcessesToAnExitedPopup()
    {
        using var engine = NewEngine();
        CmdEvent? captured = null;
        engine.EventCaptured += (_, ev) => { if (ev.ProcessId == Cmd) captured ??= ev; };
        var t = DateTimeOffset.UtcNow;

        LaunchChain(t);
        _watcher.Started(Cmd, Updater, "cmd.exe", "cmd.exe /c exit", t.AddMilliseconds(1));
        _watcher.Stopped(Cmd, t.AddMilliseconds(3));

        // Windows hands the same PID to an unrelated program, which starts a process.
        _watcher.Started(Cmd, Explorer, "notepad.exe", "notepad.exe", t.AddSeconds(2));
        _watcher.Started(Reused, Cmd, "child-of-notepad.exe", "child-of-notepad.exe", t.AddSeconds(3));

        Assert.NotNull(captured);
        Assert.Empty(captured!.ChildProcesses);
        Assert.NotNull(captured.ExitedAtUtc);
    }

    [Fact]
    public void DelayedStopForReusedPidDoesNotFinalizeTheNewPopup()
    {
        using var engine = NewEngine();
        var captured = new List<CmdEvent>();
        engine.EventCaptured += (_, ev) => captured.Add(ev);
        var t = DateTimeOffset.UtcNow;

        LaunchChain(t);
        _watcher.Started(Cmd, Updater, "cmd.exe", "cmd.exe /c first", t.AddMilliseconds(1));
        _watcher.Started(Cmd, Updater, "cmd.exe", "cmd.exe /c second", t.AddSeconds(1));

        // The old stop arrives after PID reuse, but its timestamp precedes the new start.
        _watcher.Stopped(Cmd, t.AddMilliseconds(10));

        var newer = captured.Single(ev => ev.CommandLine == "cmd.exe /c second");
        Assert.Null(newer.ExitedAtUtc);

        _watcher.Stopped(Cmd, t.AddSeconds(2), exitCode: 7);
        Assert.Equal(t.AddSeconds(2), newer.ExitedAtUtc);
        Assert.Equal(7, newer.ExitCode);
    }

    [Fact]
    public void DelayedNetworkEventAcrossPidReuseReachesTheOriginalPopup()
    {
        using var engine = NewEngine(network: true);
        var captured = new List<CmdEvent>();
        engine.EventCaptured += (_, ev) => captured.Add(ev);
        var t = DateTimeOffset.UtcNow;

        LaunchChain(t);
        _watcher.Started(Cmd, Updater, "cmd.exe", "cmd.exe /c first", t.AddMilliseconds(1));
        _watcher.Stopped(Cmd, t.AddMilliseconds(10));
        _watcher.Started(Cmd, Updater, "cmd.exe", "cmd.exe /c second", t.AddMilliseconds(20));

        NetworkConnectionInfo Conn(int port, double atMs) => new()
        {
            Protocol = "TCP", LocalAddress = "10.0.0.2", LocalPort = port,
            RemoteAddress = "93.184.216.34", RemotePort = 443, State = "CONNECT",
            OwningPid = Cmd, Source = "ETW", ObservedAtUtc = t.AddMilliseconds(atMs)
        };

        // Both callbacks arrive after reuse; their timestamps identify different incarnations.
        engine.OnConnectionObserved(Cmd, Conn(50100, 5));
        engine.OnConnectionObserved(Cmd, Conn(50101, 25));

        var older = captured.Single(ev => ev.CommandLine == "cmd.exe /c first");
        var newer = captured.Single(ev => ev.CommandLine == "cmd.exe /c second");
        Assert.Contains(older.NetworkConnections, c => c.LocalPort == 50100);
        Assert.DoesNotContain(newer.NetworkConnections, c => c.LocalPort == 50100);
        Assert.Contains(newer.NetworkConnections, c => c.LocalPort == 50101);
        Assert.DoesNotContain(older.NetworkConnections, c => c.LocalPort == 50101);
    }

    [Fact]
    public void DelayedDescendantStopDoesNotRemoveTheReusedChild()
    {
        using var engine = NewEngine(network: true);
        CmdEvent? captured = null;
        engine.EventCaptured += (_, ev) => captured = ev;
        var t = DateTimeOffset.UtcNow;

        LaunchChain(t);
        _watcher.Started(Cmd, Updater, "cmd.exe", "cmd.exe /c tools", t.AddMilliseconds(1));
        _watcher.Started(Ping, Cmd, "first.exe", "first.exe", t.AddMilliseconds(5));
        _watcher.Started(Ping, Cmd, "second.exe", "second.exe", t.AddMilliseconds(20));

        // The first child's stop is delivered after the PID has been assigned again.
        _watcher.Stopped(Ping, t.AddMilliseconds(10));
        engine.OnConnectionObserved(Ping, new NetworkConnectionInfo
        {
            Protocol = "TCP", LocalAddress = "10.0.0.2", LocalPort = 50102,
            RemoteAddress = "93.184.216.34", RemotePort = 443, State = "CONNECT",
            OwningPid = Ping, Source = "ETW", ObservedAtUtc = t.AddMilliseconds(25)
        });

        Assert.NotNull(captured);
        var older = captured!.ChildProcesses.Single(p => p.CommandLine == "first.exe");
        var newer = captured.ChildProcesses.Single(p => p.CommandLine == "second.exe");
        Assert.Equal(t.AddMilliseconds(10), older.ExitedAtUtc);
        Assert.Null(newer.ExitedAtUtc);
        Assert.Contains(captured.NetworkConnections, c => c.LocalPort == 50102);
    }

    [Fact]
    public void LiveNetworkEventsAttachToThePopupAndItsActions()
    {
        using var engine = NewEngine(network: true);
        CmdEvent? captured = null;
        engine.EventCaptured += (_, ev) => captured = ev;
        var t = DateTimeOffset.UtcNow;

        LaunchChain(t);
        // A connection reported a moment before the start event was handled is buffered, not lost.
        engine.OnConnectionObserved(Cmd, new NetworkConnectionInfo
        {
            Protocol = "TCP", LocalAddress = "10.0.0.2", LocalPort = 50000, RemoteAddress = "93.184.216.34", RemotePort = 443,
            State = "CONNECT", OwningPid = Cmd, Source = "ETW", ObservedAtUtc = t.AddMilliseconds(2)
        });
        _watcher.Started(Cmd, Updater, "cmd.exe", "cmd.exe /c curl https://example.com", t.AddMilliseconds(1));
        _watcher.Started(Ping, Cmd, "curl.exe", "curl https://example.com", t.AddMilliseconds(3));
        engine.OnConnectionObserved(Ping, new NetworkConnectionInfo
        {
            Protocol = "TCP", LocalAddress = "10.0.0.2", LocalPort = 50001, RemoteAddress = "93.184.216.34", RemotePort = 443,
            State = "CONNECT", OwningPid = Ping, Source = "ETW", ObservedAtUtc = t.AddMilliseconds(6)
        });
        // Duplicates of the same endpoint are not added twice.
        engine.OnConnectionObserved(Ping, new NetworkConnectionInfo
        {
            Protocol = "TCP", LocalAddress = "10.0.0.2", LocalPort = 50001, RemoteAddress = "93.184.216.34", RemotePort = 443,
            State = "CONNECT", OwningPid = Ping, Source = "ETW", ObservedAtUtc = t.AddMilliseconds(7)
        });

        Assert.NotNull(captured);
        var live = captured!.NetworkConnections.Where(c => c.Source == "ETW").ToList();
        Assert.Equal(2, live.Count);
        Assert.Contains(live, c => c.OwningPid == Cmd);
        Assert.Contains(live, c => c.OwningPid == Ping);
    }

    [Fact]
    public void NetworkEventsArrivingAfterTheExitStillReachThePopup()
    {
        using var engine = NewEngine(network: true);
        CmdEvent? captured = null;
        engine.EventCaptured += (_, ev) => captured = ev;
        var t = DateTimeOffset.UtcNow;

        LaunchChain(t);
        _watcher.Started(Cmd, Updater, "powershell.exe", "powershell -c iwr https://example.com", t.AddMilliseconds(1));
        _watcher.Started(Ping, Cmd, "curl.exe", "curl https://example.com", t.AddMilliseconds(5));
        _watcher.Stopped(Ping, t.AddMilliseconds(300));
        _watcher.Stopped(Cmd, t.AddMilliseconds(400));

        // The kernel network session delivers these after both exits were handled.
        NetworkConnectionInfo Conn(int pid, int port, double atMs) => new()
        {
            Protocol = "TCP", LocalAddress = "10.0.0.2", LocalPort = port, RemoteAddress = "93.184.216.34", RemotePort = 443,
            State = "CONNECT", OwningPid = pid, Source = "ETW", ObservedAtUtc = t.AddMilliseconds(atMs)
        };
        engine.OnConnectionObserved(Cmd, Conn(Cmd, 50010, 200));
        engine.OnConnectionObserved(Ping, Conn(Ping, 50011, 100));
        // ...but a connection from after the exit belongs to whatever reuses the PID.
        engine.OnConnectionObserved(Cmd, Conn(Cmd, 50012, 9_000));

        Assert.NotNull(captured);
        var ports = captured!.NetworkConnections.Select(c => c.LocalPort).OrderBy(p => p).ToList();
        Assert.Equal(new[] { 50010, 50011 }, ports);
    }

    [Fact]
    public void UntimedConnectionsRetainBufferedLiveDescendantAndLateCapture()
    {
        using var engine = NewEngine(network: true);
        CmdEvent? captured = null;
        engine.EventCaptured += (_, ev) => captured = ev;
        var t = DateTimeOffset.UtcNow;
        NetworkConnectionInfo Connection(int pid, int port) => new()
        {
            Protocol = "TCP", LocalPort = port, RemoteAddress = "198.51.100.1",
            RemotePort = 443, OwningPid = pid, Source = "compatibility"
        };

        engine.OnConnectionObserved(Cmd, Connection(Cmd, 50200));
        _watcher.Started(Cmd, 0, "cmd.exe", "cmd.exe /c tools", t);
        engine.OnConnectionObserved(Cmd, Connection(Cmd, 50201));
        _watcher.Started(Ping, Cmd, "tool.exe", "tool.exe", t.AddMilliseconds(1));
        engine.OnConnectionObserved(Ping, Connection(Ping, 50202));
        _watcher.Stopped(Ping, t.AddMilliseconds(10));
        _watcher.Stopped(Cmd, t.AddMilliseconds(20));
        engine.OnConnectionObserved(Ping, Connection(Ping, 50203));
        engine.OnConnectionObserved(Cmd, Connection(Cmd, 50204));

        Assert.NotNull(captured);
        Assert.Equal(new[] { 50200, 50201, 50202, 50203, 50204 },
            captured!.NetworkConnections.Select(c => c.LocalPort).OrderBy(p => p));
        var saved = Assert.Single(engine.Store.ReadToday());
        Assert.Equal(5, saved.NetworkConnections.Count);
    }

    [Fact]
    public void UntimedConnectionDoesNotGuessBetweenReusedIncarnations()
    {
        using var engine = NewEngine(network: true);
        var captured = new List<CmdEvent>();
        engine.EventCaptured += (_, ev) => captured.Add(ev);
        var t = DateTimeOffset.UtcNow;
        _watcher.Started(Cmd, 0, "cmd.exe", "cmd.exe /c first", t);
        _watcher.Stopped(Cmd, t.AddMilliseconds(10));
        _watcher.Started(Cmd, 0, "cmd.exe", "cmd.exe /c second", t.AddMilliseconds(20));
        engine.OnConnectionObserved(Cmd, new NetworkConnectionInfo
        {
            Protocol = "TCP", LocalPort = 50210, RemoteAddress = "198.51.100.1",
            RemotePort = 443, OwningPid = Cmd, Source = "compatibility"
        });
        Assert.All(captured, ev => Assert.DoesNotContain(ev.NetworkConnections, c => c.LocalPort == 50210));
    }

    [Fact]
    public void NetworkClockSkewIsRetainedOnlyForAnUnambiguousPid()
    {
        using var engine = NewEngine(network: true);
        var captured = new List<CmdEvent>();
        engine.EventCaptured += (_, ev) => captured.Add(ev);
        var t = DateTimeOffset.UtcNow;
        NetworkConnectionInfo Connection(int port, DateTimeOffset observed) => new()
        {
            Protocol = "TCP", LocalPort = port, RemoteAddress = "198.51.100.1",
            RemotePort = 443, OwningPid = Cmd, Source = "ETW", ObservedAtUtc = observed
        };
        _watcher.Started(Cmd, 0, "cmd.exe", "cmd.exe /c first", t);
        engine.OnConnectionObserved(Cmd, Connection(50220, t.AddMilliseconds(-100)));
        _watcher.Stopped(Cmd, t.AddSeconds(1));
        engine.OnConnectionObserved(Cmd, Connection(50221, t.AddMilliseconds(1100)));
        _watcher.Started(Cmd, 0, "cmd.exe", "cmd.exe /c second", t.AddMilliseconds(1200));
        engine.OnConnectionObserved(Cmd, Connection(50222, t.AddMilliseconds(1150)));

        Assert.Equal(new[] { 50220, 50221 }, captured[0].NetworkConnections.Select(c => c.LocalPort));
        Assert.Empty(captured[1].NetworkConnections);
    }

    [Fact]
    public void FinalRecordWaitsForTheInvestigationAndIncludesIt()
    {
        using var engine = NewEngine(investigate: true);
        CmdEvent? captured = null;
        engine.EventCaptured += (_, ev) => captured = ev;
        var t = DateTimeOffset.UtcNow;

        LaunchChain(t);
        _watcher.Started(Cmd, Updater, "powershell.exe",
            "powershell.exe -c gwmi win32_process -Filter 'ProcessId=37868 or ProcessId=39508'", t.AddMilliseconds(1));
        _watcher.Stopped(Cmd, t.AddMilliseconds(9));

        Assert.True(Wait.Until(() => captured?.Investigation is not null), "investigation never completed");
        var logPath = engine.Store.CurrentLogPath;
        Assert.True(Wait.Until(() => ReadShared(logPath).Contains("CMD POPUP — FINAL RECORD")), "final record never written");

        var log = ReadShared(logPath);
        var final = log[log.IndexOf("CMD POPUP — FINAL RECORD", StringComparison.Ordinal)..];
        Assert.Contains("-- Investigation", final);
        Assert.Contains("-- Launch chain", final);
        Assert.Contains("updater.exe", final);                 // the launcher, by name
        Assert.Contains("-- Processes referenced by the command", final);
        Assert.Contains("37868", final);
        Assert.Contains("Read-only query", final);
        Assert.Contains("-- Risk assessment", final);
        Assert.Contains("does not mean the computer is clean", final);

        // Exactly one finalized block for the popup.
        Assert.Equal(1, CountOf(log, "CMD POPUP — FINAL RECORD"));

        // And the JSON-lines record round-trips the analysis.
        var reloaded = engine.Store.ReadToday().Single(e => e.Id == captured!.Id);
        Assert.NotNull(reloaded.Investigation?.Risk);
        Assert.Equal(captured!.Investigation!.Risk!.Level, reloaded.Investigation!.Risk!.Level);
    }

    [Fact]
    public void ReanalysisAddsAnUpdatedReportToTheLog()
    {
        using var engine = NewEngine(investigate: true);
        CmdEvent? captured = null;
        engine.EventCaptured += (_, ev) => captured = ev;
        var t = DateTimeOffset.UtcNow;

        LaunchChain(t);
        _watcher.Started(Cmd, Updater, "cmd.exe", "cmd.exe /c whoami", t.AddMilliseconds(1));
        _watcher.Stopped(Cmd, t.AddMilliseconds(9));
        Assert.True(Wait.Until(() => ReadShared(engine.Store.CurrentLogPath).Contains("FINAL RECORD")));

        Assert.True(engine.Reanalyze(captured!));
        Assert.True(Wait.Until(() => ReadShared(engine.Store.CurrentLogPath).Contains("UPDATED ANALYSIS")));
        Assert.Equal(2, captured!.Investigation!.Revision);
    }

    [Fact]
    public void CapturesLoadedWithoutAVerdictAreAnalysedInTheBackground()
    {
        var options = new CmdSpyOptions
        {
            LogDirectory = _dir.Path,
            VerifySignatures = false,
            CorrelateEventLogs = false,
            CorrelateScheduledTasks = false
        };
        using var investigator = new Investigator(new Monitoring.ProcessCache(), options);
        var done = new System.Collections.Concurrent.ConcurrentDictionary<Guid, Investigation>();
        investigator.Completed += (ev, inv) => done[ev.Id] = inv;
        investigator.Start();

        var t = DateTimeOffset.UtcNow.AddHours(-3);
        var old = new CmdEvent { ProcessId = 4242, ProcessName = "cmd.exe", CommandLine = "cmd /c whoami", TimestampUtc = t };
        var live = new CmdEvent { ProcessId = 4343, ProcessName = "powershell.exe", CommandLine = "powershell -enc ZQBjAGgAbwA=", TimestampUtc = DateTimeOffset.UtcNow };

        investigator.EnqueueBacklog(old);
        investigator.EnqueueBacklog(old);   // not queued twice
        investigator.Enqueue(live);

        Assert.True(Wait.Until(() => done.ContainsKey(old.Id) && done.ContainsKey(live.Id)), "backlog item was never analysed");
        Assert.NotNull(done[old.Id].Risk);
        Assert.Equal(0, investigator.Pending);
    }

    private static string ReadShared(string path)
    {
        if (!File.Exists(path)) return "";
        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        using var reader = new StreamReader(fs);
        return reader.ReadToEnd();
    }

    private static int CountOf(string text, string needle)
    {
        int count = 0, at = 0;
        while ((at = text.IndexOf(needle, at, StringComparison.Ordinal)) >= 0) { count++; at += needle.Length; }
        return count;
    }
}
