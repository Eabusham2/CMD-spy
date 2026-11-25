using System;
using System.IO;
using System.Linq;
using CmdSpy.Core.Logging;
using CmdSpy.Core.Models;
using Xunit;

namespace CmdSpy.Core.Tests;

/// <summary>
/// The log files are the product, so these cover the round trip: what we write
/// on capture, what we write as a popup gains detail, and what a reader gets
/// back. The key guarantee is that detail captured *after* the initial write
/// (children, network endpoints, exit) survives a reload.
/// </summary>
public class EventStoreTests : IDisposable
{
    private readonly string _dir;

    public EventStoreTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "cmdspy-tests-" + Guid.NewGuid().ToString("N"));
    }

    public void Dispose()
    {
        try { if (Directory.Exists(_dir)) Directory.Delete(_dir, recursive: true); } catch { }
    }

    private static CmdEvent NewEvent(int pid = 1234, long seq = 1)
    {
        var now = DateTimeOffset.UtcNow;
        return new CmdEvent
        {
            SequenceNumber = seq,
            TimestampUtc = now,
            TimestampLocal = now.ToLocalTime(),
            SystemBootTimeLocal = now.ToLocalTime() - TimeSpan.FromHours(5),
            TimeSinceBoot = TimeSpan.FromHours(5),
            SystemUptimeSeconds = 18000,
            ProcessId = pid,
            ProcessName = "cmd.exe",
            ImagePath = @"C:\Windows\System32\cmd.exe",
            CommandLine = @"cmd.exe /c ""echo hello""",
            ParentProcessId = 4321,
            ParentProcessName = "explorer.exe",
            CaptureSource = "ETW"
        };
    }

    [Fact]
    public void Append_WritesBothJsonlAndHumanReadableLog()
    {
        var store = new EventStore(_dir);
        store.Append(NewEvent());

        Assert.True(File.Exists(store.CurrentJsonlPath));
        Assert.True(File.Exists(store.CurrentLogPath));

        var log = File.ReadAllText(store.CurrentLogPath);
        Assert.Contains("CMD POPUP CAPTURED", log);
        Assert.Contains("cmd.exe /c", log);
        Assert.Contains("explorer.exe", log);   // the cause
    }

    [Fact]
    public void ReadToday_RoundTripsCoreFields()
    {
        var store = new EventStore(_dir);
        var ev = NewEvent();
        store.Append(ev);

        var read = store.ReadToday().Single();

        Assert.Equal(ev.Id, read.Id);
        Assert.Equal(ev.ProcessId, read.ProcessId);
        Assert.Equal(ev.ProcessName, read.ProcessName);
        Assert.Equal(ev.CommandLine, read.CommandLine);
        Assert.Equal(ev.ParentProcessName, read.ParentProcessName);
        Assert.Equal(ev.CaptureSource, read.CaptureSource);
    }

    [Fact]
    public void AppendUpdate_PersistsChildrenAndNetwork_NotJustCounts()
    {
        // This is the behavior the review flagged: detail gained after the
        // initial Append must not be lost when the log is replayed.
        var store = new EventStore(_dir);
        var ev = NewEvent();
        store.Append(ev);

        ev.ChildProcesses.Add(new ProcessInfo
        {
            ProcessId = 999,
            ProcessName = "whoami.exe",
            CommandLine = "whoami"
        });
        ev.NetworkConnections.Add(new NetworkConnectionInfo
        {
            Protocol = "TCP",
            LocalAddress = "10.0.0.5",
            LocalPort = 51000,
            RemoteAddress = "93.184.216.34",
            RemotePort = 443,
            State = "ESTABLISHED",
            OwningPid = 1234
        });
        ev.OmittedNetworkConnectionCount = 3;
        store.AppendUpdate(ev, "child-process");

        var read = store.ReadToday().Single();

        Assert.Single(read.ChildProcesses);
        Assert.Equal("whoami.exe", read.ChildProcesses[0].ProcessName);
        Assert.Single(read.NetworkConnections);
        Assert.Equal(443, read.NetworkConnections[0].RemotePort);
        Assert.Equal("ESTABLISHED", read.NetworkConnections[0].State);
        Assert.Equal(3, read.OmittedNetworkConnectionCount);
    }

    [Fact]
    public void AppendUpdate_OnExit_RecordsLifetimeAndWritesFinalLogBlock()
    {
        var store = new EventStore(_dir);
        var ev = NewEvent();
        store.Append(ev);

        ev.ExitedAtUtc = ev.TimestampUtc.AddMilliseconds(47);
        ev.LifetimeMilliseconds = 47;
        ev.ExitCode = 0;
        store.AppendUpdate(ev, "exit");

        var read = store.ReadToday().Single();
        Assert.Equal(47, read.LifetimeMilliseconds);
        Assert.Equal(0, read.ExitCode);
        Assert.NotNull(read.ExitedAtUtc);

        var log = File.ReadAllText(store.CurrentLogPath);
        Assert.Contains("FINAL RECORD", log);
        Assert.Contains("47 ms", log);
    }

    [Fact]
    public void ReadToday_LastSnapshotWinsPerEventAndOrderIsPreserved()
    {
        var store = new EventStore(_dir);
        var first = NewEvent(pid: 100, seq: 1);
        var second = NewEvent(pid: 200, seq: 2);

        store.Append(first);
        store.Append(second);

        // The first event later exits — its newer snapshot must supersede the
        // original line without disturbing capture order.
        first.LifetimeMilliseconds = 12;
        first.ExitCode = 1;
        store.AppendUpdate(first, "exit");

        var read = store.ReadToday().ToList();

        Assert.Equal(2, read.Count);
        Assert.Equal(100, read[0].ProcessId);
        Assert.Equal(200, read[1].ProcessId);
        Assert.Equal(12, read[0].LifetimeMilliseconds);
    }

    [Fact]
    public void ReadToday_IgnoresCorruptLines()
    {
        var store = new EventStore(_dir);
        store.Append(NewEvent());
        File.AppendAllText(store.CurrentJsonlPath, "{ this is not json" + Environment.NewLine);
        File.AppendAllText(store.CurrentJsonlPath, Environment.NewLine);

        Assert.Single(store.ReadToday());
    }

    [Fact]
    public void ReadToday_ReturnsEmptyWhenNothingLogged()
    {
        var store = new EventStore(_dir);
        Assert.Empty(store.ReadToday());
    }
}
