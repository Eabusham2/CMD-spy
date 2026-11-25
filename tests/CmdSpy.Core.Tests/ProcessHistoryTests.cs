using System;
using System.Linq;
using CmdSpy.Core.Monitoring;
using Xunit;

namespace CmdSpy.Core.Tests;

/// <summary>
/// The process history is what keeps a parent's identity after it exits and
/// lets CMD-spy walk parent → grandparent → original launcher without being
/// fooled by Windows recycling process IDs.
/// </summary>
public class ProcessHistoryTests
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 21, 9, 0, 0, TimeSpan.Zero);

    private static ProcessStartedEventArgs Start(int pid, int ppid, string name, DateTimeOffset at, string? cmd = null, string? image = null) => new()
    {
        ProcessId = pid,
        ParentProcessId = ppid,
        ProcessName = name,
        CommandLine = cmd,
        ImagePath = image,
        TimestampUtc = at,
        Source = "ETW"
    };

    private static ProcessStoppedEventArgs Stop(int pid, DateTimeOffset at) => new() { ProcessId = pid, TimestampUtc = at, ExitCode = 0 };

    [Fact]
    public void ParentDetailsSurviveItsExit()
    {
        var cache = new ProcessCache();
        cache.RecordStart(Start(200, 100, "updater.exe", T0, "updater.exe --run", @"C:\Program Files\Vendor\updater.exe"));
        cache.RecordStop(Stop(200, T0.AddMilliseconds(5)));

        // The child's start (just before the parent exited) is processed afterwards.
        var parent = cache.TryGet(200, T0.AddMilliseconds(3), requireAlive: true);

        Assert.NotNull(parent);
        Assert.Equal("updater.exe", parent!.Name);
        Assert.Equal(@"C:\Program Files\Vendor\updater.exe", parent.ImagePath);
        Assert.Equal("updater.exe --run", parent.CommandLine);
        Assert.NotNull(parent.ExitTimeUtc);
    }

    [Fact]
    public void LiveStartReplacesTheStartupSnapshotCopyOfTheSameProcess()
    {
        // The start-up snapshot listed the popup before its live start event
        // arrived, and the two clocks differ by a few milliseconds.
        var cache = new ProcessCache();
        cache.Seed(new[]
        {
            new ProcessRecord
            {
                ProcessId = 900, ParentProcessId = 100, Name = "cmd.exe",
                ImagePath = @"C:\Windows\System32\cmd.exe", CommandLine = "cmd.exe /c echo hi",
                StartTimeUtc = T0.AddMilliseconds(4), Source = "snapshot"
            }
        });
        cache.RecordStart(Start(900, 100, "cmd.exe", T0, "cmd.exe /c echo hi"));

        Assert.Equal(1, cache.Count);
        Assert.True(cache.IsIncarnationAliveAt(900, T0, T0.AddMilliseconds(10)));
        Assert.NotNull(cache.TryGetUnambiguousIncarnation(900, T0));

        var stopped = cache.RecordStopAndGet(Stop(900, T0.AddMilliseconds(20)));
        Assert.Equal(T0, stopped!.StartTimeUtc);
        Assert.Equal(@"C:\Windows\System32\cmd.exe", stopped.ImagePath);   // kept from the snapshot
        Assert.Empty(cache.FindRunningByName("cmd.exe"));                    // no leftover "running" copy
    }

    [Fact]
    public void RecycledPidResolvesToTheIncarnationAliveAtTheTime()
    {
        var cache = new ProcessCache();
        cache.RecordStart(Start(300, 100, "first.exe", T0));
        cache.RecordStop(Stop(300, T0.AddSeconds(10)));
        cache.RecordStart(Start(300, 100, "second.exe", T0.AddMinutes(5)));

        Assert.Equal("first.exe", cache.TryGet(300, T0.AddSeconds(5))!.Name);
        Assert.Equal("second.exe", cache.TryGet(300, T0.AddMinutes(6))!.Name);
        Assert.Equal("second.exe", cache.TryGet(300)!.Name);

        // In between, the PID belonged to nothing alive.
        Assert.Null(cache.TryGet(300, T0.AddMinutes(1), requireAlive: true));
    }

    [Fact]
    public void DelayedStopDoesNotExitANewerReusedPid()
    {
        var cache = new ProcessCache();
        var first = cache.RecordStart(Start(300, 100, "first.exe", T0));
        var second = cache.RecordStart(Start(300, 100, "second.exe", T0.AddSeconds(1)));

        // The first process's stop is delivered after the second start, but its
        // source timestamp still identifies the older incarnation.
        var stopped = cache.RecordStopAndGet(Stop(300, T0.AddMilliseconds(500)));

        Assert.Equal(first.StartTimeUtc, stopped!.StartTimeUtc);
        Assert.Equal(T0.AddMilliseconds(500), first.ExitTimeUtc);
        Assert.Null(second.ExitTimeUtc);
        Assert.True(cache.IsIncarnationAliveAt(300, second.StartTimeUtc, T0.AddSeconds(2)));
    }

    [Fact]
    public void AncestryWalksToTheOriginalLauncher()
    {
        var cache = new ProcessCache();
        cache.RecordStart(Start(4, 0, "System", T0.AddHours(-1)));
        cache.RecordStart(Start(600, 4, "services.exe", T0.AddHours(-1)));
        cache.RecordStart(Start(900, 600, "svchost.exe", T0.AddMinutes(-30), @"C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule"));
        cache.RecordStart(Start(1500, 900, "launcher.exe", T0, "launcher.exe /silent"));
        cache.RecordStart(Start(1600, 1500, "cmd.exe", T0.AddMilliseconds(10), "cmd /c ping 127.0.0.1"));

        var ancestry = cache.GetAncestry(1600, T0.AddMilliseconds(20));

        Assert.Equal(new[] { "cmd.exe", "launcher.exe", "svchost.exe", "services.exe", "System" }, ancestry.Chain.Select(r => r.Name));
        Assert.True(ancestry.Complete);
    }

    [Fact]
    public void AncestryStopsHonestlyAtAGap()
    {
        var cache = new ProcessCache();
        cache.RecordStart(Start(1500, 1400, "launcher.exe", T0));   // its parent 1400 was never seen

        var ancestry = cache.GetAncestry(1500, T0.AddSeconds(1));

        Assert.Single(ancestry.Chain);
        Assert.False(ancestry.Complete);
        Assert.Equal(1400, ancestry.MissingProcessId);
        Assert.Contains("1400", ancestry.Note);
    }

    [Fact]
    public void AncestryRejectsAParentPidThatWasRecycledAfterTheChildStarted()
    {
        var cache = new ProcessCache();
        // The real parent (PID 700) exited long ago and was never recorded; a
        // newer, unrelated process now has PID 700.
        cache.RecordStart(Start(800, 700, "child.exe", T0));
        cache.RecordStart(Start(700, 4, "unrelated.exe", T0.AddMinutes(10)));

        var ancestry = cache.GetAncestry(700, T0);

        Assert.Empty(ancestry.Chain);
        Assert.Equal(700, ancestry.MissingProcessId);
    }

    [Fact]
    public void ExitedProcessesArePrunedAfterTheRetentionWindow()
    {
        var cache = new ProcessCache(retainExited: TimeSpan.FromMinutes(30));
        cache.RecordStart(Start(10, 1, "old.exe", T0));
        cache.RecordStop(Stop(10, T0.AddSeconds(1)));
        cache.RecordStart(Start(11, 1, "alive.exe", T0));

        cache.Prune(T0.AddHours(2));

        Assert.Null(cache.TryGet(10));
        Assert.NotNull(cache.TryGet(11));
    }

    [Fact]
    public void FindRunningByNameMapsNamesToPids()
    {
        var cache = new ProcessCache();
        cache.RecordStart(Start(37868, 1, "asus_framework.exe", T0));
        cache.RecordStart(Start(39508, 1, "asus_framework.exe", T0));
        cache.RecordStart(Start(5, 1, "other.exe", T0));

        var matches = cache.FindRunningByName("asus_framework");

        Assert.Equal(new[] { 37868, 39508 }, matches.Select(m => m.ProcessId));
    }
}
