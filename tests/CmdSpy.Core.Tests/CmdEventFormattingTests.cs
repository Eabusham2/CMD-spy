using System;
using CmdSpy.Core.Formatting;
using CmdSpy.Core.Models;
using Xunit;

namespace CmdSpy.Core.Tests;

/// <summary>
/// Covers the derived display values shown in the GUI grid and the text block
/// written to the .log file — including the "millisecond popup" case that is the
/// whole point of the tool.
/// </summary>
public class CmdEventFormattingTests
{
    [Fact]
    public void LifetimeDisplay_ShowsMillisecondsForVeryShortPopups()
    {
        var ev = new CmdEvent { LifetimeMilliseconds = 1 };
        Assert.Equal("1 ms", ev.LifetimeDisplay);
    }

    [Fact]
    public void LifetimeDisplay_SwitchesToSecondsForLongerPopups()
    {
        var ev = new CmdEvent { LifetimeMilliseconds = 2500 };
        Assert.Equal("2.5 s", ev.LifetimeDisplay);
    }

    [Fact]
    public void LifetimeDisplay_ReportsStillAliveWhenExitNotObserved()
    {
        Assert.Equal("(alive)", new CmdEvent().LifetimeDisplay);
    }

    [Fact]
    public void CauseDisplay_FallsBackWhenParentUnknown()
    {
        Assert.Equal("(unknown)", new CmdEvent { ParentProcessId = 0 }.CauseDisplay);

        var known = new CmdEvent { ParentProcessId = 42, ParentProcessName = "explorer.exe" };
        Assert.Equal("[42] explorer.exe", known.CauseDisplay);
    }

    [Fact]
    public void SinceBootDisplay_FormatsHoursAndDays()
    {
        var hours = new CmdEvent { TimeSinceBoot = new TimeSpan(0, 5, 48, 9, 282) };
        Assert.Equal("05:48:09.282", hours.SinceBootDisplay);

        var days = new CmdEvent { TimeSinceBoot = new TimeSpan(2, 3, 4, 5) };
        Assert.Equal("2d 03:04:05", days.SinceBootDisplay);
    }

    [Fact]
    public void CommandLineShort_CollapsesNewlinesAndTruncates()
    {
        var ev = new CmdEvent { CommandLine = "cmd /c echo a\r\necho b" };
        Assert.DoesNotContain("\n", ev.CommandLineShort);
        Assert.DoesNotContain("\r", ev.CommandLineShort);

        var longEv = new CmdEvent { CommandLine = new string('x', 500) };
        Assert.EndsWith("...", longEv.CommandLineShort);
        Assert.True(longEv.CommandLineShort.Length <= 160);
    }

    [Fact]
    public void CommandLineShort_FallsBackToImagePathThenName()
    {
        var noCmd = new CmdEvent { ProcessName = "cmd.exe", ImagePath = @"C:\cmd.exe" };
        Assert.Equal(@"C:\cmd.exe", noCmd.CommandLineShort);

        var nameOnly = new CmdEvent { ProcessName = "cmd.exe" };
        Assert.Equal("cmd.exe", nameOnly.CommandLineShort);
    }

    [Fact]
    public void Format_IncludesEverySectionTheToolPromises()
    {
        var now = DateTimeOffset.UtcNow;
        var ev = new CmdEvent
        {
            SequenceNumber = 7,
            TimestampUtc = now,
            TimestampLocal = now.ToLocalTime(),
            SystemBootTimeLocal = now.ToLocalTime() - TimeSpan.FromHours(1),
            TimeSinceBoot = TimeSpan.FromHours(1),
            ProcessId = 900,
            ProcessName = "cmd.exe",
            CommandLine = "cmd.exe /c whoami",
            UserName = @"HOST\alice",
            ParentProcessId = 500,
            ParentProcessName = "powershell.exe",
            CaptureSource = "ETW"
        };
        ev.ChildProcesses.Add(new ProcessInfo { ProcessId = 901, ProcessName = "whoami.exe" });
        ev.NetworkConnections.Add(new NetworkConnectionInfo
        {
            Protocol = "TCP",
            LocalAddress = "127.0.0.1",
            LocalPort = 1,
            RemoteAddress = "10.0.0.1",
            RemotePort = 80,
            State = "ESTABLISHED"
        });

        var text = EventTextFormatter.Format(ev);

        Assert.Contains("-- Time -", text);
        Assert.Contains("-- Task info -", text);
        Assert.Contains("-- Command line -", text);
        Assert.Contains("-- Cause (parent process) -", text);
        Assert.Contains("-- Actions (child processes) -", text);
        Assert.Contains("-- Networking -", text);
        Assert.Contains(@"HOST\alice", text);
        Assert.Contains("whoami.exe", text);
        Assert.Contains("10.0.0.1:80", text);
    }

    [Fact]
    public void Format_MarksFinalizedRecordsDistinctly()
    {
        var ev = new CmdEvent { ProcessName = "cmd.exe", LifetimeMilliseconds = 5, ExitCode = 0 };

        Assert.Contains("CMD POPUP CAPTURED", EventTextFormatter.Format(ev));
        Assert.Contains("FINAL RECORD", EventTextFormatter.Format(ev, finalized: true));
    }

    [Fact]
    public void Format_HandlesEmptyChildAndNetworkLists()
    {
        var text = EventTextFormatter.Format(new CmdEvent { ProcessName = "cmd.exe" });

        Assert.Contains("(none observed)", text);
        Assert.Contains("(no connections captured)", text);
        Assert.Contains("(not available)", text);   // missing command line
    }

    [Fact]
    public void NetworkConnectionInfo_ToString_OmitsRemoteForListeners()
    {
        var listener = new NetworkConnectionInfo
        {
            Protocol = "UDP",
            LocalAddress = "0.0.0.0",
            LocalPort = 53
        };
        Assert.Equal("UDP 0.0.0.0:53", listener.ToString());
    }
}
