using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using CmdSpy.Core.Formatting;
using CmdSpy.Core.Logging;
using CmdSpy.Core.Models;
using CmdSpy.Core.Monitoring;
using Xunit;

namespace CmdSpy.Core.Tests;

/// <summary>
/// Following the boot service's log from the GUI, the investigation sections
/// of the text report, scheduled-task matching, and importing past launches
/// from the Windows event logs.
/// </summary>
public class LogAndHistoryTests : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private static CmdEvent NewEvent(int pid = 1234, string command = "cmd.exe /c echo hi")
    {
        var now = DateTimeOffset.UtcNow;
        return new CmdEvent
        {
            SequenceNumber = 1,
            TimestampUtc = now,
            TimestampLocal = now.ToLocalTime(),
            SystemBootTimeLocal = now.ToLocalTime() - TimeSpan.FromHours(1),
            TimeSinceBoot = TimeSpan.FromHours(1),
            ProcessId = pid,
            ProcessName = "cmd.exe",
            CommandLine = command,
            ParentProcessId = 4321,
            ParentProcessName = "explorer.exe",
            CaptureSource = "ETW"
        };
    }

    // ------------------------------------------------------------ follower --

    [Fact]
    public void Follower_ReturnsExistingThenRaisesNewAndUpdatedEvents()
    {
        var store = new EventStore(_dir.Path);
        var first = NewEvent(1);
        store.Append(first);

        using var follower = new LogFollower(_dir.Path, TimeSpan.FromHours(1));   // polled by hand
        var existing = follower.Start();
        var shown = Assert.Single(existing);
        Assert.Equal(first.Id, shown.Id);

        var captured = new List<CmdEvent>();
        var updated = new List<CmdEvent>();
        follower.EventCaptured += (_, e) => captured.Add(e);
        follower.EventUpdated += (_, e) => updated.Add(e);

        var second = NewEvent(2);
        store.Append(second);
        first.ExitedAtUtc = DateTimeOffset.UtcNow;
        first.LifetimeMilliseconds = 12;
        store.AppendUpdate(first, "exit");
        follower.Poll();

        Assert.Equal(second.Id, Assert.Single(captured).Id);
        var update = Assert.Single(updated);
        Assert.Same(shown, update);                 // the GUI row's object is updated in place
        Assert.Equal(12, shown.LifetimeMilliseconds);
    }

    [Fact]
    public void Follower_WaitsForAHalfWrittenLine()
    {
        Directory.CreateDirectory(_dir.Path);
        using var follower = new LogFollower(_dir.Path, TimeSpan.FromHours(1));
        follower.Start();
        var captured = new List<CmdEvent>();
        follower.EventCaptured += (_, e) => captured.Add(e);

        var json = System.Text.Json.JsonSerializer.Serialize(NewEvent(7));
        var path = follower.PathFor(DateTime.Now);
        File.AppendAllText(path, json[..(json.Length / 2)], Encoding.UTF8);
        follower.Poll();
        Assert.Empty(captured);

        File.AppendAllText(path, json[(json.Length / 2)..] + Environment.NewLine, Encoding.UTF8);
        follower.Poll();
        Assert.Equal(7, Assert.Single(captured).ProcessId);
    }

    [Fact]
    public void Follower_SwitchesToTheNewFileAtMidnight()
    {
        Directory.CreateDirectory(_dir.Path);
        var day = new DateTime(2026, 11, 21, 23, 59, 0);
        using var follower = new LogFollower(_dir.Path, TimeSpan.FromHours(1), () => day);
        follower.Start();
        var captured = new List<CmdEvent>();
        follower.EventCaptured += (_, e) => captured.Add(e);

        string Line(CmdEvent e) => System.Text.Json.JsonSerializer.Serialize(e) + Environment.NewLine;
        File.AppendAllText(follower.PathFor(day), Line(NewEvent(1)));
        day = day.AddMinutes(2);
        File.AppendAllText(follower.PathFor(day), Line(NewEvent(2)));
        follower.Poll();

        Assert.Equal(new[] { 1, 2 }, captured.Select(e => e.ProcessId));
    }

    [Fact]
    public void Follower_IncrementallyReadsChunksAndSkipsOversizedLines()
    {
        Directory.CreateDirectory(_dir.Path);
        var day = DateTime.Now;
        using var follower = new LogFollower(_dir.Path, TimeSpan.FromHours(1), () => day,
            readBufferBytes: 32, maxBytesPerPoll: 64, maxLineBytes: 2_048, maxKnownEvents: 10);
        var valid = System.Text.Json.JsonSerializer.Serialize(NewEvent(9));
        File.WriteAllText(follower.PathFor(day), new string('x', 4_096) + Environment.NewLine +
            valid + Environment.NewLine, Encoding.UTF8);

        var existing = follower.Start();
        var captured = new List<CmdEvent>();
        follower.EventCaptured += (_, e) => captured.Add(e);
        for (int i = 0; i < 100 && captured.Count == 0; i++) follower.Poll();

        Assert.Empty(existing);
        Assert.Equal(9, Assert.Single(captured).ProcessId);
    }

    [Fact]
    public void Store_CanBeReadWhileAnotherHandleIsWriting()
    {
        var store = new EventStore(_dir.Path);
        store.Append(NewEvent());
        using var writer = new FileStream(store.CurrentJsonlPath, FileMode.Append, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete);

        store.Append(NewEvent(2));
        Assert.Equal(2, store.ReadToday().Count());
    }

    // ----------------------------------------------------------- formatter --

    [Fact]
    public void Formatter_ShowsTheInvestigationSections()
    {
        var ev = NewEvent(command: "powershell.exe -c gwmi win32_process -Filter 'ProcessId=37868'");
        ev.Investigation = new Investigation
        {
            Revision = 1,
            Ancestry = { new ProcessInfo { ProcessId = 4321, ProcessName = "explorer.exe", Depth = 1 } },
            AncestryComplete = true,
            ReferencedProcesses = { new ReferencedProcess { ProcessId = 37868, ProcessName = "asus_framework.exe", Status = "running", Context = "ProcessId=37868" } },
            Explanation = new CommandExplanation { Interpreter = "PowerShell execution", Summary = "Reads process information.", IsReadOnly = true },
            Risk = new RiskAssessment { Level = RiskLevel.Unknown, Summary = "Not enough evidence.", Disclaimer = "Not a guarantee." }
        };

        var text = EventTextFormatter.Format(ev);

        Assert.Contains("PowerShell execution detected — Read-only query", text);
        Assert.Contains("Launcher          : Not yet identified — requires parent-process evidence.", text);
        Assert.Contains("-- Launch chain", text);
        Assert.Contains("asus_framework.exe", text);
        Assert.Contains("-- Command analysis", text);
        Assert.Contains("-- Suspicious indicators", text);
        Assert.Contains("-- Authenticity", text);
        Assert.Contains("-- Windows event history", text);
        Assert.Contains("Verdict           : Unknown", text);
        // The sections that were already there are unchanged.
        Assert.Contains("-- Cause (parent process)", text);
        Assert.Contains("-- Actions (child processes)", text);
    }

    [Fact]
    public void Formatter_SaysWhenAnalysisIsStillRunning()
    {
        Assert.Contains("analysis running in the background", EventTextFormatter.Format(NewEvent()));
        Assert.Contains("not analysed", EventTextFormatter.Format(NewEvent(), finalized: true));
    }

    // ----------------------------------------------------- scheduled tasks --

    private const string TaskXml = """
        <?xml version="1.0" encoding="UTF-16"?>
        <Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
          <RegistrationInfo>
            <Author>ASUSTeK COMPUTER INC.</Author>
            <Description>Keeps ASUS software up to date.</Description>
          </RegistrationInfo>
          <Triggers>
            <LogonTrigger><Enabled>true</Enabled></LogonTrigger>
            <TimeTrigger>
              <Repetition><Interval>PT1H</Interval></Repetition>
              <StartBoundary>2026-01-01T09:00:00</StartBoundary>
              <Enabled>true</Enabled>
            </TimeTrigger>
          </Triggers>
          <Principals><Principal id="Author"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
          <Settings><Enabled>true</Enabled><Hidden>true</Hidden></Settings>
          <Actions Context="Author">
            <Exec>
              <Command>C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Command>
              <Arguments>-c gwmi win32_process -Filter 'Name="asus_framework.exe"'</Arguments>
            </Exec>
          </Actions>
        </Task>
        """;

    [Fact]
    public void ScheduledTask_DefinitionIsParsed()
    {
        var task = ScheduledTaskCatalog.Parse(@"\ASUS\Update Checker", TaskXml);

        Assert.NotNull(task);
        Assert.Equal(@"\ASUS\Update Checker", task!.Path);
        Assert.Equal("ASUSTeK COMPUTER INC.", task.Author);
        Assert.True(task.Hidden);
        var action = Assert.Single(task.Actions);
        Assert.EndsWith("powershell.exe", action.Command);
        Assert.Equal(2, task.Triggers.Count);
        Assert.Contains("At log on of any user", task.Triggers);
        Assert.Contains(task.Triggers, t => t.Contains("repeating every 1 h"));
    }

    [Fact]
    public void ScheduledTask_MatchesTheProcessItLaunches()
    {
        var task = ScheduledTaskCatalog.Parse(@"\ASUS\Update Checker", TaskXml)!;
        var other = ScheduledTaskCatalog.Parse(@"\Other\Thing", TaskXml.Replace("powershell.exe", "other.exe"))!;

        var matches = ScheduledTaskCatalog.Match(new[] { task, other },
            @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "powershell.exe -c gwmi win32_process -Filter 'Name=\"asus_framework.exe\"'");

        var best = Assert.Single(matches);
        Assert.Equal(@"\ASUS\Update Checker", best.Task.Path);
        Assert.True(best.Score >= 90);
    }

    // ------------------------------------------------------- history import --

    [Fact]
    public void History_ImportedLaunchKeepsItsCauseAndTimeSinceBoot()
    {
        var boot = DateTimeOffset.UtcNow - TimeSpan.FromHours(3);
        var launch = new HistoricalEvent
        {
            TimeUtc = boot + TimeSpan.FromMinutes(2),
            Source = "Security 4688",
            EventId = 4688,
            ProcessId = 37900,
            ParentProcessId = 37868,
            Image = @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            ParentImage = @"C:\Program Files\ASUS\asus_framework.exe",
            CommandLine = "powershell.exe -c gwmi win32_process"
        };

        var ev = HistoryImporter.ToEvent(launch, boot);

        Assert.Equal("powershell.exe", ev.ProcessName);
        Assert.Equal(37900, ev.ProcessId);
        Assert.Equal("asus_framework.exe", ev.ParentProcessName);
        Assert.Equal(@"C:\Program Files\ASUS\asus_framework.exe", ev.ParentImagePath);
        Assert.Equal(TimeSpan.FromMinutes(2), ev.TimeSinceBoot);
        Assert.StartsWith("Security 4688", ev.CaptureSource);
        Assert.Contains("Imported from the Windows event log", ev.Notes);
    }
}
