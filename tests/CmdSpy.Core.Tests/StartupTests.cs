using System;
using System.Linq;
using System.Threading;
using System.Xml.Linq;
using CmdSpy.Core.Monitoring;
using Xunit;

namespace CmdSpy.Core.Tests;

/// <summary>
/// Starting with Windows: the logon task must run CMD-spy elevated, at high
/// priority, with no delay and never twice; and only one copy may run.
/// </summary>
public class StartupTests
{
    private const string Exe = @"C:\Program Files\CmdSpy\CmdSpy.exe";

    [Fact]
    public void LogonTask_RunsElevatedAtHighPriorityWithoutDuplicates()
    {
        var xml = StartupTaskDefinition.BuildXml(Exe, @"PC\alice");
        var doc = XDocument.Parse(xml);
        XNamespace ns = "http://schemas.microsoft.com/windows/2004/02/mit/task";
        string? Value(params string[] path) =>
            path.Aggregate((XElement?)doc.Root, (node, name) => node?.Element(ns + name))?.Value;

        Assert.Equal("HighestAvailable", Value("Principals", "Principal", "RunLevel"));
        Assert.Equal("InteractiveToken", Value("Principals", "Principal", "LogonType"));
        Assert.Equal("1", Value("Settings", "Priority"));                 // HIGH_PRIORITY_CLASS
        Assert.Equal("IgnoreNew", Value("Settings", "MultipleInstancesPolicy"));
        Assert.Equal("PT0S", Value("Settings", "ExecutionTimeLimit"));     // never stopped for running long
        Assert.Equal("false", Value("Settings", "DisallowStartIfOnBatteries"));
        Assert.NotNull(doc.Root!.Element(ns + "Settings")!.Element(ns + "RestartOnFailure"));
        Assert.Null(doc.Root.Element(ns + "Triggers")!.Element(ns + "LogonTrigger")!.Element(ns + "Delay"));   // no delay
    }

    [Fact]
    public void LogonTask_IsReadBackLikeAnyRegisteredTask()
    {
        var task = ScheduledTaskCatalog.Parse(StartupTaskDefinition.TaskName, StartupTaskDefinition.BuildXml(Exe, @"PC\alice"));

        Assert.NotNull(task);
        Assert.Equal("HighestAvailable", task!.RunLevel);
        var action = Assert.Single(task.Actions);
        Assert.Equal(Exe, action.Command);
        Assert.Equal(StartupTaskDefinition.Arguments, action.Arguments);
        Assert.Contains(@"At log on of PC\alice", task.Triggers);
        Assert.Contains(task.Triggers, t => t.Contains("SessionUnlock"));
    }

    [Fact]
    public void LogonTask_EscapesUnusualNamesAndPaths()
    {
        var xml = StartupTaskDefinition.BuildXml(@"C:\Tools & Co\CmdSpy.exe", @"PC\o'brien<x>");
        var task = ScheduledTaskCatalog.Parse(StartupTaskDefinition.TaskName, xml);
        Assert.Equal(@"C:\Tools & Co\CmdSpy.exe", Assert.Single(task!.Actions).Command);
        Assert.Equal(@"PC\o'brien<x>", task.UserId);
    }

    [WindowsFact]
    public void SingleInstance_SecondCopyBringsTheFirstForward()
    {
        var name = "CmdSpy.Test." + Guid.NewGuid().ToString("N");
        using var first = new SingleInstance(name);
        Assert.True(first.IsFirst);

        using var activated = new ManualResetEventSlim();
        first.OnActivationRequested(() => activated.Set());

        using (var second = new SingleInstance(name))
        {
            Assert.False(second.IsFirst);
            Assert.True(second.ActivateFirst());
        }
        Assert.True(activated.Wait(TimeSpan.FromSeconds(5)), "the running copy was not asked to show itself");
    }

    [WindowsFact]
    public void SingleInstance_FreedWhenTheFirstCopyExits()
    {
        var name = "CmdSpy.Test." + Guid.NewGuid().ToString("N");
        using (var first = new SingleInstance(name))
            Assert.True(first.IsFirst);

        using var next = new SingleInstance(name);
        Assert.True(next.IsFirst);
    }

    [WindowsFact]
    public void SingleInstance_GlobalNameSquattingCannotSuppressStartup()
    {
        var name = "CmdSpy.Test." + Guid.NewGuid().ToString("N");
        using var squatted = new Mutex(initiallyOwned: false, @"Global\" + name, out bool createdNew);
        Assert.True(createdNew);

        using var instance = new SingleInstance(name);
        Assert.True(instance.IsFirst);
    }
}
