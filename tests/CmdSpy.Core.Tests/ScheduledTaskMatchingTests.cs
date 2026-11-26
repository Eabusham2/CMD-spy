using System.Xml.Linq;
using CmdSpy.Core.Analysis;
using CmdSpy.Core.Models;
using CmdSpy.Core.Monitoring;
using Xunit;

namespace CmdSpy.Core.Tests;

public sealed class ScheduledTaskMatchingTests : IDisposable
{
    private const string Cmd = @"C:\Windows\System32\cmd.exe";
    private readonly TempDir _dir = new();
    public void Dispose() => _dir.Dispose();

    [Theory]
    [InlineData("/c echo", "/c echo bye")]
    [InlineData("/c echo hello", "/c echo hi")]
    public void UnequalArgumentSimilarityCannotIdentifyOneOfSeveralTasks(string first, string second)
    {
        var tasks = new[] { Task(@"\ShortAction", Cmd, first), Task(@"\OtherAction", Cmd, second) };
        var process = Process(Cmd, "cmd.exe /c echo hello & whoami");
        var matches = ScheduledTaskCatalog.Match(tasks, process.ImagePath, process.CommandLine);

        Assert.Equal(2, matches.Count);
        Assert.NotEqual(matches[0].Score, matches[1].Score);
        Assert.All(matches, match => Assert.True(match.Score < ScheduledTaskCatalog.ExactActionScore));
        Assert.Null(ScheduledTaskCorrelator.UniqueBestMatch(matches, 50));
        var result = Correlate(tasks, process);
        Assert.Equal("", result!.TaskPath);
        Assert.Contains("multiple registered tasks", result.Evidence);
    }

    [Fact]
    public void MatchingArgumentsOnADifferentExecutableCannotResolveCompetingTasks()
    {
        var tasks = new[]
        {
            Task(@"\RealTask", @"C:\Apps\real\runner.exe", "--job nightly --mode slow"),
            Task(@"\OtherTask", @"C:\Apps\other\runner.exe", "--job daily --mode fast")
        };
        var process = Process(@"C:\Apps\real\runner.exe", "runner.exe --job daily --mode fast");
        var matches = ScheduledTaskCatalog.Match(tasks, process.ImagePath, process.CommandLine);

        Assert.Equal(new[] { 70, 50 }, matches.Select(match => match.Score));
        Assert.Null(ScheduledTaskCorrelator.UniqueBestMatch(matches, 50));
        Assert.Equal("", Correlate(tasks, process)!.TaskPath);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void UniqueWeakMatchRemainsAvailableWithoutClaimingExactAttribution(bool scheduler)
    {
        var tasks = new[] { Task(@"\ShortAction", Cmd, "/c echo") };
        var result = Correlate(tasks, Process(Cmd, "cmd.exe /c echo hello & whoami"), scheduler);

        Assert.Equal(@"\ShortAction", result!.TaskPath);
        Assert.Equal(TaskConfidence.Possible, result.Confidence);
        Assert.Contains("similar action", result.Evidence);
        Assert.DoesNotContain("exact", result.Evidence);
    }

    [Fact]
    public void CompleteActionOutranksDifferentArgumentsAndAcceptsQuotedWindowsPaths()
    {
        const string image = @"C:\Program Files\Vendor\runner.exe";
        var tasks = new[]
        {
            Task(@"\Exact", @"""c:/program files/vendor/RUNNER.EXE""", "--label \"daily job\" --flag"),
            Task(@"\Other", image, "--label \"nightly job\" --flag")
        };
        var process = Process(image, "\"" + image + "\" --label \"daily job\" --flag");
        var matches = ScheduledTaskCatalog.Match(tasks, image, process.CommandLine);

        Assert.Equal(ScheduledTaskCatalog.ExactActionScore, matches[0].Score);
        Assert.Equal(@"\Exact", ScheduledTaskCorrelator.UniqueBestMatch(matches, 50)!.Value.Task.Path);
        var result = Correlate(tasks, process);
        Assert.Equal(@"\Exact", result!.TaskPath);
        Assert.Equal(TaskConfidence.Likely, result.Confidence);
        Assert.Contains("exact command", result.Evidence);
    }

    [Theory]
    [InlineData("--label \"daily\"", "--label daily", true)]
    [InlineData("--label \"daily job\"", "--label daily job", false)]
    [InlineData("--label \"a  b\"", "--label \"a b\"", false)]
    [InlineData("--label CaseSensitive", "--label casesensitive", false)]
    [InlineData("--label \"\"", "--label", false)]
    public void NativeArgumentsPreserveValuesWhileAcceptingEquivalentQuoting(string action, string observed, bool exact)
    {
        const string image = @"C:\Apps\runner.exe";
        var match = Assert.Single(ScheduledTaskCatalog.Match(new[] { Task(@"\Task", image, action) },
            image, "runner.exe " + observed));

        Assert.Equal(exact, match.Score == ScheduledTaskCatalog.ExactActionScore);
    }

    [Theory]
    [InlineData("cmd.exe", "/c echo \"a\"b", "/c echo ab")]
    [InlineData("powershell.exe", "-Command Write-Output \"A\"", "-Command Write-Output A")]
    [InlineData("pwsh.exe", "-Command Write-Output \"A\"", "-Command Write-Output A")]
    public void ShellCommandTailsAreNotDeclaredEquivalentByWindowsTokenization(string program, string action, string observed)
    {
        var image = @"C:\Apps\" + program;
        var match = Assert.Single(ScheduledTaskCatalog.Match(new[] { Task(@"\Task", image, action) },
            image, program + " " + observed));

        Assert.True(match.Score < ScheduledTaskCatalog.ExactActionScore);
    }

    [Fact]
    public void MissingCommandLineDoesNotProveThereWereNoArguments()
    {
        var tasks = new[] { Task(@"\Task", Cmd, "") };
        Assert.True(Assert.Single(ScheduledTaskCatalog.Match(tasks, Cmd, null)).Score < ScheduledTaskCatalog.ExactActionScore);
        Assert.Equal(ScheduledTaskCatalog.ExactActionScore,
            Assert.Single(ScheduledTaskCatalog.Match(tasks, Cmd, "cmd.exe")).Score);
    }

    [Fact]
    public void DriveRelativeExecutablePathIsOnlyACompatibilityHint()
    {
        var match = Assert.Single(ScheduledTaskCatalog.Match(
            new[] { Task(@"\Task", @"C:Apps\runner.exe", "--run") },
            @"C:\Apps\runner.exe", "runner.exe --run"));

        Assert.True(match.Score < ScheduledTaskCatalog.ExactActionScore);
    }

    [Fact]
    public void CommandLineAloneCannotProveTheExecutableImage()
    {
        var match = Assert.Single(ScheduledTaskCatalog.Match(
            new[] { Task(@"\Task", Cmd, "/c echo hello") }, null, Cmd + " /c echo hello"));

        Assert.True(match.Score < ScheduledTaskCatalog.ExactActionScore);
    }

    [Fact]
    public void EqualExactActionsFromDifferentTasksStayAmbiguous()
    {
        var tasks = new[] { Task(@"\First", Cmd, "/c echo hello"), Task(@"\Second", Cmd, "/c echo hello") };
        var process = Process(Cmd, "cmd.exe /c echo hello");
        var matches = ScheduledTaskCatalog.Match(tasks, Cmd, process.CommandLine);

        Assert.All(matches, match => Assert.Equal(ScheduledTaskCatalog.ExactActionScore, match.Score));
        Assert.Null(ScheduledTaskCorrelator.UniqueBestMatch(matches, 50));
        Assert.Equal("", Correlate(tasks, process)!.TaskPath);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void DisabledExactActionStillProvidesOnlyAPossibleFallback(bool scheduler)
    {
        var tasks = new[] { Task(@"\Disabled", Cmd, "/c echo hello", enabled: false) };
        var process = Process(Cmd, "cmd.exe /c echo hello");
        Assert.Empty(ScheduledTaskCatalog.Match(tasks, Cmd, process.CommandLine));
        var result = Correlate(tasks, process, scheduler);

        Assert.Equal(@"\Disabled", result!.TaskPath);
        Assert.Equal(TaskConfidence.Possible, result.Confidence);
        Assert.False(result.Enabled);
        Assert.Contains("disabled now", result.Evidence);
    }

    [Fact]
    public void BareProgramNameWithIdenticalArgumentsIsAnExactAction()
    {
        // Many tasks (malicious ones included) name just "powershell.exe"; Windows finds
        // it on the search path, so the process's own image carries that file name.
        const string powershell = @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";
        var tasks = new[]
        {
            Task(@"\Updater", "powershell.exe", @"-w hidden -c iex (gc C:\x.ps1)"),
            Task(@"\Vendor", powershell, @"-NoProfile -File C:\vendor\update.ps1")
        };
        var process = Process(powershell, @"powershell.exe -w hidden -c iex (gc C:\x.ps1)");
        var matches = ScheduledTaskCatalog.Match(tasks, process.ImagePath, process.CommandLine);

        Assert.Equal(ScheduledTaskCatalog.ExactActionScore, matches[0].Score);
        var result = Correlate(tasks, process);
        Assert.Equal(@"\Updater", result!.TaskPath);
        Assert.Equal(TaskConfidence.Likely, result.Confidence);
        Assert.Contains("exact command", result.Evidence);
    }

    [Theory]
    [InlineData("cmd", Cmd, "cmd /c echo hello", true)]                  // Windows adds .exe
    [InlineData("CMD.EXE", Cmd, "CMD.EXE /c echo hello", true)]
    [InlineData("pwsh.exe", Cmd, "pwsh.exe /c echo hello", false)]       // another program
    [InlineData("cmd.exe", null, "cmd.exe /c echo hello", false)]        // image unknown: command line alone
    [InlineData(@"Apps\cmd.exe", Cmd, @"Apps\cmd.exe /c echo hello", false)] // relative path, not a bare name
    public void BareProgramNameNeedsTheProcessImageAndItsFileName(string command, string? image, string observed, bool exact)
    {
        var matches = ScheduledTaskCatalog.Match(new[] { Task(@"\Task", command, "/c echo hello") }, image, observed);
        Assert.Equal(exact, matches.Any(match => match.Score == ScheduledTaskCatalog.ExactActionScore));
    }

    [Fact]
    public void EqualBareActionsFromDifferentTasksStayAmbiguous()
    {
        var tasks = new[] { Task(@"\First", "cmd.exe", "/c echo hello"), Task(@"\Second", "cmd.exe", "/c echo hello") };
        var process = Process(Cmd, "cmd.exe /c echo hello");

        Assert.Null(ScheduledTaskCorrelator.UniqueBestMatch(ScheduledTaskCatalog.Match(tasks, Cmd, process.CommandLine), 50));
        Assert.Equal("", Correlate(tasks, process)!.TaskPath);
    }

    private static ScheduledTaskInfo Task(string path, string command, string arguments, bool enabled = true) => new()
    {
        Path = path, Enabled = enabled,
        Actions = { new TaskAction { Command = command, Arguments = arguments } }
    };

    private static ProcessInfo Process(string image, string command) => new()
    {
        ProcessId = 4321, ProcessName = CommandLineTokenizer.FileNameOf(image), ImagePath = image, CommandLine = command
    };

    private ScheduledTaskMatch? Correlate(IEnumerable<ScheduledTaskInfo> tasks, ProcessInfo process, bool scheduler = true)
    {
        var root = Path.Combine(_dir.Path, "Tasks");
        Directory.CreateDirectory(root);
        foreach (var task in tasks)
        {
            var action = task.Actions.Single();
            var definition = new XElement("Task",
                new XElement("Settings", new XElement("Enabled", task.Enabled)),
                new XElement("Actions", new XElement("Exec",
                    new XElement("Command", action.Command), new XElement("Arguments", action.Arguments))));
            File.WriteAllText(Path.Combine(root, task.Path.TrimStart('\\')), definition.ToString());
        }
        var ancestry = scheduler ? new[]
        {
            new ProcessInfo { ProcessId = 1500, ProcessName = "svchost.exe", CommandLine = "svchost.exe -k netsvcs -p -s Schedule" }
        } : Array.Empty<ProcessInfo>();
        return new ScheduledTaskCorrelator(new ScheduledTaskCatalog(root), history: null)
            .Correlate(process, ancestry, DateTimeOffset.UtcNow, new List<string>());
    }
}
