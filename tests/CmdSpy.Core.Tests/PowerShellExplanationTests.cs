using System;
using System.Linq;
using CmdSpy.Core.Analysis;
using CmdSpy.Core.Models;
using Xunit;

namespace CmdSpy.Core.Tests;

public class PowerShellExplanationTests
{
    private static CommandExplanation Explain(string script) =>
        CommandExplainer.Explain(CommandParser.Parse("powershell -c " + script));

    [Fact]
    public void AstValidation_PreservesTheOriginalSimpleExplanation()
    {
        var explanation = Explain("Get-Process");

        Assert.True(explanation.IsReadOnly);
        Assert.Equal(new[] { "Get-Process: lists running processes." }, explanation.Details);
        Assert.Equal("Windows PowerShell lists running processes. Read-only: no modification is evident in this command.",
            explanation.Summary);
    }

    [Fact]
    public void AstValidation_PreservesTheOriginalPipelineExplanationWithoutDuplicates()
    {
        var explanation = Explain("Get-Process | Where-Object { $_.CPU -gt 10 } | Select-Object Name");

        Assert.True(explanation.IsReadOnly);
        Assert.Equal(new[]
        {
            "Pipeline: Get-Process: lists running processes → Where-Object: filters/processes data → Select-Object: selects data."
        }, explanation.Details);
    }

    [Fact]
    public void AstValidation_PreservesAssignmentAndOutputDescriptions()
    {
        var explanation = Explain("$a = 1; Write-Output $a");

        Assert.True(explanation.IsReadOnly);
        Assert.Equal(new[] { "Stores into $a: 1", "Write-Output: prints/returns values." }, explanation.Details);
    }

    [Theory]
    [InlineData(@"Set-Content C:\x y")]
    [InlineData(@"Get-Process | ForEach-Object { Set-Content C:\x y }")]
    public void AlreadyExplainedMutations_AreNotDuplicated(string script)
    {
        var explanation = Explain(script);

        Assert.False(explanation.IsReadOnly);
        Assert.Single(explanation.Details);
        Assert.Contains(Effects.WritesFiles, explanation.Effects);
    }

    [Theory]
    [InlineData("Get-Process > $null")]
    [InlineData("Get-Process *> $NULL")]
    [InlineData("Get-Process 2>> $null")]
    [InlineData("Get-Process | ForEach-Object { Write-Output $_ > $null }")]
    public void NullRedirection_DiscardsOutputWithoutClaimingAFileWrite(string script)
    {
        var explanation = Explain(script);

        Assert.True(explanation.IsReadOnly);
        Assert.DoesNotContain(Effects.WritesFiles, explanation.Effects);
    }

    [Theory]
    [InlineData(@"Get-Process > C:\out.txt")]
    [InlineData(@"Get-Process | ForEach-Object { Write-Output $_ >> C:\out.txt }")]
    [InlineData("Get-Process > $destination")]
    [InlineData("Get-Process > '$null'")]
    [InlineData(@"Get-Process > { Remove-Item C:\x }")]
    public void FileRedirection_StillReportsPossibleWrites(string script)
    {
        var explanation = Explain(script);

        Assert.False(explanation.IsReadOnly);
        Assert.Contains(Effects.WritesFiles, explanation.Effects);
    }

    [Theory]
    [InlineData(@"$action = { Remove-Item C:\x }; Get-Process")]
    [InlineData(@"Write-Output { Remove-Item C:\x }")]
    [InlineData(@"Get-Process | ForEach-Object { $action = { Remove-Item C:\x }; $_ }")]
    [InlineData(@"ForEach-Object -InputObject { Remove-Item C:\x } -Process { $_ }")]
    [InlineData(@"Where-Object -InputObject { Remove-Item C:\x } -FilterScript { $true }")]
    public void ScriptBlocksUsedAsData_AreNotReportedAsExecuted(string script)
    {
        var explanation = Explain(script);

        Assert.True(explanation.IsReadOnly);
        Assert.DoesNotContain(Effects.DeletesFiles, explanation.Effects);
    }

    [Theory]
    [InlineData(@"function Unused { Remove-Item C:\x }; Get-Process")]
    [InlineData(@"function Unused { [IO.File]::Delete('C:\x'); Write-Output x > C:\out.txt }; Get-Process")]
    [InlineData(@"Get-Process | ForEach-Object { function Unused { Remove-Item C:\x }; $_ }")]
    public void UnusedFunctionBodies_DoNotClaimThatTheirContentsExecuted(string script)
    {
        var explanation = Explain(script);

        Assert.NotEqual(false, explanation.IsReadOnly);
        Assert.DoesNotContain(Effects.DeletesFiles, explanation.Effects);
        Assert.DoesNotContain(Effects.WritesFiles, explanation.Effects);
    }

    [Theory]
    [InlineData(@"Get-Process | ForEach-Object { Write-Output $_; Set-Content C:\x y }")]
    [InlineData(@"Get-Process | foreach { where { echo $_; sc C:\x y } }")]
    [InlineData(@"Get-Process | ForEach-Object { Write-Output $_; & 'Set-Content' C:\x y }")]
    [InlineData(@"& { Set-Content C:\x y }")]
    [InlineData(@". { Set-Content C:\x y }")]
    [InlineData(@"({ Set-Content C:\x y }).Invoke()")]
    [InlineData(@"({ Set-Content C:\x y }).invoke()")]
    [InlineData(@"ForEach-Object -Begin { Write-Output start } -Process { Set-Content C:\x y }")]
    [InlineData(@"ForEach-Object -Process:{ Set-Content C:\x y }")]
    [InlineData(@"Get-Process | Select-Object @{ Name='Value'; Expression={ Set-Content C:\x y } }")]
    public void ExecutedLiteralBlocks_StillAddTheNestedMutationEvidence(string script)
    {
        var explanation = Explain(script);

        Assert.False(explanation.IsReadOnly);
        Assert.Contains(Effects.WritesFiles, explanation.Effects);
        Assert.Contains(explanation.Details, detail => detail.Contains("Set-Content", StringComparison.OrdinalIgnoreCase));
    }

    [Theory]
    [InlineData("Get-Process | ForEach-Object -Begin { Write-Output start } -Process $action")]
    [InlineData("Get-Process | ForEach-Object -Process { $_ } -End $action")]
    [InlineData("Get-Process | ForEach-Object -Process:$action")]
    [InlineData("Get-Process | ForEach-Object { $_ }, $action")]
    [InlineData("Get-Process | ForEach-Object -RemainingScripts $action -Process { $_ }")]
    [InlineData("Get-Process | foreach -Begin { $_ } -Process $action")]
    [InlineData("Get-Process | ForEach-Object -Begin { $_ } @callbacks")]
    [InlineData("Get-Process | ForEach-Object Kill")]
    [InlineData("Get-Process | ForEach-Object -MemberName Kill")]
    [InlineData("Get-Process | ForEach-Object $action")]
    [InlineData("Get-Process | Where-Object -FilterScript $predicate")]
    [InlineData("Get-Process | Where-Object -FilterScript:$predicate")]
    [InlineData("Get-Process | ForEach-Object { & $command $_ }")]
    [InlineData("Get-Process | ForEach-Object { $_.Kill() }")]
    [InlineData("Get-Process | ForEach-Object { $_.Value = 1 }")]
    [InlineData("Get-Process | Where-Object { $_.Name -eq 'powershell'")]
    [InlineData("ForEach-Object {")]
    [InlineData(@"Get-CustomResult { Remove-Item C:\x }")]
    public void UnresolvedExecution_RemainsUnknownEvenAlongsideLiteralBlocks(string script)
    {
        var explanation = Explain(script);

        Assert.Null(explanation.IsReadOnly);
        Assert.Contains(Effects.Unknown, explanation.Effects);
    }

    [Theory]
    [InlineData("Get-Process | Where-Object Name -eq 'powershell'")]
    [InlineData("Get-Process | Where-Object -Property Name -EQ -Value 'powershell'")]
    [InlineData("Get-Process | ForEach-Object { $_.Name }")]
    [InlineData("ForEach-Object -InputObject $items -Process { $_ }")]
    [InlineData("Get-Process | ForEach-Object -Verbose -Process { $_ }")]
    [InlineData("Get-Process | ForEach-Object { $_ }, { Write-Output $_ }")]
    public void OrdinaryFiltersAndLiteralCallbacks_RemainReadOnly(string script)
    {
        Assert.True(Explain(script).IsReadOnly);
    }

    [Fact]
    public void LocalFunctionCalls_AreNotAssumedReadOnlyBecauseOfTheirNames()
    {
        var explanation = Explain(@"function Get-Harmless { Remove-Item C:\x }; Get-Harmless");

        Assert.Null(explanation.IsReadOnly);
        Assert.Contains(explanation.Details, detail => detail.Contains("locally defined function"));
        Assert.DoesNotContain(Effects.DeletesFiles, explanation.Effects);
    }

    [Fact]
    public void DotNetFileOpen_OnlyTheExplicitReadVariantCanBeReadOnly()
    {
        Assert.True(Explain(@"[IO.File]::OpenRead('C:\x')").IsReadOnly);
        Assert.Null(Explain(@"[IO.File]::Open('C:\x', 'Create')").IsReadOnly);
        Assert.Null(Explain(@"[IO.File]::OpenWrite('C:\x')").IsReadOnly);
    }

    [Theory]
    [InlineData("Get-Process > $null", true)]
    [InlineData("Get-Process | ForEach-Object { $_.Name }", true)]
    [InlineData("Get-Process | ForEach-Object -Begin { $_ } -Process $action", false)]
    [InlineData("Get-Process | ForEach-Object Kill", false)]
    [InlineData(@"Get-Process | ForEach-Object { Write-Output $_; Set-Content C:\x y }", false)]
    public void Risk_OnlyVerifiedReadOnlyCommandsCanReceiveLow(string script, bool canBeLow)
    {
        var risk = RiskAssessor.Assess(new RiskInput
        {
            Explanation = Explain(script),
            Launcher = new ProcessInfo { ProcessId = 123, ProcessName = "signed-launcher.exe" },
            Signatures = new[]
            {
                new SignatureInfo { Role = "this process", Status = SignatureStatus.Valid, Publisher = "Microsoft" },
                new SignatureInfo { Role = "launcher", Status = SignatureStatus.Valid, Publisher = "Trusted publisher" }
            }
        });

        Assert.Equal(canBeLow ? RiskLevel.Low : RiskLevel.Unknown, risk.Level);
    }
}
