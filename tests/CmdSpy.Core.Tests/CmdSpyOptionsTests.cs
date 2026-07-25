using System;
using System.Linq;
using CmdSpy.Core;
using Xunit;

namespace CmdSpy.Core.Tests;

/// <summary>
/// Target matching is what decides whether a popup is captured at all, so the
/// stem normalization is worth pinning down: it has to cope with full paths,
/// mixed case, and a missing ".exe".
/// </summary>
public class CmdSpyOptionsTests
{
    [Theory]
    [InlineData(@"C:\Windows\System32\cmd.exe", "cmd")]
    [InlineData("cmd.exe", "cmd")]
    [InlineData("CMD.EXE", "CMD")]
    [InlineData("cmd", "cmd")]
    [InlineData(@"C:\Program Files\WindowsApps\wt.exe", "wt")]
    [InlineData("/usr/bin/pwsh.exe", "pwsh")]
    [InlineData("", "")]
    [InlineData("   ", "")]
    public void Stem_StripsDirectoryAndExeSuffix(string input, string expected)
    {
        Assert.Equal(expected, CmdSpyOptions.Stem(input));
    }

    [Fact]
    public void Stem_IsCaseInsensitiveForMatching()
    {
        var options = new CmdSpyOptions();
        var stems = options.TargetStems();

        // The engine matches on the stem of whatever the detector reports, which
        // may be upper-case or a full path.
        Assert.Contains(CmdSpyOptions.Stem(@"C:\Windows\System32\CMD.EXE"), stems);
        Assert.Contains(CmdSpyOptions.Stem("cmd.exe"), stems);
    }

    [Fact]
    public void DefaultTargets_CoverAllKnownHostsIncludingWindowsTerminal()
    {
        var options = new CmdSpyOptions();
        var stems = options.TargetStems();

        foreach (var expected in new[]
                 {
                     "cmd", "powershell", "pwsh", "conhost",
                     "wscript", "cscript", "mshta",
                     "wt", "WindowsTerminal", "OpenConsole"
                 })
        {
            Assert.Contains(expected, stems);
        }
    }

    [Fact]
    public void DefaultTargets_AreIndependentPerInstance()
    {
        // Regression guard: the default set is seeded from a shared static list,
        // so mutating one instance must not leak into the next.
        var first = new CmdSpyOptions();
        first.TargetProcessNames.Clear();
        first.TargetProcessNames.Add("cmd.exe");

        var second = new CmdSpyOptions();

        Assert.Equal(CmdSpyOptions.ExtendedTargets.Count, second.TargetProcessNames.Count);
        Assert.Contains("wt.exe", second.TargetProcessNames);
        Assert.Single(first.TargetProcessNames);
    }

    [Fact]
    public void ExtendedTargets_HasNoDuplicates()
    {
        var stems = CmdSpyOptions.ExtendedTargets
            .Select(CmdSpyOptions.Stem)
            .ToList();

        Assert.Equal(stems.Count, stems.Distinct(StringComparer.OrdinalIgnoreCase).Count());
    }

    [Fact]
    public void DefaultLogDirectory_IsRootedUnderCmdSpy()
    {
        var dir = CmdSpyOptions.DefaultLogDirectory();

        Assert.False(string.IsNullOrWhiteSpace(dir));
        Assert.Contains("CmdSpy", dir);
    }
}
