using System;
using System.Collections.Generic;
using Xunit;

namespace CmdSpy.Core.Tests;

public class StartupTaskRegistrationTests
{
    private const string User = @"PC\alice";
    private static readonly string Xml = StartupTaskDefinition.BuildXml(@"C:\Program Files\CmdSpy\CmdSpy.exe", User);

    [Fact]
    public void SuccessfulComRegistrationDoesNotRunOrOverwriteWithSchtasks()
    {
        var calls = new List<string>();
        var usedCompatibility = StartupTaskRegistration.Register(Xml, User,
            (xml, user) =>
            {
                calls.Add("COM");
                Assert.Same(Xml, xml);
                Assert.Equal(User, user);
            },
            (_, _) => throw new InvalidOperationException("Fallback must not run after COM succeeds."));

        Assert.False(usedCompatibility);
        Assert.Equal(new[] { "COM" }, calls);
    }

    [Fact]
    public void FailedComRegistrationFallsBackOnceWithTheIdenticalDefinitionAndUser()
    {
        var calls = new List<string>();
        var usedCompatibility = StartupTaskRegistration.Register(Xml, User,
            (xml, user) =>
            {
                calls.Add("COM");
                Assert.Same(Xml, xml);
                Assert.Equal(User, user);
                throw new InvalidOperationException("COM activation failed.");
            },
            (xml, user) =>
            {
                calls.Add("schtasks");
                Assert.Same(Xml, xml);
                Assert.Equal(User, user);
            });

        Assert.True(usedCompatibility);
        Assert.Equal(new[] { "COM", "schtasks" }, calls);
    }

    [Fact]
    public void BothFailuresReportBothCausesAndKeepTheOriginalExceptions()
    {
        var comFailure = new InvalidOperationException("COM activation failed.");
        var schtasksFailure = new InvalidOperationException("schtasks exited with code 1: Access is denied.");
        var calls = new List<string>();
        var error = Assert.Throws<InvalidOperationException>(() => StartupTaskRegistration.Register(Xml, User,
            (_, _) => { calls.Add("COM"); throw comFailure; },
            (_, _) => { calls.Add("schtasks"); throw schtasksFailure; }));

        Assert.Equal(new[] { "COM", "schtasks" }, calls);
        Assert.Contains(comFailure.Message, error.Message, StringComparison.Ordinal);
        Assert.Contains(schtasksFailure.Message, error.Message, StringComparison.Ordinal);
        var causes = Assert.IsType<AggregateException>(error.InnerException).InnerExceptions;
        Assert.Equal(2, causes.Count);
        Assert.Same(comFailure, causes[0]);
        Assert.Same(schtasksFailure, causes[1]);
    }
}
