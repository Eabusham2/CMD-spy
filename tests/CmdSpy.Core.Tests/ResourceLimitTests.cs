using System;
using System.IO;
using System.Threading.Tasks;
using CmdSpy.Core.Models;
using CmdSpy.Core.Monitoring;
using Xunit;

namespace CmdSpy.Core.Tests;

public sealed class ResourceLimitTests
{
    [Fact]
    public void InvestigatorRejectsDistinctWorkWhenQueueIsFull()
    {
        var options = new CmdSpyOptions
        {
            InvestigateEvents = true,
            VerifySignatures = false,
            CorrelateScheduledTasks = false,
            CorrelateEventLogs = false,
            MaxPendingInvestigations = 2
        };
        using var investigator = new Investigator(new ProcessCache(TimeSpan.FromMinutes(1)), options);
        var warmUp = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        investigator.Start(warmUp.Task);
        var first = NewEvent(900_101);
        var second = NewEvent(900_102);
        var rejected = NewEvent(900_103);

        try
        {
            Assert.True(investigator.Enqueue(first));
            Assert.True(investigator.Enqueue(second));
            Assert.False(investigator.Enqueue(rejected));
            Assert.Equal(2, investigator.Pending);
            Assert.True(investigator.IsPending(first.Id));
            Assert.True(investigator.IsPending(second.Id));
            Assert.False(investigator.IsPending(rejected.Id));
        }
        finally
        {
            warmUp.TrySetResult(true);
        }
    }

    [Fact]
    public void SignatureHashingHonorsTheCallBudget()
    {
        var path = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(path, new byte[32]);
            var verifier = new SignatureVerifier { ComputeHashes = true, MaxHashFileBytes = 64 };

            var limited = verifier.Verify(path, "test", maxHashBytes: 16);
            var allowed = verifier.Verify(path, "test", maxHashBytes: 64);

            Assert.Null(limited.Sha256);
            Assert.NotNull(allowed.Sha256);
        }
        finally
        {
            File.Delete(path);
        }
    }

    private static CmdEvent NewEvent(int pid) => new()
    {
        ProcessId = pid,
        ProcessName = "cmd.exe",
        CommandLine = "cmd.exe /c echo bounded",
        TimestampUtc = DateTimeOffset.UtcNow,
        CaptureSource = "test"
    };
}
