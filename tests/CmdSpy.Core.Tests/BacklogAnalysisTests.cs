using System.Collections.Concurrent;
using CmdSpy.Core.Logging;
using CmdSpy.Core.Models;
using CmdSpy.Core.Monitoring;
using Xunit;

namespace CmdSpy.Core.Tests;

public sealed class BacklogAnalysisTests
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(15);

    private static Investigator NewInvestigator() => new(new ProcessCache(), new CmdSpyOptions
    {
        VerifySignatures = false,
        CorrelateEventLogs = false,
        CorrelateScheduledTasks = false
    });

    private static CmdEvent NewEvent() => new()
    {
        ProcessId = 0,
        ProcessName = "cmd.exe",
        CommandLine = "cmd /c whoami",
        TimestampUtc = DateTimeOffset.UtcNow.AddHours(-1)
    };

    [Fact]
    public void AutomaticBackfillAppliesWithoutPublishingOrWritingTheServiceLog()
    {
        using var service = new ServiceLog();
        using var done = new ManualResetEventSlim();
        using var investigator = NewInvestigator();
        var before = service.Bytes();
        int ordinaryCompletions = 0;
        bool applied = false;
        investigator.Completed += (_, _) => Interlocked.Increment(ref ordinaryCompletions);
        investigator.Start();
        investigator.EnqueueBacklog(service.Displayed, (ev, result) =>
        {
            applied = Investigator.TryApplyBacklogResult(ev, result);
            done.Set();
        });

        Assert.True(done.Wait(Timeout), "automatic analysis did not complete");
        Assert.True(applied);
        Assert.NotNull(service.Displayed.Investigation?.Risk);
        Assert.Equal(0, ordinaryCompletions);
        Assert.Equal(0, investigator.Pending);
        Assert.Equal(before, service.Bytes());
    }

    [Theory]
    [InlineData(1)]
    [InlineData(4)]
    public void ServiceVerdictArrivingWhileBacklogIsQueuedSkipsTheAutomaticPass(int revision)
    {
        using var service = new ServiceLog();
        using var drained = new ManualResetEventSlim();
        using var investigator = NewInvestigator();
        var warmUp = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        int obsoleteCompletions = 0;
        int ordinaryCompletions = 0;
        investigator.Completed += (_, _) => Interlocked.Increment(ref ordinaryCompletions);
        investigator.Start(warmUp.Task);
        try
        {
            investigator.EnqueueBacklog(service.Displayed, (ev, result) =>
            {
                Interlocked.Increment(ref obsoleteCompletions);
                Investigator.TryApplyBacklogResult(ev, result);
            });
            investigator.EnqueueBacklog(NewEvent(), (_, _) => drained.Set());
            Assert.Equal(2, investigator.Pending);

            var authoritative = service.PublishVerdict(revision);
            var afterServiceWrite = service.Bytes();
            warmUp.SetResult(true);

            Assert.True(drained.Wait(Timeout), "the backlog did not drain past the obsolete item");
            Assert.Same(authoritative, service.Displayed.Investigation);
            Assert.Equal(0, obsoleteCompletions);
            Assert.Equal(0, ordinaryCompletions);
            Assert.Equal(0, investigator.Pending);
            Assert.False(investigator.IsQueued(service.Displayed.Id));
            Assert.Equal(afterServiceWrite, service.Bytes());
        }
        finally
        {
            warmUp.TrySetResult(true);
        }
    }

    [Theory]
    [InlineData(1)]
    [InlineData(4)]
    public void ServiceVerdictArrivingAfterAnalysisStartedCannotBeOverwritten(int revision)
    {
        using var service = new ServiceLog();
        using var resultReady = new ManualResetEventSlim();
        using var allowCompletion = new ManualResetEventSlim();
        using var done = new ManualResetEventSlim();
        using var investigator = NewInvestigator();
        bool applied = true;
        Investigation? stale = null;
        investigator.Start();
        try
        {
            investigator.EnqueueBacklog(service.Displayed, (ev, result) =>
            {
                stale = result;
                resultReady.Set();
                if (allowCompletion.Wait(Timeout))
                    applied = Investigator.TryApplyBacklogResult(ev, result);
                done.Set();
            });
            Assert.True(resultReady.Wait(Timeout), "the automatic result was not ready");
            Assert.Equal(1, stale!.Revision);

            // This is the real LogFollower.CopyFrom path, on the same event the
            // GUI's completed background pass is about to update.
            var authoritative = service.PublishVerdict(revision);
            var afterServiceWrite = service.Bytes();
            allowCompletion.Set();

            Assert.True(done.Wait(Timeout), "the held automatic completion did not finish");
            Assert.False(applied);
            Assert.Same(authoritative, service.Displayed.Investigation);
            Assert.Equal(RiskLevel.High, service.Displayed.Investigation!.Risk!.Level);
            Assert.Equal(0, investigator.Pending);
            Assert.Equal(afterServiceWrite, service.Bytes());
        }
        finally
        {
            allowCompletion.Set();
        }
    }

    [Fact]
    public void ServiceVerdictArrivingAfterBackfillStillReplacesTheGuiResult()
    {
        using var service = new ServiceLog();
        using var done = new ManualResetEventSlim();
        using var investigator = NewInvestigator();
        investigator.Start();
        investigator.EnqueueBacklog(service.Displayed, (ev, result) =>
        {
            Investigator.TryApplyBacklogResult(ev, result);
            done.Set();
        });
        Assert.True(done.Wait(Timeout));
        var automatic = service.Displayed.Investigation;
        Assert.NotNull(automatic);

        var authoritative = service.PublishVerdict(2);

        Assert.NotSame(automatic, authoritative);
        Assert.Same(authoritative, service.Displayed.Investigation);
        Assert.Equal(RiskLevel.High, service.Displayed.Investigation!.Risk!.Level);
    }

    [Fact]
    public void ExplicitReanalysisPromotesBacklogAndKeepsItsOrdinaryCompletion()
    {
        using var service = new ServiceLog();
        using var drained = new ManualResetEventSlim();
        using var investigator = NewInvestigator();
        var warmUp = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var older = NewEvent();
        var tail = NewEvent();
        var order = new ConcurrentQueue<Guid>();
        int automaticCompletions = 0;
        int ordinaryCompletions = 0;
        investigator.Completed += (ev, result) =>
        {
            lock (ev) ev.Investigation = result; // The GUI's explicit reanalysis semantics.
            Interlocked.Increment(ref ordinaryCompletions);
            order.Enqueue(ev.Id);
        };
        investigator.Start(warmUp.Task);
        try
        {
            investigator.EnqueueBacklog(older, (ev, _) => order.Enqueue(ev.Id));
            investigator.EnqueueBacklog(service.Displayed, (ev, result) =>
            {
                Interlocked.Increment(ref automaticCompletions);
                Investigator.TryApplyBacklogResult(ev, result);
            });
            var authoritative = service.PublishVerdict(4);
            var afterServiceWrite = service.Bytes();

            investigator.Enqueue(service.Displayed);
            investigator.Enqueue(service.Displayed); // Duplicate foreground requests remain coalesced.
            investigator.EnqueueBacklog(tail, (ev, _) =>
            {
                order.Enqueue(ev.Id);
                drained.Set();
            });
            Assert.Equal(3, investigator.Pending); // Promotion did not add a fourth pending item.
            warmUp.SetResult(true);

            Assert.True(drained.Wait(Timeout));
            Assert.Equal(new[] { service.Displayed.Id, older.Id, tail.Id }, order.ToArray());
            Assert.Equal(0, automaticCompletions);
            Assert.Equal(1, ordinaryCompletions);
            Assert.NotSame(authoritative, service.Displayed.Investigation);
            Assert.Equal(5, service.Displayed.Investigation!.Revision);
            Assert.Equal(0, investigator.Pending);
            Assert.False(investigator.IsQueued(service.Displayed.Id));
            Assert.Equal(afterServiceWrite, service.Bytes());
        }
        finally
        {
            warmUp.TrySetResult(true);
        }
    }

    [Fact]
    public void ExplicitReanalysisDuringBackfillStillRunsAfterTheStaleResultIsRejected()
    {
        using var service = new ServiceLog();
        using var resultReady = new ManualResetEventSlim();
        using var allowCompletion = new ManualResetEventSlim();
        using var manualDone = new ManualResetEventSlim();
        using var investigator = NewInvestigator();
        bool applied = true;
        int ordinaryCompletions = 0;
        investigator.Completed += (ev, result) =>
        {
            lock (ev) ev.Investigation = result;
            Interlocked.Increment(ref ordinaryCompletions);
            manualDone.Set();
        };
        investigator.Start();
        try
        {
            investigator.EnqueueBacklog(service.Displayed, (ev, result) =>
            {
                resultReady.Set();
                if (allowCompletion.Wait(Timeout))
                    applied = Investigator.TryApplyBacklogResult(ev, result);
            });
            Assert.True(resultReady.Wait(Timeout));
            service.PublishVerdict(4);
            var afterServiceWrite = service.Bytes();
            investigator.Enqueue(service.Displayed);
            Assert.Equal(1, investigator.Pending);
            allowCompletion.Set();

            Assert.True(manualDone.Wait(Timeout));
            Assert.False(applied);
            Assert.Equal(1, ordinaryCompletions);
            Assert.Equal(5, service.Displayed.Investigation!.Revision);
            Assert.Equal(0, investigator.Pending);
            Assert.Equal(afterServiceWrite, service.Bytes());
        }
        finally
        {
            allowCompletion.Set();
        }
    }

    [Fact]
    public void ForegroundRunsBeforeBacklogAndQueuedDuplicatesCompleteOnce()
    {
        using var drained = new ManualResetEventSlim();
        using var investigator = NewInvestigator();
        var warmUp = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var old = NewEvent();
        var tail = NewEvent();
        var live = NewEvent();
        var order = new ConcurrentQueue<Guid>();
        investigator.Completed += (ev, _) =>
        {
            order.Enqueue(ev.Id);
            if (ev.Id == tail.Id) drained.Set();
        };
        investigator.Start(warmUp.Task);
        try
        {
            investigator.EnqueueBacklog(old);
            investigator.EnqueueBacklog(old);
            investigator.EnqueueBacklog(tail);
            investigator.Enqueue(live);
            investigator.Enqueue(live);
            Assert.Equal(3, investigator.Pending);
            warmUp.SetResult(true);

            Assert.True(drained.Wait(Timeout));
            Assert.Equal(new[] { live.Id, old.Id, tail.Id }, order.ToArray());
            Assert.Equal(0, investigator.Pending);
        }
        finally
        {
            warmUp.TrySetResult(true);
        }
    }

    private sealed class ServiceLog : IDisposable
    {
        private readonly TempDir _directory = new();
        private readonly EventStore _store;
        private readonly LogFollower _follower;
        private readonly CmdEvent _source = NewEvent();

        public CmdEvent Displayed { get; }

        public ServiceLog()
        {
            _store = new EventStore(_directory.Path);
            _store.Append(_source);
            _follower = new LogFollower(_directory.Path, TimeSpan.FromHours(1));
            Displayed = Assert.Single(_follower.Start());
        }

        public Investigation PublishVerdict(int revision)
        {
            _source.Investigation = new Investigation
            {
                Revision = revision,
                Risk = new RiskAssessment { Level = RiskLevel.High }
            };
            _store.AppendUpdate(_source, "analysis");
            _follower.Poll();
            return Displayed.Investigation!;
        }

        public byte[] Bytes() => File.ReadAllBytes(_store.CurrentJsonlPath);

        public void Dispose()
        {
            _follower.Dispose();
            _directory.Dispose();
        }
    }
}
