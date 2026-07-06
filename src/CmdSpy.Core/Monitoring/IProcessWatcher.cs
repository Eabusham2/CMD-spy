using System;

namespace CmdSpy.Core.Monitoring;

/// <summary>Raised the instant a process is created anywhere on the machine.</summary>
public sealed class ProcessStartedEventArgs : EventArgs
{
    public int ProcessId { get; init; }
    public int ParentProcessId { get; init; }
    public string ProcessName { get; init; } = "";
    public string? ImagePath { get; init; }
    public string? CommandLine { get; init; }
    public DateTimeOffset TimestampUtc { get; init; }
    public string Source { get; init; } = "";
}

/// <summary>Raised when a process exits — used to measure how long a popup lived.</summary>
public sealed class ProcessStoppedEventArgs : EventArgs
{
    public int ProcessId { get; init; }
    public int? ExitCode { get; init; }
    public DateTimeOffset TimestampUtc { get; init; }
}

/// <summary>
/// Abstraction over a real-time process-creation source. Two implementations
/// exist: an ETW kernel trace (primary, captures the command line at creation so
/// even a process that lives for one millisecond is fully recorded) and a WMI
/// process-start trace (fallback).
/// </summary>
public interface IProcessWatcher : IDisposable
{
    string Name { get; }
    bool SupportsCommandLine { get; }
    bool SupportsExitEvents { get; }

    event EventHandler<ProcessStartedEventArgs>? ProcessStarted;
    event EventHandler<ProcessStoppedEventArgs>? ProcessStopped;

    /// <summary>Begins watching. Throws if the source cannot be started (e.g. not elevated).</summary>
    void Start();

    void Stop();
}
