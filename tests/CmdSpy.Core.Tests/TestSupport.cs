using System;
using System.IO;
using System.Security.Principal;
using System.Threading;
using CmdSpy.Core.Monitoring;
using Xunit;

namespace CmdSpy.Core.Tests;

/// <summary>A process watcher the tests drive by hand, standing in for ETW/WMI.</summary>
internal sealed class FakeWatcher : IProcessWatcher
{
    public string Name => "Fake";
    public bool SupportsCommandLine => true;
    public bool SupportsExitEvents => true;

    public event EventHandler<ProcessStartedEventArgs>? ProcessStarted;
    public event EventHandler<ProcessStoppedEventArgs>? ProcessStopped;

    public void Start() { }
    public void Stop() { }
    public void Dispose() { }

    public void Started(int pid, int parentPid, string name, string? commandLine, DateTimeOffset at, string? imagePath = null) =>
        ProcessStarted?.Invoke(this, new ProcessStartedEventArgs
        {
            ProcessId = pid,
            ParentProcessId = parentPid,
            ProcessName = name,
            ImagePath = imagePath,
            CommandLine = commandLine,
            TimestampUtc = at,
            Source = "ETW",
            SessionId = 1
        });

    public void Stopped(int pid, DateTimeOffset at, int exitCode = 0) =>
        ProcessStopped?.Invoke(this, new ProcessStoppedEventArgs { ProcessId = pid, ExitCode = exitCode, TimestampUtc = at });
}

/// <summary>A throwaway log directory per test.</summary>
internal sealed class TempDir : IDisposable
{
    public string Path { get; } = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "cmdspy-tests-" + Guid.NewGuid().ToString("N"));

    public void Dispose()
    {
        try { if (Directory.Exists(Path)) Directory.Delete(Path, recursive: true); } catch { }
    }
}

internal static class Wait
{
    /// <summary>Polls until <paramref name="condition"/> holds or the timeout passes.</summary>
    public static bool Until(Func<bool> condition, TimeSpan? timeout = null)
    {
        var deadline = DateTime.UtcNow + (timeout ?? TimeSpan.FromSeconds(15));
        while (DateTime.UtcNow < deadline)
        {
            if (condition()) return true;
            Thread.Sleep(25);
        }
        return condition();
    }
}

/// <summary>Runs only on Windows.</summary>
public sealed class WindowsFactAttribute : FactAttribute
{
    public WindowsFactAttribute()
    {
        if (!OperatingSystem.IsWindows()) Skip = "Windows only.";
    }
}

/// <summary>Runs only on Windows with Administrator rights (kernel ETW sessions).</summary>
public sealed class AdminFactAttribute : FactAttribute
{
    public AdminFactAttribute()
    {
        if (!OperatingSystem.IsWindows()) Skip = "Windows only.";
        else if (!IsElevated()) Skip = "Needs Administrator rights (kernel ETW).";
    }

    private static bool IsElevated()
    {
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch
        {
            return false;
        }
    }
}
