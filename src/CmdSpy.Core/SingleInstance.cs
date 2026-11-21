using System;
using System.IO;
using System.Threading;

namespace CmdSpy.Core;

/// <summary>
/// Makes sure only one CMD-spy window runs on the machine. The first copy owns
/// a named mutex; any later start asks it to show its window and exits, so
/// there is never a second capture session writing the same logs.
/// </summary>
public sealed class SingleInstance : IDisposable
{
    public const string DefaultName = "CmdSpy.SingleInstance";

    private readonly Mutex? _mutex;
    private readonly EventWaitHandle? _activate;
    private readonly string _eventName;
    private RegisteredWaitHandle? _registration;

    public SingleInstance(string name = DefaultName)
    {
        _eventName = @"Global\" + name + ".Activate";
        try
        {
            _mutex = new Mutex(initiallyOwned: true, @"Global\" + name, out bool createdNew);
            IsFirst = createdNew;
        }
        catch (UnauthorizedAccessException)
        {
            IsFirst = false;   // it exists, held by a copy running with more rights
        }
        catch (Exception ex) when (ex is IOException or WaitHandleCannotBeOpenedException or PlatformNotSupportedException)
        {
            IsFirst = true;    // named mutexes unavailable: don't block start-up
        }

        if (IsFirst)
        {
            try { _activate = new EventWaitHandle(false, EventResetMode.AutoReset, _eventName); }
            catch { /* activation requests just won't be received */ }
        }
    }

    /// <summary>True for the copy that gets to run.</summary>
    public bool IsFirst { get; }

    /// <summary>Asks the running copy to bring its window forward. Returns false if it couldn't be reached.</summary>
    public bool ActivateFirst()
    {
        try
        {
            if (!EventWaitHandle.TryOpenExisting(_eventName, out var handle)) return false;
            using (handle) handle.Set();
            return true;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>Calls <paramref name="onActivate"/> (on a thread-pool thread) whenever another start asks this copy to show itself.</summary>
    public void OnActivationRequested(Action onActivate)
    {
        if (_activate is null || _registration is not null) return;
        _registration = ThreadPool.RegisterWaitForSingleObject(_activate, (_, _) =>
        {
            try { onActivate(); } catch { }
        }, null, Timeout.Infinite, executeOnlyOnce: false);
    }

    public void Dispose()
    {
        _registration?.Unregister(null);
        _registration = null;
        _activate?.Dispose();
        if (_mutex is not null)
        {
            if (IsFirst)
            {
                try { _mutex.ReleaseMutex(); } catch { /* released by another thread or already gone */ }
            }
            _mutex.Dispose();
        }
    }
}
