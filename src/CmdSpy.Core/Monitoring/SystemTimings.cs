using System;

namespace CmdSpy.Core.Monitoring;

/// <summary>
/// System-wide timing helpers used to answer "when did this happen relative to
/// boot?". <see cref="Environment.TickCount64"/> counts milliseconds since the
/// machine started (on Windows it is GetTickCount64, which includes time spent
/// in sleep), which is exactly what we want.
/// </summary>
public static class SystemTimings
{
    /// <summary>Time elapsed since the machine booted.</summary>
    public static TimeSpan Uptime => TimeSpan.FromMilliseconds(Environment.TickCount64);

    /// <summary>Local wall-clock time at which the machine last booted.</summary>
    public static DateTimeOffset BootTimeLocal => DateTimeOffset.Now - Uptime;
}
