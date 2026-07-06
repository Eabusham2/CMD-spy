using System;
using System.Runtime.InteropServices;

namespace CmdSpy.Core.Monitoring;

/// <summary>
/// System-wide timing helpers used to answer "when did this happen relative to
/// boot?". <see cref="GetTickCount64"/> counts milliseconds since the machine
/// started (including time spent in sleep), which is exactly what we want.
/// </summary>
public static class SystemTimings
{
    [DllImport("kernel32.dll")]
    private static extern ulong GetTickCount64();

    /// <summary>Time elapsed since the machine booted.</summary>
    public static TimeSpan Uptime => TimeSpan.FromMilliseconds(GetTickCount64());

    /// <summary>Local wall-clock time at which the machine last booted.</summary>
    public static DateTimeOffset BootTimeLocal => DateTimeOffset.Now - Uptime;
}
