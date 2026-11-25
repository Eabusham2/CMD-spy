using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace CmdSpy.Core;

/// <summary>Runtime configuration for the capture engine.</summary>
public sealed class CmdSpyOptions
{
    /// <summary>
    /// Executable names that count as a "cmd popup". Compared case-insensitively
    /// and with/without the ".exe" suffix. Defaults to every known console,
    /// terminal and script host (see <see cref="ExtendedTargets"/>).
    /// </summary>
    public HashSet<string> TargetProcessNames { get; set; } =
        new(ExtendedTargets, StringComparer.OrdinalIgnoreCase);

    public bool CaptureNetwork { get; set; } = true;
    public bool CaptureChildren { get; set; } = true;
    public bool CaptureParentDetails { get; set; } = true;

    /// <summary>Where JSON-lines and human-readable logs are written.</summary>
    public string LogDirectory { get; set; } = DefaultLogDirectory();

    /// <summary>Cap on in-memory retained events (the GUI's live list).</summary>
    public int MaxInMemoryEvents { get; set; } = 10_000;

    /// <summary>
    /// How long a captured popup is tracked for child-process attribution and
    /// exit/lifetime after it is first seen. Entries older than this that were
    /// never observed exiting are evicted, so the active-tracking map can't grow
    /// without bound and a reused PID isn't attributed to a long-gone process.
    /// </summary>
    public TimeSpan ActiveTrackingWindow { get; set; } = TimeSpan.FromMinutes(10);

    // ---- Investigation ----------------------------------------------------

    /// <summary>
    /// Run the background investigation for each capture: launch chain,
    /// referenced processes, command explanation, suspicious indicators,
    /// signatures, scheduled task, event-log history and risk assessment.
    /// </summary>
    public bool InvestigateEvents { get; set; } = true;

    /// <summary>Check Authenticode signatures and publishers of the executables involved.</summary>
    public bool VerifySignatures { get; set; } = true;

    /// <summary>
    /// Recheck signatures and file metadata on every analysis instead of using
    /// the size/timestamp cache. Off by default because it adds disk and CPU work.
    /// </summary>
    public bool AlwaysRecheckFileSignatures { get; set; }

    /// <summary>Compute SHA-256 hashes of the executables involved.</summary>
    public bool ComputeFileHashes { get; set; } = true;

    /// <summary>Work out which scheduled task (if any) caused a launch.</summary>
    public bool CorrelateScheduledTasks { get; set; } = true;

    /// <summary>Read related Windows event logs (Security 4688, Sysmon, PowerShell, Task Scheduler).</summary>
    public bool CorrelateEventLogs { get; set; } = true;

    /// <summary>
    /// Snapshot every running process when monitoring starts, so parents and
    /// referenced PIDs that predate CMD-spy can still be identified.
    /// </summary>
    public bool SeedProcessCache { get; set; } = true;

    /// <summary>How long exited processes are remembered for launch chains and PID lookups.</summary>
    public TimeSpan ProcessHistoryRetention { get; set; } = TimeSpan.FromHours(6);

    /// <summary>Upper bound on descendants (children, grandchildren...) recorded per popup.</summary>
    public int MaxDescendantsPerEvent { get; set; } = 200;

    // ---- Network ----------------------------------------------------------

    /// <summary>
    /// Capture connections as they happen through a separate ETW kernel network
    /// session (TCP connect/accept, UDP send), in addition to the snapshot.
    /// </summary>
    public bool CaptureNetworkEvents { get; set; } = true;

    // ---- ETW session names -------------------------------------------------

    /// <summary>Kernel process-trace session name (distinct per host so the GUI and service don't collide).</summary>
    public string EtwSessionName { get; set; } = "CmdSpy-KernelProcessSession";

    /// <summary>Kernel network-trace session name.</summary>
    public string EtwNetworkSessionName { get; set; } = "CmdSpy-KernelNetworkSession";

    public static string DefaultLogDirectory() => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "CmdSpy", "logs");

    /// <summary>
    /// Every console-host, terminal and script-host executable CMD-spy knows how
    /// to watch — anything that can produce a flashing command window. This is
    /// the default target set. Includes the Windows Terminal app
    /// (wt / WindowsTerminal / OpenConsole).
    /// </summary>
    public static IReadOnlyCollection<string> ExtendedTargets { get; } = new[]
    {
        "cmd.exe", "powershell.exe", "pwsh.exe", "conhost.exe",
        "wscript.exe", "cscript.exe", "mshta.exe",
        "wt.exe", "WindowsTerminal.exe", "OpenConsole.exe"
    };

    /// <summary>Returns the configured targets reduced to lower-case stems (no extension).</summary>
    public HashSet<string> TargetStems()
    {
        var stems = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var name in TargetProcessNames)
            stems.Add(Stem(name));
        return stems;
    }

    /// <summary>"C:\\Windows\\System32\\cmd.exe" or "CMD.EXE" -> "cmd".</summary>
    public static string Stem(string nameOrPath)
    {
        if (string.IsNullOrWhiteSpace(nameOrPath)) return "";
        var file = nameOrPath;
        int slash = file.LastIndexOfAny(new[] { '\\', '/' });
        if (slash >= 0) file = file[(slash + 1)..];
        if (file.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
            file = file[..^4];
        return file.Trim();
    }
}
