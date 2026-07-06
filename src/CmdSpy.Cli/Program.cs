using System;
using System.Threading;
using CmdSpy.Core;
using CmdSpy.Core.Models;

namespace CmdSpy.Cli;

/// <summary>
/// Headless CMD-spy: starts the capture engine, streams sightings to the console
/// and writes them to the log files. Handy for running as a background/scheduled
/// task when you only care about the log file, not the GUI.
///
/// Usage:
///   cmdspy [--extended] [--no-network] [--no-children] [--log-dir &lt;path&gt;]
/// </summary>
internal static class Program
{
    private static int Main(string[] args)
    {
        if (HasFlag(args, "--help") || HasFlag(args, "-h"))
        {
            PrintUsage();
            return 0;
        }

        var options = new CmdSpyOptions();

        if (HasFlag(args, "--extended"))
        {
            options.TargetProcessNames.Clear();
            foreach (var t in CmdSpyOptions.ExtendedTargets)
                options.TargetProcessNames.Add(t);
        }
        if (HasFlag(args, "--no-network")) options.CaptureNetwork = false;
        if (HasFlag(args, "--no-children")) options.CaptureChildren = false;

        var logDir = GetValue(args, "--log-dir");
        if (!string.IsNullOrWhiteSpace(logDir)) options.LogDirectory = logDir;

        using var engine = new CmdSpyEngine(options);

        engine.Status += (_, msg) => Console.Error.WriteLine($"[cmdspy] {msg}");
        engine.EventCaptured += (_, ev) => PrintCaptured(ev);
        engine.EventUpdated += (_, ev) => PrintUpdated(ev);

        Console.WriteLine("CMD-spy — watching for command-prompt popups. Press Ctrl+C to stop.");
        Console.WriteLine($"Targets : {string.Join(", ", options.TargetProcessNames)}");
        Console.WriteLine($"Log dir : {options.LogDirectory}");
        Console.WriteLine(new string('-', 60));

        try
        {
            engine.Start();
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Failed to start: {ex.Message}");
            return 1;
        }

        using var stop = new ManualResetEventSlim(false);
        Console.CancelKeyPress += (_, e) =>
        {
            e.Cancel = true;   // let us shut down cleanly
            stop.Set();
        };
        stop.Wait();

        Console.WriteLine("Stopping…");
        engine.Stop();
        return 0;
    }

    private static void PrintCaptured(CmdEvent ev)
    {
        Console.WriteLine(
            $"#{ev.SequenceNumber}  {ev.TimeLocalDisplay}  (+{ev.SinceBootDisplay})  " +
            $"PID {ev.ProcessId}  {ev.ProcessName}  <= {ev.CauseDisplay}");
        Console.WriteLine($"    cmd: {ev.CommandLine ?? "(not available)"}");
    }

    private static void PrintUpdated(CmdEvent ev)
    {
        if (ev.LifetimeMilliseconds is not null)
            Console.WriteLine($"    #{ev.SequenceNumber} exited after {ev.LifetimeDisplay} " +
                              $"(exit {ev.ExitCode?.ToString() ?? "?"})");
        else if (ev.ChildProcesses.Count > 0)
            Console.WriteLine($"    #{ev.SequenceNumber} action: {ev.ChildProcesses[^1]}");
    }

    private static bool HasFlag(string[] args, string flag) =>
        Array.Exists(args, a => string.Equals(a, flag, StringComparison.OrdinalIgnoreCase));

    private static string? GetValue(string[] args, string key)
    {
        for (int i = 0; i < args.Length - 1; i++)
            if (string.Equals(args[i], key, StringComparison.OrdinalIgnoreCase))
                return args[i + 1];
        return null;
    }

    private static void PrintUsage()
    {
        Console.WriteLine("""
            CMD-spy (headless logger)

            Usage:
              cmdspy [options]

            Options:
              --extended       Watch cmd, powershell, pwsh, conhost, wscript, cscript, mshta
              --no-network     Do not snapshot network connections
              --no-children    Do not record child processes (actions)
              --log-dir <dir>  Override the log directory
              -h, --help       Show this help

            Run elevated (as Administrator) for full-fidelity ETW capture.
            """);
    }
}
