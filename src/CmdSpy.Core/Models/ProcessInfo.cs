using System;

namespace CmdSpy.Core.Models;

/// <summary>
/// Lightweight description of a process. Used for both the "cause" (parent)
/// of a cmd popup and for the child processes it launches ("actions").
/// </summary>
public sealed class ProcessInfo
{
    public int ProcessId { get; set; }
    public string ProcessName { get; set; } = "";
    public string? ImagePath { get; set; }
    public string? CommandLine { get; set; }
    public DateTimeOffset ObservedAtUtc { get; set; }

    public override string ToString()
    {
        var cmd = string.IsNullOrWhiteSpace(CommandLine) ? ImagePath : CommandLine;
        return $"[{ProcessId}] {ProcessName}{(string.IsNullOrWhiteSpace(cmd) ? "" : " :: " + cmd)}";
    }
}
