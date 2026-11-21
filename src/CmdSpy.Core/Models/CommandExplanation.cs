using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace CmdSpy.Core.Models;

/// <summary>A plain-English reading of what a captured command does.</summary>
public sealed class CommandExplanation
{
    /// <summary>"PowerShell execution", "Command Prompt (cmd.exe)", "Windows Script Host"...</summary>
    public string Interpreter { get; set; } = "";

    /// <summary>The command the interpreter was asked to run (after /c, -Command, ...).</summary>
    public string? InnerCommand { get; set; }

    /// <summary>Decoded text of a -EncodedCommand payload.</summary>
    public string? DecodedCommand { get; set; }

    /// <summary>Script file run by -File / wscript / cscript.</summary>
    public string? ScriptPath { get; set; }

    /// <summary>One-paragraph explanation.</summary>
    public string Summary { get; set; } = "";

    /// <summary>Step-by-step notes, one per command in the line.</summary>
    public List<string> Details { get; set; } = new();

    /// <summary>What the command does to the system ("Process discovery", "Writes files", "Network"...).</summary>
    public List<string> Effects { get; set; } = new();

    /// <summary>Notable launch switches (hidden window, execution-policy bypass...).</summary>
    public List<string> Switches { get; set; } = new();

    /// <summary>True when every step only reads; false when something changes; null when unknown.</summary>
    public bool? IsReadOnly { get; set; }

    [JsonIgnore]
    public string Classification => IsReadOnly switch
    {
        true => "Read-only query",
        false => "Makes changes or launches activity",
        _ => "Could not fully determine"
    };
}
