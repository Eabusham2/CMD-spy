using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace CmdSpy.Core.Analysis;

/// <summary>Which interpreter a command line launches.</summary>
public enum InterpreterKind
{
    Unknown,
    Cmd,
    PowerShell,
    Pwsh,
    WScript,
    CScript,
    Mshta,
    Conhost,
    WindowsTerminal,
    Other
}

/// <summary>
/// A command line broken down into what matters for analysis: which
/// interpreter runs, what it is asked to run (after <c>/c</c>, <c>-Command</c>,
/// a decoded <c>-EncodedCommand</c>...), and the notable launch switches.
/// </summary>
public sealed class ParsedCommand
{
    public string Raw { get; init; } = "";
    public IReadOnlyList<CommandToken> Tokens { get; init; } = Array.Empty<CommandToken>();
    public string Executable { get; init; } = "";
    public string ExecutableName { get; init; } = "";
    public InterpreterKind Kind { get; init; }

    /// <summary>The command the interpreter runs (cmd /c ..., powershell -Command ...).</summary>
    public string? InnerCommand { get; set; }

    public string? EncodedCommand { get; set; }
    public string? DecodedCommand { get; set; }
    public bool DecodeFailed { get; set; }

    public string? ScriptPath { get; set; }
    public string? ScriptArguments { get; set; }

    public bool HiddenWindow { get; set; }
    public bool NoProfile { get; set; }
    public bool NonInteractive { get; set; }
    public bool NoExit { get; set; }
    public bool KeepOpen { get; set; }
    public bool BypassPolicy { get; set; }
    public bool ReadsFromStdin { get; set; }
    public bool Headless { get; set; }
    public string? ExecutionPolicy { get; set; }
    public string? WindowStyle { get; set; }

    /// <summary>Human-readable notes about notable switches, in command-line order.</summary>
    public List<string> Switches { get; } = new();

    /// <summary>Interpreters invoked from inside this command (e.g. cmd /c powershell -enc ...).</summary>
    public List<ParsedCommand> Nested { get; } = new();

    /// <summary>The text worth analysing: decoded payload, else the inner command, else the raw line.</summary>
    public string AnalysisText => DecodedCommand ?? InnerCommand ?? Raw;

    public bool IsPowerShell => Kind is InterpreterKind.PowerShell or InterpreterKind.Pwsh;

    /// <summary>Every piece of text worth scanning, including nested and decoded commands.</summary>
    public IEnumerable<(string Label, string Text)> AllTexts()
    {
        if (!string.IsNullOrWhiteSpace(Raw)) yield return ("command", Raw);
        if (!string.IsNullOrWhiteSpace(DecodedCommand)) yield return ("decoded command", DecodedCommand!);
        foreach (var nested in Nested)
            foreach (var (label, text) in nested.AllTexts())
                if (label != "command") yield return ($"nested {label}", text);
    }

    public string Label => Kind switch
    {
        InterpreterKind.Cmd => "Command Prompt (cmd.exe)",
        InterpreterKind.PowerShell => "Windows PowerShell",
        InterpreterKind.Pwsh => "PowerShell 7 (pwsh.exe)",
        InterpreterKind.WScript => "Windows Script Host (wscript.exe)",
        InterpreterKind.CScript => "Windows Script Host, console (cscript.exe)",
        InterpreterKind.Mshta => "HTML Application host (mshta.exe)",
        InterpreterKind.Conhost => "Console Window Host (conhost.exe)",
        InterpreterKind.WindowsTerminal => "Windows Terminal",
        _ => string.IsNullOrEmpty(ExecutableName) ? "Unknown program" : ExecutableName
    };
}

/// <summary>Parses interpreter command lines (cmd, PowerShell, script hosts, conhost, Windows Terminal).</summary>
public static class CommandParser
{
    private const int MaxNesting = 3;

    public static ParsedCommand Parse(string? commandLine, string? imageNameHint = null) =>
        Parse(commandLine ?? "", imageNameHint, 0);

    private static ParsedCommand Parse(string commandLine, string? imageNameHint, int depth)
    {
        var tokens = CommandLineTokenizer.Tokenize(commandLine);
        var exe = tokens.Count > 0 ? tokens[0].Value : "";
        var exeName = CommandLineTokenizer.FileNameOf(exe);
        var kind = KindOf(exeName);
        if (kind is InterpreterKind.Other or InterpreterKind.Unknown && imageNameHint is not null)
        {
            var hinted = KindOf(CommandLineTokenizer.FileNameOf(imageNameHint));
            if (hinted is not (InterpreterKind.Other or InterpreterKind.Unknown) && tokens.Count == 0)
                kind = hinted;
        }

        var parsed = new ParsedCommand
        {
            Raw = commandLine,
            Tokens = tokens,
            Executable = exe,
            ExecutableName = exeName,
            Kind = kind
        };

        switch (kind)
        {
            case InterpreterKind.Cmd: ParseCmd(parsed); break;
            case InterpreterKind.PowerShell:
            case InterpreterKind.Pwsh: ParsePowerShell(parsed); break;
            case InterpreterKind.WScript:
            case InterpreterKind.CScript: ParseScriptHost(parsed); break;
            case InterpreterKind.Mshta: ParseMshta(parsed); break;
            case InterpreterKind.Conhost: ParseConhost(parsed); break;
            case InterpreterKind.WindowsTerminal: ParseTerminal(parsed); break;
        }

        if (depth < MaxNesting)
            AddNested(parsed, depth);

        return parsed;
    }

    public static InterpreterKind KindOf(string? exeName)
    {
        var stem = CmdSpyOptions.Stem(exeName ?? "").ToLowerInvariant();
        return stem switch
        {
            "" => InterpreterKind.Unknown,
            "cmd" => InterpreterKind.Cmd,
            "powershell" or "powershell_ise" => InterpreterKind.PowerShell,
            "pwsh" => InterpreterKind.Pwsh,
            "wscript" => InterpreterKind.WScript,
            "cscript" => InterpreterKind.CScript,
            "mshta" => InterpreterKind.Mshta,
            "conhost" => InterpreterKind.Conhost,
            "wt" or "windowsterminal" or "openconsole" => InterpreterKind.WindowsTerminal,
            _ => InterpreterKind.Other
        };
    }

    // ------------------------------------------------------------------ cmd --

    private static void ParseCmd(ParsedCommand p)
    {
        bool stripQuotesFlag = false;
        for (int i = 1; i < p.Tokens.Count; i++)
        {
            var t = p.Tokens[i].Value;
            if (t.Length < 2 || t[0] != '/')
            {
                // No /c or /k: cmd runs interactively with whatever follows ignored.
                break;
            }

            var sw = char.ToLowerInvariant(t[1]);
            if (sw is 'c' or 'k')
            {
                p.KeepOpen = sw == 'k';
                p.Switches.Add(sw == 'c'
                    ? "/c — runs the command, then the window closes"
                    : "/k — runs the command and keeps the window open");

                // "/cdir" style: the command can be glued to the switch.
                var glued = t.Length > 2 ? t[2..] : "";
                var rest = CommandLineTokenizer.RawAfter(p.Raw, p.Tokens, i);
                var inner = glued.Length > 0
                    ? (p.Raw[(p.Tokens[i].Start + 2)..]).TrimStart()
                    : rest;
                p.InnerCommand = ApplyCmdQuoteRules(inner, stripQuotesFlag);
                return;
            }

            switch (sw)
            {
                case 's': stripQuotesFlag = true; break;
                case 'q': p.Switches.Add("/q — command echo turned off"); break;
                case 'd': p.Switches.Add("/d — skips AutoRun commands from the registry"); break;
                case 'v':
                    if (t.EndsWith(":on", StringComparison.OrdinalIgnoreCase))
                        p.Switches.Add("/v:on — delayed variable expansion (sometimes used to obfuscate)");
                    break;
            }
        }
    }

    /// <summary>
    /// cmd strips the first and last quote of the /c text unless it is exactly a
    /// quoted program name (two quotes, whitespace inside, no special characters).
    /// </summary>
    private static string ApplyCmdQuoteRules(string inner, bool slashS)
    {
        var text = inner.Trim();
        if (text.Length < 2 || text[0] != '"') return text;
        var last = text.LastIndexOf('"');
        if (last <= 0) return text;

        int quoteCount = text.Count(c => c == '"');
        var between = text[1..last];
        bool special = between.IndexOfAny(new[] { '&', '<', '>', '(', ')', '@', '^', '|' }) >= 0;
        bool keep = !slashS && quoteCount == 2 && !special && between.Contains(' ') && last == text.Length - 1;
        if (keep) return text;
        return (text[1..last] + text[(last + 1)..]).Trim();
    }

    // ----------------------------------------------------------- PowerShell --

    private static readonly string[] PowerShellParameters =
    {
        "PSConsoleFile", "Version", "NoLogo", "NoExit", "Sta", "Mta", "NoProfile", "NonInteractive",
        "InputFormat", "OutputFormat", "WindowStyle", "EncodedCommand", "ConfigurationName", "File",
        "ExecutionPolicy", "Command", "Help", "Login", "SettingsFile", "WorkingDirectory",
        "CommandWithArgs", "CustomPipeName", "EncodedArguments", "Interactive", "ConfigurationFile"
    };

    private static readonly Dictionary<string, string> PowerShellAliases = new(StringComparer.OrdinalIgnoreCase)
    {
        ["e"] = "EncodedCommand", ["ec"] = "EncodedCommand", ["en"] = "EncodedCommand", ["enc"] = "EncodedCommand",
        ["enco"] = "EncodedCommand", ["encod"] = "EncodedCommand",
        ["c"] = "Command", ["f"] = "File", ["w"] = "WindowStyle", ["win"] = "WindowStyle",
        ["ep"] = "ExecutionPolicy", ["ex"] = "ExecutionPolicy", ["exe"] = "ExecutionPolicy", ["exec"] = "ExecutionPolicy",
        ["nop"] = "NoProfile", ["noni"] = "NonInteractive", ["nol"] = "NoLogo", ["noe"] = "NoExit",
        ["v"] = "Version", ["s"] = "Sta", ["m"] = "Mta", ["?"] = "Help", ["h"] = "Help",
        ["cwa"] = "CommandWithArgs", ["wd"] = "WorkingDirectory", ["l"] = "Login",
        ["if"] = "InputFormat", ["of"] = "OutputFormat", ["o"] = "OutputFormat", ["config"] = "ConfigurationName"
    };

    private static readonly HashSet<string> PowerShellValueParameters = new(StringComparer.OrdinalIgnoreCase)
    {
        "PSConsoleFile", "Version", "InputFormat", "OutputFormat", "WindowStyle", "EncodedCommand",
        "ConfigurationName", "ExecutionPolicy", "SettingsFile", "WorkingDirectory", "CustomPipeName",
        "EncodedArguments", "ConfigurationFile"
    };

    private static readonly char[] SwitchPrefixes = { '-', '/', '–', '—', '―' };

    /// <summary>Maps "-enc", "/EncodedCom", "–c" (en dash) etc. to the canonical parameter name.</summary>
    public static string? ResolvePowerShellParameter(string token)
    {
        if (token.Length < 2 || Array.IndexOf(SwitchPrefixes, token[0]) < 0) return null;
        var name = token.TrimStart(SwitchPrefixes);
        var colon = name.IndexOf(':');
        if (colon > 0) name = name[..colon];
        if (name.Length == 0) return null;

        if (PowerShellAliases.TryGetValue(name, out var alias)) return alias;

        var matches = PowerShellParameters
            .Where(p => p.StartsWith(name, StringComparison.OrdinalIgnoreCase))
            .ToList();
        if (matches.Count == 1) return matches[0];
        if (matches.Count > 1)
        {
            // PowerShell's own tie-breaks for the common abbreviations.
            if (matches.Contains("EncodedCommand") && name.StartsWith("e", StringComparison.OrdinalIgnoreCase)) return "EncodedCommand";
            if (matches.Contains("Command")) return "Command";
            if (matches.Contains("NonInteractive") && name.StartsWith("non", StringComparison.OrdinalIgnoreCase)) return "NonInteractive";
            return matches[0];
        }
        return null;
    }

    private static void ParsePowerShell(ParsedCommand p)
    {
        var tokens = p.Tokens;
        for (int i = 1; i < tokens.Count; i++)
        {
            var token = tokens[i].Value;
            var param = ResolvePowerShellParameter(token);

            if (param is null)
            {
                // First bare argument: Windows PowerShell treats the rest as a
                // command; PowerShell 7 treats it as a script file.
                if (p.Kind == InterpreterKind.Pwsh)
                {
                    p.ScriptPath = token;
                    p.ScriptArguments = JoinFrom(tokens, i + 1);
                }
                else
                {
                    p.InnerCommand = JoinFrom(tokens, i);
                }
                return;
            }

            // Inline value: -WindowStyle:Hidden
            string? inlineValue = null;
            var colon = token.IndexOf(':', 1);
            if (colon > 0 && colon < token.Length - 1) inlineValue = token[(colon + 1)..];

            string? NextValue()
            {
                if (inlineValue is not null) return inlineValue;
                if (i + 1 < tokens.Count) { i++; return tokens[i].Value; }
                return null;
            }

            switch (param)
            {
                case "Command":
                case "CommandWithArgs":
                    p.Switches.Add("-Command — runs the text that follows");
                    var command = inlineValue ?? JoinFrom(tokens, i + 1);
                    if (command.Trim() == "-")
                    {
                        p.ReadsFromStdin = true;
                        p.Switches.Add("-Command - — reads the commands from standard input (not visible here)");
                    }
                    else
                    {
                        p.InnerCommand = command;
                    }
                    return;

                case "EncodedCommand":
                    var encoded = NextValue();
                    p.EncodedCommand = encoded;
                    p.Switches.Add("-EncodedCommand — the command is hidden in Base64");
                    if (encoded is not null)
                    {
                        p.DecodedCommand = DecodePowerShellBase64(encoded);
                        p.DecodeFailed = p.DecodedCommand is null;
                    }
                    break;

                case "File":
                    p.ScriptPath = NextValue();
                    p.ScriptArguments = JoinFrom(tokens, i + 1);
                    p.Switches.Add("-File — runs a script file");
                    return;

                case "WindowStyle":
                    p.WindowStyle = NextValue();
                    if (p.WindowStyle is not null &&
                        (p.WindowStyle.StartsWith("h", StringComparison.OrdinalIgnoreCase) || p.WindowStyle == "1"))
                    {
                        p.HiddenWindow = true;
                        p.Switches.Add("-WindowStyle Hidden — runs without a visible window");
                    }
                    else if (p.WindowStyle is not null)
                    {
                        p.Switches.Add($"-WindowStyle {p.WindowStyle}");
                    }
                    break;

                case "ExecutionPolicy":
                    p.ExecutionPolicy = NextValue();
                    if (p.ExecutionPolicy is not null &&
                        (p.ExecutionPolicy.Equals("Bypass", StringComparison.OrdinalIgnoreCase) ||
                         p.ExecutionPolicy.Equals("Unrestricted", StringComparison.OrdinalIgnoreCase)))
                    {
                        p.BypassPolicy = true;
                        p.Switches.Add($"-ExecutionPolicy {p.ExecutionPolicy} — ignores the script-blocking policy");
                    }
                    break;

                case "NoProfile":
                    p.NoProfile = true;
                    p.Switches.Add("-NoProfile — skips the user's PowerShell profile");
                    break;

                case "NonInteractive":
                    p.NonInteractive = true;
                    p.Switches.Add("-NonInteractive — no prompts for the user");
                    break;

                case "NoExit":
                    p.NoExit = true;
                    p.Switches.Add("-NoExit — keeps the window open");
                    break;

                case "NoLogo":
                    break;

                default:
                    if (PowerShellValueParameters.Contains(param)) NextValue();
                    break;
            }
        }
    }

    /// <summary>Decodes a -EncodedCommand payload (Base64 of UTF-16LE text).</summary>
    public static string? DecodePowerShellBase64(string encoded)
    {
        var b64 = encoded.Trim().Trim('"', '\'');
        if (b64.Length == 0) return null;
        var mod = b64.Length % 4;
        if (mod == 1) return null;
        if (mod != 0) b64 += new string('=', 4 - mod);
        try
        {
            var bytes = Convert.FromBase64String(b64);
            var unicode = Encoding.Unicode.GetString(bytes);
            if (LooksLikeText(unicode)) return unicode;
            var utf8 = Encoding.UTF8.GetString(bytes);
            if (LooksLikeText(utf8)) return utf8;
        }
        catch (FormatException)
        {
        }
        return null;
    }

    private static bool LooksLikeText(string text)
    {
        if (text.Length == 0) return false;
        int printable = text.Count(c => !char.IsControl(c) || c is '\r' or '\n' or '\t');
        return printable >= text.Length * 0.9;
    }

    // ---------------------------------------------------------- script hosts --

    private static void ParseScriptHost(ParsedCommand p)
    {
        for (int i = 1; i < p.Tokens.Count; i++)
        {
            var t = p.Tokens[i].Value;
            if (t.StartsWith("//", StringComparison.Ordinal))
            {
                if (t.Equals("//B", StringComparison.OrdinalIgnoreCase))
                    p.Switches.Add("//B — batch mode: script errors and prompts are hidden");
                else if (t.StartsWith("//E:", StringComparison.OrdinalIgnoreCase))
                    p.Switches.Add($"{t} — forces the script engine (can disguise a script's real type)");
                continue;
            }
            p.ScriptPath = t;
            p.ScriptArguments = JoinFrom(p.Tokens, i + 1);
            return;
        }
    }

    private static void ParseMshta(ParsedCommand p)
    {
        if (p.Tokens.Count > 1)
            p.InnerCommand = CommandLineTokenizer.RawAfter(p.Raw, p.Tokens, 0);
    }

    private static void ParseConhost(ParsedCommand p)
    {
        for (int i = 1; i < p.Tokens.Count; i++)
        {
            var t = p.Tokens[i].Value;
            if (t.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ||
                t.Equals("-ForceV1", StringComparison.OrdinalIgnoreCase) ||
                t.Equals("-Embedding", StringComparison.OrdinalIgnoreCase))
                continue;
            if (t.Equals("--headless", StringComparison.OrdinalIgnoreCase))
            {
                p.Headless = true;
                p.Switches.Add("--headless — runs a program with no console window at all");
                continue;
            }
            if (t is "--width" or "--height" or "--signal" or "--server" or "--vtmode" or "--feature")
            {
                i++;
                continue;
            }
            if (t.StartsWith("--", StringComparison.Ordinal)) continue;

            p.InnerCommand = p.Raw[p.Tokens[i].Start..].Trim();
            return;
        }
    }

    private static void ParseTerminal(ParsedCommand p)
    {
        if (p.Tokens.Count > 1)
            p.InnerCommand = CommandLineTokenizer.RawAfter(p.Raw, p.Tokens, 0);
    }

    // --------------------------------------------------------------- nesting --

    private static void AddNested(ParsedCommand p, int depth)
    {
        var inner = p.DecodedCommand ?? p.InnerCommand;
        if (string.IsNullOrWhiteSpace(inner)) return;

        var statements = p.Kind == InterpreterKind.Cmd || p.Kind == InterpreterKind.Conhost
            ? StatementSplitter.SplitCmd(inner)
            : StatementSplitter.SplitPowerShell(inner);

        foreach (var statement in statements)
        {
            var first = FirstWord(statement);
            var kind = KindOf(CommandLineTokenizer.FileNameOf(first));
            if (kind is InterpreterKind.Other or InterpreterKind.Unknown) continue;
            p.Nested.Add(Parse(statement, null, depth + 1));
        }
    }

    internal static string FirstWord(string statement)
    {
        var tokens = CommandLineTokenizer.Tokenize(statement.TrimStart('@', ' ', '\t', '(', '&', '.'));
        return tokens.Count > 0 ? tokens[0].Value.Replace("^", "") : "";
    }

    private static string JoinFrom(IReadOnlyList<CommandToken> tokens, int start) =>
        start >= tokens.Count ? "" : string.Join(" ", tokens.Skip(start).Select(t => t.Value));
}
