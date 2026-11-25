using System;
using System.Collections.Generic;
using System.Linq;
using System.Management.Automation.Language;
using System.Text;
using System.Text.RegularExpressions;
using CmdSpy.Core.Models;

namespace CmdSpy.Core.Analysis;

/// <summary>Effect labels used in command explanations.</summary>
public static class Effects
{
    public const string ProcessDiscovery = "Process discovery";
    public const string SystemDiscovery = "System discovery";
    public const string NetworkDiscovery = "Network discovery";
    public const string AccountDiscovery = "Account discovery";
    public const string FileDiscovery = "File discovery";
    public const string ReadsFiles = "Reads files";
    public const string ReadsRegistry = "Reads registry";
    public const string ReadsLogs = "Reads event logs";
    public const string SecurityStatus = "Reads security settings";
    public const string DataProcessing = "Formats/filters data";
    public const string ConsoleOnly = "Console output only";
    public const string Waits = "Waits / delays";
    public const string WritesFiles = "Writes files";
    public const string DeletesFiles = "Deletes files";
    public const string ModifiesRegistry = "Modifies registry";
    public const string Network = "Network activity";
    public const string Downloads = "Downloads from the internet";
    public const string LaunchesPrograms = "Launches programs";
    public const string StopsProcesses = "Stops processes";
    public const string ChangesServices = "Changes services";
    public const string ChangesTasks = "Changes scheduled tasks";
    public const string ChangesSecurity = "Changes security settings";
    public const string ChangesAccounts = "Changes user accounts";
    public const string ChangesSystem = "Changes system settings";
    public const string RunsDynamicCode = "Runs dynamically built code";
    public const string RunsScript = "Runs a script";
    public const string Unknown = "Unknown";
}

/// <summary>
/// Turns a captured command into a plain-English explanation: which
/// interpreter ran, what each command in the line does, whether anything is
/// changed, and which processes it refers to. Explanations describe evidence
/// ("no modification is evident in this command") — they never vouch that the
/// program which launched the command is safe.
/// </summary>
public static class CommandExplainer
{
    private sealed class Step
    {
        public string Detail = "";
        public string? Phrase;
        public readonly List<string> Effects = new();
        public bool? ReadOnly;

        public Step(string detail, string? phrase, bool? readOnly, params string[] effects)
        {
            Detail = detail;
            Phrase = phrase;
            ReadOnly = readOnly;
            Effects.AddRange(effects);
        }
    }

    private sealed class Context
    {
        public IReadOnlyList<ReferencedProcess> Referenced = Array.Empty<ReferencedProcess>();
        public int Depth;
    }

    private const RegexOptions Opts = RegexOptions.IgnoreCase | RegexOptions.CultureInvariant;
    private static readonly Regex UrlRegex = new(@"https?://[^\s'""\)\]>]+", Opts);
    private static readonly Regex RedirectRegex = new(@"(?<!\d)(?<op>>>?)\s*(?<target>""[^""]+""|[^\s&|]+)", Opts);

    public static CommandExplanation Explain(ParsedCommand parsed, IReadOnlyList<ReferencedProcess>? referenced = null)
    {
        var ctx = new Context { Referenced = referenced ?? Array.Empty<ReferencedProcess>() };
        return Explain(parsed, ctx);
    }

    private static CommandExplanation Explain(ParsedCommand parsed, Context ctx)
    {
        var explanation = new CommandExplanation
        {
            Interpreter = parsed.IsPowerShell ? $"PowerShell execution ({parsed.Label})" : parsed.Label,
            InnerCommand = parsed.InnerCommand,
            DecodedCommand = parsed.DecodedCommand,
            ScriptPath = parsed.ScriptPath
        };
        explanation.Switches.AddRange(parsed.Switches);

        var steps = BuildSteps(parsed, ctx);

        explanation.Details.AddRange(steps.Select(s => s.Detail).Take(30));
        var effects = steps.SelectMany(s => s.Effects).Distinct().ToList();
        explanation.Effects.AddRange(effects);

        if (steps.Count == 0)
            explanation.IsReadOnly = null;
        else if (steps.Any(s => s.ReadOnly == false))
            explanation.IsReadOnly = false;
        else if (steps.All(s => s.ReadOnly == true))
            explanation.IsReadOnly = true;
        else
            explanation.IsReadOnly = null;

        explanation.Summary = BuildSummary(parsed, steps, explanation);
        return explanation;
    }

    // --------------------------------------------------------------- steps --

    private static List<Step> BuildSteps(ParsedCommand parsed, Context ctx)
    {
        var steps = new List<Step>();

        if (parsed.EncodedCommand is not null)
        {
            steps.Add(parsed.DecodeFailed
                ? new Step("The -EncodedCommand payload could not be decoded, so what it runs can't be read.", null, null, Effects.Unknown)
                : new Step($"The real command was hidden with -EncodedCommand (Base64). Decoded, it reads: {Shorten(parsed.DecodedCommand, 300)}", null, true));
        }

        if (parsed.ReadsFromStdin)
            steps.Add(new Step("Reads its commands from standard input — they are not visible in the command line.", "runs commands fed in through standard input (not visible)", null, Effects.Unknown));

        if (parsed.ScriptPath is not null)
        {
            var args = string.IsNullOrWhiteSpace(parsed.ScriptArguments) ? "" : $" with arguments: {parsed.ScriptArguments}";
            steps.Add(new Step(
                $"Runs the script file {parsed.ScriptPath}{args}. The script's contents aren't part of the command line, so CMD-spy can't tell what it does.",
                $"runs the script {FileName(parsed.ScriptPath)}", null, Effects.RunsScript));
        }

        var text = parsed.DecodedCommand ?? parsed.InnerCommand;

        switch (parsed.Kind)
        {
            case InterpreterKind.Cmd:
                if (text is null)
                {
                    if (parsed.ScriptPath is null)
                        steps.Add(new Step("Opens an interactive Command Prompt. Anything typed into it is not part of this command line.",
                            "opens an interactive window", null, Effects.Unknown));
                    break;
                }
                foreach (var statement in StatementSplitter.SplitCmd(text))
                    steps.Add(DescribeCmdStatement(statement, ctx));
                break;

            case InterpreterKind.PowerShell:
            case InterpreterKind.Pwsh:
                if (text is null)
                {
                    if (parsed.ScriptPath is null && !parsed.ReadsFromStdin && parsed.EncodedCommand is null)
                        steps.Add(new Step("Opens an interactive PowerShell session. Anything typed into it is not part of this command line.",
                            "opens an interactive window", null, Effects.Unknown));
                    break;
                }
                steps.AddRange(DescribePowerShellScript(text, ctx));
                break;

            case InterpreterKind.WScript:
            case InterpreterKind.CScript:
                if (parsed.ScriptPath is null)
                    steps.Add(new Step("Opens the Windows Script Host settings (no script given).", "opens the script host settings", true, Effects.ConsoleOnly));
                break;

            case InterpreterKind.Mshta:
                var target = parsed.InnerCommand ?? "";
                bool inline = target.TrimStart('"').StartsWith("javascript:", StringComparison.OrdinalIgnoreCase) ||
                              target.TrimStart('"').StartsWith("vbscript:", StringComparison.OrdinalIgnoreCase);
                bool remote = UrlRegex.IsMatch(target);
                steps.Add(new Step(
                    inline ? $"Runs script code written directly in the command line: {Shorten(target, 200)}"
                           : remote ? $"Downloads and runs an HTML Application from {UrlRegex.Match(target).Value}"
                                    : $"Runs the HTML Application {Shorten(target, 200)}",
                    inline ? "runs inline script code" : remote ? "downloads and runs a remote HTML Application" : "runs an HTML Application",
                    false, remote ? new[] { Effects.Downloads, Effects.RunsDynamicCode } : new[] { Effects.RunsDynamicCode }));
                break;

            case InterpreterKind.Conhost:
                if (text is null)
                {
                    steps.Add(new Step("Console window host started by Windows to give a console program its window (normal).",
                        "provides a console window for another program (normal)", true, Effects.ConsoleOnly));
                }
                else
                {
                    steps.Add(new Step($"Uses the console host to start another program{(parsed.Headless ? " with no window at all" : "")}: {Shorten(text, 200)}",
                        $"starts another program{(parsed.Headless ? " invisibly" : "")} through the console host", false, Effects.LaunchesPrograms));
                    foreach (var statement in StatementSplitter.SplitCmd(text))
                        steps.Add(DescribeCmdStatement(statement, ctx));
                }
                break;

            case InterpreterKind.WindowsTerminal:
                steps.Add(text is null
                    ? new Step("Opens Windows Terminal.", "opens Windows Terminal", true, Effects.ConsoleOnly)
                    : new Step($"Opens Windows Terminal with: {Shorten(text, 200)}", "opens Windows Terminal with a command", null, Effects.LaunchesPrograms));
                break;

            default:
                steps.Add(DescribeProgram(parsed.Tokens.Select(t => t.Value).ToList(), parsed.Raw, ctx));
                break;
        }
        return steps;
    }

    private static string BuildSummary(ParsedCommand parsed, List<Step> steps, CommandExplanation explanation)
    {
        var noun = parsed.Kind switch
        {
            InterpreterKind.PowerShell => "Windows PowerShell",
            InterpreterKind.Pwsh => "PowerShell 7",
            InterpreterKind.Cmd => "Command Prompt",
            InterpreterKind.WScript or InterpreterKind.CScript => "Windows Script Host",
            InterpreterKind.Mshta => "mshta.exe",
            InterpreterKind.Conhost => "The console host",
            InterpreterKind.WindowsTerminal => "Windows Terminal",
            _ => parsed.ExecutableName.Length > 0 ? parsed.ExecutableName : "The program"
        };

        var phrases = steps.Select(s => s.Phrase)
            .Where(p => !string.IsNullOrWhiteSpace(p))
            .Distinct()
            .Take(4)
            .ToList();

        var sb = new StringBuilder(noun);
        if (parsed.EncodedCommand is not null && !parsed.DecodeFailed) sb.Append(" (command hidden with -EncodedCommand, decoded)");
        sb.Append(' ');
        sb.Append(phrases.Count == 0 ? "runs a command CMD-spy could not identify" : string.Join(", then ", phrases));
        sb.Append(". ");

        sb.Append(explanation.IsReadOnly switch
        {
            true => "Read-only: no modification is evident in this command.",
            false => $"It makes changes or starts activity ({string.Join(", ", explanation.Effects.Where(e => !IsReadEffect(e)).Take(4))}).",
            _ => "Part of it could not be identified, so its full effect can't be determined from the command line."
        });
        if (parsed.HiddenWindow) sb.Append(" It was set to run without a visible window.");
        return sb.ToString();
    }

    private static bool IsReadEffect(string effect) => effect is Effects.ProcessDiscovery or Effects.SystemDiscovery
        or Effects.NetworkDiscovery or Effects.AccountDiscovery or Effects.FileDiscovery or Effects.ReadsFiles
        or Effects.ReadsRegistry or Effects.ReadsLogs or Effects.SecurityStatus or Effects.DataProcessing
        or Effects.ConsoleOnly or Effects.Waits;

    // ------------------------------------------------------------------ cmd --

    private static Step DescribeCmdStatement(string statement, Context ctx)
    {
        var clean = statement.Replace("^", "").Trim().TrimStart('@').Trim();
        if (clean.Length == 0) return new Step("(empty command)", null, true);
        if (clean.StartsWith("::", StringComparison.Ordinal) || clean.StartsWith("rem ", StringComparison.OrdinalIgnoreCase) || clean.Equals("rem", StringComparison.OrdinalIgnoreCase))
            return new Step($"Comment (does nothing): {Shorten(clean, 120)}", null, true);

        // Redirection to a file (> out.txt, >> log.txt) writes a file even for "read" commands.
        string? redirectTarget = null;
        foreach (Match m in RedirectRegex.Matches(clean))
        {
            var t = m.Groups["target"].Value.Trim('"');
            if (!t.Equals("nul", StringComparison.OrdinalIgnoreCase) && !t.StartsWith("&", StringComparison.Ordinal))
                redirectTarget = t;
        }
        var withoutRedirects = RedirectRegex.Replace(clean, "").Trim();
        var tokens = CommandLineTokenizer.Tokenize(withoutRedirects).Select(t => t.Value).ToList();
        if (tokens.Count == 0) return new Step($"Runs: {clean}", null, null, Effects.Unknown);

        var step = DescribeCmdTokens(tokens, withoutRedirects, ctx);
        if (redirectTarget is not null)
        {
            step.Detail += $" Output is written to the file {redirectTarget}.";
            step.Effects.Add(Effects.WritesFiles);
            step.ReadOnly = false;
        }
        return step;
    }

    private static Step DescribeCmdTokens(List<string> tokens, string statement, Context ctx)
    {
        var name = CmdSpyOptions.Stem(CommandLineTokenizer.FileNameOf(tokens[0])).ToLowerInvariant();
        var args = tokens.Skip(1).ToList();
        var argText = string.Join(" ", args);
        bool Has(params string[] flags) => args.Any(a => flags.Any(f => a.Equals(f, StringComparison.OrdinalIgnoreCase)));
        string? First() => args.FirstOrDefault(a => !a.StartsWith("/", StringComparison.Ordinal) && !a.StartsWith("-", StringComparison.Ordinal));

        switch (name)
        {
            case "echo":
                return new Step(args.Count == 0 || argText.Equals("off", StringComparison.OrdinalIgnoreCase) || argText.Equals("on", StringComparison.OrdinalIgnoreCase)
                    ? "Turns command echo on/off." : $"Prints text: {Shorten(argText, 120)}", null, true, Effects.ConsoleOnly);
            case "cls": case "title": case "color": case "mode": case "chcp": case "prompt": case "doskey":
                return new Step($"{name}: changes how the console window looks (no effect on the system).", null, true, Effects.ConsoleOnly);
            case "exit":
                return new Step(args.Count > 0 ? $"Exits with code {args.Last()}." : "Exits.", null, true, Effects.ConsoleOnly);
            case "cd": case "chdir": case "pushd": case "popd":
                return new Step($"Changes the current folder{(args.Count > 0 ? " to " + argText : "")}.", null, true, Effects.ConsoleOnly);
            case "pause":
                return new Step("Waits for a key press.", null, true, Effects.Waits);
            case "timeout":
                var secs = args.SkipWhile(a => !a.Equals("/t", StringComparison.OrdinalIgnoreCase)).Skip(1).FirstOrDefault() ?? First();
                return new Step($"Waits {secs ?? "a few"} second(s).", "waits", true, Effects.Waits);
            case "choice":
                return new Step("Asks the user to pick an option (or waits for a timeout).", "waits", true, Effects.Waits);
            case "ver": case "vol": case "hostname": case "systeminfo": case "driverquery":
                return new Step($"{name}: shows information about this computer.", "reads system information", true, Effects.SystemDiscovery);
            case "whoami":
                return new Step("whoami: shows the current user account (and its groups/privileges with /all or /priv).", "shows who the current user is", true, Effects.AccountDiscovery);
            case "quser": case "qwinsta": case "query":
                return new Step($"{name}: lists signed-in users and sessions.", "lists user sessions", true, Effects.AccountDiscovery);
            case "set":
                if (args.Count == 0) return new Step("Lists environment variables.", "lists environment variables", true, Effects.SystemDiscovery);
                if (Has("/p")) return new Step($"Asks the user for input ({argText}).", null, true, Effects.ConsoleOnly);
                return new Step($"Sets a variable for this window only: {Shorten(argText, 120)}", null, true, Effects.ConsoleOnly);
            case "setx":
                return new Step($"Permanently sets an environment variable: {Shorten(argText, 120)}", "permanently sets an environment variable", false, Effects.ChangesSystem);
            case "if": case "for": case "goto": case "shift": case "setlocal": case "endlocal":
                return new Step($"{name}: script control flow ({Shorten(statement, 140)}).", null, null, Effects.Unknown);
            case "call":
                if (args.Count > 0 && !args[0].StartsWith(":", StringComparison.Ordinal))
                    return Prefix("Calls: ", DescribeCmdTokens(args, argText, ctx));
                return new Step($"Calls a label inside the script ({argText}).", null, null, Effects.Unknown);
            case "start":
                var startArgs = args.Where(a => !a.StartsWith("/", StringComparison.Ordinal)).ToList();
                if (startArgs.Count > 0 && startArgs[0].Length == 0) startArgs.RemoveAt(0);
                var launched = startArgs.FirstOrDefault() ?? "";
                if (UrlRegex.IsMatch(launched))
                    return new Step($"Opens the web address {launched} in the default browser.", $"opens {launched}", false, Effects.LaunchesPrograms, Effects.Network);
                var startStep = startArgs.Count > 0 ? DescribeCmdTokens(startArgs, string.Join(" ", startArgs), ctx) : null;
                return new Step($"Starts a program in a separate window: {Shorten(string.Join(" ", startArgs), 160)}" +
                                (startStep is null ? "" : $" — {startStep.Detail}"),
                    $"starts {FileName(launched)}", false, Effects.LaunchesPrograms);
            case "dir": case "tree": case "where":
                return new Step($"{name}: lists files{(First() is { } d ? " in " + d : "")}.", "lists files", true, Effects.FileDiscovery);
            case "type": case "more":
                return new Step($"Shows the contents of {First() ?? "a file"}.", $"reads {FileName(First())}", true, Effects.ReadsFiles);
            case "find": case "findstr": case "sort": case "clip":
                return new Step($"{name}: searches or filters text.", null, true, Effects.DataProcessing);
            case "copy": case "xcopy": case "robocopy":
                return new Step($"Copies files: {Shorten(argText, 160)}", "copies files", false, Effects.WritesFiles);
            case "move": case "ren": case "rename":
                return new Step($"Moves or renames files: {Shorten(argText, 160)}", "moves/renames files", false, Effects.WritesFiles);
            case "del": case "erase":
                return new Step($"Deletes files: {Shorten(argText, 160)}", "deletes files", false, Effects.DeletesFiles);
            case "rd": case "rmdir":
                return new Step($"Deletes folders: {Shorten(argText, 160)}", "deletes folders", false, Effects.DeletesFiles);
            case "md": case "mkdir":
                return new Step($"Creates the folder {argText}.", "creates a folder", false, Effects.WritesFiles);
            case "mklink":
                return new Step($"Creates a file-system link: {argText}", "creates a link", false, Effects.WritesFiles);
            case "attrib":
                return args.Any(a => a.StartsWith("+", StringComparison.Ordinal) || a.StartsWith("-", StringComparison.Ordinal))
                    ? new Step($"Changes file attributes ({argText}){(argText.Contains("+h", StringComparison.OrdinalIgnoreCase) ? " — +h hides the file" : "")}.", "changes file attributes", false, Effects.WritesFiles)
                    : new Step("Shows file attributes.", null, true, Effects.FileDiscovery);
            case "icacls": case "cacls": case "takeown":
                return name == "takeown" || Has("/grant", "/deny", "/reset", "/setowner", "/remove", "/setintegritylevel", "/e", "/g")
                    ? new Step($"Changes file permissions/ownership: {Shorten(argText, 160)}", "changes file permissions", false, Effects.ChangesSecurity)
                    : new Step($"Shows file permissions for {First()}.", null, true, Effects.SecurityStatus);
            case "cipher":
                return Has("/w") ? new Step("Wipes deleted data from free disk space (cipher /w).", "wipes free disk space", false, Effects.DeletesFiles)
                                 : new Step("Shows or changes EFS encryption (cipher).", null, null, Effects.Unknown);
            case "fsutil":
                return argText.Contains("deletejournal", StringComparison.OrdinalIgnoreCase)
                    ? new Step("Deletes the NTFS change journal (removes file-activity history).", "deletes the file-change journal", false, Effects.DeletesFiles)
                    : new Step($"File-system utility: {Shorten(argText, 120)}", null, null, Effects.Unknown);
            case "ping":
                bool delay = Regex.IsMatch(argText, @"\b(127\.0\.0\.1|localhost|::1)\b", Opts) && Regex.IsMatch(argText, @"-n\s+\d+", Opts);
                if (delay)
                {
                    var n = Regex.Match(argText, @"-n\s+(\d+)", Opts).Groups[1].Value;
                    return new Step($"Waits about {Math.Max(0, int.Parse(n) - 1)} second(s) (pinging this computer is a common delay trick).", "waits", true, Effects.Waits);
                }
                return new Step($"Tests whether {First() ?? "a host"} is reachable on the network.", $"pings {First()}", true, Effects.NetworkDiscovery);
            case "tracert": case "pathping": case "nslookup": case "netstat": case "getmac":
                return new Step($"{name}: shows network information{(First() is { } h ? " for " + h : "")}.", "reads network information", true, Effects.NetworkDiscovery);
            case "ipconfig":
                return Has("/release", "/renew", "/flushdns", "/registerdns", "/release6", "/renew6")
                    ? new Step($"Changes network settings ({argText}).", "changes network settings", false, Effects.ChangesSystem)
                    : new Step("Shows the network configuration (IP addresses, adapters).", "reads the network configuration", true, Effects.NetworkDiscovery);
            case "arp": case "route":
                return Has("-s", "-d", "add", "delete", "change", "-f")
                    ? new Step($"Changes network routing ({argText}).", "changes network routing", false, Effects.ChangesSystem)
                    : new Step($"{name}: shows the network routing/neighbour table.", "reads network tables", true, Effects.NetworkDiscovery);
            case "netsh":
                if (Regex.IsMatch(argText, @"\bkey\s*=\s*clear\b", Opts))
                    return new Step("Shows saved Wi-Fi passwords in plain text (netsh wlan ... key=clear).", "reveals saved Wi-Fi passwords", true, Effects.SecurityStatus);
                if (Regex.IsMatch(argText, @"\b(show|dump)\b", Opts))
                    return new Step($"Shows network configuration (netsh {Shorten(argText, 100)}).", "reads network settings", true, Effects.NetworkDiscovery);
                return new Step($"Changes network/firewall configuration: netsh {Shorten(argText, 140)}", "changes network/firewall settings",
                    false, argText.Contains("firewall", StringComparison.OrdinalIgnoreCase) ? Effects.ChangesSecurity : Effects.ChangesSystem);
            case "net": case "net1":
                return DescribeNet(args);
            case "tasklist":
                return new Step($"Lists running processes{(argText.Length > 0 ? $" ({Shorten(argText, 100)})" : "")}.", "lists running processes", true, Effects.ProcessDiscovery);
            case "taskkill":
                return new Step($"Ends processes: {Shorten(argText, 160)}{DescribeReferencedPids(ReferencedPidExtractor.ExtractPids(statement), ctx)}", "ends processes", false, Effects.StopsProcesses);
            case "sc":
                return DescribeSc(args);
            case "schtasks":
                return Has("/query")
                    ? new Step("Lists scheduled tasks.", "lists scheduled tasks", true, Effects.SystemDiscovery)
                    : new Step($"Changes scheduled tasks: schtasks {Shorten(argText, 160)}", Has("/create") ? "creates a scheduled task" : "changes scheduled tasks", false, Effects.ChangesTasks);
            case "reg":
                return DescribeReg(args);
            case "wmic":
                return DescribeWmic(args, statement, ctx);
            case "wevtutil":
                var verb = args.FirstOrDefault()?.ToLowerInvariant();
                return verb is "cl" or "clear-log"
                    ? new Step($"Clears the event log {args.ElementAtOrDefault(1)} (erases its history).", "clears an event log", false, Effects.ChangesSecurity)
                    : verb is "sl" or "set-log" ? new Step($"Changes event-log settings: {argText}", "changes event-log settings", false, Effects.ChangesSystem)
                    : new Step($"Reads event logs (wevtutil {verb}).", "reads event logs", true, Effects.ReadsLogs);
            case "vssadmin":
                return args.FirstOrDefault()?.Equals("list", StringComparison.OrdinalIgnoreCase) == true
                    ? new Step("Lists Volume Shadow Copies (backups).", "lists backups", true, Effects.SystemDiscovery)
                    : new Step($"Deletes or resizes Volume Shadow Copies (Windows backups): vssadmin {argText}", "deletes Windows backups", false, Effects.DeletesFiles);
            case "wbadmin":
                return Has("delete")
                    ? new Step($"Deletes Windows backups: wbadmin {argText}", "deletes Windows backups", false, Effects.DeletesFiles)
                    : new Step($"Windows backup tool: wbadmin {Shorten(argText, 120)}", null, null, Effects.Unknown);
            case "bcdedit":
                return args.Count == 0 || Has("/enum", "/v")
                    ? new Step("Shows the boot configuration.", "reads the boot configuration", true, Effects.SystemDiscovery)
                    : new Step($"Changes the boot configuration: bcdedit {argText}", "changes boot settings", false, Effects.ChangesSystem);
            case "certutil":
                if (Has("-urlcache", "/urlcache", "-verifyctl", "/verifyctl"))
                    return new Step($"Downloads a file from {UrlRegex.Match(argText).Value} using certutil (a Windows certificate tool).", "downloads a file with certutil", false, Effects.Downloads, Effects.WritesFiles);
                if (Has("-decode", "/decode", "-decodehex", "-encode", "/encode"))
                    return new Step($"Decodes/encodes a file with certutil: {argText}", "decodes a file", false, Effects.WritesFiles);
                if (Has("-hashfile", "/hashfile"))
                    return new Step($"Computes the hash of {args.ElementAtOrDefault(1)}.", "hashes a file", true, Effects.ReadsFiles);
                if (Has("-addstore", "/addstore", "-delstore", "/delstore", "-importpfx"))
                    return new Step($"Changes trusted certificates: certutil {argText}", "changes trusted certificates", false, Effects.ChangesSecurity);
                return new Step($"Certificate utility: certutil {Shorten(argText, 120)}", null, null, Effects.Unknown);
            case "bitsadmin":
                return new Step($"Background file transfer (BITS): bitsadmin {Shorten(argText, 160)}", "transfers files with BITS", false, Effects.Downloads);
            case "curl": case "wget":
                var url = UrlRegex.Match(argText).Value;
                bool saves = Has("-o", "-O", "--output", "--remote-name", "-OutFile");
                return new Step($"Sends a web request to {(url.Length > 0 ? url : First())}{(saves ? " and saves the response to a file" : "")}.",
                    saves ? "downloads a file" : "contacts a web server", false, saves ? new[] { Effects.Downloads, Effects.WritesFiles } : new[] { Effects.Network });
            case "msiexec":
                return new Step($"Windows Installer: {(Has("/x", "/uninstall") ? "uninstalls" : "installs")} software ({Shorten(argText, 140)}){(Has("/q", "/qn", "/quiet") ? " silently" : "")}.",
                    Has("/x", "/uninstall") ? "uninstalls software" : "installs software", false, Effects.ChangesSystem);
            case "rundll32":
                return new Step($"Runs a function inside a DLL: {Shorten(argText, 160)}", "runs code from a DLL", false, Effects.LaunchesPrograms);
            case "regsvr32":
                return new Step($"Registers/runs a COM DLL: {Shorten(argText, 160)}", "registers a DLL", false, Effects.ChangesSystem);
            case "explorer":
                return new Step($"Opens File Explorer{(args.Count > 0 ? " at " + argText : "")}.", "opens File Explorer", false, Effects.LaunchesPrograms);
            case "shutdown":
                return new Step($"Shuts down, restarts or logs off the computer ({argText}).", "shuts down or restarts the PC", false, Effects.ChangesSystem);
            case "logoff":
                return new Step("Signs the user out.", "signs the user out", false, Effects.ChangesSystem);
            case "format": case "diskpart":
                return new Step($"Disk/partition tool: {name} {Shorten(argText, 120)}", $"runs {name}", false, Effects.ChangesSystem);
            case "forfiles":
                return new Step($"Runs a command for each matching file: {Shorten(argText, 160)}", "runs a command per file", false, Effects.LaunchesPrograms);
            case "gpupdate":
                return new Step("Re-applies Group Policy settings.", "refreshes Group Policy", false, Effects.ChangesSystem);
            case "gpresult":
                return new Step("Shows applied Group Policy.", "reads Group Policy", true, Effects.SystemDiscovery);
            case "auditpol":
                return Has("/set", "/clear", "/remove", "/restore")
                    ? new Step($"Changes Windows audit policy: {argText}", "changes audit policy", false, Effects.ChangesSecurity)
                    : new Step("Shows Windows audit policy.", "reads audit policy", true, Effects.SecurityStatus);
            case "nltest":
                return new Step($"Queries Active Directory domain information ({argText}).", "reads domain information", true, Effects.NetworkDiscovery);
            case "klist": case "cmdkey":
                return Has("purge", "/add", "/delete", "/generic")
                    ? new Step($"Changes stored credentials/tickets: {name} {argText}", "changes stored credentials", false, Effects.ChangesSecurity)
                    : new Step($"Lists stored credentials/tickets ({name}).", "lists stored credentials", true, Effects.SecurityStatus);
            case "assoc": case "ftype":
                return argText.Contains('=')
                    ? new Step($"Changes a file-type association: {argText}", "changes file associations", false, Effects.ChangesSystem)
                    : new Step("Shows file-type associations.", null, true, Effects.SystemDiscovery);
            case "tar": case "expand": case "compact": case "makecab":
                return new Step($"Archive/compression tool: {name} {Shorten(argText, 120)}", "unpacks or packs files", false, Effects.WritesFiles);
            case "powercfg":
                return Has("/change", "/setactive", "/s", "/h", "/hibernate", "-change", "-setactive")
                    ? new Step($"Changes power settings: {argText}", "changes power settings", false, Effects.ChangesSystem)
                    : new Step("Shows power settings.", null, true, Effects.SystemDiscovery);
            case "winget":
                return Has("install", "uninstall", "upgrade", "import")
                    ? new Step($"Installs/removes software with winget: {argText}", "installs or removes software", false, Effects.ChangesSystem)
                    : new Step($"Searches/lists software with winget ({argText}).", null, true, Effects.SystemDiscovery);
            case "dism": case "sfc": case "chkdsk":
                return new Step($"{name}: Windows repair/servicing tool ({Shorten(argText, 120)}).", $"runs {name}", null, Effects.ChangesSystem);
            case "cmd": case "powershell": case "pwsh": case "wscript": case "cscript": case "mshta": case "conhost":
                return DescribeNestedInterpreter(statement, ctx);
            default:
                return DescribeProgram(tokens, statement, ctx);
        }
    }

    private static Step DescribeNet(List<string> args)
    {
        var sub = args.FirstOrDefault()?.ToLowerInvariant() ?? "";
        var rest = string.Join(" ", args.Skip(1));
        bool changes = args.Any(a => a.Equals("/add", StringComparison.OrdinalIgnoreCase) || a.Equals("/delete", StringComparison.OrdinalIgnoreCase) || a.Equals("/del", StringComparison.OrdinalIgnoreCase));
        return sub switch
        {
            "user" or "users" => changes
                ? new Step($"Creates or deletes a user account: net user {rest}", "creates/deletes a user account", false, Effects.ChangesAccounts)
                : new Step($"Lists user accounts{(rest.Length > 0 ? " / shows " + rest : "")}.", "lists user accounts", true, Effects.AccountDiscovery),
            "localgroup" or "group" => changes
                ? new Step($"Changes group membership: net {sub} {rest}", "changes group membership", false, Effects.ChangesAccounts)
                : new Step($"Lists groups or their members ({rest}).", "lists groups", true, Effects.AccountDiscovery),
            "start" => args.Count > 1
                ? new Step($"Starts the service {rest}.", $"starts the {rest} service", false, Effects.ChangesServices)
                : new Step("Lists running services.", "lists services", true, Effects.SystemDiscovery),
            "stop" => new Step($"Stops the service {rest}.", $"stops the {rest} service", false, Effects.ChangesServices),
            "use" => args.Count > 1 && !args[1].StartsWith("/", StringComparison.Ordinal)
                ? new Step($"Connects/disconnects a network drive: net use {rest}", "connects a network drive", false, Effects.Network)
                : new Step("Lists network drive connections.", "lists network drives", true, Effects.NetworkDiscovery),
            "share" => args.Count > 1
                ? new Step($"Creates or removes a network share: net share {rest}", "changes network shares", false, Effects.ChangesSystem)
                : new Step("Lists shared folders.", "lists shares", true, Effects.NetworkDiscovery),
            "view" or "session" or "config" or "statistics" => new Step($"Shows network/computer information (net {sub}).", "reads network information", true, Effects.NetworkDiscovery),
            "accounts" => args.Count > 1
                ? new Step($"Changes password/lockout policy: net accounts {rest}", "changes account policy", false, Effects.ChangesSecurity)
                : new Step("Shows password/lockout policy.", "reads account policy", true, Effects.AccountDiscovery),
            "time" => new Step($"Shows or syncs time (net time {rest}).", null, null, Effects.Unknown),
            _ => new Step($"Network command: net {string.Join(" ", args)}", null, null, Effects.Unknown)
        };
    }

    private static Step DescribeSc(List<string> args)
    {
        var verb = args.FirstOrDefault(a => !a.StartsWith(@"\\", StringComparison.Ordinal))?.ToLowerInvariant() ?? "";
        var rest = string.Join(" ", args.SkipWhile(a => !a.Equals(verb, StringComparison.OrdinalIgnoreCase)).Skip(1));
        return verb switch
        {
            "query" or "queryex" or "qc" or "qdescription" or "qfailure" or "enumdepend" or "getdisplayname" or "getkeyname" or "sdshow" or "qprivs" or "qsidtype" or "qtriggerinfo" or "quserservice" or ""
                => new Step($"Shows Windows service information ({verb} {rest}).", "reads service information", true, Effects.SystemDiscovery),
            "create" => new Step($"Creates a new Windows service: sc create {rest}", "creates a Windows service", false, Effects.ChangesServices),
            "delete" => new Step($"Deletes the Windows service {rest}.", "deletes a Windows service", false, Effects.ChangesServices),
            "start" => new Step($"Starts the service {rest}.", $"starts the {rest} service", false, Effects.ChangesServices),
            "stop" => new Step($"Stops the service {rest}.", $"stops the {rest} service", false, Effects.ChangesServices),
            _ => new Step($"Changes a Windows service: sc {verb} {rest}", "changes a Windows service", false, Effects.ChangesServices)
        };
    }

    private static Step DescribeReg(List<string> args)
    {
        var verb = args.FirstOrDefault()?.ToLowerInvariant() ?? "";
        var key = args.ElementAtOrDefault(1) ?? "";
        bool runKey = Regex.IsMatch(key, @"\\(Run|RunOnce|RunServices)\b", Opts);
        return verb switch
        {
            "query" => new Step($"Reads the registry key {key}.", "reads the registry", true, Effects.ReadsRegistry),
            "compare" => new Step($"Compares registry keys ({key}).", "reads the registry", true, Effects.ReadsRegistry),
            "export" => new Step($"Exports the registry key {key} to a file.", "exports registry data", false, Effects.ReadsRegistry, Effects.WritesFiles),
            "save" => new Step($"Saves the registry hive {key} to a file{(Regex.IsMatch(key, @"\\(SAM|SECURITY|SYSTEM)\b", Opts) ? " (this hive holds password hashes/secrets)" : "")}.",
                "saves a registry hive to a file", false, Effects.ReadsRegistry, Effects.WritesFiles),
            "add" => new Step($"Writes to the registry key {key}{(runKey ? " — a start-up (Run) key, so something will run at every logon" : "")}.",
                runKey ? "adds a start-up entry to the registry" : "writes to the registry", false, Effects.ModifiesRegistry),
            "delete" => new Step($"Deletes from the registry key {key}.", "deletes registry data", false, Effects.ModifiesRegistry),
            "import" or "restore" or "load" or "unload" or "copy" => new Step($"Changes the registry (reg {verb} {key}).", "changes the registry", false, Effects.ModifiesRegistry),
            _ => new Step($"Registry tool: reg {string.Join(" ", args)}", null, null, Effects.Unknown)
        };
    }

    private static Step DescribeWmic(List<string> args, string statement, Context ctx)
    {
        var text = string.Join(" ", args);
        if (Regex.IsMatch(text, @"\bcall\s+create\b", Opts))
            return new Step($"Starts a new process through WMI: wmic {Shorten(text, 160)}", "starts a process through WMI", false, Effects.LaunchesPrograms);
        if (Regex.IsMatch(text, @"\bcall\s+terminate\b", Opts))
            return new Step($"Ends processes through WMI: wmic {Shorten(text, 160)}{DescribeReferencedPids(ReferencedPidExtractor.ExtractPids(statement), ctx)}", "ends processes through WMI", false, Effects.StopsProcesses);
        if (Regex.IsMatch(text, @"\bdelete\b", Opts))
            return new Step($"Deletes WMI objects: wmic {Shorten(text, 160)}", "deletes objects through WMI", false, Effects.ChangesSystem);
        if (Regex.IsMatch(text, @"\b(set|call)\b", Opts))
            return new Step($"Changes settings through WMI: wmic {Shorten(text, 160)}", "changes settings through WMI", false, Effects.ChangesSystem);
        var alias = args.FirstOrDefault(a => !a.StartsWith("/", StringComparison.Ordinal))?.ToLowerInvariant() ?? "";
        var (what, effect) = alias switch
        {
            "process" => ("running processes", Effects.ProcessDiscovery),
            "service" => ("Windows services", Effects.SystemDiscovery),
            "useraccount" or "group" or "sysaccount" => ("user accounts and groups", Effects.AccountDiscovery),
            "nicconfig" or "nic" => ("network adapters", Effects.NetworkDiscovery),
            "product" => ("installed software", Effects.SystemDiscovery),
            "startup" => ("start-up programs", Effects.SystemDiscovery),
            "shadowcopy" => ("shadow copies (backups)", Effects.SystemDiscovery),
            _ => ($"WMI data ({alias})", Effects.SystemDiscovery)
        };
        return new Step($"Reads {what} through WMI (wmic {Shorten(text, 140)}){DescribeReferencedPids(ReferencedPidExtractor.ExtractPids(statement), ctx)}.",
            $"reads {what} through WMI", true, effect);
    }

    private static Step DescribeNestedInterpreter(string statement, Context ctx)
    {
        if (ctx.Depth >= 3)
            return new Step($"Starts another interpreter: {Shorten(statement, 160)}", "starts another interpreter", null, Effects.LaunchesPrograms);
        var nested = CommandParser.Parse(statement);
        var nestedCtx = new Context { Referenced = ctx.Referenced, Depth = ctx.Depth + 1 };
        var inner = Explain(nested, nestedCtx);
        var step = new Step($"Starts {nested.Label}: {inner.Summary}", LowerFirst(inner.Summary.Split(". ")[0]), inner.IsReadOnly);
        step.Effects.AddRange(inner.Effects);
        step.Effects.Add(Effects.LaunchesPrograms);
        if (step.ReadOnly == true) step.ReadOnly = true;   // starting a read-only child is still read-only
        return step;
    }

    private static Step DescribeProgram(List<string> tokens, string statement, Context ctx)
    {
        var exe = tokens.Count > 0 ? tokens[0] : statement;
        var name = CommandLineTokenizer.FileNameOf(exe);
        var args = tokens.Count > 1 ? string.Join(" ", tokens.Skip(1)) : "";
        return new Step($"Runs the program {name}{(args.Length > 0 ? " with: " + Shorten(args, 160) : "")} (not in CMD-spy's command reference, so its effect is unknown).",
            $"runs {name}", null, Effects.LaunchesPrograms, Effects.Unknown);
    }

    // ----------------------------------------------------------- PowerShell --

    private sealed record Cmdlet(string Description, string Effect, bool? ReadOnly, string? Phrase = null);

    private static readonly Dictionary<string, string> PsAliases = new(StringComparer.OrdinalIgnoreCase)
    {
        ["gwmi"] = "Get-WmiObject", ["gcim"] = "Get-CimInstance", ["iwmi"] = "Invoke-WmiMethod", ["rwmi"] = "Remove-WmiObject",
        ["swmi"] = "Set-WmiInstance", ["icim"] = "Invoke-CimMethod",
        ["gps"] = "Get-Process", ["ps"] = "Get-Process", ["spps"] = "Stop-Process", ["kill"] = "Stop-Process",
        ["saps"] = "Start-Process", ["start"] = "Start-Process", ["gsv"] = "Get-Service", ["sasv"] = "Start-Service",
        ["spsv"] = "Stop-Service", ["iwr"] = "Invoke-WebRequest", ["curl"] = "Invoke-WebRequest", ["wget"] = "Invoke-WebRequest",
        ["irm"] = "Invoke-RestMethod", ["iex"] = "Invoke-Expression", ["icm"] = "Invoke-Command", ["ii"] = "Invoke-Item",
        ["gci"] = "Get-ChildItem", ["ls"] = "Get-ChildItem", ["dir"] = "Get-ChildItem", ["gc"] = "Get-Content",
        ["cat"] = "Get-Content", ["type"] = "Get-Content", ["sc"] = "Set-Content", ["ac"] = "Add-Content",
        ["ni"] = "New-Item", ["md"] = "New-Item", ["mkdir"] = "New-Item", ["ri"] = "Remove-Item", ["rm"] = "Remove-Item",
        ["rmdir"] = "Remove-Item", ["del"] = "Remove-Item", ["erase"] = "Remove-Item", ["rd"] = "Remove-Item",
        ["cpi"] = "Copy-Item", ["cp"] = "Copy-Item", ["copy"] = "Copy-Item", ["mi"] = "Move-Item", ["mv"] = "Move-Item",
        ["move"] = "Move-Item", ["rni"] = "Rename-Item", ["ren"] = "Rename-Item", ["gp"] = "Get-ItemProperty",
        ["gpv"] = "Get-ItemPropertyValue", ["sp"] = "Set-ItemProperty", ["rp"] = "Remove-ItemProperty", ["gi"] = "Get-Item",
        ["gl"] = "Get-Location", ["pwd"] = "Get-Location", ["sl"] = "Set-Location", ["cd"] = "Set-Location",
        ["chdir"] = "Set-Location", ["echo"] = "Write-Output", ["write"] = "Write-Output", ["sleep"] = "Start-Sleep",
        ["select"] = "Select-Object", ["where"] = "Where-Object", ["?"] = "Where-Object", ["foreach"] = "ForEach-Object",
        ["%"] = "ForEach-Object", ["sort"] = "Sort-Object", ["group"] = "Group-Object", ["measure"] = "Measure-Object",
        ["ft"] = "Format-Table", ["fl"] = "Format-List", ["fw"] = "Format-Wide", ["sls"] = "Select-String",
        ["compare"] = "Compare-Object", ["diff"] = "Compare-Object", ["tee"] = "Tee-Object", ["gm"] = "Get-Member",
        ["ipmo"] = "Import-Module", ["gcm"] = "Get-Command", ["cls"] = "Clear-Host", ["clear"] = "Clear-Host",
        ["h"] = "Get-History", ["history"] = "Get-History", ["epcsv"] = "Export-Csv", ["ipcsv"] = "Import-Csv",
        ["sajb"] = "Start-Job", ["gjb"] = "Get-Job", ["rcjb"] = "Receive-Job"
    };

    private static readonly Dictionary<string, Cmdlet> Cmdlets = new(StringComparer.OrdinalIgnoreCase)
    {
        ["Get-Process"] = new("lists running processes", Effects.ProcessDiscovery, true),
        ["Stop-Process"] = new("ends processes", Effects.StopsProcesses, false),
        ["Wait-Process"] = new("waits for processes to exit", Effects.Waits, true),
        ["Start-Process"] = new("starts a program", Effects.LaunchesPrograms, false),
        ["Get-Service"] = new("lists Windows services", Effects.SystemDiscovery, true),
        ["Start-Service"] = new("starts a Windows service", Effects.ChangesServices, false),
        ["Stop-Service"] = new("stops a Windows service", Effects.ChangesServices, false),
        ["Restart-Service"] = new("restarts a Windows service", Effects.ChangesServices, false),
        ["Set-Service"] = new("changes a Windows service", Effects.ChangesServices, false),
        ["New-Service"] = new("creates a Windows service", Effects.ChangesServices, false),
        ["Remove-Service"] = new("deletes a Windows service", Effects.ChangesServices, false),
        ["Remove-WmiObject"] = new("deletes WMI objects", Effects.ChangesSystem, false),
        ["Remove-CimInstance"] = new("deletes WMI objects", Effects.ChangesSystem, false),
        ["Set-WmiInstance"] = new("changes WMI objects", Effects.ChangesSystem, false),
        ["Set-CimInstance"] = new("changes WMI objects", Effects.ChangesSystem, false),
        ["New-CimInstance"] = new("creates WMI objects", Effects.ChangesSystem, false),
        ["Register-WmiEvent"] = new("subscribes to WMI events", Effects.ChangesSystem, false),
        ["Invoke-Expression"] = new("runs a text string as PowerShell code", Effects.RunsDynamicCode, false),
        ["Invoke-Command"] = new("runs a script block (on another computer if -ComputerName is given)", Effects.RunsDynamicCode, false),
        ["Invoke-Item"] = new("opens a file with its default program", Effects.LaunchesPrograms, false),
        ["Start-BitsTransfer"] = new("downloads/uploads files with BITS", Effects.Downloads, false),
        ["Send-MailMessage"] = new("sends an e-mail", Effects.Network, false),
        ["Get-ChildItem"] = new("lists files and folders", Effects.FileDiscovery, true),
        ["Get-Content"] = new("reads a file", Effects.ReadsFiles, true),
        ["Set-Content"] = new("writes a file", Effects.WritesFiles, false),
        ["Add-Content"] = new("appends to a file", Effects.WritesFiles, false),
        ["Out-File"] = new("writes output to a file", Effects.WritesFiles, false),
        ["Export-Csv"] = new("writes a CSV file", Effects.WritesFiles, false),
        ["Export-Clixml"] = new("writes an XML file", Effects.WritesFiles, false),
        ["Import-Csv"] = new("reads a CSV file", Effects.ReadsFiles, true),
        ["Import-Clixml"] = new("reads an XML file", Effects.ReadsFiles, true),
        ["New-Item"] = new("creates a file, folder or registry key", Effects.WritesFiles, false),
        ["Remove-Item"] = new("deletes files, folders or registry keys", Effects.DeletesFiles, false),
        ["Copy-Item"] = new("copies files", Effects.WritesFiles, false),
        ["Move-Item"] = new("moves files", Effects.WritesFiles, false),
        ["Rename-Item"] = new("renames a file", Effects.WritesFiles, false),
        ["Get-Item"] = new("reads a file or registry item", Effects.ReadsFiles, true),
        ["Get-ItemProperty"] = new("reads registry values / file properties", Effects.ReadsRegistry, true),
        ["Get-ItemPropertyValue"] = new("reads a registry value", Effects.ReadsRegistry, true),
        ["Set-ItemProperty"] = new("writes a registry value / file property", Effects.ModifiesRegistry, false),
        ["New-ItemProperty"] = new("creates a registry value", Effects.ModifiesRegistry, false),
        ["Remove-ItemProperty"] = new("deletes a registry value", Effects.ModifiesRegistry, false),
        ["Test-Path"] = new("checks whether a path exists", Effects.FileDiscovery, true),
        ["Resolve-Path"] = new("resolves a path", Effects.FileDiscovery, true),
        ["Get-FileHash"] = new("computes a file hash", Effects.ReadsFiles, true),
        ["Expand-Archive"] = new("unpacks a ZIP archive", Effects.WritesFiles, false),
        ["Compress-Archive"] = new("creates a ZIP archive", Effects.WritesFiles, false),
        ["Unblock-File"] = new("removes the downloaded-from-internet mark from a file", Effects.ChangesSecurity, false),
        ["Get-Location"] = new("shows the current folder", Effects.ConsoleOnly, true),
        ["Set-Location"] = new("changes the current folder", Effects.ConsoleOnly, true),
        ["Push-Location"] = new("changes the current folder", Effects.ConsoleOnly, true),
        ["Pop-Location"] = new("changes the current folder", Effects.ConsoleOnly, true),
        ["Write-Host"] = new("prints text", Effects.ConsoleOnly, true),
        ["Write-Output"] = new("prints/returns values", Effects.ConsoleOnly, true),
        ["Write-Verbose"] = new("prints diagnostic text", Effects.ConsoleOnly, true),
        ["Write-Warning"] = new("prints a warning", Effects.ConsoleOnly, true),
        ["Write-Error"] = new("prints an error", Effects.ConsoleOnly, true),
        ["Out-Host"] = new("prints output", Effects.ConsoleOnly, true),
        ["Out-Null"] = new("discards output", Effects.ConsoleOnly, true),
        ["Out-String"] = new("converts output to text", Effects.DataProcessing, true),
        ["Clear-Host"] = new("clears the console", Effects.ConsoleOnly, true),
        ["Start-Sleep"] = new("waits", Effects.Waits, true),
        ["Read-Host"] = new("asks the user for input", Effects.ConsoleOnly, true),
        ["Get-Date"] = new("reads the date/time", Effects.DataProcessing, true),
        ["Get-Random"] = new("generates a random number", Effects.DataProcessing, true),
        ["Get-Member"] = new("lists an object's properties", Effects.DataProcessing, true),
        ["Get-Command"] = new("lists PowerShell commands", Effects.DataProcessing, true),
        ["Get-Help"] = new("shows help", Effects.ConsoleOnly, true),
        ["Get-History"] = new("shows command history", Effects.ConsoleOnly, true),
        ["Get-Variable"] = new("reads variables", Effects.DataProcessing, true),
        ["Set-Variable"] = new("sets a variable", Effects.DataProcessing, true),
        ["Get-Host"] = new("reads PowerShell host information", Effects.SystemDiscovery, true),
        ["Get-ComputerInfo"] = new("reads detailed computer information", Effects.SystemDiscovery, true),
        ["Get-HotFix"] = new("lists installed updates", Effects.SystemDiscovery, true),
        ["Get-Volume"] = new("lists disk volumes", Effects.SystemDiscovery, true),
        ["Get-Disk"] = new("lists disks", Effects.SystemDiscovery, true),
        ["Get-PSDrive"] = new("lists drives", Effects.SystemDiscovery, true),
        ["Get-Counter"] = new("reads performance counters (CPU, memory...)", Effects.SystemDiscovery, true),
        ["Get-PnpDevice"] = new("lists hardware devices", Effects.SystemDiscovery, true),
        ["Get-NetTCPConnection"] = new("lists network connections", Effects.NetworkDiscovery, true),
        ["Get-NetUDPEndpoint"] = new("lists network endpoints", Effects.NetworkDiscovery, true),
        ["Get-NetAdapter"] = new("lists network adapters", Effects.NetworkDiscovery, true),
        ["Get-NetIPAddress"] = new("lists IP addresses", Effects.NetworkDiscovery, true),
        ["Get-NetIPConfiguration"] = new("reads the network configuration", Effects.NetworkDiscovery, true),
        ["Get-NetRoute"] = new("reads the routing table", Effects.NetworkDiscovery, true),
        ["Get-DnsClientCache"] = new("reads the DNS cache", Effects.NetworkDiscovery, true),
        ["Resolve-DnsName"] = new("looks up a DNS name", Effects.NetworkDiscovery, true),
        ["Test-Connection"] = new("pings a host", Effects.NetworkDiscovery, true),
        ["Test-NetConnection"] = new("tests a network connection", Effects.NetworkDiscovery, true),
        ["Get-NetFirewallRule"] = new("lists firewall rules", Effects.SecurityStatus, true),
        ["Get-NetFirewallProfile"] = new("reads firewall settings", Effects.SecurityStatus, true),
        ["Set-NetFirewallProfile"] = new("changes firewall settings", Effects.ChangesSecurity, false),
        ["New-NetFirewallRule"] = new("adds a firewall rule", Effects.ChangesSecurity, false),
        ["Set-NetFirewallRule"] = new("changes a firewall rule", Effects.ChangesSecurity, false),
        ["Remove-NetFirewallRule"] = new("deletes a firewall rule", Effects.ChangesSecurity, false),
        ["Disable-NetFirewallRule"] = new("disables a firewall rule", Effects.ChangesSecurity, false),
        ["Get-LocalUser"] = new("lists local user accounts", Effects.AccountDiscovery, true),
        ["Get-LocalGroup"] = new("lists local groups", Effects.AccountDiscovery, true),
        ["Get-LocalGroupMember"] = new("lists group members", Effects.AccountDiscovery, true),
        ["New-LocalUser"] = new("creates a user account", Effects.ChangesAccounts, false),
        ["Set-LocalUser"] = new("changes a user account", Effects.ChangesAccounts, false),
        ["Remove-LocalUser"] = new("deletes a user account", Effects.ChangesAccounts, false),
        ["Add-LocalGroupMember"] = new("adds a user to a group", Effects.ChangesAccounts, false),
        ["Get-ScheduledTask"] = new("lists scheduled tasks", Effects.SystemDiscovery, true),
        ["Get-ScheduledTaskInfo"] = new("reads scheduled-task details", Effects.SystemDiscovery, true),
        ["Register-ScheduledTask"] = new("creates a scheduled task", Effects.ChangesTasks, false),
        ["Unregister-ScheduledTask"] = new("deletes a scheduled task", Effects.ChangesTasks, false),
        ["Set-ScheduledTask"] = new("changes a scheduled task", Effects.ChangesTasks, false),
        ["Start-ScheduledTask"] = new("runs a scheduled task", Effects.LaunchesPrograms, false),
        ["Disable-ScheduledTask"] = new("disables a scheduled task", Effects.ChangesTasks, false),
        ["Enable-ScheduledTask"] = new("enables a scheduled task", Effects.ChangesTasks, false),
        ["Get-WinEvent"] = new("reads event logs", Effects.ReadsLogs, true),
        ["Get-EventLog"] = new("reads event logs", Effects.ReadsLogs, true),
        ["Clear-EventLog"] = new("clears event logs", Effects.ChangesSecurity, false),
        ["Remove-EventLog"] = new("deletes an event log", Effects.ChangesSecurity, false),
        ["Write-EventLog"] = new("writes an event-log entry", Effects.ChangesSystem, false),
        ["Get-MpComputerStatus"] = new("reads Microsoft Defender status", Effects.SecurityStatus, true),
        ["Get-MpPreference"] = new("reads Microsoft Defender settings", Effects.SecurityStatus, true),
        ["Get-MpThreat"] = new("lists threats Defender found", Effects.SecurityStatus, true),
        ["Get-MpThreatDetection"] = new("lists Defender detections", Effects.SecurityStatus, true),
        ["Set-MpPreference"] = new("changes Microsoft Defender settings", Effects.ChangesSecurity, false),
        ["Add-MpPreference"] = new("adds Microsoft Defender exclusions/settings", Effects.ChangesSecurity, false),
        ["Remove-MpPreference"] = new("removes Microsoft Defender settings", Effects.ChangesSecurity, false),
        ["Start-MpScan"] = new("starts a Microsoft Defender scan", Effects.LaunchesPrograms, false),
        ["Update-MpSignature"] = new("updates Defender signatures", Effects.ChangesSystem, false),
        ["Get-ExecutionPolicy"] = new("reads the script execution policy", Effects.SecurityStatus, true),
        ["Set-ExecutionPolicy"] = new("changes the script execution policy", Effects.ChangesSecurity, false),
        ["Get-Acl"] = new("reads permissions", Effects.SecurityStatus, true),
        ["Set-Acl"] = new("changes permissions", Effects.ChangesSecurity, false),
        ["Add-Type"] = new("compiles and loads .NET code", Effects.RunsDynamicCode, false),
        ["Import-Module"] = new("loads a PowerShell module", Effects.RunsDynamicCode, false),
        ["Get-Module"] = new("lists PowerShell modules", Effects.DataProcessing, true),
        ["Install-Module"] = new("installs a PowerShell module", Effects.ChangesSystem, false),
        ["Install-Package"] = new("installs software", Effects.ChangesSystem, false),
        ["Uninstall-Package"] = new("uninstalls software", Effects.ChangesSystem, false),
        ["Get-Package"] = new("lists installed software", Effects.SystemDiscovery, true),
        ["Get-AppxPackage"] = new("lists installed Store apps", Effects.SystemDiscovery, true),
        ["Remove-AppxPackage"] = new("uninstalls a Store app", Effects.ChangesSystem, false),
        ["Add-AppxPackage"] = new("installs a Store app", Effects.ChangesSystem, false),
        ["Restart-Computer"] = new("restarts the computer", Effects.ChangesSystem, false),
        ["Stop-Computer"] = new("shuts down the computer", Effects.ChangesSystem, false),
        ["Start-Job"] = new("starts a background job", Effects.LaunchesPrograms, false),
        ["Get-Job"] = new("lists background jobs", Effects.DataProcessing, true),
        ["Receive-Job"] = new("reads background-job results", Effects.DataProcessing, true),
        ["Get-Clipboard"] = new("reads the clipboard", Effects.DataProcessing, true),
        ["Set-Clipboard"] = new("sets the clipboard", Effects.ConsoleOnly, true),
        ["Enter-PSSession"] = new("opens a remote PowerShell session", Effects.Network, false),
        ["New-PSSession"] = new("opens a remote PowerShell session", Effects.Network, false),
        ["Clear-RecycleBin"] = new("empties the Recycle Bin", Effects.DeletesFiles, false),
        ["New-Object"] = new("creates a .NET/COM object", Effects.DataProcessing, true),
        ["Where-Object"] = new("filters data", Effects.DataProcessing, true),
        ["Select-Object"] = new("selects data", Effects.DataProcessing, true),
        ["ForEach-Object"] = new("processes each item", Effects.DataProcessing, true),
        ["Sort-Object"] = new("sorts data", Effects.DataProcessing, true),
        ["Group-Object"] = new("groups data", Effects.DataProcessing, true),
        ["Measure-Object"] = new("counts/measures data", Effects.DataProcessing, true),
        ["Format-Table"] = new("formats output as a table", Effects.DataProcessing, true),
        ["Format-List"] = new("formats output as a list", Effects.DataProcessing, true),
        ["Format-Wide"] = new("formats output", Effects.DataProcessing, true),
        ["ConvertTo-Json"] = new("converts data to JSON", Effects.DataProcessing, true),
        ["ConvertFrom-Json"] = new("parses JSON", Effects.DataProcessing, true),
        ["ConvertTo-Csv"] = new("converts data to CSV", Effects.DataProcessing, true),
        ["ConvertFrom-Csv"] = new("parses CSV", Effects.DataProcessing, true),
        ["ConvertTo-Html"] = new("converts data to HTML", Effects.DataProcessing, true),
        ["ConvertTo-SecureString"] = new("converts text to a secure string", Effects.DataProcessing, true),
        ["Select-String"] = new("searches text", Effects.DataProcessing, true),
        ["Compare-Object"] = new("compares data", Effects.DataProcessing, true),
        ["Get-Unique"] = new("removes duplicates", Effects.DataProcessing, true),
        ["Add-Member"] = new("adds a property to an object", Effects.DataProcessing, true),
        ["Join-String"] = new("joins text", Effects.DataProcessing, true),
        ["Tee-Object"] = new("copies output to a variable or file", Effects.DataProcessing, true),
        ["Out-GridView"] = new("shows output in a window", Effects.ConsoleOnly, true),
        ["Get-CimClass"] = new("lists WMI classes", Effects.SystemDiscovery, true),
    };

    private static List<Step> DescribePowerShellScript(string text, Context ctx)
    {
        var script = Parser.ParseInput(text, out _, out var parseErrors);

        // FindAll(..., true) descends into every nested ScriptBlockAst. Describing
        // each PipelineAst separately prevents an outer data cmdlet from hiding a
        // later command in its script block.
        var statements = script.FindAll(node => node is StatementAst, searchNestedScriptBlocks: true)
            .OfType<StatementAst>()
            .ToList();
        var steps = statements
            .OfType<PipelineAst>()
            .OrderBy(pipeline => pipeline.Extent.StartOffset)
            .ThenByDescending(pipeline => pipeline.Extent.EndOffset - pipeline.Extent.StartOffset)
            .Select(pipeline => DescribePowerShellStatement(pipeline.Extent.Text, ctx))
            .ToList();

        if (steps.Count == 0 && parseErrors.Length == 0 && text.TrimStart().StartsWith("#", StringComparison.Ordinal))
            steps.Add(new Step("Comment.", null, true));

        if (parseErrors.Length > 0)
        {
            steps.Add(new Step(
                $"PowerShell could not fully parse this command near: {Shorten(parseErrors[0].Extent.Text, 80)}.",
                "contains PowerShell syntax that could not be parsed", null, Effects.Unknown));
        }

        var commands = script.FindAll(node => node is CommandAst, searchNestedScriptBlocks: true)
            .OfType<CommandAst>();
        foreach (var command in commands)
        {
            var commandName = command.GetCommandName();
            if (commandName is null)
            {
                steps.Add(new Step(
                    $"Runs a dynamically resolved PowerShell command: {Shorten(command.Extent.Text, 120)}. Its effect is unknown.",
                    "runs a dynamically resolved command", null, Effects.Unknown));
                continue;
            }

            if (UsesUnresolvedScriptBlock(command, commandName))
            {
                steps.Add(new Step(
                    $"{commandName} receives executable behavior that is not visible as a literal script block: {Shorten(command.Extent.Text, 120)}.",
                    "uses a dynamically supplied script block", null, Effects.Unknown));
            }

            // Normalize call-operator forms such as & 'Set-Content' so the
            // classifier uses the AST-resolved command name, not quote syntax.
            var firstElement = command.CommandElements.FirstOrDefault();
            var argumentOffset = firstElement is null
                ? command.Extent.Text.Length
                : firstElement.Extent.EndOffset - command.Extent.StartOffset;
            var arguments = argumentOffset >= 0 && argumentOffset <= command.Extent.Text.Length
                ? command.Extent.Text[argumentOffset..]
                : "";
            var inPipeline = command.Parent is PipelineAst pipeline && pipeline.PipelineElements.Count > 1;
            steps.Add(DescribePowerShellElement(commandName + arguments, ctx, inPipeline));
        }

        var memberCalls = script.FindAll(node => node is InvokeMemberExpressionAst, searchNestedScriptBlocks: true)
            .OfType<InvokeMemberExpressionAst>();
        foreach (var call in memberCalls)
        {
            steps.Add(DescribeExpression(call.Extent.Text) ?? new Step(
                $"Calls a .NET method whose effect is unknown: {Shorten(call.Extent.Text, 120)}.",
                "calls a .NET method with an unknown effect", null, Effects.Unknown));
        }

        var propertyAssignments = statements
            .OfType<AssignmentStatementAst>()
            .Where(assignment => assignment.Left is not VariableExpressionAst);
        foreach (var assignment in propertyAssignments)
        {
            steps.Add(new Step(
                $"Assigns through a property or expression whose effect is unknown: {Shorten(assignment.Extent.Text, 120)}.",
                "assigns through an expression with an unknown effect", null, Effects.Unknown));
        }

        var fileRedirections = script.FindAll(node => node is FileRedirectionAst, searchNestedScriptBlocks: true)
            .OfType<FileRedirectionAst>();
        foreach (var redirection in fileRedirections)
        {
            steps.Add(new Step(
                $"Redirects PowerShell output to a file: {Shorten(redirection.Extent.Text, 100)}.",
                "writes redirected output to a file", false, Effects.WritesFiles));
        }

        if (steps.Count == 0)
        {
            steps.Add(new Step(
                $"PowerShell syntax was parsed but its effect could not be classified: {Shorten(text, 120)}.",
                "contains PowerShell syntax with an unknown effect", null, Effects.Unknown));
        }

        return steps;
    }

    private static bool UsesUnresolvedScriptBlock(CommandAst command, string commandName)
    {
        var canonical = PsAliases.TryGetValue(commandName, out var alias) ? alias : commandName;
        var isForEach = canonical.Equals("ForEach-Object", StringComparison.OrdinalIgnoreCase);
        var isWhere = canonical.Equals("Where-Object", StringComparison.OrdinalIgnoreCase);
        if ((!isForEach && !isWhere) || command.CommandElements.OfType<ScriptBlockExpressionAst>().Any())
            return false;

        var elements = command.CommandElements;
        if (isForEach)
        {
            if (elements.Count == 2 && elements[1] is VariableExpressionAst)
                return true;

            return elements.OfType<CommandParameterAst>().Any(parameter =>
                IsParameterPrefix(parameter.ParameterName, "Begin", "End", "MemberName", "Parallel", "Process"));
        }

        if (elements.Count == 2 && elements[1] is VariableExpressionAst)
            return true;

        return elements.OfType<CommandParameterAst>().Any(parameter =>
            IsParameterPrefix(parameter.ParameterName, "FilterScript"));
    }

    private static bool IsParameterPrefix(string parameterName, params string[] names) =>
        parameterName.Length > 0 && names.Any(name => name.StartsWith(parameterName, StringComparison.OrdinalIgnoreCase));

    private static Step DescribePowerShellStatement(string statement, Context ctx)
    {
        var elements = StatementSplitter.SplitPipeline(statement);
        if (elements.Count == 0) return new Step("(empty statement)", null, true);

        var described = new List<Step>();
        foreach (var element in elements)
            described.Add(DescribePowerShellElement(element, ctx, elements.Count > 1));

        if (described.Count == 1) return described[0];

        // A pipeline: report it as one step, combining its parts.
        var main = described.FirstOrDefault(s => s.ReadOnly != true) ?? described[0];
        var step = new Step(
            "Pipeline: " + string.Join(" → ", described.Select(s => s.Detail.TrimEnd('.'))) + ".",
            main.Phrase ?? described.Select(s => s.Phrase).FirstOrDefault(p => p is not null),
            described.Any(s => s.ReadOnly == false) ? false : described.All(s => s.ReadOnly == true) ? true : null);
        foreach (var s in described) step.Effects.AddRange(s.Effects);
        return step;
    }

    private static Step DescribePowerShellElement(string element, Context ctx, bool inPipeline)
    {
        var text = element.Trim().TrimStart('&', '.').Trim();
        if (text.Length == 0) return new Step("(empty)", null, true);

        // $var = <expression>
        var assign = Regex.Match(text, @"^\$(?<var>[\w:]+)\s*=\s*(?<rhs>.+)$", Opts | RegexOptions.Singleline);
        if (assign.Success)
        {
            var rhs = assign.Groups["rhs"].Value.Trim();
            var inner = rhs.Length > 0 && (char.IsLetter(rhs[0]) || rhs[0] == '[' || rhs[0] == '(')
                ? DescribePowerShellStatement(rhs.Trim('(', ')'), ctx)
                : new Step(Shorten(rhs, 80), null, true, Effects.DataProcessing);
            var step = new Step($"Stores into ${assign.Groups["var"].Value}: {inner.Detail}", inner.Phrase, inner.ReadOnly);
            step.Effects.AddRange(inner.Effects);
            return step;
        }

        if (text.StartsWith("#", StringComparison.Ordinal)) return new Step("Comment.", null, true);

        if (text.StartsWith("(", StringComparison.Ordinal) || text.StartsWith("[", StringComparison.Ordinal))
        {
            var expressionStep = DescribeExpression(text);
            if (expressionStep is not null) return expressionStep;
        }
        if (text.StartsWith("$", StringComparison.Ordinal) || text.StartsWith("'", StringComparison.Ordinal) || text.StartsWith("\"", StringComparison.Ordinal) || char.IsDigit(text[0]))
            return new Step($"Evaluates an expression: {Shorten(text, 120)}", null, true, Effects.DataProcessing);

        var words = PsWords(text);
        if (words.Count == 0) return new Step($"Runs: {Shorten(text, 120)}", null, null, Effects.Unknown);

        var commandName = words[0];
        var canonical = PsAliases.TryGetValue(commandName, out var alias) ? alias : commandName;
        var aliasNote = alias is not null ? $" ({commandName})" : "";

        // Interpreters and programs started from PowerShell.
        var programKind = CommandParser.KindOf(CommandLineTokenizer.FileNameOf(commandName));
        if (programKind is not (InterpreterKind.Other or InterpreterKind.Unknown))
            return DescribeNestedInterpreter(text, ctx);
        if (commandName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) || commandName.Contains('\\'))
            return DescribeCmdTokens(CommandLineTokenizer.Tokenize(text).Select(t => t.Value).ToList(), text, ctx);

        switch (canonical.ToLowerInvariant())
        {
            case "invoke-expression":
            {
                var payload = text[commandName.Length..].Trim();
                var inner = DescribeExpression(payload)
                            ?? (payload.Length > 0 ? DescribePowerShellStatement(payload.Trim('(', ')', '"', '\''), ctx) : null);
                bool downloads = inner?.Effects.Contains(Effects.Downloads) == true;
                var step = new Step(
                    downloads
                        ? $"Invoke-Expression{aliasNote}: downloads PowerShell code and runs it immediately in memory (a \"download cradle\") — {inner!.Detail}"
                        : $"Invoke-Expression{aliasNote}: runs text as PowerShell code{(inner is null ? "" : " — " + inner.Detail)}",
                    downloads ? $"downloads code from {HostOf(UrlRegex.Match(payload).Value)} and runs it immediately" : "runs dynamically built code",
                    false, Effects.RunsDynamicCode);
                if (inner is not null) step.Effects.AddRange(inner.Effects);
                return step;
            }
            case "foreach-object":
            case "where-object":
                return new Step($"{canonical}{aliasNote}: filters/processes data.", null, true, Effects.DataProcessing);
            case "get-wmiobject":
            case "get-ciminstance":
                return DescribeWmiQuery(canonical + aliasNote, words, text, ctx);
            case "invoke-wmimethod":
            case "invoke-cimmethod":
                return DescribeWmiMethod(canonical + aliasNote, words, text, ctx);
            case "invoke-webrequest":
            case "invoke-restmethod":
                var url = UrlRegex.Match(text).Value;
                bool saves = Regex.IsMatch(text, @"-OutFile\b", Opts);
                return new Step($"{canonical}{aliasNote}: contacts {(url.Length > 0 ? url : "a web server")}{(saves ? " and saves the download to a file" : "")}.",
                    saves ? $"downloads a file from {HostOf(url)}" : $"contacts {HostOf(url)}", false,
                    saves ? new[] { Effects.Downloads, Effects.WritesFiles } : new[] { Effects.Network });
            case "start-process":
                var target = words.Skip(1).FirstOrDefault(w => !w.StartsWith("-", StringComparison.Ordinal))
                             ?? ValueOf(words, "-FilePath");
                bool hidden = Regex.IsMatch(text, @"-WindowStyle\s+Hidden", Opts);
                bool elevated = Regex.IsMatch(text, @"-Verb\s+RunAs", Opts);
                return new Step($"Start-Process{aliasNote}: starts {target ?? "a program"}{(hidden ? " with a hidden window" : "")}{(elevated ? " as administrator" : "")}.",
                    $"starts {FileName(target)}", false, Effects.LaunchesPrograms);
            case "get-process":
            case "stop-process":
            case "wait-process":
            {
                var info = Cmdlets[canonical];
                var refs = ReferencedPidExtractor.ExtractPids(text);
                var names = ReferencedPidExtractor.ExtractNames(text);
                var scope = refs.Count > 0 ? DescribeReferencedPids(refs, ctx)
                          : names.Count > 0 ? $" named {string.Join(", ", names.Select(n => n.Name))}" : "";
                return new Step($"{canonical}{aliasNote}: {info.Description}{scope}.", info.Description + (refs.Count > 0 ? $" ({refs.Count} specific)" : ""), info.ReadOnly, info.Effect);
            }
        }

        if (Cmdlets.TryGetValue(canonical, out var cmdlet))
        {
            var detail = $"{canonical}{aliasNote}: {cmdlet.Description}";
            var arg = words.Skip(1).FirstOrDefault(w => !w.StartsWith("-", StringComparison.Ordinal));
            if (arg is not null && cmdlet.Effect is Effects.WritesFiles or Effects.DeletesFiles or Effects.ReadsFiles or Effects.ModifiesRegistry or Effects.ReadsRegistry)
                detail += $" ({Shorten(arg, 100)})";
            bool runKey = Regex.IsMatch(text, @"\\(Run|RunOnce)\b", Opts) && cmdlet.Effect == Effects.ModifiesRegistry;
            if (runKey) detail += " — a start-up (Run) key, so something will run at every logon";
            return new Step(detail + ".", inPipeline && cmdlet.ReadOnly == true && cmdlet.Effect == Effects.DataProcessing ? null : cmdlet.Phrase ?? cmdlet.Description,
                cmdlet.ReadOnly, cmdlet.Effect);
        }

        // Unknown Verb-Noun cmdlet: judge by its verb.
        var verbMatch = Regex.Match(canonical, @"^(?<verb>[A-Za-z]+)-(?<noun>\w+)$");
        if (verbMatch.Success)
        {
            var verb = verbMatch.Groups["verb"].Value;
            var noun = verbMatch.Groups["noun"].Value;
            var (desc, effect, ro) = verb.ToLowerInvariant() switch
            {
                "get" or "test" or "find" or "search" or "read" or "resolve" or "show" => ($"reads {noun} information", Effects.SystemDiscovery, (bool?)true),
                "select" or "where" or "sort" or "group" or "measure" or "format" or "convertto" or "convertfrom" or "compare" or "join" or "split" => ($"processes data", Effects.DataProcessing, true),
                "write" or "out" => ($"outputs {noun}", Effects.ConsoleOnly, true),
                "set" or "new" or "add" or "remove" or "clear" or "rename" or "copy" or "move" or "update" or "enable" or "disable" or "register" or "unregister" or "install" or "uninstall" or "reset" or "suspend" or "resume" or "restart" or "lock" or "unlock" or "mount" or "dismount" or "protect" or "unprotect" or "grant" or "revoke" or "block" or "unblock" or "publish" or "unpublish" or "import" or "export" or "save" or "restore" or "initialize"
                    => ($"{verb.ToLowerInvariant()}s {noun}", Effects.ChangesSystem, false),
                "start" or "invoke" or "enter" or "connect" or "send" or "receive" or "submit" or "use" or "debug" or "trace"
                    => ($"{verb.ToLowerInvariant()}s {noun}", Effects.LaunchesPrograms, false),
                "stop" => ($"stops {noun}", Effects.StopsProcesses, false),
                "wait" => ($"waits for {noun}", Effects.Waits, true),
                _ => ($"runs {canonical}", Effects.Unknown, null)
            };
            return new Step($"{canonical}: {desc} (judged from its name).", desc, ro, effect);
        }

        return new Step($"Runs '{Shorten(commandName, 60)}' (not in CMD-spy's command reference, so its effect is unknown).",
            $"runs {Shorten(commandName, 40)}", null, Effects.Unknown);
    }

    /// <summary>.NET method calls and other expression forms worth naming.</summary>
    private static Step? DescribeExpression(string text)
    {
        if (Regex.IsMatch(text, @"\.(DownloadString|DownloadData|DownloadFile|OpenRead|UploadString|UploadData|UploadFile)\s*\(", Opts))
            return new Step($"Downloads/uploads data from {(UrlRegex.Match(text) is { Success: true } m ? m.Value : "a web address")} using .NET WebClient.",
                $"downloads data from {HostOf(UrlRegex.Match(text).Value)}", false, Effects.Downloads);
        if (Regex.IsMatch(text, @"\[(System\.)?Reflection\.Assembly\]::(Load|LoadFile|LoadFrom|UnsafeLoadFrom)\s*\(", Opts))
            return new Step("Loads a .NET program into memory (can run code that never touches the disk).", "loads code into memory", false, Effects.RunsDynamicCode);
        if (Regex.IsMatch(text, @"\[(System\.)?Diagnostics\.Process\]::Start\s*\(", Opts))
            return new Step($"Starts a program: {Shorten(text, 140)}", "starts a program", false, Effects.LaunchesPrograms);
        if (Regex.IsMatch(text, @"\[(System\.)?IO\.File\]::(WriteAll\w*|AppendAll\w*|Copy|Move|Delete|Create)\s*\(", Opts))
            return new Step($"Writes/changes a file through .NET: {Shorten(text, 140)}", "writes a file", false, Effects.WritesFiles);
        if (Regex.IsMatch(text, @"\[(System\.)?IO\.File\]::(ReadAll\w*|Exists|OpenRead)\s*\(", Opts))
            return new Step($"Reads a file through .NET: {Shorten(text, 140)}", "reads a file", true, Effects.ReadsFiles);
        if (Regex.IsMatch(text, @"\[(System\.)?Convert\]::FromBase64String\s*\(", Opts))
            return new Step("Decodes Base64 data (often used to unpack a hidden payload).", "decodes Base64 data", true, Effects.DataProcessing);
        return null;
    }

    private static Step DescribeWmiQuery(string cmdlet, List<string> words, string text, Context ctx)
    {
        var query = ValueOf(words, "-Query");
        var cls = ValueOf(words, "-Class", "-ClassName", "-cl");
        if (cls is null && query is not null)
        {
            var from = Regex.Match(query, @"\bFROM\s+(\w+)", Opts);
            if (from.Success) cls = from.Groups[1].Value;
        }
        cls ??= FirstPositional(words, "-Class", "-ClassName", "-Filter", "-Query", "-Namespace", "-ComputerName", "-Property", "-cn", "-ns", "-Credential", "-Credentials");
        var computer = ValueOf(words, "-ComputerName", "-cn");
        var (what, effect) = WmiClass(cls);

        var refs = ReferencedPidExtractor.ExtractPids(text);
        var scope = refs.Count > 0 ? $", limited to {refs.Count} specific process{(refs.Count == 1 ? "" : "es")}{DescribeReferencedPids(refs, ctx, includeLeadIn: false)}" : "";
        var remote = computer is null ? "" : $" on the remote computer {computer}";
        var detail = $"{cmdlet}: queries WMI class {cls ?? "(unknown)"}{remote} — {what}{scope}. Read-only.";
        var phrase = refs.Count > 0 && effect == Effects.ProcessDiscovery
            ? $"runs a WMI query that reads information about {refs.Count} specific process{(refs.Count == 1 ? "" : "es")}{DescribeReferencedPids(refs, ctx, includeLeadIn: false)}: {WmiProcessFields}"
            : $"runs a WMI query that reads {what}{remote}";
        return new Step(detail, phrase, true, effect);
    }

    private const string WmiProcessFields = "creation time, parent process ID, CPU and memory usage, executable path and command line";

    private static Step DescribeWmiMethod(string cmdlet, List<string> words, string text, Context ctx)
    {
        var cls = ValueOf(words, "-Class", "-ClassName") ?? FirstPositional(words, "-Class", "-ClassName", "-Name", "-MethodName", "-ArgumentList", "-Arguments", "-ComputerName", "-Namespace");
        var method = ValueOf(words, "-Name", "-MethodName") ?? "";
        if (cls?.Equals("Win32_Process", StringComparison.OrdinalIgnoreCase) == true && method.Equals("Create", StringComparison.OrdinalIgnoreCase))
            return new Step($"{cmdlet}: starts a new process through WMI ({Shorten(text, 140)}).", "starts a process through WMI", false, Effects.LaunchesPrograms);
        if (method.Equals("Terminate", StringComparison.OrdinalIgnoreCase))
            return new Step($"{cmdlet}: ends processes through WMI{DescribeReferencedPids(ReferencedPidExtractor.ExtractPids(text), ctx)}.", "ends processes through WMI", false, Effects.StopsProcesses);
        return new Step($"{cmdlet}: calls WMI method {method} on {cls} ({Shorten(text, 120)}).", $"calls WMI method {method}", false, Effects.ChangesSystem);
    }

    private static (string What, string Effect) WmiClass(string? cls) => (cls ?? "").ToLowerInvariant() switch
    {
        "win32_process" => ($"running processes: name, executable path, command line, creation time, parent process ID, CPU time and memory usage", Effects.ProcessDiscovery),
        "win32_service" => ("Windows services and their settings", Effects.SystemDiscovery),
        "win32_operatingsystem" => ("operating-system details (version, boot time, memory)", Effects.SystemDiscovery),
        "win32_computersystem" => ("computer details (model, domain, logged-on user)", Effects.SystemDiscovery),
        "win32_bios" => ("BIOS details (vendor, serial number)", Effects.SystemDiscovery),
        "win32_processor" => ("CPU details and load", Effects.SystemDiscovery),
        "win32_physicalmemory" => ("installed memory modules", Effects.SystemDiscovery),
        "win32_logicaldisk" or "win32_diskdrive" or "win32_volume" => ("disk and drive details", Effects.SystemDiscovery),
        "win32_videocontroller" => ("graphics-card details", Effects.SystemDiscovery),
        "win32_networkadapter" or "win32_networkadapterconfiguration" => ("network adapter settings", Effects.NetworkDiscovery),
        "win32_product" => ("installed software (note: this query also makes Windows Installer verify every package)", Effects.SystemDiscovery),
        "win32_startupcommand" => ("programs that run at start-up", Effects.SystemDiscovery),
        "win32_useraccount" or "win32_group" or "win32_groupuser" or "win32_loggedonuser" or "win32_logonsession" => ("user accounts and sessions", Effects.AccountDiscovery),
        "win32_shadowcopy" => ("shadow copies (Windows backups)", Effects.SystemDiscovery),
        "win32_quickfixengineering" => ("installed updates", Effects.SystemDiscovery),
        "win32_perfformatteddata_perfproc_process" => ("per-process CPU and memory usage", Effects.ProcessDiscovery),
        "antivirusproduct" or "firewallproduct" or "antispywareproduct" => ("installed security products", Effects.SecurityStatus),
        "msft_mpcomputerstatus" or "msft_mppreference" => ("Microsoft Defender status/settings", Effects.SecurityStatus),
        "win32_pnpentity" => ("hardware devices", Effects.SystemDiscovery),
        "win32_battery" => ("battery status", Effects.SystemDiscovery),
        "win32_share" => ("shared folders", Effects.NetworkDiscovery),
        "" => ("WMI data", Effects.SystemDiscovery),
        _ => ($"WMI data ({cls})", Effects.SystemDiscovery)
    };

    // -------------------------------------------------------------- helpers --

    /// <summary>"(PIDs 37868, 39508 — all asus_framework.exe)" using what the investigation resolved.</summary>
    private static string DescribeReferencedPids(IReadOnlyList<PidReference> refs, Context ctx, bool includeLeadIn = true)
    {
        if (refs.Count == 0) return "";
        var pids = string.Join(", ", refs.Take(12).Select(r => r.ProcessId)) + (refs.Count > 12 ? ", ..." : "");
        var lead = includeLeadIn ? " for " : " ";
        var resolved = refs
            .Select(r => ctx.Referenced.FirstOrDefault(x => x.ProcessId == r.ProcessId))
            .Where(x => x is not null && !string.IsNullOrEmpty(x.ProcessName))
            .Select(x => x!.ProcessName!)
            .ToList();

        string names = "";
        if (resolved.Count > 0)
        {
            var groups = resolved.GroupBy(n => n, StringComparer.OrdinalIgnoreCase).ToList();
            names = groups.Count == 1 && resolved.Count == refs.Count
                ? (refs.Count == 1 ? $" — {groups[0].Key}" : $" — all {groups[0].Key}")
                : " — " + string.Join(", ", groups.Select(g => g.Count() > 1 ? $"{g.Key} ×{g.Count()}" : g.Key)) +
                  (resolved.Count < refs.Count ? $", {refs.Count - resolved.Count} not identified" : "");
        }
        return $"{lead}(PID{(refs.Count == 1 ? "" : "s")} {pids}{names})";
    }

    /// <summary>Splits a PowerShell command into words, keeping quoted strings and (...)/{...} together.</summary>
    internal static List<string> PsWords(string text)
    {
        var words = new List<string>();
        var sb = new StringBuilder();
        char quote = '\0';
        int depth = 0;
        foreach (var c in text)
        {
            if (quote != '\0')
            {
                if (c == quote) quote = '\0';
                else sb.Append(c);
                continue;
            }
            if (c is '\'' or '"') { quote = c; continue; }
            if (c is '(' or '{') depth++;
            if (c is ')' or '}') depth = Math.Max(0, depth - 1);
            if (char.IsWhiteSpace(c) && depth == 0)
            {
                if (sb.Length > 0) { words.Add(sb.ToString()); sb.Clear(); }
                continue;
            }
            sb.Append(c);
        }
        if (sb.Length > 0) words.Add(sb.ToString());
        return words;
    }

    private static string? ValueOf(List<string> words, params string[] names)
    {
        for (int i = 0; i < words.Count - 1; i++)
        {
            var w = words[i];
            foreach (var name in names)
            {
                if (w.Equals(name, StringComparison.OrdinalIgnoreCase)) return words[i + 1];
                if (w.StartsWith(name + ":", StringComparison.OrdinalIgnoreCase)) return w[(name.Length + 1)..];
            }
        }
        return null;
    }

    private static string? FirstPositional(List<string> words, params string[] valueParameters)
    {
        for (int i = 1; i < words.Count; i++)
        {
            var w = words[i];
            if (w.StartsWith("-", StringComparison.Ordinal))
            {
                if (valueParameters.Any(p => p.Equals(w, StringComparison.OrdinalIgnoreCase))) i++;
                continue;
            }
            return w;
        }
        return null;
    }

    private static Step Prefix(string prefix, Step step)
    {
        step.Detail = prefix + step.Detail;
        return step;
    }

    private static string FileName(string? path) =>
        string.IsNullOrWhiteSpace(path) ? "a program" : CommandLineTokenizer.FileNameOf(path);

    private static string HostOf(string url)
    {
        if (Uri.TryCreate(url, UriKind.Absolute, out var uri)) return uri.Host;
        return "a web server";
    }

    private static string LowerFirst(string s) => s.Length == 0 ? s : char.ToLowerInvariant(s[0]) + s[1..];

    internal static string Shorten(string? s, int max)
    {
        if (string.IsNullOrEmpty(s)) return "";
        s = s.Replace("\r", " ").Replace("\n", " ");
        return s.Length <= max ? s : s[..(max - 1)] + "…";
    }
}
