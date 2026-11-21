using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using CmdSpy.Core.Models;

namespace CmdSpy.Core.Analysis;

/// <summary>What the detector looks at for one captured popup.</summary>
public sealed class DetectionContext
{
    public string? CommandLine { get; init; }
    public ParsedCommand? Parsed { get; init; }
    public string? ProcessName { get; init; }
    public string? ImagePath { get; init; }

    /// <summary>Launch chain, parent first.</summary>
    public IReadOnlyList<ProcessInfo> Ancestry { get; init; } = Array.Empty<ProcessInfo>();

    /// <summary>Processes the popup launched (children, grandchildren...).</summary>
    public IReadOnlyList<ProcessInfo> Children { get; init; } = Array.Empty<ProcessInfo>();

    /// <summary>
    /// Set when the process is verifiably one of CMD-spy's own self-test
    /// launches (see <see cref="CaptureSelfTest.IsGenuine"/>). The marker text
    /// alone is never trusted.
    /// </summary>
    public bool IsSelfTest { get; init; }
}

/// <summary>
/// Rule-based detection of suspicious execution: hidden/encoded commands,
/// download-and-run cradles, abused Windows binaries, credential theft,
/// ransomware-style recovery deletion, log wiping, security-tool tampering,
/// persistence, obfuscation, odd parent→child launches and masquerading.
/// Each finding says why it matters and maps to a MITRE ATT&amp;CK technique.
/// </summary>
public static class SuspiciousCommandDetector
{
    /// <summary>Marker CMD-spy puts in its own self-test command lines.</summary>
    public const string SelfTestMarker = "cmdspy-selftest";

    private const RegexOptions Opts = RegexOptions.IgnoreCase | RegexOptions.CultureInvariant;

    private sealed record Rule(string Id, string Severity, string Title, string Detail, string? Technique, Regex Pattern);

    private static Regex R(string pattern) => new(pattern, Opts);

    private static readonly Regex DownloadPattern = R(
        @"(DownloadString|DownloadData|DownloadFile|OpenRead\s*\(|Invoke-WebRequest|\biwr\b|Invoke-RestMethod|\birm\b|Net\.WebClient|Start-BitsTransfer|Net\.Http\.HttpClient|\bcurl(\.exe)?\s[^&|]*https?://|\bwget(\.exe)?\s[^&|]*https?://)");

    private static readonly Regex ExecutePattern = R(
        @"(\bIEX\b|Invoke-Expression|\|\s*iex\b|\.Invoke\s*\(\s*\)|\bInvoke-Command\b|\bStart-Process\b|\bsaps\b|&\s*\(\s*\[scriptblock\]|\[scriptblock\]::Create)");

    private static readonly Rule[] TextRules =
    {
        new("LOLBIN.CertutilDownload", Severity.High, "certutil used to download a file",
            "certutil is a certificate tool; downloading files with it is a well-known way to fetch malware past security tools.", "T1105",
            R(@"\bcertutil(\.exe)?\b[^&|\r\n]*[-/](urlcache|verifyctl)\b")),
        new("LOLBIN.CertutilDecode", Severity.Medium, "certutil used to decode a file",
            "Decoding with certutil is often used to unpack a hidden payload.", "T1140",
            R(@"\bcertutil(\.exe)?\b[^&|\r\n]*[-/](decode|decodehex)\b")),
        new("LOLBIN.Bitsadmin", Severity.High, "bitsadmin used to transfer files",
            "BITS jobs are abused to download payloads and to persist.", "T1197",
            R(@"\bbitsadmin(\.exe)?\b[^&|\r\n]*/(transfer|addfile|setnotifycmdline|create)\b")),
        new("LOLBIN.MshtaRemote", Severity.High, "mshta runs remote or inline script",
            "mshta executing a URL or inline JavaScript/VBScript is a classic malware launcher.", "T1218.005",
            R(@"\bmshta(\.exe)?\b[^&|\r\n]*(https?://|javascript:|vbscript:)")),
        new("LOLBIN.Regsvr32Remote", Severity.High, "regsvr32 loads a remote script (Squiblydoo)",
            "regsvr32 with /i:URL or scrobj.dll runs remote script code while bypassing application control.", "T1218.010",
            R(@"\bregsvr32(\.exe)?\b[^&|\r\n]*(/i:\s*[""']?https?://|scrobj\.dll)")),
        new("LOLBIN.Rundll32Script", Severity.High, "rundll32 runs script or a URL",
            "rundll32 used to run JavaScript, HTML applications or URLs is a common evasion technique.", "T1218.011",
            R(@"\brundll32(\.exe)?\b[^&|\r\n]*(javascript:|vbscript:|url\.dll\s*,\s*(FileProtocolHandler|OpenURL)|mshtml(\.dll)?\s*,\s*RunHTMLApplication|advpack\.dll\s*,\s*(RegisterOCX|LaunchINFSection)|zipfldr\.dll\s*,\s*RouteTheCall|pcwutl\.dll\s*,\s*LaunchApplication)")),
        new("CRED.LsassDump", Severity.High, "Dumps credentials / LSASS memory",
            "Reading LSASS memory or running Mimikatz-style commands steals passwords and hashes.", "T1003.001",
            R(@"(comsvcs(\.dll)?\s*,?\s*#?(MiniDump|24)\b|procdump(64)?(\.exe)?[^&|\r\n]*\blsass|\bsekurlsa::|\bmimikatz\b|lsadump::|kerberos::(golden|ptt)|privilege::debug|Out-Minidump)")),
        new("CRED.HiveSave", Severity.High, "Saves password registry hives",
            "Saving the SAM/SECURITY/SYSTEM hives lets an attacker extract password hashes offline.", "T1003.002",
            R(@"\breg(\.exe)?\s+(save|export)\s+[""']?(HKLM|HKEY_LOCAL_MACHINE)\\(SAM|SECURITY|SYSTEM)\b")),
        new("CRED.WifiPasswords", Severity.Medium, "Reveals saved Wi-Fi passwords",
            "'netsh wlan show profile ... key=clear' prints stored Wi-Fi passwords in plain text.", "T1555",
            R(@"\bnetsh(\.exe)?\s+wlan\s+show\s+profiles?\b[^&|\r\n]*key\s*=\s*clear")),
        new("IMPACT.InhibitRecovery", Severity.High, "Deletes backups / disables recovery (ransomware behaviour)",
            "Deleting shadow copies or disabling Windows recovery is what ransomware does before encrypting files.", "T1490",
            R(@"(vssadmin(\.exe)?\s+(delete\s+shadows|resize\s+shadowstorage)|wmic(\.exe)?\s+shadowcopy\s+delete|Win32_ShadowCopy[^|;\r\n]*\|\s*(Remove-WmiObject|Remove-CimInstance|ForEach-Object\s*\{\s*\$_\.Delete)|wbadmin(\.exe)?\s+delete\s+(catalog|systemstatebackup|backup)|bcdedit(\.exe)?[^&|\r\n]*(recoveryenabled\s+no|bootstatuspolicy\s+ignoreallfailures))")),
        new("EVASION.ClearLogs", Severity.High, "Clears event logs / activity history",
            "Wiping logs is used to hide what happened on the machine.", "T1070.001",
            R(@"(wevtutil(\.exe)?\s+(cl|clear-log)\b|\bClear-EventLog\b|\bRemove-EventLog\b|fsutil(\.exe)?\s+usn\s+deletejournal)")),
        new("EVASION.Defender", Severity.High, "Tampers with Microsoft Defender",
            "Disabling Defender protections or adding exclusions lets malware run undetected.", "T1562.001",
            R(@"(Set-MpPreference[^;|\r\n]*-Disable(RealtimeMonitoring|BehaviorMonitoring|IOAVProtection|ScriptScanning|IntrusionPreventionSystem|BlockAtFirstSeen|ArchiveScanning)\b|Add-MpPreference[^;|\r\n]*-Exclusion(Path|Process|Extension|IpAddress)|\b(sc|net1?)(\.exe)?\s+(stop|config|delete)\s+(WinDefend|WdNisSvc|Sense|wscsvc|SecurityHealthService)\b|DisableAntiSpyware|DisableRealtimeMonitoring|MpCmdRun(\.exe)?[^&|\r\n]*-RemoveDefinitions)")),
        new("EVASION.Firewall", Severity.High, "Turns off the Windows firewall",
            "Disabling the firewall opens the machine to remote access.", "T1562.004",
            R(@"(netsh(\.exe)?\s+(advfirewall\s+set\s+\w+\s+state\s+off|firewall\s+set\s+opmode\s+(mode=)?disable)|Set-NetFirewallProfile[^;|\r\n]*-Enabled\s+(False|\$false|0)\b)")),
        new("EVASION.Amsi", Severity.High, "AMSI bypass attempt",
            "Tampering with AMSI disables the scanning PowerShell uses to catch malicious scripts.", "T1562.001",
            R(@"(AmsiUtils|amsiInitFailed|AmsiScanBuffer|AmsiOpenSession)")),
        new("EVASION.KillSecurityTool", Severity.High, "Stops a security product",
            "Killing antivirus/EDR processes is a common step before running malware.", "T1562.001",
            R(@"(taskkill|Stop-Process|\bkill\b|\bspps\b)[^&|;\r\n]*\b(MsMpEng|MsSense|SecurityHealthService|avp|avgui|avastsvc|mbam|mbamservice|ekrn|egui|bdagent|vsserv|SavService|ccSvcHst|mcshield|SentinelAgent|CylanceSvc|csfalconservice|xagt|tmbmsrv)\b")),
        new("PERSIST.WmiSubscription", Severity.High, "Creates a WMI event subscription",
            "WMI event consumers run code automatically and survive reboots — a stealthy persistence method.", "T1546.003",
            R(@"(__EventFilter|CommandLineEventConsumer|ActiveScriptEventConsumer|__FilterToConsumerBinding)")),
        new("PERSIST.Ifeo", Severity.High, "Hijacks program start-up (IFEO / SilentProcessExit)",
            "Image File Execution Options 'Debugger' values make another program run whenever the target starts.", "T1546.012",
            R(@"(Image File Execution Options[^&|;\r\n]*\b(Debugger|GlobalFlag)\b|SilentProcessExit)")),
        new("PERSIST.Winlogon", Severity.High, "Changes the Winlogon shell/userinit",
            "Modifying Winlogon's Shell/Userinit runs code at every logon.", "T1547.004",
            R(@"(reg(\.exe)?\s+add|Set-ItemProperty|New-ItemProperty|\bsp\s)[^&|;\r\n]*\\Winlogon\b[^&|;\r\n]*\b(Shell|Userinit|Notify)\b")),
        new("ACCOUNT.AddAdmin", Severity.High, "Adds a user to an administrators/remote-access group",
            "Granting admin or Remote Desktop rights is a classic way to keep access.", "T1098",
            R(@"(net1?(\.exe)?\s+localgroup\s+[""']?(administrators|Remote Desktop Users)[""']?\s+\S+\s+/add|Add-LocalGroupMember[^;|\r\n]*-Group\s+[""']?(Administrators|Remote Desktop Users))")),
        new("ACCOUNT.CreateUser", Severity.Medium, "Creates a user account",
            "Scripts rarely create accounts; attackers do it to keep access.", "T1136.001",
            R(@"(net1?(\.exe)?\s+user\s+\S+(\s+\S+)?\s+/add\b|\bNew-LocalUser\b)")),
        new("NETWORK.PortProxy", Severity.High, "Sets up port forwarding (netsh portproxy)",
            "Port proxies are used to tunnel traffic into a network through this machine.", "T1090",
            R(@"\bnetsh(\.exe)?\s+interface\s+portproxy\s+add\b")),
        new("EXEC.ReflectiveLoad", Severity.High, "Loads a program directly into memory",
            "Reflective .NET loading runs code that never touches the disk, avoiding file scanning.", "T1620",
            R(@"\[(System\.)?Reflection\.Assembly\]::(Load|LoadFile|LoadFrom|UnsafeLoadFrom)\s*\(")),
        new("EXEC.ProcessInjection", Severity.High, "Process-injection API usage",
            "Allocating memory and creating threads through Win32 APIs is how code is injected into other processes.", "T1055",
            R(@"\b(VirtualAlloc(Ex)?|WriteProcessMemory|CreateRemoteThread|NtCreateThreadEx|QueueUserAPC)\b")),
        new("EXEC.WmiCreate", Severity.Medium, "Starts a process through WMI",
            "Creating processes through WMI hides the real parent and is used for remote execution.", "T1047",
            R(@"(wmic(\.exe)?[^&|\r\n]*\bprocess\s+call\s+create\b|Invoke-(Wmi|Cim)Method[^;|\r\n]*Win32_Process[^;|\r\n]*Create|\[wmiclass\][^)]*Win32_Process[^)]*\)\s*\.\s*Create)")),
        new("PERSIST.ScheduledTask", Severity.Medium, "Creates a scheduled task",
            "Scheduled tasks make code run again later or at every start — useful for software, and for malware persistence.", "T1053.005",
            R(@"(schtasks(\.exe)?\s+/create\b|\bRegister-ScheduledTask\b|\bNew-ScheduledTaskAction\b)")),
        new("PERSIST.RunKey", Severity.Medium, "Adds a start-up (Run key) entry",
            "Run keys start a program at every logon.", "T1547.001",
            R(@"(reg(\.exe)?\s+add|Set-ItemProperty|New-ItemProperty|\bsp\s)[^&|;\r\n]*\\CurrentVersion\\(Run|RunOnce|Policies\\Explorer\\Run)\b")),
        new("PERSIST.StartupFolder", Severity.Medium, "Writes to the Startup folder",
            "Files in the Startup folder run at every logon.", "T1547.001",
            R(@"(copy|move|xcopy|Copy-Item|Move-Item|\bcp\b|\bmv\b|Set-Content|Out-File|New-Item|>)[^&|;\r\n]*\\Start Menu\\Programs\\Startup\b")),
        new("PERSIST.Service", Severity.Medium, "Creates a Windows service",
            "Services run automatically at boot with high privileges.", "T1543.003",
            R(@"(\bsc(\.exe)?\s+(\\\\\S+\s+)?create\b|\bNew-Service\b)")),
        new("DEOBF.FromBase64", Severity.Medium, "Decodes Base64 data inside the command",
            "Decoding Base64 at run time is commonly used to unpack a hidden payload.", "T1140",
            R(@"FromBase64String")),
        new("NETWORK.RawIp", Severity.Medium, "Web address uses a raw IP address",
            "Legitimate software normally uses domain names; raw-IP downloads are typical of malware.", "T1071.001",
            R(@"https?://\d{1,3}(\.\d{1,3}){3}(:\d+)?/")),
        new("NETWORK.PasteSite", Severity.Medium, "Contacts a paste or file-sharing site",
            "Paste and file-sharing sites are frequently used to host malicious payloads.", "T1102",
            R(@"https?://[^\s'""]*(pastebin\.com|paste\.ee|hastebin|transfer\.sh|ngrok\.io|ngrok-free\.app|raw\.githubusercontent\.com|cdn\.discordapp\.com|discord(app)?\.com/attachments|bit\.ly|tinyurl\.com|temp\.sh|anonfiles|file\.io|mega\.nz|dropboxusercontent\.com|drive\.google\.com/uc)")),
        new("OBFUSCATION.EnvSubstring", Severity.Medium, "Builds commands from environment-variable fragments",
            "Slicing variables like %COMSPEC:~-7,1% is a cmd obfuscation trick to hide keywords.", "T1027",
            R(@"%\w+:~-?\d+(,-?\d+)?%")),
        new("OBFUSCATION.CharCodes", Severity.Medium, "Builds text from character codes",
            "Assembling strings from [char] codes hides keywords from simple scanning.", "T1027",
            R(@"(\[char\]\s*\d{2,3}\s*\+\s*\[char\]|-join\s*\(\s*\d{2,3}\s*,\s*\d{2,3}|\[char\[\]\]\s*\(\s*\d{2,3}\s*,)")),
        new("OBFUSCATION.Concat", Severity.Medium, "Splits keywords into concatenated pieces",
            "Joining fragments like 'Down'+'loadString' hides keywords from detection.", "T1027",
            R(@"(['""][\w.\-]{1,15}['""]\s*\+\s*){2,}['""][\w.\-]{1,15}['""]")),
        new("PERMS.Everyone", Severity.Medium, "Grants everyone full control of files",
            "Opening permissions to Everyone weakens the system's protection.", "T1222.001",
            R(@"\bicacls(\.exe)?\b[^&|\r\n]*(/grant|/g)\b[^&|\r\n]*(Everyone|\*S-1-1-0|Users):\(?F")),
        new("LOLBIN.Proxy", Severity.Medium, "Uses a Windows binary often abused to run code",
            "Tools like msbuild, installutil, regasm, cmstp and odbcconf can run arbitrary code while looking legitimate.", "T1218",
            R(@"\b(msbuild|installutil|regasm|regsvcs|cmstp|odbcconf|pcalua|mavinject|msxsl|ieexec)(\.exe)?\b")),
        new("HIDE.Attrib", Severity.Low, "Hides files (attrib +h)",
            "Marking files hidden/system is used to keep payloads out of sight.", "T1564.001",
            R(@"\battrib(\.exe)?\s+[^&|\r\n]*\+h\b")),
        new("EVASION.WipeFreeSpace", Severity.Low, "Wipes free disk space",
            "cipher /w makes deleted files unrecoverable.", "T1070.004",
            R(@"\bcipher(\.exe)?\s+/w\b")),
    };

    private static readonly Regex UserWritableExec = R(
        @"([A-Za-z]:\\(Users\\[^\\]+\\AppData\\Local\\Temp|Windows\\Temp|Users\\Public|Users\\[^\\]+\\Downloads|ProgramData)\\|%TEMP%\\|%TMP%\\|\$env:TEMP|\$env:TMP|%PUBLIC%\\|%APPDATA%\\|\$env:APPDATA)[^""'\s]*\.(exe|dll|scr|bat|cmd|ps1|vbs|vbe|js|jse|hta|wsf|lnk|pif|com|msi)\b");

    private static readonly (string Pattern, string Name)[] ReconCommands =
    {
        (@"\bwhoami\b", "whoami"), (@"\bnet1?(\.exe)?\s+(user|group|localgroup|accounts|share|view|session)\b", "net"),
        (@"\bsysteminfo\b", "systeminfo"), (@"\bipconfig(\.exe)?\s+/all\b", "ipconfig /all"),
        (@"\btasklist\b", "tasklist"), (@"\bnetstat(\.exe)?\s+-\w*a", "netstat"), (@"\bnltest\b", "nltest"),
        (@"\b(quser|qwinsta|query\s+user)\b", "query user"), (@"\barp(\.exe)?\s+-a\b", "arp -a"),
        (@"\bhostname\b", "hostname"), (@"\bGet-ComputerInfo\b", "Get-ComputerInfo"),
        (@"\bwmic(\.exe)?\s+(computersystem|useraccount|qfe|os|product)\b", "wmic"),
        (@"AntiVirusProduct", "antivirus query"), (@"\bGet-LocalUser\b", "Get-LocalUser"),
        (@"\broute(\.exe)?\s+print\b", "route print"), (@"\bcmdkey(\.exe)?\s+/list\b", "cmdkey /list")
    };

    private static readonly HashSet<string> SystemBinaries = new(StringComparer.OrdinalIgnoreCase)
    {
        "svchost", "lsass", "csrss", "smss", "services", "winlogon", "wininit", "explorer", "taskhostw",
        "conhost", "cmd", "powershell", "rundll32", "dllhost", "spoolsv", "regsvr32", "mshta", "wscript",
        "cscript", "msiexec", "sihost", "ctfmon", "RuntimeBroker", "lsm", "taskmgr", "WmiPrvSE", "userinit"
    };

    private static readonly string[] Typosquats =
    {
        "scvhost", "svch0st", "svchosts", "svhost", "svchost32", "lsasss", "lsas", "isass", "csrsss", "csrrs",
        "expl0rer", "explore", "iexplorer", "winlogin", "winiinit", "smsss", "taskhosts", "conhosts", "rundl32", "rundll"
    };

    private static readonly HashSet<string> OfficeApps = new(StringComparer.OrdinalIgnoreCase)
    { "winword", "excel", "powerpnt", "outlook", "msaccess", "mspub", "visio", "onenote", "eqnedt32" };

    private static readonly HashSet<string> PdfReaders = new(StringComparer.OrdinalIgnoreCase)
    { "acrord32", "acrobat", "foxitreader", "foxitphantompdf", "foxitpdfreader", "sumatrapdf" };

    private static readonly HashSet<string> Browsers = new(StringComparer.OrdinalIgnoreCase)
    { "chrome", "msedge", "firefox", "iexplore", "brave", "opera", "vivaldi" };

    private static readonly HashSet<string> SystemCriticalParents = new(StringComparer.OrdinalIgnoreCase)
    { "lsass", "spoolsv", "smss", "csrss", "wininit" };

    /// <summary>Strips common obfuscation so rules see the real keywords.</summary>
    public static string Normalize(string text)
    {
        var s = text.Replace("^", "");
        s = Regex.Replace(s, @"`(?=[A-Za-z])", "");                         // b`a`c`k`ticks
        s = Regex.Replace(s, @"(['""])\s*\+\s*\1", "");                      // 'Down'+'load' → 'Download'
        s = s.Replace('\u2013', '-').Replace('\u2014', '-').Replace('\u2015', '-');
        return s;
    }

    public static List<Finding> Analyze(DetectionContext ctx)
    {
        var findings = new List<Finding>();
        var parsed = ctx.Parsed ?? CommandParser.Parse(ctx.CommandLine, ctx.ProcessName);

        // Texts to scan: the command, decoded/nested payloads, and every action's command line.
        var subjects = new List<(string Subject, string Text)>();
        foreach (var (label, text) in parsed.AllTexts()) subjects.Add((label, text));
        foreach (var child in ctx.Children)
            if (!string.IsNullOrWhiteSpace(child.CommandLine))
                subjects.Add(($"action [{child.ProcessId}] {child.ProcessName}", child.CommandLine!));

        foreach (var (subject, text) in subjects)
            ScanText(subject, text, findings);

        // Self-test processes are labelled, not judged — but only when CMD-spy
        // really launched them. Anything else wearing the marker is trying to
        // pass itself off as CMD-spy, which is suspicious in its own right.
        if (ctx.IsSelfTest)
            Add(findings, "INFO.SelfTest", Severity.Info, "CMD-spy capture self-test process",
                "Started by CMD-spy's own self-test to verify that short-lived windows are captured.", null, SelfTestMarker, "command");
        else if (subjects.Any(s => s.Text.Contains(SelfTestMarker, StringComparison.OrdinalIgnoreCase)))
            Add(findings, "EVASION.FakeSelfTest", Severity.Medium, "Imitates CMD-spy's self-test marker",
                "The command carries CMD-spy's self-test label but was not started by CMD-spy — something may be trying to hide from this monitor.",
                "T1036", SelfTestMarker, "command");

        AnalyzeLaunchSwitches(parsed, findings);
        AnalyzeLineage(ctx, parsed, findings);
        AnalyzeLocations(ctx, findings);

        return Order(findings);
    }

    private static void ScanText(string subject, string text, List<Finding> findings)
    {
        var normalized = Normalize(text);

        // Download + execute together is a cradle; on their own, a download is still worth noting.
        bool downloads = DownloadPattern.IsMatch(normalized);
        bool executes = ExecutePattern.IsMatch(normalized);
        if (downloads && executes)
            Add(findings, "EXEC.DownloadCradle", Severity.High, "Downloads code and runs it (download cradle)",
                "Fetching code from the internet and executing it immediately is the most common way malware gets onto a PC.",
                "T1105", Snippet(DownloadPattern.Match(normalized).Value), subject);
        else if (downloads)
            Add(findings, "NETWORK.Download", Severity.Medium, "Downloads content from the internet",
                "The command fetches data from the web; check that the address is one you expect.", "T1105",
                Snippet(DownloadPattern.Match(normalized).Value), subject);
        else if (executes && Regex.IsMatch(normalized, @"(\bIEX\b|Invoke-Expression)", Opts))
            Add(findings, "EXEC.Iex", Severity.Medium, "Runs dynamically built code (Invoke-Expression)",
                "Invoke-Expression executes text as code, which hides what actually runs.", "T1059.001",
                Snippet(Regex.Match(normalized, @"(\bIEX\b|Invoke-Expression)[^;|\r\n]{0,60}", Opts).Value), subject);

        foreach (var rule in TextRules)
        {
            var m = rule.Pattern.Match(normalized);
            if (m.Success)
                Add(findings, rule.Id, rule.Severity, rule.Title, rule.Detail, rule.Technique, Snippet(m.Value), subject);
        }

        // Caret / backtick obfuscation is judged on the raw text (normalisation removes it).
        if (Regex.IsMatch(text, @"\w\^\w\^\w", Opts) || text.Count(c => c == '^') >= 6)
            Add(findings, "OBFUSCATION.Caret", Severity.Medium, "Caret-obfuscated command (p^o^w^e^r...)",
                "Inserting ^ between letters hides command names from simple detection.", "T1027",
                Snippet(Regex.Match(text, @"\S*\^\S*", Opts).Value), subject);
        if (Regex.IsMatch(text, @"[A-Za-z]`[A-Za-z]`[A-Za-z]", Opts))
            Add(findings, "OBFUSCATION.Backtick", Severity.Medium, "Backtick-obfuscated PowerShell (I`E`X...)",
                "PowerShell ignores backticks inside words, so they are used to break up keywords.", "T1027",
                Snippet(Regex.Match(text, @"\S*`\S*", Opts).Value), subject);

        if (UserWritableExec.Match(text) is { Success: true } path)
            Add(findings, "EXEC.UserWritablePath", Severity.Medium, "Runs a file from a temporary or public folder",
                "Malware is usually dropped into Temp, Downloads, Public or ProgramData before running.", "T1204.002",
                Snippet(path.Value), subject);

        var recon = ReconCommands.Where(r => Regex.IsMatch(normalized, r.Pattern, Opts)).Select(r => r.Name).Distinct().ToList();
        if (recon.Count >= 3)
            Add(findings, "RECON.Bundle", Severity.Medium, "Gathers system and user information (reconnaissance)",
                "Running several discovery commands together is typical of an attacker mapping a machine.", "T1082",
                string.Join(", ", recon), subject);

        if (text.Length > 2000)
            Add(findings, "OBFUSCATION.Long", Severity.Low, "Unusually long command line",
                "Very long command lines often carry embedded scripts or payloads.", "T1027",
                $"{text.Length} characters", subject);
    }

    private static void AnalyzeLaunchSwitches(ParsedCommand parsed, List<Finding> findings)
    {
        void Check(ParsedCommand p, string subject)
        {
            if (p.EncodedCommand is not null)
                Add(findings, "PS.Encoded", Severity.Medium, "PowerShell command hidden with -EncodedCommand",
                    "Encoding the command in Base64 hides what it does; CMD-spy decoded it above.", "T1027",
                    Snippet(p.EncodedCommand), subject);
            if (p.HiddenWindow)
                Add(findings, "PS.HiddenWindow", Severity.Medium, "Runs with a hidden window",
                    "Hiding the window prevents the user from seeing what runs.", "T1564.003",
                    p.WindowStyle, subject);
            if (p.BypassPolicy)
                Add(findings, "PS.Bypass", Severity.Low, "Bypasses the PowerShell execution policy",
                    "Common in installers and admin scripts, but also in malware launchers.", "T1059.001",
                    $"-ExecutionPolicy {p.ExecutionPolicy}", subject);
            if (p.Kind == InterpreterKind.Conhost && p.InnerCommand is not null)
                Add(findings, "EXEC.ConhostProxy", p.Headless ? Severity.High : Severity.Medium,
                    p.Headless ? "Runs a program headless through conhost" : "Uses conhost to launch another program",
                    "Launching programs through conhost.exe hides the real parent and, with --headless, the window.", "T1202",
                    Snippet(p.InnerCommand), subject);
            if (p.ReadsFromStdin)
                Add(findings, "PS.Stdin", Severity.Low, "Commands piped in through standard input",
                    "The commands are not visible in the command line.", "T1059.001", "-Command -", subject);
        }

        Check(parsed, "command");
        foreach (var nested in parsed.Nested) Check(nested, "nested command");
    }

    private static void AnalyzeLineage(DetectionContext ctx, ParsedCommand parsed, List<Finding> findings)
    {
        if (ctx.Ancestry.Count == 0) return;
        var parent = ctx.Ancestry[0];
        var parentStem = CmdSpyOptions.Stem(parent.ProcessName);
        bool interpreter = parsed.Kind is InterpreterKind.Cmd or InterpreterKind.PowerShell or InterpreterKind.Pwsh
            or InterpreterKind.WScript or InterpreterKind.CScript or InterpreterKind.Mshta;
        if (!interpreter) return;

        var evidence = $"{parent.ProcessName} (PID {parent.ProcessId}) → {ctx.ProcessName}";

        if (OfficeApps.Contains(parentStem))
            Add(findings, "LINEAGE.Office", Severity.High, "An Office application started a command interpreter",
                "Documents with malicious macros typically launch cmd/PowerShell exactly like this.", "T1204.002", evidence, "launch chain");
        else if (PdfReaders.Contains(parentStem))
            Add(findings, "LINEAGE.Pdf", Severity.High, "A PDF reader started a command interpreter",
                "PDF readers have no normal reason to run commands; this pattern indicates an exploit.", "T1203", evidence, "launch chain");
        else if (Browsers.Contains(parentStem))
        {
            bool nativeMessaging = (ctx.CommandLine ?? "").Contains("chrome-extension://", StringComparison.OrdinalIgnoreCase) ||
                                   (ctx.CommandLine ?? "").Contains("moz-extension://", StringComparison.OrdinalIgnoreCase) ||
                                   (ctx.CommandLine ?? "").Contains("--parent-window", StringComparison.OrdinalIgnoreCase);
            if (nativeMessaging)
                Add(findings, "LINEAGE.BrowserNativeMessaging", Severity.Info, "Browser extension helper (native messaging)",
                    "Browsers start helpers this way for installed extensions (password managers etc.) — normal if you trust the extension.", null, evidence, "launch chain");
            else
                Add(findings, "LINEAGE.Browser", Severity.Medium, "A web browser started a command interpreter",
                    "Browsers rarely run cmd/PowerShell; it can indicate a malicious download or exploit.", "T1189", evidence, "launch chain");
        }
        else if (parentStem is "wscript" or "cscript" or "mshta")
            Add(findings, "LINEAGE.ScriptHost", Severity.Medium, "A script host started a command interpreter",
                "Script files (.js/.vbs/.hta) launching cmd/PowerShell is a common malware chain.", "T1059.005", evidence, "launch chain");
        else if (parentStem.Equals("WmiPrvSE", StringComparison.OrdinalIgnoreCase))
            Add(findings, "LINEAGE.Wmi", Severity.Medium, "Started through WMI",
                "WMI-launched commands hide the real requester and are used for remote execution — though some management software also does this.", "T1047", evidence, "launch chain");
        else if (parentStem.Equals("services", StringComparison.OrdinalIgnoreCase) && parsed.Kind is InterpreterKind.Cmd or InterpreterKind.PowerShell or InterpreterKind.Pwsh)
            Add(findings, "LINEAGE.ServiceDirect", Severity.Medium, "Started directly as a Windows service",
                "A command interpreter registered as a service is how PsExec-style remote tools (and attackers) run commands.", "T1569.002", evidence, "launch chain");
        else if (SystemCriticalParents.Contains(parentStem))
            Add(findings, "LINEAGE.SystemProcess", Severity.High, "A core Windows process started a command interpreter",
                $"{parent.ProcessName} has no normal reason to run commands; this pattern indicates exploitation.", "T1068", evidence, "launch chain");
    }

    private static void AnalyzeLocations(DetectionContext ctx, List<Finding> findings)
    {
        void CheckImage(string? name, string? path, string subject)
        {
            if (string.IsNullOrWhiteSpace(path) || !IsRooted(path)) return;
            var file = Path.GetFileName(path.Replace('/', '\\').Split('\\').Last());
            var stem = CmdSpyOptions.Stem(file);

            if (Typosquats.Any(t => stem.Equals(t, StringComparison.OrdinalIgnoreCase)))
                Add(findings, "MASQ.Typosquat", Severity.High, "Name imitates a Windows process",
                    $"'{file}' looks like a Windows system file but is misspelled — a classic disguise.", "T1036.005", path, subject);
            else if (SystemBinaries.Contains(stem) && !IsSystemLocation(path, stem))
                Add(findings, "MASQ.Location", Severity.High, "Windows system file name running from the wrong folder",
                    $"The real {file} lives in the Windows folder; a copy elsewhere is a common malware disguise.", "T1036.005", path, subject);

            if (Regex.IsMatch(path, @"\\(AppData\\Local\\Temp|Windows\\Temp|Users\\Public|Downloads)\\", Opts))
                Add(findings, "LOCATION.Temp", Severity.Medium, "Runs from a temporary, public or download folder",
                    "Programs started from Temp/Public/Downloads are often freshly dropped files.", "T1204.002", path, subject);
        }

        CheckImage(ctx.ProcessName, ctx.ImagePath, "this process");
        for (int i = 0; i < ctx.Ancestry.Count; i++)
            CheckImage(ctx.Ancestry[i].ProcessName, ctx.Ancestry[i].ImagePath, i == 0 ? "parent" : "launch chain");
        foreach (var child in ctx.Children)
            CheckImage(child.ProcessName, child.ImagePath, $"action [{child.ProcessId}] {child.ProcessName}");
    }

    /// <summary>Findings about the digital signatures of the files involved.</summary>
    public static List<Finding> AnalyzeSignatures(IReadOnlyList<SignatureInfo> signatures)
    {
        var findings = new List<Finding>();
        foreach (var sig in signatures)
        {
            var file = Path.GetFileName(sig.Path.Replace('/', '\\').Split('\\').Last());
            var stem = CmdSpyOptions.Stem(file);
            var role = sig.Role;
            bool windowsName = SystemBinaries.Contains(stem) || stem is "pwsh" or "wt" or "WindowsTerminal" or "OpenConsole";
            bool userWritable = Regex.IsMatch(sig.Path, @"\\(AppData|Temp|Users\\Public|Downloads|ProgramData)\\", Opts);

            if (sig.Status == SignatureStatus.Invalid)
            {
                Add(findings, "SIG.Invalid", Severity.High, $"{file} has an INVALID signature",
                    "The file was changed after it was signed (or the signature is forged) — a strong tampering indicator.", "T1553.002",
                    $"{sig.Path} ({sig.Detail})", role);
                continue;
            }

            if (windowsName && IsRooted(sig.Path) && !sig.IsMicrosoft)
            {
                if (sig.Status == SignatureStatus.Valid)
                {
                    // Signed — but by someone other than Microsoft: a disguise, not a glitch.
                    Add(findings, "SIG.NotMicrosoft", Severity.High, $"{file} is signed by someone other than Microsoft",
                        $"A genuine {file} is signed by Microsoft; this one is signed by {sig.Publisher} — a disguised program.",
                        "T1036.005", sig.Path, role);
                    continue;
                }
                if (sig.Status is SignatureStatus.Unsigned or SignatureStatus.Untrusted)
                {
                    bool inWindowsFolder = IsSystemLocation(sig.Path, stem);
                    Add(findings, inWindowsFolder ? "SIG.WindowsFileUnverified" : "SIG.NotMicrosoft",
                        inWindowsFolder ? Severity.Medium : Severity.High,
                        inWindowsFolder ? $"{file} could not be verified as Microsoft-signed" : $"{file} is not signed by Microsoft",
                        inWindowsFolder
                            ? "This Windows file failed signature verification. It may have been replaced — or the system catalog may simply be out of date after an update. Worth a follow-up scan."
                            : $"A genuine {file} is signed by Microsoft and lives in the Windows folder; this copy is {sig.Status.ToLowerInvariant()} — likely a disguised program.",
                        "T1036.005", sig.Path, role);
                    continue;
                }
            }

            bool isLauncher = role.Contains("launcher", StringComparison.OrdinalIgnoreCase);
            bool isAction = role.Contains("action", StringComparison.OrdinalIgnoreCase);
            bool isChain = isLauncher || role.Contains("parent", StringComparison.OrdinalIgnoreCase) || role.Contains("ancestor", StringComparison.OrdinalIgnoreCase);

            if (sig.Status == SignatureStatus.Unsigned && (isChain || isAction))
            {
                var severity = userWritable ? Severity.Medium : (isLauncher ? Severity.Medium : Severity.Low);
                Add(findings, isLauncher ? "SIG.UnsignedLauncher" : "SIG.Unsigned", severity,
                    $"{file} is not digitally signed",
                    isLauncher
                        ? "The program that started this is unsigned, so its publisher can't be verified. Many small tools are unsigned, but malware usually is too."
                        : "Unsigned programs can't be traced to a publisher.",
                    null, sig.Path, role);
            }
            else if (sig.Status == SignatureStatus.Untrusted && (isChain || isAction))
            {
                Add(findings, "SIG.Untrusted", Severity.Medium, $"{file}'s signature is not trusted",
                    "It is signed, but the certificate isn't trusted on this PC (unknown, revoked or self-signed).", "T1553.002",
                    $"{sig.Path} ({sig.Detail})", role);
            }
        }
        return Order(findings);
    }

    // -------------------------------------------------------------- helpers --

    private static void Add(List<Finding> findings, string id, string severity, string title, string detail,
        string? technique, string? evidence, string subject)
    {
        // One finding per rule: keep the first subject, but upgrade severity if needed.
        var existing = findings.FirstOrDefault(f => f.RuleId == id);
        if (existing is not null)
        {
            if (Severity.Rank(severity) > Severity.Rank(existing.Severity)) existing.Severity = severity;
            return;
        }
        findings.Add(new Finding
        {
            RuleId = id,
            Severity = severity,
            Title = title,
            Detail = detail,
            Technique = technique,
            Evidence = evidence,
            Subject = subject
        });
    }

    private static List<Finding> Order(List<Finding> findings) =>
        findings.OrderByDescending(f => Severity.Rank(f.Severity)).ToList();

    private static string Snippet(string? text) => CommandExplainer.Shorten(text?.Trim(), 160);

    private static bool IsRooted(string path) =>
        path.Length > 2 && (path[1] == ':' || path.StartsWith(@"\\", StringComparison.Ordinal));

    private static bool IsSystemLocation(string path, string stem)
    {
        var p = path.Replace('/', '\\');
        if (Regex.IsMatch(p, @"^[A-Za-z]:\\Windows\\(System32|SysWOW64|SystemApps|WinSxS|servicing)\\", Opts)) return true;
        if (Regex.IsMatch(p, @"^[A-Za-z]:\\Windows\\[^\\]+\.exe$", Opts) && stem is "explorer" or "notepad" or "regedit" or "HelpPane" or "splwow64") return true;
        if (Regex.IsMatch(p, @"^[A-Za-z]:\\Windows\\(Microsoft\.NET|ImmersiveControlPanel)\\", Opts)) return true;
        return false;
    }
}
