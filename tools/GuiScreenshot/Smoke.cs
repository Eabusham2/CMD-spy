using System.Diagnostics;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Xml.Linq;

namespace GuiScreenshot;

/// <summary>
/// Smoke-tests the start-up paths on a real Windows machine, registering them
/// exactly the way the app does (its own ServiceControl / StartupTaskDefinition
/// code is called through reflection): the boot service running as LocalSystem,
/// the elevated high-priority logon task, and single-instance protection.
/// Everything it registers is removed again.
/// </summary>
internal static class Smoke
{
    private static StreamWriter? _log;
    private static readonly List<(string Check, bool Pass, string Detail)> Results = new();

    public static int Run(string appExe, string outDir)
    {
        Directory.CreateDirectory(outDir);
        _log = new StreamWriter(Path.Combine(outDir, "smoke.log")) { AutoFlush = true };
        appExe = Path.GetFullPath(appExe);
        Log($"App under test: {appExe}");
        var logDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "CmdSpy", "logs");

        try { BootService(appExe, logDir); }
        catch (Exception ex) { Check("Boot service smoke test ran", false, ex.ToString()); }
        finally { Sc("stop CmdSpy"); Sc("delete CmdSpy"); }

        try { ProtectedTaskXml(); }
        catch (Exception ex) { Check("Protected task XML smoke test ran", false, ex.ToString()); }

        foreach (var forceCompatibility in new[] { false, true })
        {
            try { LogonTask(appExe, forceCompatibility); }
            catch (Exception ex) { Check($"Logon task smoke test ran ({(forceCompatibility ? "schtasks fallback" : "COM")})", false, ex.ToString()); }
        }

        Log("");
        Log($"{Results.Count(r => r.Pass)}/{Results.Count} checks passed");
        return Results.All(r => r.Pass) ? 0 : 1;
    }

    // ------------------------------------------------------------ service --

    private static void BootService(string appExe, string logDir)
    {
        var serviceControl = typeof(CmdSpy.App.MainForm).Assembly.GetType("CmdSpy.App.ServiceControl")
            ?? throw new InvalidOperationException("This build has no ServiceControl.");
        var binPath = (string)serviceControl.GetMethod("BuildBinPath", BindingFlags.NonPublic | BindingFlags.Static)!
            .Invoke(null, new object[] { appExe })!;
        var displayName = (string?)serviceControl.GetField("DisplayName")?.GetValue(null) ?? "CMD-spy popup monitor";
        Log($"sc binPath argument built by the app: {binPath}");

        var create = Sc($"create CmdSpy binPath= {binPath} start= auto DisplayName= \"{displayName}\"");
        Check("Boot service registers (same sc.exe command as the app)", create.Code == 0, create.Output.Trim());

        var qc = Sc("qc CmdSpy").Output;
        Check("Service command line is quoted correctly", qc.Contains($"\"{appExe}\" --service", StringComparison.OrdinalIgnoreCase),
            Line(qc, "BINARY_PATH_NAME"));
        Check("Service starts automatically with Windows", qc.Contains("AUTO_START"), Line(qc, "START_TYPE"));

        var started = Stopwatch.StartNew();
        Sc("start CmdSpy");
        bool running = WaitFor(() => Sc("query CmdSpy").Output.Contains("RUNNING"), 45_000);
        Check($"Service reaches RUNNING as LocalSystem ({started.Elapsed.TotalSeconds:0.0} s)", running, Line(Sc("query CmdSpy").Output, "STATE"));

        var statusLog = Path.Combine(logDir, "cmdspy-service.log");
        bool monitoring = WaitFor(() => ReadShared(statusLog).Contains("Monitoring started via"), 30_000);
        Check($"Service is monitoring ({started.Elapsed.TotalSeconds:0.0} s after start)", monitoring, LastLines(ReadShared(statusLog), 3));

        var pid = ServicePid();
        if (pid is int servicePid)
        {
            using var proc = Process.GetProcessById(servicePid);
            Check("Service runs at high priority during start-up", proc.PriorityClass == ProcessPriorityClass.High, proc.PriorityClass.ToString());
        }

        var marker = "service-smoke-" + Guid.NewGuid().ToString("N")[..8];
        RunHidden(Path.Combine(Environment.SystemDirectory, "cmd.exe"), $"/d /c rem {marker}");
        var jsonl = Path.Combine(logDir, $"cmdspy-{DateTime.Now:yyyyMMdd}.jsonl");
        bool captured = WaitFor(() => ReadShared(jsonl).Contains(marker), 30_000);
        Check("Service captured a popup with nobody using the app", captured, marker);

        Sc("stop CmdSpy");
        bool stopped = WaitFor(() => Sc("query CmdSpy").Output.Contains("STOPPED"), 30_000);
        var delete = Sc("delete CmdSpy");
        Check("Service stops and is removed cleanly", stopped && delete.Code == 0, delete.Output.Trim());
    }

    private static int? ServicePid()
    {
        var output = Sc("queryex CmdSpy").Output;
        var line = Line(output, "PID");
        var digits = new string(line.SkipWhile(c => c != ':').Skip(1).Where(char.IsDigit).ToArray());
        return int.TryParse(digits, out var pid) && pid > 0 ? pid : null;
    }

    // --------------------------------------------------------- logon task --

    private static void ProtectedTaskXml()
    {
        var fileType = typeof(CmdSpy.App.MainForm).Assembly.GetType("CmdSpy.App.StartupTaskXmlFile")
            ?? throw new InvalidOperationException("This build has no protected task XML file helper.");
        const string xml = "<?xml version=\"1.0\" encoding=\"UTF-16\"?><test>task XML — same content</test>";
        var file = (IDisposable)fileType.GetMethod("Create")!.Invoke(null, new object[] { xml })!;
        var path = (string)fileType.GetProperty("FilePath")!.GetValue(file)!;
        try
        {
            Check("Compatibility XML can be read intact by a second reader", File.ReadAllText(path) == xml, "UTF-16 round trip");
            Check("Compatibility XML uses the protected system directory", Path.GetDirectoryName(path) == Environment.SystemDirectory, path);
            var security = new FileInfo(path).GetAccessControl(AccessControlSections.Access | AccessControlSections.Owner);
            var administrators = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
            var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
            Check("Compatibility XML is owned by Administrators, not the unelevated user",
                administrators.Equals(security.GetOwner(typeof(SecurityIdentifier))), "owner SID");
            var rules = security.GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>().ToArray();
            Check("Compatibility XML has a protected Administrators/SYSTEM-only DACL",
                security.AreAccessRulesProtected && rules.Length == 2 &&
                rules.All(rule => rule.AccessControlType == AccessControlType.Allow && !rule.IsInherited &&
                    (rule.IdentityReference.Equals(administrators) || rule.IdentityReference.Equals(system)) &&
                    (rule.FileSystemRights & FileSystemRights.FullControl) == FileSystemRights.FullControl), "explicit ACL at creation");
            bool writeBlocked = false;
            try { using var writer = new FileStream(path, FileMode.Open, FileAccess.Write, FileShare.ReadWrite); }
            catch (IOException) { writeBlocked = true; }
            catch (UnauthorizedAccessException) { writeBlocked = true; }
            Check("Compatibility XML stays locked against writes while schtasks reads it", writeBlocked, "held read handle denies write sharing");
        }
        finally
        {
            file.Dispose();
            Check("Compatibility XML is removed after use", !File.Exists(path), path);
        }
    }

    private static void LogonTask(string appExe, bool forceCompatibility)
    {
        var definition = Type.GetType("CmdSpy.Core.StartupTaskDefinition, CmdSpy.Core")
            ?? throw new InvalidOperationException("This build has no StartupTaskDefinition.");
        var taskName = (string)definition.GetField("TaskName")!.GetValue(null)!;
        string user;
        using (var identity = WindowsIdentity.GetCurrent()) user = identity.Name;
        var xml = (string)definition.GetMethod("BuildXml")!.Invoke(null, new object[] { appExe, user })!;

        var startupManager = typeof(CmdSpy.App.MainForm).Assembly.GetType("CmdSpy.App.StartupManager")
            ?? throw new InvalidOperationException("This build has no StartupManager.");
        var register = startupManager.GetMethod("RegisterTask", BindingFlags.NonPublic | BindingFlags.Static)
            ?? throw new InvalidOperationException("This build has no task registration entry point.");
        var mode = forceCompatibility ? "schtasks fallback after COM failure" : "COM";
        Log($"Testing logon task registration through {mode}.");
        try
        {
            Action<string, string>? comRegistration = forceCompatibility
                ? (_, _) => throw new COMException("Intentional COM failure for the compatibility smoke test.")
                : null;
            var usedCompatibility = (bool)register.Invoke(null, new object?[] { xml, user, comRegistration })!;
            Check($"Logon task registers through {mode}", usedCompatibility == forceCompatibility,
                usedCompatibility ? "schtasks compatibility path" : "direct COM path");
            var registered = Schtasks($"/Query /TN \"{taskName}\" /XML").Output;
            var task = XDocument.Parse(registered);
            XNamespace ns = "http://schemas.microsoft.com/windows/2004/02/mit/task";
            var principal = task.Root?.Element(ns + "Principals")?.Element(ns + "Principal");
            using var identity = WindowsIdentity.GetCurrent();
            var registeredUser = principal?.Element(ns + "UserId")?.Value;
            Check("Task keeps the current user's interactive identity",
                (string.Equals(registeredUser, user, StringComparison.OrdinalIgnoreCase) || registeredUser == identity.User?.Value) &&
                principal?.Element(ns + "LogonType")?.Value == "InteractiveToken", registeredUser ?? "missing principal");
            var action = task.Root?.Element(ns + "Actions")?.Element(ns + "Exec");
            Check("Task keeps the executable and tray/startup arguments",
                string.Equals(action?.Element(ns + "Command")?.Value, appExe, StringComparison.OrdinalIgnoreCase) &&
                action?.Element(ns + "Arguments")?.Value == "--tray --startup", mode);
            Check("Task runs with highest privileges (elevated, no UAC prompt)", registered.Contains("<RunLevel>HighestAvailable</RunLevel>"), "RunLevel");
            Check("Task runs at high priority", registered.Contains("<Priority>1</Priority>"), "Priority 1 = HIGH_PRIORITY_CLASS");
            Check("Task never starts a second copy", registered.Contains("<MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>"), "IgnoreNew");
            Check("Task triggers: log on, unlock, console + remote connect",
                registered.Contains("<LogonTrigger>") && registered.Contains("SessionUnlock") &&
                registered.Contains("ConsoleConnect") && registered.Contains("RemoteConnect"), "");
            Check("Task restarts CMD-spy if it crashes", registered.Contains("<RestartOnFailure>"), "");

            // Run it the way Windows does at log on, and time how long until capture is live.
            var clock = Stopwatch.StartNew();
            var run = Schtasks($"/Run /TN \"{taskName}\"");
            Check("Task starts on demand", run.Code == 0, run.Output.Trim());

            Process? app = null;
            bool appStarted = WaitFor(() => (app = FindApp(appExe)) is not null, 30_000);
            Check($"CMD-spy started from the task ({clock.Elapsed.TotalSeconds:0.0} s)", appStarted, app is null ? "" : $"PID {app.Id}");
            bool live = WaitFor(() => EtwSessionExists("CmdSpy-KernelProcessSession"), 30_000);
            Check($"Monitoring live {clock.Elapsed.TotalSeconds:0.0} s after the task fired (tray, no window)", live, "kernel trace session open");

            if (app is not null)
            {
                app.Refresh();
                Check("Started at high priority", app.PriorityClass == ProcessPriorityClass.High, app.PriorityClass.ToString());

                // A second start must not open another copy.
                using var second = Process.Start(new ProcessStartInfo(appExe, "--tray --startup") { UseShellExecute = false })!;
                bool secondExited = second.WaitForExit(15_000);
                app.Refresh();
                Check("A second copy exits at once — only one instance", secondExited && !app.HasExited,
                    $"second exited={secondExited} (code {(secondExited ? second.ExitCode : -1)}), first still running={!app.HasExited}");
                try { app.Kill(); app.WaitForExit(10_000); } catch { }
            }
        }
        finally
        {
            Schtasks($"/End /TN \"{taskName}\"");
            var delete = Schtasks($"/Delete /TN \"{taskName}\" /F");
            Check("Logon task removed again", delete.Code == 0, delete.Output.Trim());
        }
    }

    private static Process? FindApp(string appExe)
    {
        foreach (var p in Process.GetProcessesByName(Path.GetFileNameWithoutExtension(appExe)))
        {
            try
            {
                if (string.Equals(p.MainModule?.FileName, appExe, StringComparison.OrdinalIgnoreCase)) return p;
            }
            catch
            {
                // exited or not accessible
            }
        }
        return null;
    }

    private static bool EtwSessionExists(string name) => Exec("logman.exe", $"query \"{name}\" -ets").Code == 0;

    // ------------------------------------------------------------ plumbing --

    private static (int Code, string Output) Sc(string arguments) => Exec(Path.Combine(Environment.SystemDirectory, "sc.exe"), arguments);
    private static (int Code, string Output) Schtasks(string arguments) => Exec(Path.Combine(Environment.SystemDirectory, "schtasks.exe"), arguments);

    private static (int Code, string Output) Exec(string file, string arguments)
    {
        var psi = new ProcessStartInfo(file, arguments)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };
        using var p = Process.Start(psi)!;
        var output = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
        p.WaitForExit(60_000);
        return (p.ExitCode, output);
    }

    private static void RunHidden(string file, string arguments)
    {
        using var p = Process.Start(new ProcessStartInfo(file, arguments) { UseShellExecute = false, CreateNoWindow = true })!;
        p.WaitForExit(30_000);
    }

    private static bool WaitFor(Func<bool> condition, int timeoutMs)
    {
        var clock = Stopwatch.StartNew();
        while (clock.ElapsedMilliseconds < timeoutMs)
        {
            try { if (condition()) return true; } catch { }
            Thread.Sleep(200);
        }
        try { return condition(); } catch { return false; }
    }

    private static string ReadShared(string path)
    {
        try
        {
            if (!File.Exists(path)) return "";
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var reader = new StreamReader(fs);
            return reader.ReadToEnd();
        }
        catch
        {
            return "";
        }
    }

    private static string Line(string text, string key) =>
        text.Split('\n').FirstOrDefault(l => l.Contains(key, StringComparison.OrdinalIgnoreCase))?.Trim() ?? "";

    private static string LastLines(string text, int count) =>
        string.Join(" | ", text.Split('\n', StringSplitOptions.RemoveEmptyEntries).TakeLast(count).Select(l => l.Trim()));

    private static void Check(string name, bool pass, string detail)
    {
        Results.Add((name, pass, detail));
        Log($"{(pass ? "PASS" : "FAIL")}  {name}{(string.IsNullOrWhiteSpace(detail) ? "" : " — " + detail)}");
    }

    private static void Log(string message)
    {
        var line = $"{DateTime.Now:HH:mm:ss.fff}  {message}";
        _log?.WriteLine(line);
        Console.WriteLine(line);
    }
}
