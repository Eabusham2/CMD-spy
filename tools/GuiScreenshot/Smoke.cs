using System.Diagnostics;
using System.Reflection;
using System.Security.Principal;
using System.Text;

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

        try { LogonTask(appExe); }
        catch (Exception ex) { Check("Logon task smoke test ran", false, ex.ToString()); }

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

    private static void LogonTask(string appExe)
    {
        var definition = Type.GetType("CmdSpy.Core.StartupTaskDefinition, CmdSpy.Core")
            ?? throw new InvalidOperationException("This build has no StartupTaskDefinition.");
        var taskName = (string)definition.GetField("TaskName")!.GetValue(null)!;
        string user;
        using (var identity = WindowsIdentity.GetCurrent()) user = identity.Name;
        var xml = (string)definition.GetMethod("BuildXml")!.Invoke(null, new object[] { appExe, user })!;

        var xmlPath = Path.Combine(Path.GetTempPath(), $"cmdspy-smoke-task-{Guid.NewGuid():N}.xml");
        File.WriteAllText(xmlPath, xml, Encoding.Unicode);
        var create = Schtasks($"/Create /TN \"{taskName}\" /XML \"{xmlPath}\" /F");
        Check("Logon task accepted by Task Scheduler", create.Code == 0, create.Output.Trim());
        try
        {
            var registered = Schtasks($"/Query /TN \"{taskName}\" /XML").Output;
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
            try { File.Delete(xmlPath); } catch { }
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
