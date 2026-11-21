using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using CmdSpy.Core.Models;
using CmdSpy.Core.Monitoring;
using Xunit;
using Xunit.Abstractions;

namespace CmdSpy.Core.Tests;

/// <summary>
/// Real-machine checks that only make sense on Windows (CI runs them on a
/// Windows runner with Administrator rights): a stress test of capturing
/// windows that exit within milliseconds, the referenced-PID scenario from a
/// real investigation, a launcher that exits immediately, live network
/// capture, and Authenticode verification.
/// Kernel trace sessions get unique names so they never collide with a
/// CMD-spy GUI or service running on the same machine.
/// </summary>
[Collection("ETW")]
public class WindowsIntegrationTests : IDisposable
{
    private readonly ITestOutputHelper _output;
    private readonly TempDir _dir = new();

    public WindowsIntegrationTests(ITestOutputHelper output) => _output = output;

    public void Dispose() => _dir.Dispose();

    private CmdSpyEngine StartEngine(bool investigate, bool network = false)
    {
        var id = Guid.NewGuid().ToString("N")[..8];
        var engine = new CmdSpyEngine(new CmdSpyOptions
        {
            LogDirectory = _dir.Path,
            InvestigateEvents = investigate,
            CorrelateEventLogs = investigate,
            CaptureNetwork = network,
            CaptureNetworkEvents = network,
            EtwSessionName = $"CmdSpy-Test-Process-{id}",
            EtwNetworkSessionName = $"CmdSpy-Test-Network-{id}"
        });
        engine.Status += (_, message) => _output.WriteLine($"[engine] {message}");
        engine.Start();
        Assert.Equal("ETW kernel process trace", engine.WatcherName);
        return engine;
    }

    private static Process StartHidden(string file, string arguments) =>
        Process.Start(new ProcessStartInfo(file, arguments) { UseShellExecute = false, CreateNoWindow = true })!;

    private static string SystemExe(string name) => Path.Combine(Environment.SystemDirectory, name);

    // ----------------------------------------------------------- stress --

    [AdminFact]
    public void Stress_EveryInstantWindowIsCapturedWithItsFullCommandLine()
    {
        using var engine = StartEngine(investigate: false);

        var result = CaptureSelfTest.Run(engine, count: 150, timeout: TimeSpan.FromSeconds(90));

        _output.WriteLine(result.Summary);
        foreach (var problem in result.Problems) _output.WriteLine("  " + problem);
        _output.WriteLine($"Kernel events lost: {engine.EventsLost}");
        Assert.Equal(150, result.Launched);
        Assert.True(result.Passed, result.Summary + Environment.NewLine + string.Join(Environment.NewLine, result.Problems));
        Assert.Equal(result.Launched, result.ExitObserved);
    }

    // ------------------------------------------- referenced PIDs, launcher --

    [AdminFact]
    public void ReferencedPidsAreResolvedToTheirExecutables_AndTheLauncherIsNamed()
    {
        using var engine = StartEngine(investigate: true);
        var captured = new ConcurrentBag<CmdEvent>();
        engine.EventCaptured += (_, ev) => captured.Add(ev);

        using var ping = StartHidden(SystemExe("PING.EXE"), "-n 120 127.0.0.1");
        try
        {
            var marker = "refpid-" + Guid.NewGuid().ToString("N")[..8];
            using var ps = StartHidden(SystemExe(@"WindowsPowerShell\v1.0\powershell.exe"),
                $"-NoProfile -c gwmi win32_process -Filter 'ProcessId={ping.Id}' | Out-Null; '{marker}' | Out-Null");
            ps.WaitForExit(60_000);

            CmdEvent? ev = null;
            Assert.True(Wait.Until(() => (ev = captured.FirstOrDefault(e => e.CommandLine?.Contains(marker) == true)) is not null,
                TimeSpan.FromSeconds(30)), "the PowerShell launch was not captured");
            Assert.True(Wait.Until(() => ev!.Investigation is not null, TimeSpan.FromSeconds(90)), "no investigation");

            var inv = ev!.Investigation!;
            _output.WriteLine(Formatting.EventTextFormatter.Format(ev));

            var referenced = Assert.Single(inv.ReferencedProcesses, r => r.ProcessId == ping.Id);
            Assert.Equal("ping", CmdSpyOptions.Stem(referenced.ProcessName ?? "").ToLowerInvariant());
            Assert.True(inv.Explanation?.IsReadOnly);

            // This test process launched it: the chain starts with us, by name.
            var parent = Assert.IsType<ProcessInfo>(inv.Ancestry.First());
            Assert.Equal(Environment.ProcessId, parent.ProcessId);
            Assert.NotNull(inv.Launcher);

            // The PowerShell binary is Microsoft-signed and hashed.
            var self = Assert.Single(inv.Signatures, s => s.Role.Contains("this process"));
            Assert.Equal(SignatureStatus.Valid, self.Status);
            Assert.Equal(64, self.Sha256?.Length);
            Assert.NotNull(inv.Risk);
        }
        finally
        {
            try { ping.Kill(); } catch { }
        }
    }

    [AdminFact]
    public void ALauncherThatExitsImmediatelyIsStillIdentified()
    {
        using var engine = StartEngine(investigate: false);
        var captured = new ConcurrentBag<CmdEvent>();
        engine.EventCaptured += (_, ev) => captured.Add(ev);

        var marker = "gone-parent-" + Guid.NewGuid().ToString("N")[..8];
        // The outer cmd starts the inner one in the background and exits at once.
        using var outer = StartHidden(SystemExe("cmd.exe"),
            $"/d /c start \"\" /b {SystemExe("cmd.exe")} /d /c \"ping -n 3 127.0.0.1 >nul & rem {marker}\"");
        outer.WaitForExit(30_000);

        CmdEvent? inner = null;
        Assert.True(Wait.Until(() => (inner = captured.FirstOrDefault(e =>
            e.CommandLine?.Contains(marker) == true && e.CommandLine.Contains("ping", StringComparison.OrdinalIgnoreCase) &&
            !e.CommandLine.Contains("start", StringComparison.OrdinalIgnoreCase))) is not null, TimeSpan.FromSeconds(30)));

        Assert.Equal("cmd", CmdSpyOptions.Stem(inner!.ParentProcessName ?? ""), ignoreCase: true);
        Assert.Contains("start", inner.ParentCommandLine ?? "", StringComparison.OrdinalIgnoreCase);
        Assert.EndsWith("cmd.exe", inner.ParentImagePath ?? "", StringComparison.OrdinalIgnoreCase);
    }

    // ------------------------------------------------------------ network --

    [AdminFact]
    public void ConnectionsAreCapturedLiveAsTheyHappen()
    {
        using var engine = StartEngine(investigate: false, network: true);
        Assert.NotNull(engine.NetworkWatcherName);
        var captured = new ConcurrentBag<CmdEvent>();
        engine.EventCaptured += (_, ev) => captured.Add(ev);

        // An independent session records everything the kernel reports, to explain a failure.
        var seen = new ConcurrentBag<(int Pid, NetworkConnectionInfo Connection)>();
        using var diagnostics = new EtwNetworkWatcher($"CmdSpy-Test-NetDiag-{Guid.NewGuid():N}"[..40]);
        diagnostics.ConnectionObserved += (pid, c) => seen.Add((pid, c));
        diagnostics.Start();

        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        try
        {
            // A short-lived window: connects locally and to the internet, then exits.
            using var ps = StartHidden(SystemExe(@"WindowsPowerShell\v1.0\powershell.exe"),
                "-NoProfile -c \"$c = New-Object Net.Sockets.TcpClient; $c.Connect('127.0.0.1', " + port + "); " +
                "try { $w = New-Object Net.Sockets.TcpClient; $w.Connect('github.com', 443); $w.Close() } catch { }; " +
                "Start-Sleep -Milliseconds 300; $c.Close()\"");
            ps.WaitForExit(60_000);

            CmdEvent? ev = null;
            Assert.True(Wait.Until(() => (ev = captured.FirstOrDefault(e => e.CommandLine?.Contains(port.ToString()) == true)) is not null,
                TimeSpan.FromSeconds(30)));
            bool live = Wait.Until(() =>
            {
                lock (ev!) return ev.NetworkConnections.Any(c => c.Source == "ETW" && (c.RemotePort == port || c.RemotePort == 443));
            }, TimeSpan.FromSeconds(20));

            _output.WriteLine($"PowerShell PID {ev!.ProcessId}; captured on the popup:");
            lock (ev) foreach (var c in ev.NetworkConnections) _output.WriteLine($"  {c} pid={c.OwningPid} via {c.Source}");
            _output.WriteLine($"Kernel reported {seen.Count} connection(s); for this test:");
            foreach (var (pid, c) in seen.Where(x => x.Pid == ev.ProcessId || x.Connection.RemotePort == port || x.Connection.LocalPort == port))
                _output.WriteLine($"  pid={pid} {c}");
            Assert.True(live, "the popup's connections were not captured live");
        }
        finally
        {
            listener.Stop();
        }
    }

    // --------------------------------------------------------- signatures --

    [WindowsFact]
    public void WindowsBinariesVerifyAsMicrosoftSigned()
    {
        var info = new SignatureVerifier().Verify(SystemExe("cmd.exe"), "test");

        _output.WriteLine($"{info.Status} {info.Kind} {info.Publisher} {info.Detail}");
        Assert.Equal(SignatureStatus.Valid, info.Status);
        Assert.Contains("Microsoft", info.Publisher ?? "");
        Assert.Equal(64, info.Sha256?.Length);
        Assert.True(info.IsMicrosoft);
    }

    [WindowsFact]
    public void AnUnsignedProgramIsReportedAsUnsigned()
    {
        // Our own freshly built library is a PE file without a signature.
        var info = new SignatureVerifier().Verify(typeof(CmdSpyEngine).Assembly.Location, "test");
        _output.WriteLine($"{info.Status} {info.Detail}");
        Assert.Equal(SignatureStatus.Unsigned, info.Status);
        Assert.NotNull(info.Sha256);
    }

    [WindowsFact]
    public void LiveLookupFindsThisProcess()
    {
        var (path, started) = ProcessImageResolver.TryQueryLive(Environment.ProcessId);
        Assert.Equal(Path.GetFileName(Environment.ProcessPath), Path.GetFileName(path), ignoreCase: true);
        using var me = Process.GetCurrentProcess();
        Assert.NotNull(started);
        Assert.True((started!.Value.UtcDateTime - me.StartTime.ToUniversalTime()).Duration() < TimeSpan.FromSeconds(2));
    }

    [WindowsFact]
    public void EventLogSourcesCanBeQueried()
    {
        var status = new WindowsEventHistory().GetSourceStatus(refresh: true);
        foreach (var s in status) _output.WriteLine($"{s.Name}: active={s.Active} {s.Detail}");
        Assert.Contains(status, s => s.LogName == WindowsEventHistory.SecurityLog);
    }

    [AdminFact]
    public void RegisteredScheduledTasksAreRead()
    {
        var catalog = new ScheduledTaskCatalog();
        var tasks = catalog.GetTasks();
        _output.WriteLine($"{tasks.Count} tasks; error: {catalog.LastError}");
        Assert.Contains(tasks, t => t.Path.StartsWith(@"\Microsoft\Windows\", StringComparison.OrdinalIgnoreCase));
    }
}

/// <summary>Interop layouts must match the Windows headers exactly (x64).</summary>
public class InteropLayoutTests
{
    [Fact]
    public void WinTrustStructuresHaveTheNativeSizes()
    {
        if (IntPtr.Size != 8) return;   // sizes below are for 64-bit processes
        Assert.Equal(88, Marshal.SizeOf<SignatureVerifier.WinTrust.WINTRUST_DATA>());
        Assert.Equal(32, Marshal.SizeOf<SignatureVerifier.WinTrust.WINTRUST_FILE_INFO>());
        Assert.Equal(72, Marshal.SizeOf<SignatureVerifier.WinTrust.WINTRUST_CATALOG_INFO>());
        Assert.Equal(524, Marshal.SizeOf<SignatureVerifier.WinTrust.CATALOG_INFO>());
    }
}
