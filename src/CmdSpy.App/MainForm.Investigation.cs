using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using CmdSpy.Core;
using CmdSpy.Core.Formatting;
using CmdSpy.Core.Logging;
using CmdSpy.Core.Models;
using CmdSpy.Core.Monitoring;

namespace CmdSpy.App;

/// <summary>
/// Investigation and boot-service features of the dashboard: risk colouring,
/// re-analysis, importing past popups from the Windows event logs, Windows
/// logging setup, the capture self-test, and following the boot service.
/// </summary>
public sealed partial class MainForm
{
    // ---------------------------------------------------------- menus ----

    private ToolStripDropDownButton BuildInvestigateDropDown()
    {
        var drop = new ToolStripDropDownButton("Investigate ▾")
        {
            ToolTipText = "Analyse captures, import past popups, check Windows logging, test capture"
        };

        var reanalyze = new ToolStripMenuItem("Re-analyse selected popup");
        reanalyze.Click += (_, _) => ReanalyzeSelected();

        var copy = new ToolStripMenuItem("Copy full report of selected popup");
        copy.Click += (_, _) => CopySelectedReport();

        var import = new ToolStripMenuItem("Import past popups from Windows event logs");
        void AddImport(string label, Func<DateTimeOffset> since)
        {
            var item = new ToolStripMenuItem(label);
            item.Click += (_, _) => ImportHistory(label, since());
            import.DropDownItems.Add(item);
        }
        AddImport("Since this boot", () => SystemTimings.BootTimeLocal.ToUniversalTime() - TimeSpan.FromMinutes(1));
        AddImport("Last 24 hours", () => DateTimeOffset.UtcNow - TimeSpan.FromHours(24));
        AddImport("Last 7 days", () => DateTimeOffset.UtcNow - TimeSpan.FromDays(7));

        var status = new ToolStripMenuItem("Windows logging status…");
        status.Click += (_, _) => ShowLoggingStatus();

        var enable = new ToolStripMenuItem("Turn on recommended Windows logging…");
        enable.Click += (_, _) => EnableRecommendedLogging();

        var selfTest = new ToolStripMenuItem("Run capture self-test (25 instant windows)");
        selfTest.Click += (_, _) => RunSelfTest();

        var freshSignatures = new ToolStripMenuItem("Always recheck file signatures (slower)")
        {
            CheckOnClick = true,
            Checked = _engine.Options.AlwaysRecheckFileSignatures,
            ToolTipText = "Re-read files for each analysis in this window, even when size and modification time are unchanged. Uses more disk and CPU time."
        };
        freshSignatures.CheckedChanged += (_, _) => SetFreshSignatureChecks(freshSignatures.Checked);

        drop.DropDownItems.AddRange(new ToolStripItem[]
        {
            reanalyze, copy, new ToolStripSeparator(),
            import, status, enable, new ToolStripSeparator(),
            selfTest, new ToolStripSeparator(), freshSignatures
        });
        return drop;
    }

    private void SetFreshSignatureChecks(bool enabled)
    {
        _engine.Options.AlwaysRecheckFileSignatures = enabled;
        if (_engine.Investigator is { } active) active.Signatures.AlwaysRecheck = enabled;
        if (_onDemand is { } onDemand) onDemand.Signatures.AlwaysRecheck = enabled;
        _settings.AlwaysRecheckFileSignatures = enabled;
        _settings.Save();
    }

    private ToolStripDropDownButton BuildServiceDropDown()
    {
        var drop = new ToolStripDropDownButton("Boot service ▾")
        {
            ToolTipText = "Run CMD-spy as a Windows service so it captures from boot, before anyone logs in"
        };

        var install = new ToolStripMenuItem("Install && start — monitor from boot, before login");
        install.Click += (_, _) => InstallService();
        var start = new ToolStripMenuItem("Start service");
        start.Click += (_, _) => ServiceAction("start", () => { ServiceControl.StartService(); return new List<string> { "✓ Service is running." }; });
        var stop = new ToolStripMenuItem("Stop service");
        stop.Click += (_, _) => ServiceAction("stop", () => { ServiceControl.StopService(); return new List<string> { "✓ Service stopped." }; });
        var uninstall = new ToolStripMenuItem("Uninstall service");
        uninstall.Click += (_, _) => UninstallService();
        var statusLog = new ToolStripMenuItem("Open service status log");
        statusLog.Click += (_, _) => OpenServiceStatusLog();

        drop.DropDownOpening += (_, _) =>
        {
            var state = ServiceControl.GetStatus();
            install.Text = state is null
                ? "Install && start — monitor from boot, before login"
                : "Reinstall / update the service";
            start.Enabled = state is System.ServiceProcess.ServiceControllerStatus.Stopped;
            stop.Enabled = state is System.ServiceProcess.ServiceControllerStatus.Running;
            uninstall.Enabled = state is not null;
        };

        drop.DropDownItems.AddRange(new ToolStripItem[]
        {
            install, new ToolStripSeparator(), start, stop, uninstall, new ToolStripSeparator(), statusLog
        });
        return drop;
    }

    // ------------------------------------------------------- risk colour --

    private void ColorByRisk(DataGridViewCellFormattingEventArgs e)
    {
        if (e.RowIndex < 0 || e.RowIndex >= _view.Count) return;
        var ev = _view[e.RowIndex];
        var level = ev.Investigation?.Risk?.Level;
        var style = e.CellStyle;
        if (style is null) return;

        switch (level)
        {
            case RiskLevel.High:
                style.BackColor = Color.FromArgb(110, 24, 24);
                style.ForeColor = Color.White;
                break;
            case RiskLevel.Suspicious:
                style.BackColor = Color.FromArgb(105, 72, 0);
                style.ForeColor = Color.White;
                break;
            case RiskLevel.SelfTest:
                style.ForeColor = Color.Gray;
                break;
            case RiskLevel.Unknown when _grid.Columns[e.ColumnIndex].DataPropertyName == nameof(CmdEvent.RiskDisplay):
                style.ForeColor = Color.Khaki;
                break;
            case RiskLevel.Low when _grid.Columns[e.ColumnIndex].DataPropertyName == nameof(CmdEvent.RiskDisplay):
                style.ForeColor = Color.LightGreen;
                break;
        }
    }

    // --------------------------------------------------------- analysis --

    private CmdEvent? SelectedEvent => _grid.CurrentRow?.DataBoundItem as CmdEvent;

    /// <summary>A GUI-side investigator for when this window isn't the one capturing (service mode or stopped).</summary>
    private Investigator OnDemand()
    {
        if (_onDemand is not null) return _onDemand;
        var processes = new ProcessCache(_engine.Options.ProcessHistoryRetention);
        try { processes.Seed(ProcessSnapshot.SnapshotAll()); } catch { }
        _onDemand = new Investigator(processes, _engine.Options);
        _onDemand.Completed += (ev, investigation) =>
        {
            lock (ev) ev.Investigation = investigation;
            UiInvoke(() => OnUpdated(ev));
        };
        _onDemand.Start();
        return _onDemand;
    }

    private void OnBacklogCompleted(CmdEvent ev, Investigation investigation)
    {
        // A service verdict received while this automatic pass was queued or
        // running is authoritative. Manual reanalysis keeps its own handler.
        if (Investigator.TryApplyBacklogResult(ev, investigation))
            UiInvoke(() => OnUpdated(ev));
    }

    private void ReanalyzeSelected()
    {
        if (SelectedEvent is not { } ev)
        {
            MessageBox.Show(this, "Select a popup in the list first.", "CMD-spy", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }
        // The capturing engine logs the new report; otherwise analyse here (shown in this window).
        if (!(_engine.IsRunning && _follower is null && _engine.Reanalyze(ev)))
            OnDemand().Enqueue(ev);
        _lblStatus.Text = $"Re-analysing #{ev.SequenceNumber} ({ev.ProcessName})…";
    }

    private void CopySelectedReport()
    {
        if (SelectedEvent is not { } ev) return;
        try
        {
            Clipboard.SetText(EventTextFormatter.Format(ev));
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "CMD-spy", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    private async void ImportHistory(string label, DateTimeOffset sinceUtc)
    {
        Cursor = Cursors.WaitCursor;
        _lblStatus.Text = $"Reading Windows event logs ({label.ToLowerInvariant()})…";
        try
        {
            var known = _all.ToList();
            IReadOnlyList<CmdEvent> imported;
            bool viaEngine = _engine.IsRunning && _follower is null;
            if (viaEngine)
            {
                // Logged and analysed by the engine; rows arrive through EventCaptured.
                imported = await Task.Run(() => _engine.ImportHistory(sinceUtc, known));
            }
            else
            {
                var investigator = OnDemand();
                imported = await Task.Run(() => HistoryImporter.Read(investigator.History, _engine.Options, sinceUtc, known));
                foreach (var ev in imported)
                {
                    OnCaptured(ev);
                    investigator.Enqueue(ev);
                }
            }

            if (imported.Count > 0)
            {
                MessageBox.Show(this,
                    $"Imported {imported.Count} past launch(es) of console/script hosts from the Windows event logs.\n\n" +
                    "Each one is being analysed now (launch chain, signatures, scheduled task, risk) — watch the Risk column." +
                    (viaEngine ? "" : "\n\nThey are shown here only; the boot service owns the log files."),
                    "CMD-spy — history import", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            else
            {
                MessageBox.Show(this,
                    "No new launches were found in the Windows event logs for that period.\n\n" +
                    "Windows only records program starts when process-creation auditing (Security event 4688) or Sysmon is on — " +
                    "it is off by default. Use Investigate ▸ Turn on recommended Windows logging so future popups can be traced " +
                    "even when CMD-spy isn't running.\n\n" + LoggingStatusText(),
                    "CMD-spy — history import", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, $"Could not read the event logs:\n{ex.Message}", "CMD-spy", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
        finally
        {
            Cursor = Cursors.Default;
            RestoreStatusLabel();
        }
    }

    private string LoggingStatusText()
    {
        var history = _engine.Investigator?.History ?? _onDemand?.History ?? new WindowsEventHistory();
        var sb = new StringBuilder();
        foreach (var source in history.GetSourceStatus(refresh: true))
            sb.AppendLine($"{(source.Active ? "✓" : "✗")} {source.Name}: {source.Detail}");
        return sb.ToString();
    }

    private void ShowLoggingStatus()
    {
        try
        {
            MessageBox.Show(this,
                "Windows logs CMD-spy can use to trace launches (including ones from before it was running):\n\n" +
                LoggingStatusText() +
                "\nCMD-spy captures popups itself while it runs; these logs add history and fill gaps " +
                "(e.g. a parent that already exited, or the scheduled task behind a launch).",
                "CMD-spy — Windows logging", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "CMD-spy", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    private void EnableRecommendedLogging()
    {
        var confirm = MessageBox.Show(this,
            "This turns on the following Windows logging (system-wide, needs Administrator):\n\n• " +
            string.Join("\n• ", WindowsLoggingSetup.Changes) +
            "\n\nIt makes launches traceable after the fact — even when CMD-spy isn't running. " +
            "Logs use some disk space (Windows rotates them automatically). Continue?",
            "CMD-spy — Windows logging", MessageBoxButtons.YesNo, MessageBoxIcon.Question);
        if (confirm != DialogResult.Yes) return;

        try
        {
            var results = WindowsLoggingSetup.EnableRecommended();
            MessageBox.Show(this, string.Join("\n", results), "CMD-spy — Windows logging",
                MessageBoxButtons.OK, MessageBoxIcon.Information);
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "CMD-spy", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    private async void RunSelfTest()
    {
        ICaptureFeed? feed = _follower is not null ? _follower : _engine.IsRunning ? _engine : null;
        if (feed is null)
        {
            MessageBox.Show(this, "Start monitoring first (▶ Start), then run the self-test.", "CMD-spy",
                MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        Cursor = Cursors.WaitCursor;
        _lblStatus.Text = "Self-test: launching 25 windows that close within milliseconds…";
        try
        {
            var result = await Task.Run(() => CaptureSelfTest.Run(feed, 25));
            var details = result.Problems.Count == 0 ? "" : "\n\nDetails:\n" + string.Join("\n", result.Problems.Take(10));
            var lost = _engine.EventsLost is int n && n > 0 ? $"\n\nThe kernel reported {n} dropped events this session." : "";
            MessageBox.Show(this, result.Summary + lost + details, "CMD-spy — capture self-test", MessageBoxButtons.OK,
                result.Passed ? MessageBoxIcon.Information : MessageBoxIcon.Warning);
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "CMD-spy", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
        finally
        {
            Cursor = Cursors.Default;
            RestoreStatusLabel();
        }
    }

    // ------------------------------------------------------ boot service --

    private void InstallService()
    {
        var confirm = MessageBox.Show(this,
            "Install CMD-spy as a Windows service?\n\n" +
            $"• CMD-spy is copied to {ServiceControl.InstallDirectory} (an admin-only folder, so the service can't be tampered with).\n" +
            "• It starts automatically at boot — before anyone logs in — and captures every popup into the same log files.\n" +
            "• While it runs, this window shows its captures live instead of capturing separately.",
            "CMD-spy — boot service", MessageBoxButtons.YesNo, MessageBoxIcon.Question);
        if (confirm != DialogResult.Yes) return;
        ServiceAction("install", ServiceControl.Install);
    }

    private void UninstallService()
    {
        var confirm = MessageBox.Show(this, "Stop and remove the CMD-spy boot service? Log files are kept.",
            "CMD-spy — boot service", MessageBoxButtons.YesNo, MessageBoxIcon.Question);
        if (confirm != DialogResult.Yes) return;
        ServiceAction("uninstall", ServiceControl.Uninstall);
    }

    private async void ServiceAction(string what, Func<List<string>> action)
    {
        Cursor = Cursors.WaitCursor;
        _lblStatus.Text = $"Boot service: {what}…";
        try
        {
            // Hand capture over before the service starts, so nothing is logged twice.
            if (what is "install" or "start" && _engine.IsRunning) StopMonitoring();

            var log = await Task.Run(action);
            SyncWithService();
            MessageBox.Show(this, string.Join("\n", log), "CMD-spy — boot service", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }
        catch (Exception ex)
        {
            SyncWithService();
            MessageBox.Show(this, $"Boot service {what} failed:\n{ex.Message}", "CMD-spy",
                MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
        finally
        {
            Cursor = Cursors.Default;
            RestoreStatusLabel();
        }
    }

    private void OpenServiceStatusLog()
    {
        var path = ServiceControl.StatusLogPath(_engine.Store.Directory);
        if (!File.Exists(path))
        {
            MessageBox.Show(this, "The service hasn't written a status log yet.", "CMD-spy", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }
        try
        {
            Process.Start(new ProcessStartInfo { FileName = path, UseShellExecute = true });
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "CMD-spy", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    private void UpdateServiceLabel()
    {
        var text = ServiceControl.StatusText;
        _lblService.Text = $"Boot service: {text}";
        _lblService.ForeColor = text == "running" ? Color.LimeGreen : Color.DimGray;
    }

    /// <summary>Switches between capturing here and following the service, as the service starts or stops.</summary>
    private void SyncWithService()
    {
        UpdateServiceLabel();
        bool serviceRunning = ServiceControl.IsRunning;
        if (serviceRunning && _follower is null)
        {
            if (_engine.IsRunning) StopMonitoring();
            StartFollowing();
        }
        else if (!serviceRunning && _follower is not null)
        {
            StopFollowing();
            StartMonitoring();
        }
    }

    private void StartFollowing()
    {
        try
        {
            _follower = new LogFollower(_engine.Store.Directory);
            _follower.EventCaptured += (_, ev) => UiInvoke(() => OnCaptured(ev));
            _follower.EventUpdated += (_, ev) => UiInvoke(() => OnUpdated(ev));
            var existing = _follower.Start();

            // The service's log is the source of truth now (it includes anything captured here earlier).
            _all.Clear();
            _view.Clear();
            foreach (var ev in existing)
            {
                _all.Add(ev);
                if (PassesFilter(ev)) _view.Add(ev);
            }
            UpdateCount();
            _btnStart.Enabled = false;
            _btnStop.Enabled = false;
            RestoreStatusLabel();
            AnalyzeBacklog(existing);
        }
        catch (Exception ex)
        {
            _follower?.Dispose();
            _follower = null;
            MessageBox.Show(this, $"Could not follow the boot service's log:\n{ex.Message}", "CMD-spy",
                MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    private void StopFollowing()
    {
        _follower?.Dispose();
        _follower = null;
    }

    private void RestoreStatusLabel()
    {
        if (_follower is not null)
        {
            _lblStatus.Text = "Boot service is capturing — showing its log live";
            _lblStatus.ForeColor = Color.LimeGreen;
        }
        else if (_engine.IsRunning)
        {
            _lblStatus.Text = $"Monitoring ({_engine.WatcherName ?? "?"})";
            _lblStatus.ForeColor = Color.LimeGreen;
        }
        else
        {
            _lblStatus.Text = "Stopped";
            _lblStatus.ForeColor = Color.OrangeRed;
        }
    }
}
