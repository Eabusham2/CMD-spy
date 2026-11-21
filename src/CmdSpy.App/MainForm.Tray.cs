using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Threading.Tasks;
using System.Windows.Forms;
using CmdSpy.Core.Models;

namespace CmdSpy.App;

/// <summary>
/// Notification-area (tray) mode and start-with-Windows options: CMD-spy keeps
/// monitoring when its window is closed, can start hidden at log on, and pops
/// up an alert when a popup is analysed as High risk or Suspicious.
/// </summary>
public sealed partial class MainForm
{
    private readonly bool _startInTray;
    private readonly AppSettings _settings = AppSettings.Load();
    private NotifyIcon? _tray;
    private ToolStripMenuItem? _trayStatus;
    private ToolStripMenuItem? _trayPause;
    private bool _allowShow;
    private bool _loaded;
    private bool _exiting;

    // Alerts: one per popup, at most one notification every few seconds.
    private readonly HashSet<Guid> _alerted = new();
    private DateTime _lastAlertUtc = DateTime.MinValue;
    private int _unshownAlerts;
    private CmdEvent? _alertEvent;

    private static Icon? _appIcon;

    /// <summary>A small console-prompt icon, drawn once (no icon file needed).</summary>
    internal static Icon AppIcon => _appIcon ??= DrawIcon();

    private static Icon DrawIcon()
    {
        using var bmp = new Bitmap(32, 32);
        using (var g = Graphics.FromImage(bmp))
        {
            g.SmoothingMode = SmoothingMode.AntiAlias;
            g.Clear(Color.Transparent);
            using var background = new SolidBrush(Color.FromArgb(28, 28, 30));
            using var border = new Pen(Color.FromArgb(0, 122, 204), 2f);
            g.FillRectangle(background, 2, 4, 28, 24);
            g.DrawRectangle(border, 2, 4, 28, 24);
            using var prompt = new Pen(Color.LimeGreen, 3f) { StartCap = LineCap.Round, EndCap = LineCap.Round, LineJoin = LineJoin.Round };
            g.DrawLines(prompt, new[] { new Point(8, 11), new Point(14, 16), new Point(8, 21) });
            g.DrawLine(prompt, 17, 22, 24, 22);
        }
        return Icon.FromHandle(bmp.GetHicon());
    }

    // ------------------------------------------------------------- tray --

    private void BuildTray()
    {
        var menu = new ContextMenuStrip();

        var open = new ToolStripMenuItem("Open CMD-spy") { Font = new Font(menu.Font, FontStyle.Bold) };
        open.Click += (_, _) => ShowFromTray();

        _trayStatus = new ToolStripMenuItem("Starting…") { Enabled = false };

        _trayPause = new ToolStripMenuItem("Pause monitoring");
        _trayPause.Click += (_, _) =>
        {
            if (_engine.IsRunning) StopMonitoring();
            else if (_follower is null) StartMonitoring();
        };

        var startWithWindows = new ToolStripMenuItem("Start with Windows (boot service + tray at log on)") { CheckOnClick = false };
        startWithWindows.Click += (_, _) => ToggleStartWithWindows();

        var alerts = new ToolStripMenuItem("Alert me about suspicious popups") { Checked = _settings.AlertOnSuspicious };
        alerts.Click += (_, _) =>
        {
            _settings.AlertOnSuspicious = !_settings.AlertOnSuspicious;
            _settings.Save();
        };

        var exit = new ToolStripMenuItem("Exit CMD-spy");
        exit.Click += (_, _) => ExitFromTray();

        menu.Items.AddRange(new ToolStripItem[]
        {
            open, new ToolStripSeparator(),
            _trayStatus, _trayPause, new ToolStripSeparator(),
            startWithWindows, alerts, new ToolStripSeparator(),
            exit
        });
        menu.Opening += (_, _) =>
        {
            UpdateTrayText();
            _trayPause.Text = _engine.IsRunning ? "Pause monitoring" : "Resume monitoring";
            _trayPause.Enabled = _follower is null;   // the boot service is capturing; nothing to pause here
            startWithWindows.Checked = StartupManager.IsLogonTaskInstalled && StartupManager.IsServiceInstalled;
            alerts.Checked = _settings.AlertOnSuspicious;
        };

        _tray = new NotifyIcon
        {
            Icon = AppIcon,
            Text = "CMD-spy",
            ContextMenuStrip = menu,
            Visible = true
        };
        _tray.DoubleClick += (_, _) => ShowFromTray();
        _tray.BalloonTipClicked += (_, _) =>
        {
            ShowFromTray();
            if (_alertEvent is { } ev) SelectEvent(ev);
        };
    }

    private void DisposeTray()
    {
        if (_tray is null) return;
        _tray.Visible = false;
        _tray.Dispose();
        _tray = null;
    }

    /// <summary>Started in the tray: create the window (so monitoring runs) but keep it hidden.</summary>
    protected override void SetVisibleCore(bool value)
    {
        if (_startInTray && !_allowShow)
        {
            if (!IsHandleCreated)
            {
                CreateHandle();
                BeginInvoke(new Action(OnFormLoad));   // Load only fires on first show
            }
            value = false;
        }
        base.SetVisibleCore(value);
    }

    private void ShowFromTray()
    {
        _allowShow = true;
        if (!Visible) Show();
        if (WindowState == FormWindowState.Minimized) WindowState = FormWindowState.Normal;
        Activate();
        BringToFront();
    }

    private void OnFormClosingToTray(object? sender, FormClosingEventArgs e)
    {
        if (_exiting || _tray is null || !_settings.KeepRunningInTray || e.CloseReason != CloseReason.UserClosing)
            return;

        // Keep monitoring: closing the window only hides it.
        e.Cancel = true;
        Hide();
        if (!_settings.TrayHintShown)
        {
            _settings.TrayHintShown = true;
            _settings.Save();
            _tray.ShowBalloonTip(5000, "CMD-spy is still monitoring",
                "It keeps capturing popups from the notification area. Right-click the icon to open it or exit.", ToolTipIcon.Info);
        }
    }

    private void ExitFromTray()
    {
        if (_follower is null && _engine.IsRunning)
        {
            var answer = MessageBox.Show(this,
                "Exit CMD-spy and stop monitoring?\n\n" +
                (StartupManager.IsLogonTaskInstalled
                    ? "It will start again the next time you log in or unlock."
                    : "Nothing will be captured until you start it again."),
                "CMD-spy", MessageBoxButtons.YesNo, MessageBoxIcon.Question);
            if (answer != DialogResult.Yes) return;
        }
        _exiting = true;
        Close();
    }

    private void UpdateTrayText()
    {
        if (_tray is null) return;
        string state = _follower is not null ? "boot service capturing"
            : _engine.IsRunning ? $"monitoring ({(_engine.WatcherName?.StartsWith("ETW", StringComparison.Ordinal) == true ? "ETW" : "WMI")})"
            : "paused";
        if (_trayStatus is not null) _trayStatus.Text = $"Status: {state} — {_all.Count} popup(s)";
        var text = $"CMD-spy — {state}, {_all.Count} popup(s)";
        _tray.Text = text.Length > 120 ? text[..120] : text;
    }

    private void SelectEvent(CmdEvent ev)
    {
        var index = _view.IndexOf(ev);
        if (index < 0 || index >= _grid.Rows.Count) return;
        _grid.ClearSelection();
        _grid.Rows[index].Selected = true;
        _grid.CurrentCell = _grid.Rows[index].Cells[0];
        _grid.FirstDisplayedScrollingRowIndex = index;
    }

    // ----------------------------------------------------------- alerts --

    private void NotifyIfSuspicious(CmdEvent ev)
    {
        if (_tray is null || !_settings.AlertOnSuspicious) return;
        var risk = ev.Investigation?.Risk;
        if (risk is null || risk.Level is not (RiskLevel.High or RiskLevel.Suspicious)) return;
        if (!_alerted.Add(ev.Id)) return;
        if (_alerted.Count > 10_000) _alerted.Clear();

        var now = DateTime.UtcNow;
        if (now - _lastAlertUtc < TimeSpan.FromSeconds(6))
        {
            _unshownAlerts++;   // mentioned with the next alert
            return;
        }
        _lastAlertUtc = now;
        _alertEvent = ev;

        var more = _unshownAlerts > 0 ? $" (+{_unshownAlerts} more)" : "";
        _unshownAlerts = 0;
        var title = $"{risk.Level}: {ev.ProcessName}{more}";
        var body = $"{ev.CommandLineShort}\nLaunched by: {(string.IsNullOrEmpty(ev.OriginDisplay) ? ev.CauseDisplay : ev.OriginDisplay)}\nClick to investigate.";
        _tray.ShowBalloonTip(15_000, title.Length > 60 ? title[..60] : title, body.Length > 250 ? body[..250] : body,
            risk.Level == RiskLevel.High ? ToolTipIcon.Error : ToolTipIcon.Warning);
    }

    // ---------------------------------------------------------- startup --

    private ToolStripDropDownButton BuildStartupDropDown()
    {
        var drop = new ToolStripDropDownButton("Startup ▾")
        {
            ToolTipText = "Start CMD-spy with Windows and keep it in the notification area"
        };

        var all = new ToolStripMenuItem("Start with Windows — every method (recommended)");
        all.Click += (_, _) => StartupAction("enable start-up", StartupManager.EnableAll);

        var logon = new ToolStripMenuItem("Open in the tray when I log in (elevated, high priority, no delay)");
        logon.Click += (_, _) => StartupAction("change the logon start",
            () => StartupManager.IsLogonTaskInstalled ? StartupManager.DisableLogonTask() : StartupManager.EnableLogonTask());

        var boot = new ToolStripMenuItem("Capture from boot, before login (background service)");
        boot.Click += (_, _) => StartupAction("change the boot service",
            () => StartupManager.IsServiceInstalled ? ServiceControl.Uninstall() : ServiceControl.Install());

        var tray = new ToolStripMenuItem("Keep monitoring in the tray when the window is closed");
        tray.Click += (_, _) =>
        {
            _settings.KeepRunningInTray = !_settings.KeepRunningInTray;
            _settings.Save();
        };

        var alerts = new ToolStripMenuItem("Alert me about suspicious popups");
        alerts.Click += (_, _) =>
        {
            _settings.AlertOnSuspicious = !_settings.AlertOnSuspicious;
            _settings.Save();
        };

        var none = new ToolStripMenuItem("Don't start with Windows");
        none.Click += (_, _) => StartupAction("remove start-up", StartupManager.DisableAll);

        drop.DropDownOpening += (_, _) =>
        {
            bool logonOn = StartupManager.IsLogonTaskInstalled, bootOn = StartupManager.IsServiceInstalled;
            all.Checked = logonOn && bootOn;
            logon.Checked = logonOn;
            boot.Checked = bootOn;
            tray.Checked = _settings.KeepRunningInTray;
            alerts.Checked = _settings.AlertOnSuspicious;
            none.Enabled = logonOn || bootOn;
        };

        drop.DropDownItems.AddRange(new ToolStripItem[]
        {
            all, new ToolStripSeparator(), logon, boot, new ToolStripSeparator(), tray, alerts, new ToolStripSeparator(), none
        });
        return drop;
    }

    private void ToggleStartWithWindows()
    {
        if (StartupManager.IsLogonTaskInstalled && StartupManager.IsServiceInstalled)
            StartupAction("remove start-up", StartupManager.DisableAll);
        else
            StartupAction("enable start-up", StartupManager.EnableAll);
    }

    private async void StartupAction(string what, Func<List<string>> action)
    {
        Cursor = Cursors.WaitCursor;
        _lblStatus.Text = $"Startup: {what}…";
        try
        {
            // Installing the service hands capture over to it (so nothing is logged twice).
            bool installsService = !StartupManager.IsServiceInstalled &&
                                   (what == "enable start-up" || what == "change the boot service");
            if (installsService && _engine.IsRunning) StopMonitoring();
            var log = await Task.Run(action);
            SyncWithService();
            if (!_engine.IsRunning && _follower is null) StartMonitoring();
            MessageBox.Show(this, string.Join("\n", log), "CMD-spy — startup", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }
        catch (Exception ex)
        {
            SyncWithService();
            if (!_engine.IsRunning && _follower is null) StartMonitoring();
            MessageBox.Show(this, $"Could not {what}:\n{ex.Message}", "CMD-spy", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
        finally
        {
            Cursor = Cursors.Default;
            RestoreStatusLabel();
        }
    }
}
