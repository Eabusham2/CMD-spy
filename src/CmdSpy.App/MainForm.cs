using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Windows.Forms;
using CmdSpy.Core;
using CmdSpy.Core.Formatting;
using CmdSpy.Core.Models;

namespace CmdSpy.App;

/// <summary>
/// The CMD-spy dashboard: a live list of every cmd popup that has appeared,
/// with a details pane, filtering, target configuration and quick access to the
/// on-disk logs.
/// </summary>
public sealed class MainForm : Form
{
    private readonly CmdSpyEngine _engine;

    // Master list of everything captured this session, plus the filtered view
    // that the grid is bound to.
    private readonly List<CmdEvent> _all = new();
    private readonly BindingList<CmdEvent> _view = new();
    private string _filter = "";

    private DataGridView _grid = null!;
    private TextBox _details = null!;
    private ToolStrip _toolbar = null!;
    private StatusStrip _statusBar = null!;
    private ToolStripStatusLabel _lblStatus = null!;
    private ToolStripStatusLabel _lblCount = null!;
    private ToolStripStatusLabel _lblBoot = null!;
    private ToolStripStatusLabel _lblUptime = null!;
    private ToolStripButton _btnStart = null!;
    private ToolStripButton _btnStop = null!;
    private ToolStripTextBox _txtFilter = null!;
    private System.Windows.Forms.Timer _uptimeTimer = null!;
    private bool _warnedEtw;

    public MainForm()
    {
        _engine = new CmdSpyEngine();
        _engine.EventCaptured += (_, ev) => UiInvoke(() => OnCaptured(ev));
        _engine.EventUpdated += (_, ev) => UiInvoke(() => OnUpdated(ev));
        _engine.Status += (_, msg) => UiInvoke(() => OnStatus(msg));

        BuildUi();
    }

    // ----------------------------------------------------------------- UI ----

    private void BuildUi()
    {
        Text = "CMD-spy — command-prompt popup monitor";
        Width = 1200;
        Height = 720;
        MinimumSize = new Size(820, 480);
        StartPosition = FormStartPosition.CenterScreen;

        BuildToolbar();
        BuildStatusBar();

        var split = new SplitContainer
        {
            Dock = DockStyle.Fill,
            Orientation = Orientation.Horizontal,
            SplitterDistance = 420
        };

        BuildGrid();
        _details = new TextBox
        {
            Dock = DockStyle.Fill,
            Multiline = true,
            ReadOnly = true,
            ScrollBars = ScrollBars.Both,
            WordWrap = false,
            Font = new Font(FontFamily.GenericMonospace, 9f),
            BackColor = Color.FromArgb(24, 24, 24),
            ForeColor = Color.Gainsboro
        };

        split.Panel1.Controls.Add(_grid);
        split.Panel2.Controls.Add(_details);

        Controls.Add(split);
        Controls.Add(_toolbar);
        Controls.Add(_statusBar);

        _uptimeTimer = new System.Windows.Forms.Timer { Interval = 1000 };
        _uptimeTimer.Tick += (_, _) => UpdateUptime();
        _uptimeTimer.Start();

        Load += (_, _) => OnFormLoad();
        FormClosing += (_, _) => _engine.Dispose();
    }

    private void BuildToolbar()
    {
        _toolbar = new ToolStrip { GripStyle = ToolStripGripStyle.Hidden };

        _btnStart = new ToolStripButton("▶ Start") { ToolTipText = "Start monitoring" };
        _btnStart.Click += (_, _) => StartMonitoring();

        _btnStop = new ToolStripButton("■ Stop") { ToolTipText = "Stop monitoring", Enabled = false };
        _btnStop.Click += (_, _) => StopMonitoring();

        var btnClear = new ToolStripButton("Clear view") { ToolTipText = "Clear the on-screen list (log files are kept)" };
        btnClear.Click += (_, _) => ClearView();

        var btnLogs = new ToolStripButton("Open log folder");
        btnLogs.Click += (_, _) => OpenLogFolder();

        var btnExport = new ToolStripButton("Export…");
        btnExport.Click += (_, _) => ExportView();

        var targets = BuildTargetsDropDown();

        _txtFilter = new ToolStripTextBox { Width = 220, ToolTipText = "Filter by command line, process or parent" };
        _txtFilter.TextChanged += (_, _) => ApplyFilter(_txtFilter.Text);

        _toolbar.Items.AddRange(new ToolStripItem[]
        {
            _btnStart, _btnStop, new ToolStripSeparator(),
            btnClear, btnLogs, btnExport, new ToolStripSeparator(),
            targets, new ToolStripSeparator(),
            new ToolStripLabel("Filter:"), _txtFilter
        });
    }

    private ToolStripDropDownButton BuildTargetsDropDown()
    {
        var drop = new ToolStripDropDownButton("Targets ▾")
        {
            ToolTipText = "Choose which console/script hosts count as a popup"
        };

        foreach (var name in CmdSpyOptions.ExtendedTargets)
        {
            var item = new ToolStripMenuItem(name)
            {
                CheckOnClick = true,
                Checked = _engine.Options.TargetProcessNames.Contains(name),
                Tag = name
            };
            item.CheckedChanged += (_, _) =>
            {
                if (item.Checked) _engine.Options.TargetProcessNames.Add(name);
                else _engine.Options.TargetProcessNames.Remove(name);
                _engine.RefreshTargets();
            };
            drop.DropDownItems.Add(item);
        }

        drop.DropDownItems.Add(new ToolStripSeparator());

        var net = new ToolStripMenuItem("Capture networking")
        {
            CheckOnClick = true,
            Checked = _engine.Options.CaptureNetwork
        };
        net.CheckedChanged += (_, _) => _engine.Options.CaptureNetwork = net.Checked;

        var kids = new ToolStripMenuItem("Capture child processes (actions)")
        {
            CheckOnClick = true,
            Checked = _engine.Options.CaptureChildren
        };
        kids.CheckedChanged += (_, _) => _engine.Options.CaptureChildren = kids.Checked;

        drop.DropDownItems.Add(net);
        drop.DropDownItems.Add(kids);
        return drop;
    }

    private void BuildGrid()
    {
        _grid = new DataGridView
        {
            Dock = DockStyle.Fill,
            ReadOnly = true,
            AllowUserToAddRows = false,
            AllowUserToDeleteRows = false,
            AllowUserToResizeRows = false,
            AutoGenerateColumns = false,
            SelectionMode = DataGridViewSelectionMode.FullRowSelect,
            MultiSelect = false,
            RowHeadersVisible = false,
            AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.None,
            AllowUserToOrderColumns = true,
            BackgroundColor = Color.FromArgb(30, 30, 30),
            BorderStyle = BorderStyle.None,
            EnableHeadersVisualStyles = false
        };
        _grid.ColumnHeadersDefaultCellStyle.BackColor = Color.FromArgb(45, 45, 48);
        _grid.ColumnHeadersDefaultCellStyle.ForeColor = Color.White;
        _grid.DefaultCellStyle.BackColor = Color.FromArgb(30, 30, 30);
        _grid.DefaultCellStyle.ForeColor = Color.Gainsboro;
        _grid.DefaultCellStyle.SelectionBackColor = Color.FromArgb(0, 90, 158);
        _grid.AlternatingRowsDefaultCellStyle.BackColor = Color.FromArgb(37, 37, 38);

        AddColumn("#", nameof(CmdEvent.SequenceNumber), 55);
        AddColumn("Time", nameof(CmdEvent.TimeLocalDisplay), 155);
        AddColumn("Since boot", nameof(CmdEvent.SinceBootDisplay), 110);
        AddColumn("PID", nameof(CmdEvent.ProcessId), 65);
        AddColumn("Process", nameof(CmdEvent.ProcessName), 100);
        AddColumn("Command line", nameof(CmdEvent.CommandLineShort), 340);
        AddColumn("Cause (parent)", nameof(CmdEvent.CauseDisplay), 160);
        AddColumn("Lifetime", nameof(CmdEvent.LifetimeDisplay), 90);
        AddColumn("Net", nameof(CmdEvent.NetworkCount), 45);
        AddColumn("Kids", nameof(CmdEvent.ChildCount), 45);
        AddColumn("Src", nameof(CmdEvent.CaptureSource), 55);

        _grid.DataSource = _view;
        _grid.SelectionChanged += (_, _) => ShowSelectedDetails();
    }

    private void AddColumn(string header, string property, int width)
    {
        _grid.Columns.Add(new DataGridViewTextBoxColumn
        {
            HeaderText = header,
            DataPropertyName = property,
            Width = width,
            SortMode = DataGridViewColumnSortMode.NotSortable
        });
    }

    private void BuildStatusBar()
    {
        _statusBar = new StatusStrip();
        _lblStatus = new ToolStripStatusLabel("Idle") { Spring = false, ForeColor = Color.DimGray };
        _lblCount = new ToolStripStatusLabel("Events: 0");
        _lblBoot = new ToolStripStatusLabel("Boot: —");
        _lblUptime = new ToolStripStatusLabel("Uptime: —") { Spring = true, TextAlign = ContentAlignment.MiddleRight };
        _statusBar.Items.AddRange(new ToolStripItem[]
        {
            _lblStatus, new ToolStripStatusLabel("|"),
            _lblCount, new ToolStripStatusLabel("|"),
            _lblBoot, _lblUptime
        });
    }

    // ------------------------------------------------------------- Behaviour --

    private void OnFormLoad()
    {
        // Surface any history already logged today.
        try
        {
            foreach (var ev in _engine.Store.ReadToday())
            {
                _all.Add(ev);
                if (PassesFilter(ev)) _view.Add(ev);
            }
        }
        catch { /* ignore unreadable history */ }

        UpdateCount();
        StartMonitoring();
    }

    private void StartMonitoring()
    {
        try
        {
            _engine.Start();
            _btnStart.Enabled = false;
            _btnStop.Enabled = true;
            var via = _engine.WatcherName ?? "?";
            _lblStatus.Text = $"Monitoring ({via})";
            _lblStatus.ForeColor = Color.LimeGreen;
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, $"Could not start monitoring:\n{ex.Message}",
                "CMD-spy", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    private void StopMonitoring()
    {
        _engine.Stop();
        _btnStart.Enabled = true;
        _btnStop.Enabled = false;
        _lblStatus.Text = "Stopped";
        _lblStatus.ForeColor = Color.OrangeRed;
    }

    private void OnCaptured(CmdEvent ev)
    {
        _all.Add(ev);
        if (PassesFilter(ev))
        {
            _view.Add(ev);
            // Auto-follow the newest capture.
            if (_grid.Rows.Count > 0)
            {
                var idx = _view.Count - 1;
                _grid.ClearSelection();
                _grid.Rows[idx].Selected = true;
                _grid.FirstDisplayedScrollingRowIndex = idx;
            }
        }
        UpdateCount();
    }

    private void OnUpdated(CmdEvent ev)
    {
        var idx = _view.IndexOf(ev);
        if (idx >= 0)
        {
            _view.ResetItem(idx);
            if (_grid.CurrentRow?.DataBoundItem == ev)
                ShowSelectedDetails();
        }
    }

    private void OnStatus(string message)
    {
        // If ETW fell back to WMI, tell the user once — it means "run as admin".
        if (!_warnedEtw && message.StartsWith("ETW unavailable", StringComparison.Ordinal))
        {
            _warnedEtw = true;
            MessageBox.Show(this, message + "\n\nRestart CMD-spy as Administrator for full fidelity.",
                "CMD-spy — limited mode", MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }
        Debug.WriteLine(message);
    }

    private void ShowSelectedDetails()
    {
        if (_grid.CurrentRow?.DataBoundItem is CmdEvent ev)
            _details.Text = EventTextFormatter.Format(ev);
    }

    private void ApplyFilter(string text)
    {
        _filter = text?.Trim() ?? "";
        _view.RaiseListChangedEvents = false;
        _view.Clear();
        foreach (var ev in _all)
            if (PassesFilter(ev))
                _view.Add(ev);
        _view.RaiseListChangedEvents = true;
        _view.ResetBindings();
        UpdateCount();
    }

    private bool PassesFilter(CmdEvent ev)
    {
        if (string.IsNullOrEmpty(_filter)) return true;
        var f = _filter;
        return Contains(ev.CommandLine, f)
            || Contains(ev.ProcessName, f)
            || Contains(ev.ParentProcessName, f)
            || Contains(ev.ParentCommandLine, f)
            || Contains(ev.UserName, f)
            || ev.ProcessId.ToString().Contains(f);
    }

    private static bool Contains(string? haystack, string needle) =>
        !string.IsNullOrEmpty(haystack) &&
        haystack.Contains(needle, StringComparison.OrdinalIgnoreCase);

    private void ClearView()
    {
        _all.Clear();
        _view.Clear();
        _details.Clear();
        UpdateCount();
    }

    private void OpenLogFolder()
    {
        try
        {
            Directory.CreateDirectory(_engine.Store.Directory);
            Process.Start(new ProcessStartInfo
            {
                FileName = _engine.Store.Directory,
                UseShellExecute = true
            });
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "CMD-spy", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    private void ExportView()
    {
        using var dlg = new SaveFileDialog
        {
            Title = "Export captured events",
            Filter = "Text report (*.txt)|*.txt|JSON lines (*.jsonl)|*.jsonl",
            FileName = $"cmdspy-export-{DateTime.Now:yyyyMMdd-HHmmss}"
        };
        if (dlg.ShowDialog(this) != DialogResult.OK) return;

        try
        {
            if (dlg.FilterIndex == 2)
            {
                var opts = new System.Text.Json.JsonSerializerOptions { WriteIndented = false };
                using var w = new StreamWriter(dlg.FileName);
                foreach (var ev in _all)
                {
                    string line;
                    lock (ev) { line = System.Text.Json.JsonSerializer.Serialize(ev, opts); }
                    w.WriteLine(line);
                }
            }
            else
            {
                using var w = new StreamWriter(dlg.FileName);
                foreach (var ev in _all)
                    w.WriteLine(EventTextFormatter.Format(ev));
            }
            MessageBox.Show(this, $"Exported {_all.Count} event(s).", "CMD-spy",
                MessageBoxButtons.OK, MessageBoxIcon.Information);
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "CMD-spy", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    private void UpdateCount() => _lblCount.Text = $"Events: {_all.Count}" +
        (_view.Count != _all.Count ? $" (showing {_view.Count})" : "");

    private void UpdateUptime()
    {
        var boot = Core.Monitoring.SystemTimings.BootTimeLocal;
        var up = Core.Monitoring.SystemTimings.Uptime;
        _lblBoot.Text = $"Boot: {boot:yyyy-MM-dd HH:mm:ss}";
        _lblUptime.Text = $"Uptime: {(int)up.TotalHours:D2}:{up.Minutes:D2}:{up.Seconds:D2}";
    }

    private void UiInvoke(Action action)
    {
        if (!IsHandleCreated || IsDisposed) return;
        try
        {
            if (InvokeRequired) BeginInvoke(action);
            else action();
        }
        catch (ObjectDisposedException) { /* form is closing */ }
        catch (InvalidOperationException) { /* handle gone */ }
    }
}
