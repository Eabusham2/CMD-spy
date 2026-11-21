using System.Collections;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Imaging;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using CmdSpy.Core.Models;

namespace GuiScreenshot;

/// <summary>
/// Screenshots the real CMD-spy window (any version: everything beyond the
/// public MainForm is reached by reflection, so the same harness builds against
/// old and new code), and smoke-tests the start-up paths of the current one.
///
///   GuiScreenshot.exe &lt;outDir&gt; &lt;label&gt; [width] [height]
///   GuiScreenshot.exe --smoke &lt;path\to\CmdSpy.exe&gt; &lt;outDir&gt;
/// </summary>
internal static class Program
{
    [STAThread]
    private static int Main(string[] args)
    {
        if (args.Length >= 3 && args[0] == "--smoke")
            return Smoke.Run(args[1], args[2]);

        var outDir = args.Length > 0 ? args[0] : "shots";
        var label = args.Length > 1 ? args[1] : "shot";
        int width = args.Length > 2 ? int.Parse(args[2]) : 1500;
        int height = args.Length > 3 ? int.Parse(args[3]) : 880;
        Directory.CreateDirectory(outDir);

        Application.SetHighDpiMode(HighDpiMode.SystemAware);
        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);

        var director = new Director(outDir, label, width, height);
        return director.Run();
    }
}

/// <summary>Drives one MainForm through the demo and captures it.</summary>
internal sealed class Director
{
    private const BindingFlags AnyMember = BindingFlags.Instance | BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic;

    private readonly string _outDir;
    private readonly string _label;
    private readonly int _width, _height;
    private readonly StreamWriter _log;
    private readonly List<Process> _demo = new();
    private Form _form = null!;
    private int _exitCode = 1;

    public Director(string outDir, string label, int width, int height)
    {
        _outDir = outDir;
        _label = label;
        _width = width;
        _height = height;
        _log = new StreamWriter(Path.Combine(outDir, $"{label}-harness.log")) { AutoFlush = true };
    }

    public int Run()
    {
        Log($"Screen {Screen.PrimaryScreen?.Bounds}, max window track size {SystemInformation.MaxWindowTrackSize}, " +
            $"elevated {IsElevated()}, CmdSpy assembly {typeof(CmdSpy.App.MainForm).Assembly.GetName().Version}");

        _form = new CmdSpy.App.MainForm
        {
            StartPosition = FormStartPosition.Manual,
            Bounds = new Rectangle(0, 0, _width, _height)
        };
        _form.Shown += async (_, _) => await ScriptAsync();
        Application.Run(_form);
        return _exitCode;
    }

    // ---------------------------------------------------------------- script --

    private async Task ScriptAsync()
    {
        try
        {
            Log($"Window bounds {_form.Bounds}");
            await WaitUntil(() => Engine is not null && (bool)(Prop(Engine, "IsRunning") ?? false), 30_000, "engine running");
            Log($"Watcher: {Prop(Engine!, "WatcherName")}");
            await Task.Delay(1500);

            await LaunchDemoAsync();

            bool captured = await WaitUntil(() => DemoEvents().Count >= 4, 60_000, "all demo popups captured");
            bool investigates = typeof(CmdEvent).GetProperty("Investigation") is not null;
            bool analysed = !investigates || await WaitUntil(() => DemoEvents().All(e => Prop(e, "Investigation") is not null), 120_000, "demo popups analysed");
            await WaitForQuiet(TimeSpan.FromSeconds(3), TimeSpan.FromSeconds(30));
            foreach (var e in DemoEvents())
                Log($"  demo #{e.SequenceNumber} {e.ProcessName}: {e.CommandLineShort}  risk={(investigates ? RiskOf(e) : "n/a")}");

            // 1. The main window, with the user's kind of command (gwmi ... ProcessId=...) selected.
            Select(e => e.CommandLine?.Contains("gwmi", StringComparison.OrdinalIgnoreCase) == true);
            await Task.Delay(1000);
            Save(CaptureWindow(_form), "main");
            SaveReport("gwmi");

            if (investigates)
            {
                // 2. A popup the analysis rates High risk (row turns red).
                Select(e => e.CommandLine?.Contains("vssadmin", StringComparison.OrdinalIgnoreCase) == true);
                await Task.Delay(1000);
                Save(CaptureWindow(_form), "main-high-risk");

                // 3. The new menus, opened over the window.
                Select(e => e.CommandLine?.Contains("gwmi", StringComparison.OrdinalIgnoreCase) == true);
                await Task.Delay(500);
                foreach (var menu in new[] { "Startup ▾", "Investigate ▾", "Boot service ▾" })
                    await CaptureDropDownAsync(menu);
                await CaptureTrayMenuAsync();
            }
            else
            {
                await CaptureDropDownAsync("Targets ▾");
            }

            _exitCode = captured && analysed ? 0 : 1;
            Log($"Finished: captured={captured} analysed={analysed}");
        }
        catch (Exception ex)
        {
            Log("FAILED: " + ex);
            _exitCode = 2;
        }
        finally
        {
            foreach (var p in _demo) { try { if (!p.HasExited) p.Kill(); } catch { } }
            Application.Exit();
        }
    }

    private async Task LaunchDemoAsync()
    {
        var sys = Environment.SystemDirectory;
        var powershell = Path.Combine(sys, @"WindowsPowerShell\v1.0\powershell.exe");
        var cmd = Path.Combine(sys, "cmd.exe");

        // A running process for the command below to refer to (stands in for asus_framework.exe).
        var ping = Start(Path.Combine(sys, "PING.EXE"), "-n 600 127.0.0.1");
        await Task.Delay(800);

        Start(cmd, "/d /c \"echo CMD-spy demo popup & ping -n 2 127.0.0.1 >nul\"");
        await Task.Delay(1500);
        Start(powershell, $"-NoProfile -c gwmi win32_process -Filter 'ProcessId={ping.Id} or ProcessId={Environment.ProcessId}'");
        await Task.Delay(1500);
        Start(powershell, "-NoProfile -WindowStyle Hidden -EncodedCommand " +
                          Convert.ToBase64String(Encoding.Unicode.GetBytes("Get-Date | Out-Null")));
        await Task.Delay(1500);
        // Harmless: only *prints* a ransomware-style command, which the detector recognises.
        Start(cmd, "/d /c echo vssadmin delete shadows /all /quiet");
        Log($"Demo popups launched (reference process PING.EXE PID {ping.Id}).");
    }

    private Process Start(string file, string arguments)
    {
        var p = Process.Start(new ProcessStartInfo(file, arguments) { UseShellExecute = false, CreateNoWindow = true })!;
        _demo.Add(p);
        return p;
    }

    // ------------------------------------------------------------ form access --

    private object? Field(string name) => _form.GetType().GetField(name, AnyMember)?.GetValue(_form);
    private static object? Prop(object target, string name) => target.GetType().GetProperty(name, AnyMember)?.GetValue(target);
    private object? Engine => Field("_engine");

    private List<CmdEvent> AllEvents() => ((IEnumerable?)Field("_all"))?.Cast<CmdEvent>().ToList() ?? new();

    private static readonly string[] DemoMarkers = { "CMD-spy demo popup", "gwmi win32_process", "-EncodedCommand", "vssadmin" };

    private List<CmdEvent> DemoEvents() => AllEvents()
        .Where(e => !e.ProcessName.StartsWith("conhost", StringComparison.OrdinalIgnoreCase) &&
                    DemoMarkers.Any(m => e.CommandLine?.Contains(m, StringComparison.OrdinalIgnoreCase) == true))
        .GroupBy(e => DemoMarkers.First(m => e.CommandLine!.Contains(m, StringComparison.OrdinalIgnoreCase)))
        .Select(g => g.First())
        .ToList();

    private static string RiskOf(CmdEvent e)
    {
        var inv = Prop(e, "Investigation");
        var risk = inv is null ? null : Prop(inv, "Risk");
        return risk is null ? "(none)" : $"{Prop(risk, "Level")} {Prop(risk, "Score")}";
    }

    private void Select(Func<CmdEvent, bool> match)
    {
        var grid = (DataGridView)Field("_grid")!;
        var view = (IList)Field("_view")!;
        for (int i = 0; i < view.Count; i++)
        {
            if (view[i] is CmdEvent e && match(e) && i < grid.Rows.Count)
            {
                grid.ClearSelection();
                grid.CurrentCell = grid.Rows[i].Cells[0];
                grid.Rows[i].Selected = true;
                grid.FirstDisplayedScrollingRowIndex = Math.Max(0, i - 2);
                Log($"Selected row {i}: {e.ProcessName} {e.CommandLineShort}");
                return;
            }
        }
        Log("No row matched the selection.");
    }

    // ------------------------------------------------------------- captures --

    private async Task CaptureDropDownAsync(string text)
    {
        var toolbar = (ToolStrip)Field("_toolbar")!;
        var button = toolbar.Items.OfType<ToolStripDropDownButton>().FirstOrDefault(b => b.Text == text);
        if (button is null) { Log($"No '{text}' menu."); return; }
        button.ShowDropDown();
        await Task.Delay(800);
        var shot = Composite(CaptureWindow(_form), button.DropDown);
        button.HideDropDown();
        Save(shot, "menu-" + Slug(text));
        await Task.Delay(300);
    }

    private async Task CaptureTrayMenuAsync()
    {
        if (Field("_tray") is not NotifyIcon tray || tray.ContextMenuStrip is null) { Log("No tray icon."); return; }
        var menu = tray.ContextMenuStrip;
        menu.Show(_form, new Point(_form.ClientSize.Width - 460, 60));
        await Task.Delay(800);
        var shot = Composite(CaptureWindow(_form), menu);
        menu.Close();
        Save(shot, "menu-tray");
        await Task.Delay(300);
    }

    /// <summary>The window as Windows draws it (PrintWindow, DWM frame included), falling back to DrawToBitmap.</summary>
    private Bitmap CaptureWindow(Form form)
    {
        form.Refresh();
        Application.DoEvents();
        var hwnd = form.Handle;
        GetWindowRect(hwnd, out var wr);
        var full = new Bitmap(Math.Max(1, wr.Right - wr.Left), Math.Max(1, wr.Bottom - wr.Top), PixelFormat.Format32bppArgb);
        bool printed;
        using (var g = Graphics.FromImage(full))
        {
            var hdc = g.GetHdc();
            try { printed = PrintWindow(hwnd, hdc, 2 /* PW_RENDERFULLCONTENT */); }
            finally { g.ReleaseHdc(hdc); }
        }

        if (printed && !LooksBlank(full))
        {
            // Trim Windows' invisible resize borders.
            if (DwmGetWindowAttribute(hwnd, 9 /* DWMWA_EXTENDED_FRAME_BOUNDS */, out var fr, Marshal.SizeOf<RECT>()) == 0)
            {
                var crop = Rectangle.Intersect(new Rectangle(fr.Left - wr.Left, fr.Top - wr.Top, fr.Right - fr.Left, fr.Bottom - fr.Top),
                    new Rectangle(Point.Empty, full.Size));
                if (crop.Width > 0 && crop.Height > 0 && crop.Size != full.Size)
                {
                    var trimmed = full.Clone(crop, full.PixelFormat);
                    full.Dispose();
                    _lastOrigin = new Point(fr.Left, fr.Top);
                    return trimmed;
                }
            }
            _lastOrigin = new Point(wr.Left, wr.Top);
            return full;
        }

        Log("PrintWindow gave nothing usable; using DrawToBitmap.");
        full.Dispose();
        var bmp = new Bitmap(form.Width, form.Height);
        form.DrawToBitmap(bmp, new Rectangle(Point.Empty, form.Size));
        _lastOrigin = form.Location;
        return bmp;
    }

    private Point _lastOrigin;

    /// <summary>Pastes a drop-down (its own top-level window) onto the window capture where it appears on screen.</summary>
    private Bitmap Composite(Bitmap window, ToolStripDropDown dropDown)
    {
        var menu = new Bitmap(Math.Max(1, dropDown.Width), Math.Max(1, dropDown.Height));
        dropDown.DrawToBitmap(menu, new Rectangle(Point.Empty, dropDown.Size));
        var at = new Point(dropDown.Bounds.Left - _lastOrigin.X, dropDown.Bounds.Top - _lastOrigin.Y);
        var canvas = new Bitmap(Math.Max(window.Width, at.X + menu.Width + 12), Math.Max(window.Height, at.Y + menu.Height + 12));
        using (var g = Graphics.FromImage(canvas))
        {
            g.Clear(Color.FromArgb(240, 240, 240));
            g.DrawImage(window, 0, 0);
            using var shadow = new SolidBrush(Color.FromArgb(70, 0, 0, 0));
            g.FillRectangle(shadow, at.X + 5, at.Y + 5, menu.Width, menu.Height);
            g.DrawImage(menu, at);
            g.DrawRectangle(Pens.DimGray, at.X, at.Y, menu.Width - 1, menu.Height - 1);
        }
        window.Dispose();
        menu.Dispose();
        return canvas;
    }

    /// <summary>The selected popup's full text report (what the details pane and the .log show), as an image and as text.</summary>
    private void SaveReport(string what)
    {
        var details = (TextBox)Field("_details")!;
        var text = details.Text;
        File.WriteAllText(Path.Combine(_outDir, $"{_label}-report-{what}.txt"), text);

        var lines = new List<string>();
        foreach (var raw in text.Replace("\r", "").Split('\n'))
        {
            var line = raw;
            while (line.Length > 150) { lines.Add(line[..150]); line = "      " + line[150..]; }
            lines.Add(line);
        }
        using var font = new Font(details.Font.FontFamily, details.Font.Size);
        var lineHeight = TextRenderer.MeasureText("Ag", font).Height;
        int width = 40 + lines.Max(l => TextRenderer.MeasureText(l.Length == 0 ? " " : l, font, Size.Empty, TextFormatFlags.NoPadding).Width);
        int height = 30 + lineHeight * lines.Count;
        using var bmp = new Bitmap(Math.Min(width, 2400), Math.Min(height, 9000));
        using (var g = Graphics.FromImage(bmp))
        {
            g.Clear(details.BackColor);
            for (int i = 0; i < lines.Count; i++)
                TextRenderer.DrawText(g, lines[i], font, new Point(16, 14 + i * lineHeight), details.ForeColor, TextFormatFlags.NoPadding);
        }
        Save(bmp, $"report-{what}");
    }

    private void Save(Bitmap bmp, string name)
    {
        var path = Path.Combine(_outDir, $"{_label}-{name}.png");
        bmp.Save(path, ImageFormat.Png);
        Log($"Saved {path} ({bmp.Width}x{bmp.Height})");
        bmp.Dispose();
    }

    private static bool LooksBlank(Bitmap bmp)
    {
        var first = bmp.GetPixel(bmp.Width / 2, bmp.Height / 2);
        int same = 0, total = 0;
        for (int x = 0; x < bmp.Width; x += Math.Max(1, bmp.Width / 40))
            for (int y = 0; y < bmp.Height; y += Math.Max(1, bmp.Height / 40))
            {
                total++;
                if (bmp.GetPixel(x, y).ToArgb() == first.ToArgb()) same++;
            }
        return same > total * 0.97;
    }

    // ---------------------------------------------------------------- helpers --

    private async Task<bool> WaitUntil(Func<bool> condition, int timeoutMs, string what)
    {
        var clock = Stopwatch.StartNew();
        while (clock.ElapsedMilliseconds < timeoutMs)
        {
            if (condition()) { Log($"OK ({clock.ElapsedMilliseconds} ms): {what}"); return true; }
            await Task.Delay(250);
        }
        Log($"TIMED OUT after {timeoutMs} ms: {what}");
        return condition();
    }

    private async Task WaitForQuiet(TimeSpan quiet, TimeSpan max)
    {
        var clock = Stopwatch.StartNew();
        int count = AllEvents().Count;
        var since = Stopwatch.StartNew();
        while (clock.Elapsed < max && since.Elapsed < quiet)
        {
            await Task.Delay(250);
            int now = AllEvents().Count;
            if (now != count) { count = now; since.Restart(); }
        }
    }

    private static string Slug(string text) => new string(text.Where(char.IsLetter).ToArray()).ToLowerInvariant();

    private void Log(string message)
    {
        var line = $"{DateTime.Now:HH:mm:ss.fff}  {message}";
        _log.WriteLine(line);
        Console.WriteLine(line);
    }

    private static bool IsElevated()
    {
        using var id = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct RECT { public int Left, Top, Right, Bottom; }

    [DllImport("user32.dll")] private static extern bool GetWindowRect(IntPtr hwnd, out RECT rect);
    [DllImport("user32.dll")] private static extern bool PrintWindow(IntPtr hwnd, IntPtr hdc, uint flags);
    [DllImport("dwmapi.dll")] private static extern int DwmGetWindowAttribute(IntPtr hwnd, int attribute, out RECT value, int size);
}
