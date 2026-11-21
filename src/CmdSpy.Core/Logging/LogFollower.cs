using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading;
using CmdSpy.Core.Models;

namespace CmdSpy.Core.Logging;

/// <summary>
/// Follows the JSON-lines log that another CMD-spy instance — normally the
/// boot-start background service — is writing, and replays it as a live
/// <see cref="ICaptureFeed"/>. This lets the GUI show captures (and their
/// analyses) from before anyone logged in, without running a second capture
/// session alongside the service.
/// </summary>
public sealed class LogFollower : ICaptureFeed, IDisposable
{
    private readonly string _directory;
    private readonly TimeSpan _interval;
    private readonly Dictionary<Guid, CmdEvent> _known = new();
    private readonly Func<DateTime> _clock;
    private Timer? _timer;
    private string? _path;
    private long _position;
    private int _busy;

    public LogFollower(string directory, TimeSpan? interval = null, Func<DateTime>? clock = null)
    {
        _directory = directory;
        _interval = interval ?? TimeSpan.FromMilliseconds(500);
        _clock = clock ?? (() => DateTime.Now);
    }

    public event EventHandler<CmdEvent>? EventCaptured;
    public event EventHandler<CmdEvent>? EventUpdated;

    public string Directory => _directory;
    public bool IsRunning => _timer is not null;

    /// <summary>The JSON-lines file for a given day (same naming as <see cref="EventStore"/>).</summary>
    public string PathFor(DateTime day) => Path.Combine(_directory, $"cmdspy-{day:yyyyMMdd}.jsonl");

    /// <summary>
    /// Reads everything already in today's log (returned, last snapshot per
    /// event, in capture order — no events are raised for these), then keeps
    /// following the file and raises <see cref="EventCaptured"/> /
    /// <see cref="EventUpdated"/> for whatever is written after.
    /// </summary>
    public IReadOnlyList<CmdEvent> Start()
    {
        var existing = new List<CmdEvent>();
        _path = PathFor(_clock());
        _position = 0;
        foreach (var ev in ReadNewLines(_path))
        {
            if (_known.TryGetValue(ev.Id, out var known))
            {
                lock (known) known.CopyFrom(ev);
            }
            else
            {
                _known[ev.Id] = ev;
                existing.Add(ev);
            }
        }

        _timer ??= new Timer(_ => Poll(), null, _interval, _interval);
        return existing;
    }

    public void Stop()
    {
        _timer?.Dispose();
        _timer = null;
    }

    public void Dispose() => Stop();

    /// <summary>Reads any newly completed lines and raises events for them. Safe to call directly (tests).</summary>
    public void Poll()
    {
        if (Interlocked.Exchange(ref _busy, 1) == 1) return;
        try
        {
            var today = PathFor(_clock());
            if (_path is not null && !string.Equals(_path, today, StringComparison.OrdinalIgnoreCase))
            {
                // Midnight: drain what's left of yesterday's file, then switch.
                Dispatch(ReadNewLines(_path));
                _path = today;
                _position = 0;
            }
            _path ??= today;
            Dispatch(ReadNewLines(_path));
        }
        catch
        {
            // A log being rotated or briefly locked — try again next tick.
        }
        finally
        {
            Volatile.Write(ref _busy, 0);
        }
    }

    private void Dispatch(List<CmdEvent> events)
    {
        foreach (var ev in events)
        {
            if (_known.TryGetValue(ev.Id, out var known))
            {
                lock (known) known.CopyFrom(ev);
                EventUpdated?.Invoke(this, known);
            }
            else
            {
                _known[ev.Id] = ev;
                if (_known.Count > 50_000) _known.Clear();   // bound memory on very long sessions
                EventCaptured?.Invoke(this, ev);
            }
        }
    }

    /// <summary>
    /// Parses the complete lines added since the last read. Works on bytes and
    /// stops at the last newline, so a line the writer is still in the middle
    /// of (or a multi-byte character split across reads) is picked up whole on
    /// the next poll.
    /// </summary>
    private List<CmdEvent> ReadNewLines(string path)
    {
        var result = new List<CmdEvent>();
        if (!File.Exists(path)) return result;

        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        if (fs.Length < _position) _position = 0;   // file was replaced
        if (fs.Length == _position) return result;

        fs.Seek(_position, SeekOrigin.Begin);
        var buffer = new byte[fs.Length - _position];
        int read = 0;
        while (read < buffer.Length)
        {
            int n = fs.Read(buffer, read, buffer.Length - read);
            if (n <= 0) break;
            read += n;
        }

        if (read == 0) return result;
        int lastNewline = Array.LastIndexOf(buffer, (byte)'\n', read - 1);
        if (lastNewline < 0) return result;   // no complete line yet

        var text = Encoding.UTF8.GetString(buffer, 0, lastNewline + 1);
        _position += lastNewline + 1;

        foreach (var raw in text.Split('\n'))
        {
            var ev = EventStore.ParseLine(raw.TrimStart('﻿').TrimEnd('\r'));
            if (ev is not null) result.Add(ev);
        }
        return result;
    }
}
